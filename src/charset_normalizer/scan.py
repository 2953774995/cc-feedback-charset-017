"""
Directory-level encoding survey.

``from_path``/``from_bytes`` answer "what is the encoding of this payload?".
``scan_tree`` answers "what does a whole directory contain?" by walking every
regular file once and aggregating the per-file best guess.

A file is counted in ``ScanReport.encodings`` only when detection produced a
confident match.  Files that look binary (a high share of NUL/control bytes,
or a well-known binary signature) are ignored entirely.  Files that look like
text but that detection could not pin down are reported by relative path in
``ScanReport.unclear`` and are NOT part of ``ScanReport.files``.  Therefore
``files == sum(encodings.values())`` always holds, while the number of text
files seen is ``files + len(unclear)``.
"""

from __future__ import annotations

import logging
import unicodedata
from dataclasses import dataclass, field
from os import PathLike, fspath, walk
from pathlib import Path

from .api import from_bytes
from .models import CharsetMatch

logger = logging.getLogger("charset_normalizer")

# Only the head of a file is inspected by the cheap text/binary heuristic.
# Detection itself always sees the full payload.
_HEURISTIC_SAMPLE_SIZE = 65536

# Bytes that practically never occur in text: NUL, most C0 controls and DEL.
# Tab, LF and CR are deliberately not part of this set; VT and FF are kept
# because they are sometimes used as page separators in legacy exports.
_NON_TEXT_CONTROL_BYTES = frozenset(
    [*range(0x00, 0x09), 0x0B, 0x0C, *range(0x0E, 0x20), 0x7F]
)

# A small share of stray control bytes is tolerated (old exports sometimes
# carry them), a large share means the payload is not text.  In UTF-16/32
# text NUL bytes are expected, so those encodings are validated on the
# decoded string instead.
_MAX_CONTROL_BYTE_RATIO = 0.05

# NUL bytes and most control bytes are legitimate in these encodings, so a
# NUL/control-heavy payload may still be text when detected as such.
_NUL_FRIENDLY_ENCODINGS = frozenset(
    {
        "utf_16",
        "utf_16_le",
        "utf_16_be",
        "utf_32",
        "utf_32_le",
        "utf_32_be",
    }
)

# Above this share of combining marks a NUL/control-heavy payload decoded as
# UTF-16/32 is far more likely to be arbitrary binary data than real text.
_MAX_COMBINING_MARK_RATIO = 0.10

# File signatures that unambiguously denote binary containers.  Very short
# printable-ASCII prefixes that a text file could plausibly start with (e.g.
# "MZ", "RIFF", "ID3") are deliberately left out; such payloads are still
# caught by the control-byte heuristic below.
_BINARY_SIGNATURES = (
    b"\x89PNG\r\n\x1a\n",  # PNG
    b"\xff\xd8\xff",  # JPEG
    b"GIF87a",
    b"GIF89a",
    b"%PDF-",
    b"PK\x03\x04",  # ZIP / docx / xlsx / jar
    b"PK\x05\x06",  # empty ZIP
    b"PK\x07\x08",  # spanned ZIP
    b"\x1f\x8b",  # gzip
    b"BZh",  # bzip2
    b"\xfd7zXZ\x00",  # xz
    b"7z\xbc\xaf\x27\x1c",  # 7z
    b"Rar!\x1a\x07",  # RAR
    b"\x7fELF",
    b"\xca\xfe\xba\xbe",  # Mach-O fat / Java class
    b"\xfe\xed\xfa\xce",  # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit
    b"\xce\xfa\xed\xfe",  # Mach-O 32-bit LE
    b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit LE
    b"SQLite format 3\x00",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",  # OLE2 (doc/xls/msg)
    b"OggS",
    b"fLaC",
    b"\x00asm",  # WebAssembly
)


@dataclass
class ScanReport:
    """Aggregated result of :func:`scan_tree`.

    ``files``
        Number of text files whose encoding could be determined.  Equal to
        ``sum(encodings.values())`` by construction.
    ``encodings``
        IANA encoding name -> number of files, most frequent first.
    ``unclear``
        Relative paths of text-like files whose encoding could not be
        determined, sorted for stable output.
    """

    files: int = 0
    encodings: dict[str, int] = field(default_factory=dict)
    unclear: list[str] = field(default_factory=list)


def _has_binary_signature(payload: bytes) -> bool:
    """Check for a well-known binary container signature."""
    return payload.startswith(_BINARY_SIGNATURES)


def _looks_non_text(payload: bytes) -> bool:
    """Conservative check for payloads that are clearly not text.

    Only called when detection found no candidate at all, or when the payload
    was decoded with an encoding that does not tolerate NUL bytes.  A payload
    with NUL bytes is treated as binary; UTF-16/32 text decodes cleanly and is
    therefore validated on the decoded string instead (see
    :func:`_decoded_looks_binary`).
    """
    sample = payload[:_HEURISTIC_SAMPLE_SIZE]

    control_count = 0
    for byte in sample:
        if byte == 0x00:
            return True
        if byte in _NON_TEXT_CONTROL_BYTES:
            control_count += 1

    return control_count / len(sample) > _MAX_CONTROL_BYTE_RATIO


def _decoded_looks_binary(match: CharsetMatch) -> bool:
    """Check the decoded text of a NUL-friendly match for binary garbage.

    Arbitrary bytes decoded as UTF-16/32 often turn into long runs of
    combining marks or other non-printable characters.  Real text in any
    language stays far below the thresholds used here.
    """
    try:
        text = str(match)
    except UnicodeDecodeError:
        return False

    sample = text[:_HEURISTIC_SAMPLE_SIZE]
    if not sample:
        return False

    marks = 0
    suspicious = 0
    for char in sample:
        category = unicodedata.category(char)
        if category == "Mn":
            marks += 1
        elif category in {"Cc", "Cf", "Cs", "Co", "Cn"} and char not in "\t\n\r":
            suspicious += 1

    return (
        marks / len(sample) > _MAX_COMBINING_MARK_RATIO
        or suspicious / len(sample) > _MAX_CONTROL_BYTE_RATIO
    )


def scan_tree(
    root: str | PathLike[str],
    *,
    threshold: float = 0.20,
) -> ScanReport:
    """Survey the encodings of every regular file below ``root``.

    Symlinks are not followed, empty files are ignored, and unreadable files
    are skipped with a warning.  ``threshold`` is the maximum chaos ratio a
    match may carry to be considered determined, following the default of
    :func:`charset_normalizer.from_bytes`.

    Raises :class:`FileNotFoundError` if ``root`` does not exist and
    :class:`NotADirectoryError` if it is not a directory.
    """
    root_path = Path(fspath(root))

    if not root_path.exists():
        raise FileNotFoundError(f"No such directory: {root_path}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {root_path}")

    counts: dict[str, int] = {}
    unclear: list[str] = []

    for dirpath, dirnames, filenames in walk(root_path, followlinks=False):
        dirnames.sort()

        for filename in sorted(filenames):
            file_path = Path(dirpath) / filename

            if file_path.is_symlink():
                continue

            try:
                payload = file_path.read_bytes()
            except OSError as exc:
                logger.warning("Unable to read %s: %s", file_path, exc)
                continue

            if not payload or _has_binary_signature(payload):
                continue

            best_guess = from_bytes(
                payload,
                threshold=threshold,
                enable_fallback=False,
            ).best()

            if best_guess is None:
                if not _looks_non_text(payload):
                    unclear.append(file_path.relative_to(root_path).as_posix())
                continue

            if best_guess.chaos > threshold:
                unclear.append(file_path.relative_to(root_path).as_posix())
                continue

            # NUL/control bytes are expected in UTF-16/32, so the raw
            # heuristic cannot be used there; inspect the decoded text
            # instead to tell real text from binary garbage.
            if _looks_non_text(payload) and (
                best_guess.encoding not in _NUL_FRIENDLY_ENCODINGS
                or _decoded_looks_binary(best_guess)
            ):
                continue

            counts[best_guess.encoding] = counts.get(best_guess.encoding, 0) + 1

    return ScanReport(
        files=sum(counts.values()),
        encodings=dict(sorted(counts.items(), key=lambda item: (-item[1], item[0]))),
        unclear=unclear,
    )
