from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from charset_normalizer import ScanReport, scan_tree


def _write(root: Path, name: str, payload: bytes) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def test_empty_directory(tmp_path: Path) -> None:
    rep = scan_tree(tmp_path)

    assert isinstance(rep, ScanReport)
    assert rep.files == 0
    assert rep.encodings == {}
    assert rep.unclear == []


def test_counts_are_consistent(tmp_path: Path) -> None:
    _write(tmp_path, "utf8.txt", ("中文内容" * 200).encode("utf-8"))
    _write(tmp_path, "sub/gbk.txt", ("中文内容" * 200).encode("gbk"))

    rep = scan_tree(tmp_path)

    assert rep.files == 2
    assert sum(rep.encodings.values()) == rep.files
    assert rep.unclear == []


def test_binary_files_are_ignored(tmp_path: Path) -> None:
    _write(tmp_path, "ok.txt", ("中文内容" * 200).encode("utf-8"))
    _write(tmp_path, "payload.bin", b"\x00\x01\x02" * 100)
    _write(tmp_path, "image.png", b"\x89PNG\r\n\x1a\n" + bytes(range(200)))
    _write(tmp_path, "archive.zip", b"PK\x03\x04" + bytes(range(200)))

    rep = scan_tree(tmp_path)

    assert rep.files == 1
    assert rep.unclear == []


def test_undeterminable_text_is_reported(tmp_path: Path) -> None:
    _write(tmp_path, "noise.txt", bytes(range(128, 256)))

    rep = scan_tree(tmp_path)

    assert rep.files == 0
    assert rep.encodings == {}
    assert rep.unclear == ["noise.txt"]


def test_utf16_text_is_counted(tmp_path: Path) -> None:
    _write(tmp_path, "le.txt", ("中文内容测试" * 200).encode("utf-16-le"))
    _write(tmp_path, "bom.txt", ("中文内容测试" * 200).encode("utf-16"))

    rep = scan_tree(tmp_path)

    assert rep.files == 2
    assert sum(rep.encodings.values()) == rep.files
    assert rep.unclear == []


def test_empty_files_are_ignored(tmp_path: Path) -> None:
    _write(tmp_path, "empty.txt", b"")

    rep = scan_tree(tmp_path)

    assert rep.files == 0
    assert rep.unclear == []


def test_relative_paths_keep_subdirectories(tmp_path: Path) -> None:
    _write(tmp_path, "nested/deeper/noise.txt", bytes(range(128, 256)))

    rep = scan_tree(tmp_path)

    assert rep.unclear == ["nested/deeper/noise.txt"]


def test_missing_root_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        scan_tree(tmp_path / "does-not-exist")


def test_file_root_raises(tmp_path: Path) -> None:
    _write(tmp_path, "a.txt", b"hello")

    with pytest.raises(NotADirectoryError):
        scan_tree(tmp_path / "a.txt")


def test_from_path_is_unchanged(tmp_path: Path) -> None:
    import charset_normalizer

    _write(tmp_path, "a.txt", ("中文一" * 200).encode("utf-8"))

    best = charset_normalizer.from_path(str(tmp_path / "a.txt")).best()

    assert best is not None
    assert best.encoding.lower().startswith("utf")
