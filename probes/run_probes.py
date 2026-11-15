#!/usr/bin/env python3
"""目录级编码探测报告验收探针。

契约：
  from charset_normalizer.scan import scan_tree
  rep = scan_tree(root)
  rep.files      扫到的文件数
  rep.encodings  {编码名: 命中文件数}
  rep.unclear    无法判定的文件列表（相对路径）
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

FAILED = 0
PASSED = 0


def check(code, desc, fn):
    global FAILED, PASSED
    try:
        fn()
        print(f"[PASS] {code} {desc}")
        PASSED += 1
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] {code} {desc}")
        print(f"        {type(exc).__name__}: {exc}")
        FAILED += 1


def main():
    try:
        from charset_normalizer.scan import scan_tree  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] P0 导入 charset_normalizer.scan 失败：{type(exc).__name__}: {exc}")
        print("-" * 60)
        print("探针汇总：0/5 通过")
        return 1

    def tree():
        root = Path(tempfile.mkdtemp())
        (root / "a.txt").write_text("中文一" * 200, encoding="utf-8")
        (root / "sub").mkdir()
        (root / "sub" / "b.txt").write_text("中文二" * 200, encoding="gbk")
        (root / "c.bin").write_bytes(b"\x00\x01\x02" * 10)
        return root

    def p1():
        rep = scan_tree(tree())
        assert rep.files == 2, rep.files

    def p2():
        rep = scan_tree(tree())
        assert rep.encodings, rep.encodings
        assert sum(rep.encodings.values()) == rep.files, rep.encodings

    def p3():
        rep = scan_tree(tree())
        assert "c.bin" not in str(rep.unclear), rep.unclear
        assert rep.unclear == [], rep.unclear

    def p4():
        rep = scan_tree(Path(tempfile.mkdtemp()))
        assert rep.files == 0 and rep.encodings == {}, (rep.files, rep.encodings)

    def p5():
        import charset_normalizer
        assert charset_normalizer.from_path(
            str(tree() / "a.txt")).best().encoding.lower().startswith("utf")

    check("P1", "只统计文本文件", p1)
    check("P2", "编码分布计数与总数自洽", p2)
    check("P3", "二进制不进报告", p3)
    check("P4", "空目录", p4)
    check("P5", "既有 from_path 不变", p5)

    print("-" * 60)
    print(f"探针汇总：{PASSED}/{PASSED + FAILED} 通过")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
