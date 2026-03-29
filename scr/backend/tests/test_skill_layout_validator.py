from __future__ import annotations

from pathlib import Path

import pytest

from engine import pipeline


def _write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def test_validate_skill_layout_accepts_root_skill_md(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", b"# demo\n")
    pipeline.validate_skill_layout(tmp_path)


def test_validate_skill_layout_accepts_first_level_skill_md(tmp_path: Path) -> None:
    _write(tmp_path / "foo" / "skill.md", b"# demo\n")
    pipeline.validate_skill_layout(tmp_path)


def test_validate_skill_layout_rejects_missing_skill_md(tmp_path: Path) -> None:
    _write(tmp_path / "README.md", b"hello")
    with pytest.raises(ValueError, match=pipeline.SKILL_LAYOUT_INVALID_MISSING_SKILL_MD):
        pipeline.validate_skill_layout(tmp_path)


def test_validate_skill_layout_rejects_deep_only_skill_md(tmp_path: Path) -> None:
    _write(tmp_path / "a" / "b" / "c" / "SKILL.md", b"# deep\n")
    with pytest.raises(ValueError, match=pipeline.SKILL_LAYOUT_INVALID_SKILL_MD_DEPTH):
        pipeline.validate_skill_layout(tmp_path)


def test_validate_skill_layout_rejects_empty_skill_md(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", b"  \n\t")
    with pytest.raises(ValueError, match=pipeline.SKILL_LAYOUT_INVALID_SKILL_MD_EMPTY):
        pipeline.validate_skill_layout(tmp_path)


def test_validate_skill_layout_rejects_non_utf8_skill_md(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", b"\xff\xfe\xfa")
    with pytest.raises(ValueError, match=pipeline.SKILL_LAYOUT_INVALID_SKILL_MD_NOT_UTF8):
        pipeline.validate_skill_layout(tmp_path)


def test_validate_skill_layout_rejects_disguised_names(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md.bak", b"fake")
    _write(tmp_path / "skill.mdx", b"fake")
    with pytest.raises(ValueError, match=pipeline.SKILL_LAYOUT_INVALID_MISSING_SKILL_MD):
        pipeline.validate_skill_layout(tmp_path)


def test_validate_skill_layout_rejects_mixed_top_level_when_skill_in_subdir(tmp_path: Path) -> None:
    _write(tmp_path / "skill-a" / "SKILL.md", b"# demo\n")
    _write(tmp_path / "README.md", b"not a skill package root")
    with pytest.raises(ValueError, match="skill_layout_invalid_package_structure"):
        pipeline.validate_skill_layout(tmp_path)


def test_validate_skill_layout_rejects_multiple_skill_roots(tmp_path: Path) -> None:
    _write(tmp_path / "skill-a" / "SKILL.md", b"# demo\n")
    _write(tmp_path / "skill-b" / "SKILL.md", b"# demo\n")
    with pytest.raises(ValueError, match="skill_layout_invalid_package_structure"):
        pipeline.validate_skill_layout(tmp_path)
