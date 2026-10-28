import os
from pathlib import Path
import git
from src.git_hook import install_hook, uninstall_hook, extract_staged_diffs


def test_hook_install_and_uninstall(tmp_path: Path):
    repo = git.Repo.init(tmp_path)
    hook_file = install_hook(tmp_path)
    assert hook_file.exists()
    assert "VibeSec-Local Pre-Commit Hook" in hook_file.read_text(encoding="utf-8")

    uninstalled = uninstall_hook(tmp_path)
    assert uninstalled is True
    assert not hook_file.exists()


def test_extract_staged_diffs(tmp_path: Path):
    repo = git.Repo.init(tmp_path)
    file1 = tmp_path / "hello.py"
    file1.write_text("print('hello world')\n", encoding="utf-8")
    repo.index.add(["hello.py"])

    hunks = extract_staged_diffs(tmp_path)
    assert len(hunks) > 0
    assert hunks[0].file_path == "hello.py"
    assert "print('hello world')" in hunks[0].added_lines
