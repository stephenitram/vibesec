import os
from pathlib import Path
from src.watcher import should_scan_file, audit_single_file
from src.config import VibeSecConfig


def test_should_scan_file():
    assert should_scan_file(Path("src/app.py")) is True
    assert should_scan_file(Path("frontend/index.tsx")) is True
    assert should_scan_file(Path("public/index.html")) is True
    assert should_scan_file(Path(".env")) is True
    assert should_scan_file(Path(".git/config")) is False
    assert should_scan_file(Path("node_modules/express/index.js")) is False
    assert should_scan_file(Path("venv/lib/python3.11/site-packages/pkg.py")) is False
    assert should_scan_file(Path("image.png")) is False


def test_audit_single_file_detects_flaw(tmp_path: Path):
    target = tmp_path / "unsafe.py"
    target.write_text("API_SECRET_KEY = 'AKIA1234567890EXAMPLEKEY'\n", encoding="utf-8")
    
    config = VibeSecConfig()
    detected = audit_single_file(target, tmp_path, config, auto_fix=False)
    assert len(detected) > 0
    assert any(v.cwe_id == "CWE-798" for v in detected)
