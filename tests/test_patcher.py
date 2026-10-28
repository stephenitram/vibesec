import os
from pathlib import Path
import git
from src.schemas import Vulnerability, SeverityLevel
from src.patcher import apply_vulnerability_patch


def test_apply_vulnerability_patch(tmp_path: Path):
    # Initialize a temporary git repo
    repo = git.Repo.init(tmp_path)
    
    test_file = tmp_path / "app.py"
    vulnerable_content = """import sqlite3

def find_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchone()
"""
    test_file.write_text(vulnerable_content, encoding="utf-8")
    repo.index.add(["app.py"])

    vuln = Vulnerability(
        cwe_id="CWE-89",
        title="SQL Injection",
        severity=SeverityLevel.CRITICAL,
        file_path="app.py",
        line_number=6,
        explanation="SQL injection detected",
        original_code="cursor.execute(f\"SELECT * FROM users WHERE name = '{username}'\")",
        remediation_patch="cursor.execute(\"SELECT * FROM users WHERE name = ?\", (username,))",
    )

    success, msg = apply_vulnerability_patch(vuln, repo_path=tmp_path)
    assert success is True
    assert "Successfully applied patch" in msg

    patched_content = test_file.read_text(encoding="utf-8")
    assert "cursor.execute(\"SELECT * FROM users WHERE name = ?\", (username,))" in patched_content
    assert "f\"SELECT * FROM users" not in patched_content
