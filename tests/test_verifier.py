import pytest
from pathlib import Path
from src.schemas import Vulnerability, SeverityLevel
from src.verifier import detect_test_command, run_test_suite, verify_patch, VerificationResult

def test_detect_test_command_custom(tmp_path: Path):
    cmd = detect_test_command(tmp_path, custom_command="npm run test:ci")
    assert cmd == "npm run test:ci"

def test_detect_test_command_python(tmp_path: Path):
    (tmp_path / "tests").mkdir()
    cmd = detect_test_command(tmp_path)
    assert cmd is not None
    assert "pytest" in cmd

def test_detect_test_command_node(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    cmd = detect_test_command(tmp_path)
    assert cmd == "npm test -- --silent"

def test_run_test_suite_no_tests(tmp_path: Path):
    res = run_test_suite(tmp_path)
    assert res.passed is True
    assert res.command == "none"

def test_verify_patch_restores_file(tmp_path: Path):
    target = tmp_path / "app.py"
    original_code = "query = f'SELECT * FROM users WHERE id = {user_id}'\n"
    target.write_text(original_code, encoding="utf-8")

    vuln = Vulnerability(
        cwe_id="CWE-89",
        title="SQL Injection",
        severity=SeverityLevel.HIGH,
        file_path="app.py",
        line_number=1,
        explanation="SQL Injection vulnerability",
        original_code=original_code,
        remediation_patch="query = 'SELECT * FROM users WHERE id = %s'\nparams = (user_id,)\n",
    )

    # Run verify_patch (which should apply patch, test, and restore)
    passed, result = verify_patch(vuln, repo_path=tmp_path, test_command="python -c \"print('ok')\"")
    assert passed is True
    assert result.returncode == 0
    # Crucial assertion: original file content is restored
    assert target.read_text(encoding="utf-8") == original_code
