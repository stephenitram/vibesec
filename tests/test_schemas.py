import pytest
from src.schemas import SeverityLevel, Vulnerability, LLMScanResult, HeuristicFinding


def test_severity_level_ranking():
    assert SeverityLevel.LOW.rank < SeverityLevel.MEDIUM.rank
    assert SeverityLevel.MEDIUM.rank < SeverityLevel.HIGH.rank
    assert SeverityLevel.HIGH.rank < SeverityLevel.CRITICAL.rank


def test_vulnerability_validation():
    vuln = Vulnerability(
        cwe_id="CWE-89",
        title="SQL Injection",
        severity=SeverityLevel.CRITICAL,
        file_path="src/auth.py",
        line_number=42,
        sink_pattern="cursor.execute",
        explanation="Untrusted input passed to SQL query",
        original_code="cursor.execute(f'SELECT * FROM users WHERE username = \"{user}\"')",
        remediation_patch="cursor.execute('SELECT * FROM users WHERE username = %s', (user,))",
    )
    assert vuln.cwe_id == "CWE-89"
    assert vuln.severity == SeverityLevel.CRITICAL
    assert vuln.line_number == 42


def test_llm_scan_result_validation():
    data = {
        "is_vulnerable": True,
        "summary": "1 Critical SQL injection found",
        "vulnerabilities": [
            {
                "cwe_id": "CWE-89",
                "title": "SQL Injection",
                "severity": "CRITICAL",
                "file_path": "auth.py",
                "line_number": 10,
                "explanation": "SQLi in query",
                "original_code": "SELECT * FROM users WHERE name = " + "foo",
                "remediation_patch": "SELECT * FROM users WHERE name = %s",
            }
        ],
    }
    result = LLMScanResult.model_validate(data)
    assert result.is_vulnerable is True
    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].severity == SeverityLevel.CRITICAL
