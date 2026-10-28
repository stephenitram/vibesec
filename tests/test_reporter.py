import pytest
from pathlib import Path
from src.schemas import Vulnerability, SeverityLevel
from src.sca import DependencyVulnerability
from src.reporter import generate_sarif_report, generate_executive_markdown_report

def test_generate_sarif_report():
    vuln = Vulnerability(
        cwe_id="CWE-89",
        title="SQL Injection",
        severity=SeverityLevel.HIGH,
        file_path="src/server.py",
        line_number=42,
        explanation="SQL Injection detected in server",
        original_code="cursor.execute(f'SELECT {user_id}')",
        remediation_patch="cursor.execute('SELECT %s', (user_id,))",
    )

    sca = DependencyVulnerability(
        package_name="axios",
        installed_version="0.21.1",
        safe_version="0.21.2",
        cve_id="CVE-2021-3749",
        severity=SeverityLevel.HIGH,
        cvss_score=7.5,
        title="ReDoS in Axios",
        description="ReDoS vulnerability in Axios trim",
        manifest_file="package.json",
        ecosystem="npm",
        remediation_cmd="npm install axios@^1.7.0"
    )

    sarif = generate_sarif_report([vuln], [sca])
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    results = sarif["runs"][0]["results"]
    assert len(results) == 2
    rule_ids = [r["ruleId"] for r in results]
    assert "CWE-89" in rule_ids
    assert "CVE-2021-3749" in rule_ids

def test_generate_executive_markdown_report(tmp_path: Path):
    vuln = Vulnerability(
        cwe_id="CWE-798",
        title="Hardcoded Secret Key",
        severity=SeverityLevel.CRITICAL,
        file_path="src/auth.py",
        line_number=10,
        explanation="Hardcoded Secret Key detected",
        original_code="SECRET_KEY = '12345'",
        remediation_patch="SECRET_KEY = os.environ.get('SECRET_KEY')",
    )

    report = generate_executive_markdown_report(
        repo_path=tmp_path,
        vulnerabilities=[vuln],
        sca_findings=[],
        health_score=85
    )

    assert "# VibeSec Cybersecurity & Code Audit Report" in report
    assert "OWASP Top 10" in report
    assert "CWE-798" in report
    assert "85%" in report
