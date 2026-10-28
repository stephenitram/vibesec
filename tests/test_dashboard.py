import os
from pathlib import Path
from src.dashboard.server import DashboardState


def test_dashboard_state_clean_repo(tmp_path: Path):
    clean_file = tmp_path / "main.py"
    clean_file.write_text("def hello(): return 'world'\n", encoding="utf-8")

    state = DashboardState(tmp_path)
    summary = state.run_full_scan()
    assert summary["health_score"] == 100
    assert summary["total_vulnerabilities"] == 0
    assert summary["critical"] == 0


def test_dashboard_state_with_vulnerabilities(tmp_path: Path):
    vuln_file = tmp_path / "db.py"
    vuln_file.write_text("cursor.execute(f'SELECT * FROM users WHERE id = {uid}')\n", encoding="utf-8")

    state = DashboardState(tmp_path)
    summary = state.run_full_scan()
    assert summary["total_vulnerabilities"] > 0
    assert summary["health_score"] < 100
    assert any(v["cwe_id"] == "CWE-89" for v in summary["vulnerabilities"])
