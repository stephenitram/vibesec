import time
import threading
import httpx
from pathlib import Path
from src.dashboard.server import run_dashboard_server, DashboardState


from unittest.mock import patch
from src.schemas import LLMScanResult, Vulnerability, SeverityLevel


def test_dashboard_server_endpoints(tmp_path: Path):
    mock_vuln = Vulnerability(
        cwe_id="CWE-798",
        title="Hardcoded Secret Key",
        severity=SeverityLevel.HIGH,
        file_path="login.py",
        line_number=1,
        sink_pattern="API_SECRET_KEY = 'AKIA...'",
        explanation="Detected hardcoded secret key.",
        original_code="API_SECRET_KEY = 'AKIA1234567890EXAMPLEKEY'",
        remediation_patch="API_SECRET_KEY = os.environ.get('API_SECRET_KEY', '')",
    )
    mock_result = LLMScanResult(is_vulnerable=True, summary="Hardcoded secret found", vulnerabilities=[mock_vuln])

    with patch("src.dashboard.server.scan_with_ollama", return_value=(mock_result, True)):
        # Create test vulnerable file
        f = tmp_path / "login.py"
        f.write_text("API_SECRET_KEY = 'AKIA1234567890EXAMPLEKEY'\n", encoding="utf-8")

        # Start dashboard server on port 5499 in a thread
        t = threading.Thread(
            target=run_dashboard_server,
            kwargs={"port": 5499, "root_dir": tmp_path, "open_browser": False},
            daemon=True,
        )
        t.start()
        time.sleep(0.8)

        # Test GET /api/status
        with httpx.Client(base_url="http://127.0.0.1:5499", timeout=10.0) as client:
            res = client.get("/api/status")
            assert res.status_code == 200
            data = res.json()
            assert "health_score" in data
            assert "vulnerabilities" in data

            # Test GET / (HTML)
            res_html = client.get("/")
            assert res_html.status_code == 200
            assert "VibeSec-Local" in res_html.text
            assert "Health Score" in res_html.text

            # Test POST /api/scan
            res_scan = client.post("/api/scan")
            assert res_scan.status_code == 200
            scan_data = res_scan.json()
            assert scan_data["total_vulnerabilities"] > 0

            # Test POST /api/fix
            res_fix = client.post("/api/fix", json={})
            assert res_fix.status_code == 200
