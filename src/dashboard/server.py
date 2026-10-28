import json
import os
import sys
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse, parse_qs

from src.config import VibeSecConfig
from src.heuristics import scan_text_heuristics, should_trigger_llm_scan
from src.llm_scanner import scan_with_ollama, check_ollama_health
from src.patcher import apply_vulnerability_patch
from src.reporter import generate_sarif_report, generate_executive_markdown_report
from src.sca import scan_dependencies_sca, DependencyVulnerability
from src.schemas import Vulnerability
from src.verifier import verify_patch, detect_test_command
from src.watcher import should_scan_file

if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    STATIC_DIR = Path(sys._MEIPASS) / "src" / "dashboard" / "static"
else:
    STATIC_DIR = Path(__file__).parent / "static"


class DashboardState:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir.resolve()
        cfg_path = self.root_dir / ".vibesec.yaml"
        if not cfg_path.exists():
            cfg_path = self.root_dir / ".vibesec.yml"
        self.config = VibeSecConfig.load(config_path=cfg_path if cfg_path.exists() else None)
        self.scan_lock = threading.Lock()
        self.scanned_files_count = 0
        self.total_files_to_scan = 0
        self.current_scanning_file = ""
        self.last_scan_time = None
        self.vulnerabilities: List[Vulnerability] = []
        self.sca_findings: List[DependencyVulnerability] = []
        self.is_scanning = False
        self.has_completed_initial_scan = False

    def start_background_scan(self):
        if not self.is_scanning:
            threading.Thread(target=self.run_full_scan, daemon=True).start()

    def run_full_scan(self) -> Dict[str, Any]:
        with self.scan_lock:
            self.is_scanning = True
            vulns: List[Vulnerability] = []
            scanned_count = 0

            try:
                # 1. Gather all scannable files first to accurately compute progress
                all_files: List[Path] = []
                for p in self.root_dir.rglob("*"):
                    if p.is_file() and should_scan_file(p):
                        all_files.append(p)

                self.total_files_to_scan = len(all_files)
                self.scanned_files_count = 0

                # 2. Iterate and scan each file
                for p in all_files:
                    rel_path = p.relative_to(self.root_dir).as_posix()
                    self.current_scanning_file = rel_path
                    scanned_count += 1
                    self.scanned_files_count = scanned_count

                    try:
                        with open(p, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                    except Exception:
                        continue

                    if not content.strip():
                        continue

                    findings = scan_text_heuristics(rel_path, content, line_offset=1)
                    if not should_trigger_llm_scan(findings):
                        continue

                    scan_result, _ = scan_with_ollama(
                        file_path=rel_path,
                        diff_or_code=content,
                        heuristic_findings=findings,
                        config=self.config,
                    )
                    vulns.extend(scan_result.vulnerabilities)

                self.vulnerabilities = vulns
                self.scanned_files_count = scanned_count
                # Audit 3rd party dependencies (SCA)
                try:
                    self.sca_findings = scan_dependencies_sca(self.root_dir)
                except Exception:
                    self.sca_findings = []

                self.has_completed_initial_scan = True
                self.current_scanning_file = ""
                return self.get_summary()
            finally:
                self.is_scanning = False

    def get_summary(self) -> Dict[str, Any]:
        total_vulns = len(self.vulnerabilities)

        def get_sev_str(v: Vulnerability) -> str:
            if hasattr(v.severity, "value"):
                return str(v.severity.value).upper()
            return str(v.severity).upper()

        crit_count = sum(1 for v in self.vulnerabilities if get_sev_str(v) == "CRITICAL")
        high_count = sum(1 for v in self.vulnerabilities if get_sev_str(v) == "HIGH")
        med_count = sum(1 for v in self.vulnerabilities if get_sev_str(v) == "MEDIUM")
        low_count = sum(1 for v in self.vulnerabilities if get_sev_str(v) == "LOW")

        # Factor SCA supply-chain vulnerabilities into health score
        for sca in self.sca_findings:
            if sca.severity.value == "CRITICAL":
                crit_count += 1
            elif sca.severity.value == "HIGH":
                high_count += 1
            elif sca.severity.value == "MEDIUM":
                med_count += 1
            elif sca.severity.value == "LOW":
                low_count += 1

        # Compute Security Health Score (100 is perfect)
        score = 100
        score -= crit_count * 25
        score -= high_count * 15
        score -= med_count * 5
        score -= low_count * 2
        score = max(0, min(100, score))

        ollama_ok, ollama_msg = check_ollama_health(self.config)

        # Progress calculation
        progress_pct = 0
        if self.total_files_to_scan > 0:
            progress_pct = int((self.scanned_files_count / self.total_files_to_scan) * 100)
        elif self.has_completed_initial_scan:
            progress_pct = 100

        test_runner_detected = detect_test_command(self.root_dir)

        return {
            "health_score": score,
            "total_vulnerabilities": total_vulns,
            "critical": crit_count,
            "high": high_count,
            "medium": med_count,
            "low": low_count,
            "scanned_files": self.scanned_files_count,
            "total_files": self.total_files_to_scan,
            "is_scanning": self.is_scanning,
            "scan_progress": progress_pct,
            "current_file": self.current_scanning_file,
            "has_completed_initial_scan": self.has_completed_initial_scan,
            "test_runner": test_runner_detected,
            "root_dir": str(self.root_dir),
            "ollama_status": {
                "online": ollama_ok,
                "message": ollama_msg,
                "model": self.config.model,
                "url": self.config.ollama_url,
            },
            "vulnerabilities": [v.model_dump(mode="json") for v in self.vulnerabilities],
            "sca_findings": [s.model_dump(mode="json") for s in self.sca_findings],
        }

    def apply_fix(
        self,
        vuln_index: Optional[int] = None,
        cwe_id: Optional[str] = None,
        file_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        patched = 0
        failed = 0
        remaining_vulns = []

        for idx, v in enumerate(self.vulnerabilities):
            match = True
            if vuln_index is not None and idx != vuln_index:
                match = False
            if cwe_id and v.cwe_id != cwe_id:
                match = False
            if file_path and v.file_path != file_path and v.file_path.replace("\\", "/") != file_path.replace("\\", "/"):
                match = False

            if match and v.remediation_patch:
                success, msg = apply_vulnerability_patch(v, repo_path=self.root_dir)
                if success:
                    patched += 1
                else:
                    failed += 1
                    remaining_vulns.append(v)
            else:
                remaining_vulns.append(v)

        self.vulnerabilities = remaining_vulns
        # Run fresh scan over workspace to accurately recompute score and state
        rescan_summary = self.run_full_scan()
        rescan_summary["patched_count"] = patched
        rescan_summary["failed_count"] = failed
        return rescan_summary


from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

class ThreadingDashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def create_handler(state: DashboardState):
    class DashboardHTTPHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # Suppress default server logs for clean terminal

        def send_json(self, data: Any, status: int = 200):
            response_bytes = json.dumps(data).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(response_bytes)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()
            self.wfile.write(response_bytes)

        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()

        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/api/status" or parsed.path == "/api/vulnerabilities":
                self.send_json(state.get_summary())
            elif parsed.path == "/api/report":
                query_params = parse_qs(parsed.query)
                fmt = query_params.get("format", ["markdown"])[0].lower()
                summary = state.get_summary()

                if fmt == "sarif":
                    sarif_data = generate_sarif_report(state.vulnerabilities, state.sca_findings)
                    self.send_json(sarif_data)
                else:
                    md_text = generate_executive_markdown_report(
                        repo_path=state.root_dir,
                        vulnerabilities=state.vulnerabilities,
                        sca_findings=state.sca_findings,
                        health_score=summary.get("health_score", 100),
                    )
                    self.send_json({"report_markdown": md_text, "health_score": summary.get("health_score", 100)})

            elif parsed.path == "/" or parsed.path == "/index.html":
                html_path = STATIC_DIR / "index.html"
                if html_path.exists():
                    with open(html_path, "rb") as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                else:
                    self.send_error(404, "Dashboard HTML not found")
            else:
                self.send_error(404)

        def do_POST(self):
            parsed = urlparse(self.path)
            length_str = self.headers.get("Content-Length")
            payload = {}
            if length_str and length_str.isdigit():
                content_length = int(length_str)
                if content_length > 0:
                    body = self.rfile.read(content_length)
                    try:
                        payload = json.loads(body.decode("utf-8"))
                    except Exception:
                        payload = {}

            if parsed.path == "/api/scan":
                result = state.run_full_scan()
                self.send_json(result)
            elif parsed.path == "/api/fix":
                vuln_index = payload.get("vuln_index")
                cwe_id = payload.get("cwe_id")
                file_path = payload.get("file_path")
                result = state.apply_fix(vuln_index=vuln_index, cwe_id=cwe_id, file_path=file_path)
                self.send_json(result)
            elif parsed.path == "/api/verify":
                vuln_index = payload.get("vuln_index")
                custom_patch = payload.get("custom_patch")
                if vuln_index is not None and 0 <= vuln_index < len(state.vulnerabilities):
                    target_vuln = state.vulnerabilities[vuln_index]
                    passed, res = verify_patch(
                        vuln=target_vuln,
                        custom_patch=custom_patch,
                        repo_path=state.root_dir,
                    )
                    self.send_json(res.model_dump(mode="json"))
                else:
                    self.send_json({"passed": False, "error_summary": "Invalid vulnerability index"}, status=400)
            elif parsed.path == "/api/apply_custom_patch":
                vuln_index = payload.get("vuln_index")
                custom_patch = payload.get("custom_patch")
                if vuln_index is not None and 0 <= vuln_index < len(state.vulnerabilities) and custom_patch:
                    target_vuln = state.vulnerabilities[vuln_index].model_copy()
                    target_vuln.remediation_patch = custom_patch
                    success, msg = apply_vulnerability_patch(target_vuln, repo_path=state.root_dir)
                    rescan = state.run_full_scan()
                    rescan["patch_success"] = success
                    rescan["patch_message"] = msg
                    self.send_json(rescan)
                else:
                    self.send_json({"error": "Invalid patch payload"}, status=400)
            else:
                self.send_error(404)

    return DashboardHTTPHandler


def run_dashboard_server(
    port: int = 5432,
    root_dir: Optional[Path] = None,
    open_browser: bool = True,
):
    """Start the VibeSec Local Web HUD Dashboard."""
    target_dir = (root_dir or Path.cwd()).resolve()
    state = DashboardState(target_dir)

    handler_class = create_handler(state)
    
    try:
        httpd = ThreadingDashboardServer(("127.0.0.1", port), handler_class)
    except OSError:
        # If port is busy, fallback to next available
        port = port + 1
        httpd = ThreadingDashboardServer(("127.0.0.1", port), handler_class)

    url = f"http://localhost:{port}"
    print(f"\n🚀 [VibeSec Web HUD] Running at {url}")
    print("⚡ Press Ctrl+C in terminal to stop dashboard server.\n")

    # Start initial workspace scan in a background thread
    threading.Thread(target=state.run_full_scan, daemon=True).start()

    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n⏹ [VibeSec Web HUD] Stopped.")
        httpd.server_close()

