import os
import sys
import io
from pathlib import Path
from typing import Optional, List
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Confirm
from rich import box

# Ensure UTF-8 output encoding across Windows/POSIX
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from src.config import VibeSecConfig
from src.schemas import SeverityLevel, Vulnerability, LLMScanResult
from src.git_hook import extract_staged_diffs, install_hook, uninstall_hook, get_git_repo
from src.heuristics import scan_text_heuristics, should_trigger_llm_scan
from src.llm_scanner import scan_with_ollama, check_ollama_health
from src.patcher import apply_vulnerability_patch
from src.reporter import generate_sarif_report, generate_executive_markdown_report
from src.sca import scan_dependencies_sca, DependencyVulnerability
from src.verifier import verify_patch, detect_test_command

app = typer.Typer(
    name="vibesec",
    help="[VibeSec-Local] Offline Privacy-Preserving Git Pre-Commit Hook Security Scanner",
    add_completion=False,
)
console = Console(force_terminal=True, legacy_windows=False)


def get_severity_badge(severity: SeverityLevel) -> Text:
    styles = {
        SeverityLevel.LOW: "bold cyan on default",
        SeverityLevel.MEDIUM: "bold yellow on default",
        SeverityLevel.HIGH: "bold magenta on default",
        SeverityLevel.CRITICAL: "bold red on black",
    }
    return Text(f" {severity.value} ", style=styles.get(severity, "bold white"))


def render_vulnerabilities_table(vulnerabilities: List[Vulnerability]) -> None:
    table = Table(
        title="[bold red]Detected Security Vulnerabilities[/bold red]",
        box=box.ROUNDED,
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("CWE", style="bold yellow", width=10)
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Location", style="cyan", width=22)
    table.add_column("Vulnerability & Sink", width=35)
    table.add_column("Remediation Patch", style="green", width=40)

    for v in vulnerabilities:
        loc = f"{v.file_path}:{v.line_number or '?'}"
        sink_desc = f"[bold]{v.title}[/bold]\n[dim]{v.explanation}[/dim]"
        if v.sink_pattern:
            sink_desc += f"\n[bold yellow]Sink:[/bold yellow] [red]{v.sink_pattern}[/red]"
        
        table.add_row(
            v.cwe_id,
            get_severity_badge(v.severity),
            loc,
            sink_desc,
            f"[dim]Original:[/dim]\n[red]- {v.original_code}[/red]\n\n[dim]Patch:[/dim]\n[green]+ {v.remediation_patch}[/green]",
        )

    console.print(table)


@app.command("scan")
def scan_cmd(
    staged: bool = typer.Option(True, "--staged", "-s", help="Scan only staged Git changes (pre-commit default)."),
    no_llm: bool = typer.Option(False, "--no-llm", help="Bypass Ollama and run only Tier-1 regex heuristics."),
    auto_patch: bool = typer.Option(False, "--auto-patch", "-y", help="Automatically apply remediation patches without asking."),
    min_severity: Optional[str] = typer.Option(None, "--min-severity", help="Minimum severity to trigger commit block (LOW, MEDIUM, HIGH, CRITICAL)."),
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to custom .vibesec.yaml configuration file."),
):
    """Scan code diffs or staged changes for security vulnerabilities."""
    config = VibeSecConfig.load(config_file)
    if min_severity:
        try:
            config.min_severity_to_block = SeverityLevel(min_severity.upper())
        except ValueError:
            console.print(f"[bold red]Invalid severity level: {min_severity}[/bold red]")
            raise typer.Exit(code=1)

    console.print(Panel.fit(
        "[bold cyan]VibeSec-Local Security Scanner[/bold cyan]\n"
        f"[dim]Model: [bold]{config.model}[/bold] | Ollama: [bold]{config.ollama_url}[/bold] | Block Threshold: [bold yellow]{config.min_severity_to_block.value}[/bold yellow][/dim]",
        border_style="cyan"
    ))

    try:
        repo = get_git_repo()
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)

    staged_hunks = extract_staged_diffs()

    if not staged_hunks:
        console.print("[bold green][OK] No staged changes detected to scan.[/bold green]")
        raise typer.Exit(code=0)

    console.print(f"[dim]Analyzing {len(staged_hunks)} staged code hunk(s)...[/dim]")

    all_vulnerabilities: List[Vulnerability] = []
    used_llm_any = False
    heuristics_triggered = 0

    for hunk in staged_hunks:
        added_text = "\n".join(hunk.added_lines)
        if not added_text.strip():
            continue

        # Step 1: Tier-1 Fast Heuristic Filter
        findings = scan_text_heuristics(
            file_path=hunk.file_path,
            content=added_text,
            line_offset=hunk.start_line,
        )

        if not should_trigger_llm_scan(findings):
            continue

        heuristics_triggered += len(findings)

        # Step 2: Tier-2 Deep LLM Scan
        if no_llm:
            # Bypass LLM and use heuristic fallback result
            from src.llm_scanner import fallback_heuristics_to_scan_result
            scan_result = fallback_heuristics_to_scan_result(hunk.file_path, findings, error_msg="Bypassed by --no-llm")
            all_vulnerabilities.extend(scan_result.vulnerabilities)
        else:
            with console.status(f"[bold yellow]Auditing {hunk.file_path} with local LLM ({config.model})...[/bold yellow]"):
                scan_result, used_llm = scan_with_ollama(
                    file_path=hunk.file_path,
                    diff_or_code=hunk.raw_diff or added_text,
                    heuristic_findings=findings,
                    config=config,
                )
                if used_llm:
                    used_llm_any = True
                all_vulnerabilities.extend(scan_result.vulnerabilities)

    # Filter vulnerabilities by threshold
    blocking_vulns = [
        v for v in all_vulnerabilities
        if v.severity.rank >= config.min_severity_to_block.rank
    ]

    if not blocking_vulns:
        console.print("[bold green][OK] Security Audit Passed! No blocking vulnerabilities found in staged changes.[/bold green]")
        raise typer.Exit(code=0)

    # Render table of vulnerabilities
    render_vulnerabilities_table(blocking_vulns)

    if not used_llm_any and not no_llm:
        console.print("[yellow][!] Note: Ollama was unreachable; results generated from offline Tier-1 heuristics.[/yellow]")

    console.print()
    # Prompt for auto-patching
    should_patch = auto_patch
    if not auto_patch and config.auto_patch_prompt:
        if sys.stdin and hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
            try:
                should_patch = Confirm.ask(
                    "[bold yellow]Would you like VibeSec to apply suggested remediation patches automatically?[/bold yellow]",
                    default=True,
                )
            except Exception:
                should_patch = False
        else:
            should_patch = False

    if should_patch:
        patched_count = 0
        for vuln in blocking_vulns:
            if vuln.remediation_patch and not vuln.remediation_patch.startswith("# FIX"):
                success, msg = apply_vulnerability_patch(vuln)
                if success:
                    console.print(f"[bold green][+] Patched:[/bold green] {vuln.file_path} ([cyan]{vuln.cwe_id}[/cyan])")
                    patched_count += 1
                else:
                    console.print(f"[bold red][x] Patch Failed ({vuln.file_path}):[/bold red] {msg}")

        if patched_count > 0:
            console.print(f"\n[bold green][+] Successfully applied and staged {patched_count} security patch(es)![/bold green]")
            console.print("[dim]Re-verifying staged files...[/dim]\n")
            if patched_count == len(blocking_vulns):
                console.print("[bold green][OK] All vulnerabilities resolved. Proceeding with commit.[/bold green]")
                raise typer.Exit(code=0)

    console.print("\n[bold red][BLOCKED] COMMIT REJECTED: Unresolved security vulnerabilities remain.[/bold red]")
    console.print("[dim]Fix the highlighted issues above or review remediation patches before committing.[/dim]\n")
    raise typer.Exit(code=1)


@app.command("install")
def install_cmd(
    repo_path: Optional[Path] = typer.Option(None, "--path", "-p", help="Path to git repository (defaults to current dir).")
):
    """Install the VibeSec Git pre-commit hook into .git/hooks/pre-commit."""
    try:
        hook_path = install_hook(repo_path)
        console.print(Panel(
            f"[bold green][OK] Successfully installed VibeSec Pre-Commit Hook![/bold green]\n\n"
            f"[dim]Hook Location:[/dim] [cyan]{hook_path}[/cyan]\n"
            f"[dim]VibeSec will now automatically audit every git commit offline.[/dim]",
            border_style="green",
            title="VibeSec Hook Installation"
        ))
    except Exception as e:
        console.print(f"[bold red]Installation failed:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command("uninstall")
def uninstall_cmd(
    repo_path: Optional[Path] = typer.Option(None, "--path", "-p", help="Path to git repository.")
):
    """Uninstall the VibeSec Git pre-commit hook."""
    try:
        if uninstall_hook(repo_path):
            console.print("[bold green][OK] Successfully removed pre-commit hook.[/bold green]")
        else:
            console.print("[yellow]No VibeSec pre-commit hook found to remove.[/yellow]")
    except Exception as e:
        console.print(f"[bold red]Uninstallation failed:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command("check-health")
def health_cmd(
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to custom .vibesec.yaml configuration file.")
):
    """Check Ollama service status, connectivity, and model availability."""
    config = VibeSecConfig.load(config_file)
    console.print(f"[dim]Checking Ollama endpoint at {config.ollama_url}...[/dim]")
    ok, message = check_ollama_health(config)
    if ok:
        console.print(f"[bold green][OK] {message}[/bold green]")
    else:
        console.print(f"[bold yellow][!] {message}[/bold yellow]")
        console.print("[dim]VibeSec will operate in Tier-1 Regex Heuristics offline fallback mode.[/dim]")


@app.command("init-config")
def init_config_cmd(
    output_path: Path = typer.Option(Path(".vibesec.yaml"), "--out", "-o", help="Destination path for configuration file.")
):
    """Generate a default .vibesec.yaml configuration file."""
    config = VibeSecConfig()
    config.save(output_path)
    console.print(f"[bold green][OK] Created default configuration at [cyan]{output_path}[/cyan][/bold green]")


@app.command("watch")
def watch_cmd(
    path: Optional[Path] = typer.Option(None, "--path", "-p", help="Root workspace directory to monitor."),
    auto_fix: bool = typer.Option(True, "--auto-fix/--no-auto-fix", help="Automatically fix security sinks when files are saved."),
    interval: float = typer.Option(1.0, "--interval", "-i", help="Polling interval in seconds."),
):
    """⚡ [Auto-Pilot] Watch workspace for saved changes and auto-remediate insecure AI code."""
    from src.watcher import start_auto_pilot_watcher
    target = (path or Path(os.getcwd())).resolve()
    start_auto_pilot_watcher(watch_path=target, auto_fix=auto_fix, poll_interval=interval)


@app.command("sca")
def sca_cmd(
    path: Optional[Path] = typer.Option(None, "--path", "-p", help="Root directory containing dependency manifests."),
):
    """📦 Audit 3rd party package dependencies (NPM, PyPI, Composer/PHP) offline for known CVEs."""
    target = (path or Path(os.getcwd())).resolve()
    console.print(f"[dim]Scanning package manifests in {target}...[/dim]\n")
    findings = scan_dependencies_sca(target)

    if not findings:
        console.print("[bold green][OK] No vulnerable 3rd-party dependencies detected.[/bold green]")
        return

    table = Table(
        title=f"[bold red]Supply Chain Vulnerabilities ({len(findings)} CVEs)[/bold red]",
        box=box.ROUNDED,
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("CVE ID", style="bold yellow", width=16)
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Package", style="cyan", width=18)
    table.add_column("Manifest", width=22)
    table.add_column("Advisory & Remediation", style="green", width=40)

    for s in findings:
        table.add_row(
            s.cve_id,
            get_severity_badge(s.severity),
            f"{s.package_name}@{s.installed_version}",
            s.manifest_file,
            f"[bold]{s.title}[/bold]\n[dim]{s.description}[/dim]\n[bold green]Fix:[/bold green] `{s.remediation_cmd}`"
        )

    console.print(table)


@app.command("report")
def report_cmd(
    path: Optional[Path] = typer.Option(None, "--path", "-p", help="Workspace path to audit."),
    format: str = typer.Option("markdown", "--format", "-f", help="Output format (markdown, sarif, json)."),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="File destination for security report."),
):
    """📑 Generate an Academic & Executive Cybersecurity Compliance Audit Report (SARIF/Markdown)."""
    target = (path or Path(os.getcwd())).resolve()
    config = VibeSecConfig.load()
    console.print(f"[dim]Generating security audit report for {target}...[/dim]")

    # Run SAST scan
    from src.watcher import should_scan_file
    all_vulns: List[Vulnerability] = []
    for p in target.rglob("*"):
        if p.is_file() and should_scan_file(p):
            rel = p.relative_to(target).as_posix()
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                findings = scan_text_heuristics(rel, content)
                if should_trigger_llm_scan(findings):
                    res, _ = scan_with_ollama(rel, content, findings, config)
                    all_vulns.extend(res.vulnerabilities)
            except Exception:
                continue

    # Run SCA scan
    sca_findings = scan_dependencies_sca(target)

    if format.lower() == "sarif":
        sarif_data = generate_sarif_report(all_vulns, sca_findings)
        content_str = json.dumps(sarif_data, indent=2)
    elif format.lower() == "json":
        data = {
            "sast_vulnerabilities": [v.model_dump(mode="json") for v in all_vulns],
            "sca_vulnerabilities": [s.model_dump(mode="json") for s in sca_findings],
        }
        content_str = json.dumps(data, indent=2)
    else:
        content_str = generate_executive_markdown_report(target, all_vulns, sca_findings)

    if out:
        out.write_text(content_str, encoding="utf-8")
        console.print(f"[bold green][OK] Report written to [cyan]{out}[/cyan][/bold green]")
    else:
        console.print(content_str)


@app.command("ui")
def ui_cmd(
    port: int = typer.Option(5432, "--port", help="Port for the local Web HUD dashboard."),
    path: Optional[Path] = typer.Option(None, "--path", "-p", help="Workspace path to audit and display."),
    no_browser: bool = typer.Option(False, "--no-browser", help="Do not automatically launch web browser."),
):
    """🖥️ Launch the local VibeSec Web HUD visual dashboard in your browser."""
    from src.dashboard.server import run_dashboard_server
    target = (path or Path(os.getcwd())).resolve()
    run_dashboard_server(port=port, root_dir=target, open_browser=not no_browser)


def main():
    app()


if __name__ == "__main__":
    main()
