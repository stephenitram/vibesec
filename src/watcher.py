import time
import os
from pathlib import Path
from typing import Dict, Set, List, Optional, Callable
from rich.console import Console
from rich.panel import Panel

from src.config import VibeSecConfig
from src.heuristics import scan_text_heuristics, should_trigger_llm_scan
from src.llm_scanner import scan_with_ollama
from src.patcher import apply_vulnerability_patch
from src.schemas import Vulnerability

console = Console(force_terminal=True, legacy_windows=False)

IGNORED_DIRS = {
    ".git",
    "venv",
    ".venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".idea",
    ".vscode",
    "build",
    "dist",
    ".next",
    ".nuxt",
}

IGNORED_FILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.lock",
    "cargo.lock",
    "poetry.lock",
    "gemfile.lock",
    "go.sum",
}

# Complete coverage of Frontend, Backend, Mobile, Scripting & Config file formats
SCANNABLE_EXTENSIONS = {
    # Frontend & Web Languages
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".mts",
    ".cts",
    ".jsx",
    ".tsx",
    ".html",
    ".htm",
    ".xhtml",
    ".vue",
    ".svelte",
    ".astro",
    # Template Engines & Dynamic Views
    ".ejs",
    ".hbs",
    ".handlebars",
    ".mustache",
    ".pug",
    ".jade",
    ".jinja",
    ".jinja2",
    ".j2",
    ".twig",
    ".liquid",
    # Styles & UI Assets
    ".css",
    ".scss",
    ".sass",
    ".less",
    # Backend & Server Languages
    ".py",
    ".pyw",
    ".go",
    ".java",
    ".kt",
    ".kts",
    ".scala",
    ".groovy",
    ".cs",
    ".fs",
    ".vb",
    ".php",
    ".phtml",
    ".rb",
    ".erb",
    ".rs",
    ".c",
    ".cpp",
    ".cc",
    ".cxx",
    ".h",
    ".hpp",
    ".hxx",
    ".swift",
    ".m",
    ".mm",
    # Database, Queries & Schemas
    ".sql",
    ".prisma",
    ".graphql",
    ".gql",
    # Shell & DevOps Scripts
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".ps1",
    ".bat",
    ".cmd",
    # Config & Secret Formats
    ".yaml",
    ".yml",
    ".json",
    ".json5",
    ".jsonc",
    ".env",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".config",
    ".xml",
    ".properties",
}


def should_scan_file(file_path: Path) -> bool:
    """Determine if a file should be scanned based on extension, ignored directories, and size."""
    # Ignore build/dependency directories
    for part in file_path.parts:
        if part in IGNORED_DIRS:
            return False

    name_lower = file_path.name.lower()
    if name_lower in IGNORED_FILES:
        return False

    # Ignore minified or source map files
    if name_lower.endswith(".min.js") or name_lower.endswith(".min.css") or name_lower.endswith(".map"):
        return False

    # Dotfiles like .env, .env.local, .env.production
    if name_lower.startswith(".env"):
        return True

    ext = file_path.suffix.lower()
    return ext in SCANNABLE_EXTENSIONS


def audit_single_file(
    file_path: Path,
    root_dir: Path,
    config: VibeSecConfig,
    auto_fix: bool = True,
    on_vuln_callback: Optional[Callable[[Vulnerability, bool], None]] = None,
) -> List[Vulnerability]:
    """Scan and optionally auto-remediate a single file."""
    try:
        if not file_path.is_file():
            return []

        rel_path = file_path.relative_to(root_dir).as_posix()
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []

        if not content.strip():
            return []

        findings = scan_text_heuristics(rel_path, content, line_offset=1)
        if not should_trigger_llm_scan(findings):
            return []

        # Audit with Ollama (or fallback)
        scan_result, used_llm = scan_with_ollama(
            file_path=rel_path,
            diff_or_code=content,
            heuristic_findings=findings,
            config=config,
        )

        detected = scan_result.vulnerabilities
        if not detected:
            return []

        for vuln in detected:
            patched = False
            if auto_fix and vuln.remediation_patch:
                # Apply patch
                patched, _ = apply_vulnerability_patch(vuln, repo_path=root_dir)

            if on_vuln_callback:
                on_vuln_callback(vuln, patched)

        return detected
    except Exception as e:
        console.print(f"[dim red]Error auditing {file_path}: {e}[/dim red]")
        return []


def start_auto_pilot_watcher(
    watch_path: Optional[Path] = None,
    auto_fix: bool = True,
    poll_interval: float = 1.0,
    config: Optional[VibeSecConfig] = None,
):
    """
    Continuous workspace watcher for Vibe Coders.
    Silently audits files when saved and applies auto-patches.
    """
    root_dir = (watch_path or Path.cwd()).resolve()
    cfg = config or VibeSecConfig.load()

    mode_text = "[bold green]SILENT AUTO-FIX[/bold green]" if auto_fix else "[bold yellow]NOTIFY ONLY[/bold yellow]"
    console.print(Panel(
        f"[bold cyan]🤖 VibeSec Auto-Pilot Active[/bold cyan]\n\n"
        f"[dim]Watching:[/dim] [cyan]{root_dir}[/cyan]\n"
        f"[dim]Mode:[/dim] {mode_text}\n"
        f"[dim]Model:[/dim] [bold]{cfg.model}[/bold] | [dim]Press Ctrl+C to stop.[/dim]",
        border_style="cyan",
        title="⚡ VibeSec Live Watcher"
    ))

    # Track file modification timestamps
    file_timestamps: Dict[Path, float] = {}

    # Initial scan of timestamps
    for p in root_dir.rglob("*"):
        if p.is_file() and should_scan_file(p):
            try:
                file_timestamps[p] = p.stat().st_mtime
            except Exception:
                pass

    def handle_vuln(vuln: Vulnerability, patched: bool):
        if patched:
            console.print(f"[bold green]✨ [Auto-Patched][/bold green] {vuln.file_path}:{vuln.line_number or '?'} ➔ [cyan]{vuln.cwe_id}[/cyan] ({vuln.title})")
        else:
            console.print(f"[bold red]⚠️  [Vulnerability Found][/bold red] {vuln.file_path}:{vuln.line_number or '?'} ➔ [yellow]{vuln.cwe_id}[/yellow] ({vuln.title})")

    try:
        while True:
            time.sleep(poll_interval)
            current_files = set()

            for p in root_dir.rglob("*"):
                if not p.is_file() or not should_scan_file(p):
                    continue

                current_files.add(p)
                try:
                    mtime = p.stat().st_mtime
                except Exception:
                    continue

                prev_mtime = file_timestamps.get(p)
                if prev_mtime is None:
                    # New file
                    file_timestamps[p] = mtime
                    audit_single_file(p, root_dir, cfg, auto_fix, handle_vuln)
                elif mtime > prev_mtime:
                    # Modified file
                    file_timestamps[p] = mtime
                    audit_single_file(p, root_dir, cfg, auto_fix, handle_vuln)

            # Cleanup deleted files
            for p in list(file_timestamps.keys()):
                if p not in current_files:
                    file_timestamps.pop(p, None)

    except KeyboardInterrupt:
        console.print("\n[bold yellow]⏹ VibeSec Auto-Pilot stopped.[/bold yellow]")
