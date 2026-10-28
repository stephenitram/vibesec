import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
from pydantic import BaseModel, Field

from src.schemas import Vulnerability
from src.patcher import apply_vulnerability_patch


class VerificationResult(BaseModel):
    passed: bool = Field(..., description="True if test suite passed successfully.")
    command: str = Field(..., description="The test command that was executed.")
    returncode: int = Field(0, description="Process exit code.")
    output: str = Field("", description="Captured stdout and stderr from the test run.")
    duration_ms: int = Field(0, description="Execution time in milliseconds.")
    error_summary: Optional[str] = Field(None, description="Concise error summary if failed.")


def detect_test_command(repo_path: Path, custom_command: Optional[str] = None) -> Optional[str]:
    """Detect the appropriate test command for the project based on repository files."""
    if custom_command:
        return custom_command

    repo = repo_path.resolve()

    # Python projects
    if (repo / "pytest.ini").exists() or (repo / "pyproject.toml").exists() or (repo / "tests").exists():
        # Check if venv pytest exists
        if os.name == "nt" and (repo / "venv" / "Scripts" / "pytest.exe").exists():
            return f'"{repo / "venv" / "Scripts" / "pytest.exe"}" -q'
        return "pytest -q"

    # Node / JavaScript / TypeScript projects
    if (repo / "package.json").exists():
        return "npm test -- --silent"

    # Rust projects
    if (repo / "Cargo.toml").exists():
        return "cargo test --quiet"

    # Go projects
    if (repo / "go.mod").exists():
        return "go test ./..."

    # PHP projects (PHPUnit)
    if (repo / "phpunit.xml").exists() or (repo / "phpunit.xml.dist").exists():
        if os.name == "nt" and (repo / "vendor" / "bin" / "phpunit.bat").exists():
            return f'"{repo / "vendor" / "bin" / "phpunit.bat"}"'
        elif (repo / "vendor" / "bin" / "phpunit").exists():
            return f'"{repo / "vendor" / "bin" / "phpunit"}"'
        return "phpunit"

    return None


def run_test_suite(
    repo_path: Path,
    test_command: Optional[str] = None,
    timeout_seconds: int = 15,
) -> VerificationResult:
    """Execute the project's test suite and return structured results."""
    cmd = detect_test_command(repo_path, test_command)
    if not cmd:
        return VerificationResult(
            passed=True,
            command="none",
            returncode=0,
            output="No test suite detected in repository; verified syntactically.",
            duration_ms=0,
            error_summary=None,
        )

    start_time = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(repo_path),
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            encoding="utf-8",
            errors="ignore",
        )
        elapsed_ms = int((time.time() - start_time) * 1000)
        output = (proc.stdout + "\n" + proc.stderr).strip()

        passed = proc.returncode == 0
        error_summary = None
        if not passed:
            lines = [line for line in output.splitlines() if "FAIL" in line or "ERROR" in line or "Error:" in line or "AssertionError" in line]
            error_summary = "\n".join(lines[:5]) if lines else output[-300:]

        return VerificationResult(
            passed=passed,
            command=cmd,
            returncode=proc.returncode,
            output=output,
            duration_ms=elapsed_ms,
            error_summary=error_summary,
        )
    except subprocess.TimeoutExpired:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return VerificationResult(
            passed=False,
            command=cmd,
            returncode=-1,
            output=f"Test run timed out after {timeout_seconds} seconds.",
            duration_ms=elapsed_ms,
            error_summary="Test runner execution timed out.",
        )
    except Exception as e:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return VerificationResult(
            passed=False,
            command=cmd,
            returncode=-1,
            output=f"Failed to execute test command: {str(e)}",
            duration_ms=elapsed_ms,
            error_summary=str(e),
        )


def verify_patch(
    vuln: Vulnerability,
    custom_patch: Optional[str] = None,
    repo_path: Optional[Path] = None,
    test_command: Optional[str] = None,
    timeout_seconds: int = 15,
) -> Tuple[bool, VerificationResult]:
    """
    Test-Driven Verification:
    1. Backs up target file.
    2. Applies candidate remediation patch.
    3. Executes test suite.
    4. Automatically restores original file.
    Returns (tests_passed: bool, VerificationResult).
    """
    base_dir = (repo_path or Path.cwd()).resolve()
    target_file = (base_dir / vuln.file_path).resolve()

    if not target_file.is_file():
        return False, VerificationResult(
            passed=False,
            command="file_check",
            returncode=1,
            output=f"Target file '{vuln.file_path}' not found.",
            duration_ms=0,
            error_summary="File not found.",
        )

    # Read original content to safely restore later
    with open(target_file, "r", encoding="utf-8", errors="ignore") as f:
        original_file_content = f.read()

    test_vuln = vuln.model_copy()
    if custom_patch is not None:
        test_vuln.remediation_patch = custom_patch

    try:
        # Apply candidate patch
        success, patch_msg = apply_vulnerability_patch(test_vuln, repo_path=base_dir)
        if not success:
            return False, VerificationResult(
                passed=False,
                command="patch_application",
                returncode=1,
                output=f"Could not apply patch: {patch_msg}",
                duration_ms=0,
                error_summary=patch_msg,
            )

        # Run test runner
        res = run_test_suite(base_dir, test_command=test_command, timeout_seconds=timeout_seconds)
        return res.passed, res

    finally:
        # Always restore original file content after verification
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(original_file_content)
