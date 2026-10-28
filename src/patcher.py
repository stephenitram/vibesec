import os
import re
from pathlib import Path
from typing import Optional, Tuple
import git
from src.schemas import Vulnerability
from src.git_hook import get_git_repo


def apply_vulnerability_patch(
    vuln: Vulnerability,
    repo_path: Optional[Path] = None,
) -> Tuple[bool, str]:
    """
    Applies the remediation patch to the target source file and re-stages it if inside a Git repo.
    Returns (success: bool, message: str).
    """
    try:
        base_dir = (repo_path or Path.cwd()).resolve()
        repo = None
        try:
            repo = get_git_repo(base_dir)
            base_dir = Path(repo.working_tree_dir).resolve()
        except Exception:
            pass  # Not a git repo, apply directly in base_dir

        target_file = (base_dir / vuln.file_path).resolve()

        if not target_file.is_file():
            # Try direct path if relative resolution failed
            direct_p = Path(vuln.file_path)
            if direct_p.is_file():
                target_file = direct_p.resolve()
            else:
                return False, f"Target file '{vuln.file_path}' does not exist at {target_file}"

        with open(target_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        original_code = vuln.original_code.strip()
        patch_code = vuln.remediation_patch.strip()

        if not original_code or not patch_code:
            return False, "Original code or remediation patch is empty."

        new_content = None

        # Strategy 1: Exact substring replacement
        if original_code in content:
            new_content = content.replace(original_code, patch_code, 1)

        # Strategy 2: Line-based replacement using line number
        if new_content is None and vuln.line_number:
            lines = content.splitlines()
            if 1 <= vuln.line_number <= len(lines):
                target_idx = vuln.line_number - 1
                target_line = lines[target_idx]
                
                # Check if the line matches or contains original_code or sink_pattern
                if original_code in target_line or target_line.strip() == original_code or vuln.sink_pattern in target_line:
                    indentation = " " * (len(target_line) - len(target_line.lstrip()))
                    indented_patch = "\n".join(
                        indentation + p if i > 0 and not p.startswith(" ") else indentation + p if i == 0 and not p.startswith(" ") else p
                        for i, p in enumerate(patch_code.splitlines())
                    )
                    lines[target_idx] = indented_patch
                    new_content = "\n".join(lines) + ("\n" if content.endswith("\n") else "")

        # Strategy 3: Strip whitespace line matching
        if new_content is None:
            lines = content.splitlines()
            matched_idx = -1
            for idx, line in enumerate(lines):
                if original_code in line or line.strip() == original_code or (vuln.sink_pattern and vuln.sink_pattern in line):
                    matched_idx = idx
                    break

            if matched_idx != -1:
                target_line = lines[matched_idx]
                indentation = " " * (len(target_line) - len(target_line.lstrip()))
                indented_patch = "\n".join(
                    indentation + p if i > 0 and not p.startswith(" ") else indentation + p if i == 0 and not p.startswith(" ") else p
                    for i, p in enumerate(patch_code.splitlines())
                )
                lines[matched_idx] = indented_patch
                new_content = "\n".join(lines) + ("\n" if content.endswith("\n") else "")

        # Strategy 4: Regex-based tag replacement for HTML/CSP
        if new_content is None and vuln.cwe_id == "CWE-693" and "<meta" in content:
            new_content = re.sub(
                r"""<meta\s+[^>]*?http-equiv=["']Content-Security-Policy["'][^>]*?>""",
                patch_code,
                content,
                count=1,
                flags=re.IGNORECASE | re.DOTALL,
            )

        if new_content is None:
            return False, f"Could not locate matching code block to patch in '{vuln.file_path}'."

        # Write updated content
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(new_content)

        # If inside a Git repository, stage changes
        if repo is not None:
            try:
                rel_git_path = target_file.relative_to(base_dir).as_posix()
                repo.git.add(rel_git_path)
            except Exception:
                pass

        return True, f"Successfully applied patch to '{vuln.file_path}'."

    except Exception as e:
        return False, f"Failed to apply patch: {str(e)}"
