import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field

from src.schemas import SeverityLevel


class DependencyVulnerability(BaseModel):
    package_name: str = Field(..., description="Vulnerable dependency package name.")
    installed_version: str = Field(..., description="Currently installed / declared version.")
    safe_version: str = Field(..., description="Recommended safe upgrade version.")
    cve_id: str = Field(..., description="CVE or GHSA security identifier.")
    severity: SeverityLevel = Field(..., description="Severity level (CRITICAL, HIGH, MEDIUM, LOW).")
    cvss_score: float = Field(..., description="CVSS v3 vulnerability score (0.0 to 10.0).")
    title: str = Field(..., description="Short vulnerability advisory title.")
    description: str = Field(..., description="Advisory description and risk explanation.")
    manifest_file: str = Field(..., description="Manifest file where dependency was found.")
    ecosystem: str = Field(..., description="Package ecosystem (npm, pypi, cargo, golang).")
    remediation_cmd: str = Field(..., description="Command to upgrade the package safely.")


# Curated high-impact offline advisory database for prevalent dependencies in startup & AI stacks
CURATED_OFFLINE_ADVISORIES: List[Dict[str, Any]] = [
    # NPM Ecosystem
    {
        "ecosystem": "npm",
        "package": "axios",
        "vulnerable_below": "0.21.2",
        "safe_version": "0.21.2",
        "cve": "CVE-2021-3749",
        "severity": SeverityLevel.HIGH,
        "cvss": 7.5,
        "title": "Regular Expression Denial of Service (ReDoS) in Axios",
        "description": "Insecure regex in data trimming allows remote attackers to cause denial of service via large payloads.",
        "remediation_cmd": "npm install axios@^1.7.0",
    },
    {
        "ecosystem": "npm",
        "package": "jsonwebtoken",
        "vulnerable_below": "9.0.0",
        "safe_version": "9.0.0",
        "cve": "CVE-2022-23529",
        "severity": SeverityLevel.CRITICAL,
        "cvss": 9.8,
        "title": "Remote Code Execution via Insecure Secret Key Object in jsonwebtoken",
        "description": "Crafted key objects passed to verify() can lead to arbitrary code execution on Node.js backend.",
        "remediation_cmd": "npm install jsonwebtoken@^9.0.2",
    },
    {
        "ecosystem": "npm",
        "package": "lodash",
        "vulnerable_below": "4.17.21",
        "safe_version": "4.17.21",
        "cve": "CVE-2021-23337",
        "severity": SeverityLevel.HIGH,
        "cvss": 7.2,
        "title": "Command Injection / Prototype Pollution in Lodash",
        "description": "Unsanitized template utilities allow prototype pollution and potential command injection.",
        "remediation_cmd": "npm install lodash@^4.17.21",
    },
    {
        "ecosystem": "npm",
        "package": "express",
        "vulnerable_below": "4.19.2",
        "safe_version": "4.19.2",
        "cve": "CVE-2024-29041",
        "severity": SeverityLevel.MEDIUM,
        "cvss": 6.5,
        "title": "Open Redirect via Malformed URLs in Express",
        "description": "Express fails to properly sanitize encoded routing destinations, enabling client-side redirection.",
        "remediation_cmd": "npm install express@^4.21.0",
    },
    {
        "ecosystem": "npm",
        "package": "tar",
        "vulnerable_below": "6.2.1",
        "safe_version": "6.2.1",
        "cve": "CVE-2024-28863",
        "severity": SeverityLevel.HIGH,
        "cvss": 8.1,
        "title": "Arbitrary File Overwrite via Path Traversal in node-tar",
        "description": "Symlink traversal allows malicious archive unpacking to overwrite sensitive files outside destination.",
        "remediation_cmd": "npm install tar@^6.2.1",
    },
    {
        "ecosystem": "npm",
        "package": "axios",
        "vulnerable_below": "1.7.4",
        "safe_version": "1.7.4",
        "cve": "CVE-2024-39338",
        "severity": SeverityLevel.HIGH,
        "cvss": 7.5,
        "title": "Server-Side Request Forgery (SSRF) via Protocol Smuggling in Axios",
        "description": "Insecure handling of relative URLs in Axios client allows SSRF attacks to internal endpoints.",
        "remediation_cmd": "npm install axios@^1.7.4",
    },
    {
        "ecosystem": "npm",
        "package": "next",
        "vulnerable_below": "14.1.1",
        "safe_version": "14.1.1",
        "cve": "CVE-2024-34351",
        "severity": SeverityLevel.HIGH,
        "cvss": 7.5,
        "title": "Server-Side Request Forgery (SSRF) in Next.js Server Actions",
        "description": "Host header poisoning in Next.js Server Actions redirects internal requests to attacker-controlled origins.",
        "remediation_cmd": "npm install next@^14.1.1",
    },
    {
        "ecosystem": "npm",
        "package": "micromatch",
        "vulnerable_below": "4.0.8",
        "safe_version": "4.0.8",
        "cve": "CVE-2024-4067",
        "severity": SeverityLevel.HIGH,
        "cvss": 7.5,
        "title": "Regular Expression Denial of Service (ReDoS) in Micromatch",
        "description": "Catastrophic backtracking in regex parsing allows remote attackers to freeze the Node.js event loop.",
        "remediation_cmd": "npm install micromatch@^4.0.8",
    },
    # Python Ecosystem
    {
        "ecosystem": "pypi",
        "package": "requests",
        "vulnerable_below": "2.31.0",
        "safe_version": "2.31.0",
        "cve": "CVE-2023-32681",
        "severity": SeverityLevel.MEDIUM,
        "cvss": 6.1,
        "title": "Proxy Authorization Header Leakage on Cross-Origin Redirects",
        "description": "Requests forwards Authorization headers to unintended HTTPS destinations upon redirect.",
        "remediation_cmd": "pip install --upgrade requests>=2.32.0",
    },
    {
        "ecosystem": "pypi",
        "package": "cryptography",
        "vulnerable_below": "42.0.4",
        "safe_version": "42.0.4",
        "cve": "CVE-2024-26130",
        "severity": SeverityLevel.HIGH,
        "cvss": 7.5,
        "title": "NULL Pointer Dereference / Crash in PKCS#7 Decryption",
        "description": "Improper handling of invalid encrypted PKCS#7 data leads to memory corruption and process termination.",
        "remediation_cmd": "pip install --upgrade cryptography>=43.0.0",
    },
    {
        "ecosystem": "pypi",
        "package": "jinja2",
        "vulnerable_below": "3.1.4",
        "safe_version": "3.1.4",
        "cve": "CVE-2024-34064",
        "severity": SeverityLevel.MEDIUM,
        "cvss": 5.4,
        "title": "HTML Attribute Injection / Cross-Site Scripting in Jinja2",
        "description": "Flawed XML/HTML attribute escaping in xmlattr filter enables cross-site scripting attacks.",
        "remediation_cmd": "pip install --upgrade jinja2>=3.1.4",
    },
    {
        "ecosystem": "pypi",
        "package": "urllib3",
        "vulnerable_below": "2.2.2",
        "safe_version": "2.2.2",
        "cve": "CVE-2024-37891",
        "severity": SeverityLevel.HIGH,
        "cvss": 7.5,
        "title": "Proxy-Authorization Header Proxy Leakage in urllib3",
        "description": "urllib3 strips Authorization headers on 303 redirects but retains Proxy-Authorization headers.",
        "remediation_cmd": "pip install --upgrade urllib3>=2.2.2",
    },
    {
        "ecosystem": "pypi",
        "package": "pyyaml",
        "vulnerable_below": "5.4",
        "safe_version": "5.4",
        "cve": "CVE-2020-14343",
        "severity": SeverityLevel.CRITICAL,
        "cvss": 9.8,
        "title": "Arbitrary Code Execution via FullLoader in PyYAML",
        "description": "Unsafe deserialization allows attackers to execute arbitrary commands when parsing untrusted YAML documents.",
        "remediation_cmd": "pip install --upgrade pyyaml>=6.0.1",
    },
    {
        "ecosystem": "pypi",
        "package": "starlette",
        "vulnerable_below": "0.40.0",
        "safe_version": "0.40.0",
        "cve": "CVE-2024-47875",
        "severity": SeverityLevel.HIGH,
        "cvss": 7.5,
        "title": "Denial of Service (DoS) via Multipart Form Boundaries in Starlette",
        "description": "Malicious multipart payloads consume excessive CPU and memory during boundary matching.",
        "remediation_cmd": "pip install --upgrade starlette>=0.40.0",
    },
    {
        "ecosystem": "pypi",
        "package": "langchain-core",
        "vulnerable_below": "0.1.30",
        "safe_version": "0.1.30",
        "cve": "CVE-2024-28088",
        "severity": SeverityLevel.CRITICAL,
        "cvss": 9.3,
        "title": "Arbitrary Code Execution via Unsafe Prompt Template Format in LangChain",
        "description": "Evaluation of malicious prompt template variables leads to arbitrary Python code execution.",
        "remediation_cmd": "pip install --upgrade langchain-core>=0.1.30",
    },
    {
        "ecosystem": "pypi",
        "package": "ollama",
        "vulnerable_below": "0.1.34",
        "safe_version": "0.1.34",
        "cve": "CVE-2024-37032",
        "severity": SeverityLevel.CRITICAL,
        "cvss": 9.8,
        "title": "Probllama: Remote Code Execution via Path Traversal in Ollama API",
        "description": "Unsanitized digest inputs in Ollama model pull API allow arbitrary file write and remote code execution.",
        "remediation_cmd": "pip install --upgrade ollama>=0.1.34",
    },
    # PHP & Composer Ecosystem (Core Runtime & Libraries)
    {
        "ecosystem": "composer",
        "package": "php",
        "vulnerable_below": "8.5.12",
        "safe_version": "8.5.12",
        "branch_safe_versions": {
            "8.2": "8.2.35",
            "8.3": "8.3.36",
            "8.4": "8.4.27",
            "8.5": "8.5.12",
        },
        "cve": "CVE-2026-109618",
        "severity": SeverityLevel.CRITICAL,
        "cvss": 9.2,
        "title": "Remote Code Execution via Out-of-Memory Uninitialized State (PHP2Shell)",
        "description": "PHP engine longjmp() OOM error handling leaves request memory in an uninitialized state, allowing unauthenticated attackers to trigger remote code execution.",
        "remediation_cmd": "Upgrade PHP runtime to >=8.5.12, >=8.4.27, >=8.3.36, or >=8.2.35",
    },
    {
        "ecosystem": "composer",
        "package": "php",
        "vulnerable_below": "8.5.12",
        "safe_version": "8.5.12",
        "branch_safe_versions": {
            "8.2": "8.2.35",
            "8.3": "8.3.36",
            "8.4": "8.4.27",
            "8.5": "8.5.12",
        },
        "cve": "CVE-2026-109619",
        "severity": SeverityLevel.CRITICAL,
        "cvss": 9.2,
        "title": "Remote Code Execution via Stale Global State Use-After-Free (PHP2Shell)",
        "description": "Persistent PHP worker processes (mod_php, PHP-FPM) retain request-bound pointers across requests, leading to heap use-after-free and remote code execution.",
        "remediation_cmd": "Upgrade PHP runtime to >=8.5.12, >=8.4.27, >=8.3.36, or >=8.2.35",
    },
    {
        "ecosystem": "composer",
        "package": "php",
        "vulnerable_below": "8.3.8",
        "safe_version": "8.3.8",
        "branch_safe_versions": {
            "8.1": "8.1.29",
            "8.2": "8.2.20",
            "8.3": "8.3.8",
        },
        "cve": "CVE-2024-4577",
        "severity": SeverityLevel.CRITICAL,
        "cvss": 9.8,
        "title": "PHP-CGI Windows Unicode Best-Fit Command Argument Injection RCE",
        "description": "Windows best-fit character mapping allows unauthenticated remote attackers to inject command line arguments into php-cgi.exe and execute arbitrary code.",
        "remediation_cmd": "Upgrade PHP to >=8.3.8, >=8.2.20, or >=8.1.29 and migrate from CGI to FastCGI/PHP-FPM",
    },
    {
        "ecosystem": "composer",
        "package": "php",
        "vulnerable_below": "8.3.12",
        "safe_version": "8.3.12",
        "branch_safe_versions": {
            "8.1": "8.1.30",
            "8.2": "8.2.24",
            "8.3": "8.3.12",
        },
        "cve": "CVE-2024-8926",
        "severity": SeverityLevel.CRITICAL,
        "cvss": 9.8,
        "title": "PHP Windows Best-Fit Codepage Argument Injection Bypass",
        "description": "Incomplete fix for CVE-2024-4577 allows command-line option injection and RCE on Windows with non-standard codepages.",
        "remediation_cmd": "Upgrade PHP to >=8.3.12, >=8.2.24, or >=8.1.30",
    },
    {
        "ecosystem": "composer",
        "package": "php",
        "vulnerable_below": "8.3.12",
        "safe_version": "8.3.12",
        "branch_safe_versions": {
            "8.1": "8.1.30",
            "8.2": "8.2.24",
            "8.3": "8.3.12",
        },
        "cve": "CVE-2024-8927",
        "severity": SeverityLevel.HIGH,
        "cvss": 9.1,
        "title": "PHP-CGI cgi.force_redirect Bypass via Environment Variable Collision",
        "description": "Spoofing HTTP_REDIRECT_STATUS environment variables allows bypassing cgi.force_redirect directives to directly access the PHP-CGI binary.",
        "remediation_cmd": "Upgrade PHP to >=8.3.12, >=8.2.24, or >=8.1.30",
    },
    {
        "ecosystem": "composer",
        "package": "php",
        "vulnerable_below": "8.3.8",
        "safe_version": "8.3.8",
        "branch_safe_versions": {
            "8.1": "8.1.29",
            "8.2": "8.2.20",
            "8.3": "8.3.8",
        },
        "cve": "CVE-2024-5585",
        "severity": SeverityLevel.CRITICAL,
        "cvss": 9.8,
        "title": "Command Injection via proc_open Trailing Space on Windows",
        "description": "Command names with trailing whitespace in proc_open() bypass argument escaping on Windows, allowing arbitrary command execution.",
        "remediation_cmd": "Upgrade PHP to >=8.3.8, >=8.2.20, or >=8.1.29",
    },
    {
        "ecosystem": "composer",
        "package": "php",
        "vulnerable_below": "8.3.8",
        "safe_version": "8.3.8",
        "branch_safe_versions": {
            "8.1": "8.1.29",
            "8.2": "8.2.20",
            "8.3": "8.3.8",
        },
        "cve": "CVE-2024-5458",
        "severity": SeverityLevel.HIGH,
        "cvss": 7.5,
        "title": "URL Validation Logic Bypass in filter_var (FILTER_VALIDATE_URL)",
        "description": "Logic error in PHP URL validation allows malformed URLs with special characters to pass validation, enabling SSRF.",
        "remediation_cmd": "Upgrade PHP to >=8.3.8, >=8.2.20, or >=8.1.29",
    },
    {
        "ecosystem": "composer",
        "package": "guzzlehttp/guzzle",
        "vulnerable_below": "7.4.5",
        "safe_version": "7.4.5",
        "cve": "CVE-2022-31090",
        "severity": SeverityLevel.HIGH,
        "cvss": 7.5,
        "title": "Sensitive Header Leakage on Cross-Origin Redirect in Guzzle",
        "description": "Guzzle forwards Authorization or sensitive headers to third-party domains on redirects.",
        "remediation_cmd": "composer require guzzlehttp/guzzle:^7.4.5",
    },
    {
        "ecosystem": "composer",
        "package": "phpunit/phpunit",
        "vulnerable_below": "9.5.3",
        "safe_version": "9.5.3",
        "cve": "CVE-2021-26180",
        "severity": SeverityLevel.HIGH,
        "cvss": 8.8,
        "title": "Remote Code Execution via Insecure Evaluation in PHPUnit",
        "description": "Vulnerable PHPUnit test runner versions allow arbitrary PHP code execution via insecure test runner invocations.",
        "remediation_cmd": "composer require --dev phpunit/phpunit:^9.5.3",
    },
    {
        "ecosystem": "composer",
        "package": "twig/twig",
        "vulnerable_below": "3.4.4",
        "safe_version": "3.4.4",
        "cve": "CVE-2022-24894",
        "severity": SeverityLevel.HIGH,
        "cvss": 7.5,
        "title": "Template Context Leakage / Code Injection in Twig",
        "description": "Unsanitized variables in Twig template contexts allow unintended expression evaluation.",
        "remediation_cmd": "composer require twig/twig:^3.4.4",
    },
    {
        "ecosystem": "composer",
        "package": "laravel/framework",
        "vulnerable_below": "10.48.16",
        "safe_version": "10.48.16",
        "cve": "CVE-2024-40638",
        "severity": SeverityLevel.HIGH,
        "cvss": 7.5,
        "title": "SQL Injection in Laravel Validation Database Rules",
        "description": "Improper input sanitization in certain database validation rule queries allows SQL injection.",
        "remediation_cmd": "composer require laravel/framework:^10.48.16",
    },
]


def compare_versions(v1: str, v2: str) -> int:
    """Compare two semantic version strings (e.g., '1.2.3' vs '1.2.4'). Returns -1 if v1 < v2, 1 if v1 > v2, 0 if equal."""
    def normalize(v):
        cleaned = re.sub(r"[^0-9\.]", "", v).split(".")
        return [int(x) if x.isdigit() else 0 for x in cleaned if x]

    p1, p2 = normalize(v1), normalize(v2)
    max_len = max(len(p1), len(p2))
    p1 += [0] * (max_len - len(p1))
    p2 += [0] * (max_len - len(p2))

    if p1 < p2:
        return -1
    elif p1 > p2:
        return 1
    return 0


def is_version_vulnerable(installed: str, advisory: Dict[str, Any]) -> Tuple[bool, str]:
    """Check if an installed version is vulnerable according to the advisory, respecting release branches."""
    branch_map = advisory.get("branch_safe_versions")
    if branch_map:
        clean_installed = re.sub(r"[^0-9\.]", "", installed)
        parts = clean_installed.split(".") if clean_installed else []
        if len(parts) >= 2:
            branch = f"{parts[0]}.{parts[1]}"
            if branch in branch_map:
                target_safe = branch_map[branch]
                if compare_versions(installed, target_safe) < 0:
                    return True, target_safe
                return False, advisory["safe_version"]
            # If installed branch is older than any branch in branch_map, it's vulnerable to all
            min_branch = min(branch_map.keys(), key=lambda b: [int(x) for x in b.split(".")])
            if compare_versions(branch, min_branch) < 0:
                return True, advisory["safe_version"]
            # If installed branch is newer than all branches in branch_map, it is patched
            max_branch = max(branch_map.keys(), key=lambda b: [int(x) for x in b.split(".")])
            if compare_versions(branch, max_branch) > 0:
                return False, advisory["safe_version"]

    if compare_versions(installed, advisory["vulnerable_below"]) < 0:
        return True, advisory["safe_version"]
    return False, advisory["safe_version"]


def parse_package_json(path: Path) -> List[Tuple[str, str]]:
    """Extract (package_name, version) from package.json."""
    packages = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        all_deps = {}
        all_deps.update(data.get("dependencies", {}))
        all_deps.update(data.get("devDependencies", {}))
        for pkg, ver in all_deps.items():
            clean_ver = re.sub(r"[\^~>=<]", "", str(ver)).strip()
            if clean_ver:
                packages.append((pkg.lower(), clean_ver))
    except Exception:
        pass
    return packages


def parse_requirements_txt(path: Path) -> List[Tuple[str, str]]:
    """Extract (package_name, version) from requirements.txt."""
    packages = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for line in lines:
            line = line.strip().split("#")[0]
            if not line:
                continue
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=)\s*([0-9\.]+)", line)
            if match:
                packages.append((match.group(1).lower(), match.group(2)))
    except Exception:
        pass
    return packages


def parse_composer_json(path: Path) -> List[Tuple[str, str]]:
    """Extract (package_name, version) from composer.json."""
    packages = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        all_deps = {}
        # Also check config.platform for runtime pins like "php": "8.2.0"
        platform = data.get("config", {}).get("platform", {})
        if isinstance(platform, dict):
            all_deps.update(platform)
        all_deps.update(data.get("require", {}))
        all_deps.update(data.get("require-dev", {}))
        for pkg, ver in all_deps.items():
            ver_str = str(ver).strip()
            ver_clean = re.sub(r"[~^><=\*]", "", ver_str).strip()
            m = re.search(r"(\d+(?:\.\d+)*)", ver_clean)
            if m:
                clean_ver = m.group(1)
                parts = clean_ver.split(".")
                while len(parts) < 3:
                    parts.append("0")
                packages.append((pkg.lower(), ".".join(parts)))
    except Exception:
        pass
    return packages


def parse_composer_lock(path: Path) -> List[Tuple[str, str]]:
    """Extract (package_name, version) from composer.lock."""
    packages = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        platform = data.get("platform", {})
        if isinstance(platform, dict):
            for pkg, ver in platform.items():
                m = re.search(r"(\d+(?:\.\d+)*)", str(ver))
                if m:
                    clean_ver = m.group(1)
                    parts = clean_ver.split(".")
                    while len(parts) < 3:
                        parts.append("0")
                    packages.append((pkg.lower(), ".".join(parts)))

        for section in ["packages", "packages-dev"]:
            for item in data.get(section, []):
                pkg_name = item.get("name", "")
                ver_str = item.get("version", "")
                m = re.search(r"(\d+(?:\.\d+)*)", str(ver_str))
                if pkg_name and m:
                    clean_ver = m.group(1)
                    parts = clean_ver.split(".")
                    while len(parts) < 3:
                        parts.append("0")
                    packages.append((pkg_name.lower(), ".".join(parts)))
    except Exception:
        pass
    return packages


def parse_php_version_file(path: Path) -> List[Tuple[str, str]]:
    """Extract ('php', version) from .php-version file."""
    packages = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore").strip()
        m = re.search(r"(\d+(?:\.\d+)*)", content)
        if m:
            clean_ver = m.group(1)
            parts = clean_ver.split(".")
            while len(parts) < 3:
                parts.append("0")
            packages.append(("php", ".".join(parts)))
    except Exception:
        pass
    return packages


def scan_dependencies_sca(repo_path: Path) -> List[DependencyVulnerability]:
    """Audit all workspace manifests (package.json, requirements.txt, composer.json, composer.lock, .php-version) for known CVEs."""
    findings: List[DependencyVulnerability] = []
    repo = repo_path.resolve()

    # 1. Audit package.json files
    for pkg_json in repo.rglob("package.json"):
        if "node_modules" in str(pkg_json) or ".git" in str(pkg_json):
            continue
        rel_path = pkg_json.relative_to(repo).as_posix()
        for pkg_name, installed_ver in parse_package_json(pkg_json):
            for adv in CURATED_OFFLINE_ADVISORIES:
                if adv["ecosystem"] == "npm" and adv["package"].lower() == pkg_name:
                    is_vuln, safe_ver = is_version_vulnerable(installed_ver, adv)
                    if is_vuln:
                        if not any(f.manifest_file == rel_path and f.cve_id == adv["cve"] for f in findings):
                            findings.append(
                                DependencyVulnerability(
                                    package_name=pkg_name,
                                    installed_version=installed_ver,
                                    safe_version=safe_ver,
                                    cve_id=adv["cve"],
                                    severity=adv["severity"],
                                    cvss_score=adv["cvss"],
                                    title=adv["title"],
                                    description=adv["description"],
                                    manifest_file=rel_path,
                                    ecosystem=adv["ecosystem"],
                                    remediation_cmd=adv["remediation_cmd"],
                                )
                            )

    # 2. Audit requirements.txt files
    for req_txt in repo.rglob("requirements*.txt"):
        if "venv" in str(req_txt) or ".git" in str(req_txt) or ".pytest_cache" in str(req_txt):
            continue
        rel_path = req_txt.relative_to(repo).as_posix()
        for pkg_name, installed_ver in parse_requirements_txt(req_txt):
            for adv in CURATED_OFFLINE_ADVISORIES:
                if adv["ecosystem"] == "pypi" and adv["package"].lower() == pkg_name:
                    is_vuln, safe_ver = is_version_vulnerable(installed_ver, adv)
                    if is_vuln:
                        if not any(f.manifest_file == rel_path and f.cve_id == adv["cve"] for f in findings):
                            findings.append(
                                DependencyVulnerability(
                                    package_name=pkg_name,
                                    installed_version=installed_ver,
                                    safe_version=safe_ver,
                                    cve_id=adv["cve"],
                                    severity=adv["severity"],
                                    cvss_score=adv["cvss"],
                                    title=adv["title"],
                                    description=adv["description"],
                                    manifest_file=rel_path,
                                    ecosystem=adv["ecosystem"],
                                    remediation_cmd=adv["remediation_cmd"],
                                )
                            )

    # 3. Audit PHP / Composer manifests (composer.json, composer.lock, .php-version)
    scanned_composer_dirs = set()
    for comp_json in repo.rglob("composer.json"):
        if "vendor" in str(comp_json) or ".git" in str(comp_json):
            continue
        scanned_composer_dirs.add(comp_json.parent)
        rel_path = comp_json.relative_to(repo).as_posix()
        for pkg_name, installed_ver in parse_composer_json(comp_json):
            for adv in CURATED_OFFLINE_ADVISORIES:
                if adv["ecosystem"] == "composer" and adv["package"].lower() == pkg_name:
                    is_vuln, safe_ver = is_version_vulnerable(installed_ver, adv)
                    if is_vuln:
                        if not any(f.manifest_file == rel_path and f.cve_id == adv["cve"] for f in findings):
                            findings.append(
                                DependencyVulnerability(
                                    package_name=pkg_name,
                                    installed_version=installed_ver,
                                    safe_version=safe_ver,
                                    cve_id=adv["cve"],
                                    severity=adv["severity"],
                                    cvss_score=adv["cvss"],
                                    title=adv["title"],
                                    description=adv["description"],
                                    manifest_file=rel_path,
                                    ecosystem=adv["ecosystem"],
                                    remediation_cmd=adv["remediation_cmd"],
                                )
                            )

    # If composer.lock exists without composer.json or provides lock-level audit
    for comp_lock in repo.rglob("composer.lock"):
        if "vendor" in str(comp_lock) or ".git" in str(comp_lock):
            continue
        rel_path = comp_lock.relative_to(repo).as_posix()
        for pkg_name, installed_ver in parse_composer_lock(comp_lock):
            for adv in CURATED_OFFLINE_ADVISORIES:
                if adv["ecosystem"] == "composer" and adv["package"].lower() == pkg_name:
                    is_vuln, safe_ver = is_version_vulnerable(installed_ver, adv)
                    if is_vuln:
                        if not any(f.cve_id == adv["cve"] for f in findings):
                            findings.append(
                                DependencyVulnerability(
                                    package_name=pkg_name,
                                    installed_version=installed_ver,
                                    safe_version=safe_ver,
                                    cve_id=adv["cve"],
                                    severity=adv["severity"],
                                    cvss_score=adv["cvss"],
                                    title=adv["title"],
                                    description=adv["description"],
                                    manifest_file=rel_path,
                                    ecosystem=adv["ecosystem"],
                                    remediation_cmd=adv["remediation_cmd"],
                                )
                            )

    # Check standalone .php-version files
    for php_ver_file in repo.rglob(".php-version"):
        if "vendor" in str(php_ver_file) or ".git" in str(php_ver_file):
            continue
        rel_path = php_ver_file.relative_to(repo).as_posix()
        for pkg_name, installed_ver in parse_php_version_file(php_ver_file):
            for adv in CURATED_OFFLINE_ADVISORIES:
                if adv["ecosystem"] == "composer" and adv["package"].lower() == pkg_name:
                    is_vuln, safe_ver = is_version_vulnerable(installed_ver, adv)
                    if is_vuln:
                        if not any(f.manifest_file == rel_path and f.cve_id == adv["cve"] for f in findings):
                            findings.append(
                                DependencyVulnerability(
                                    package_name=pkg_name,
                                    installed_version=installed_ver,
                                    safe_version=safe_ver,
                                    cve_id=adv["cve"],
                                    severity=adv["severity"],
                                    cvss_score=adv["cvss"],
                                    title=adv["title"],
                                    description=adv["description"],
                                    manifest_file=rel_path,
                                    ecosystem=adv["ecosystem"],
                                    remediation_cmd=adv["remediation_cmd"],
                                )
                            )

    return findings

