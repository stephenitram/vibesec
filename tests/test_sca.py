import pytest
from pathlib import Path
import json
from src.sca import (
    scan_dependencies_sca,
    compare_versions,
    parse_package_json,
    parse_requirements_txt,
    parse_composer_json,
    parse_php_version_file,
    is_version_vulnerable,
)
from src.schemas import SeverityLevel

def test_compare_versions():
    assert compare_versions("0.21.1", "0.21.2") == -1
    assert compare_versions("1.0.0", "1.0.0") == 0
    assert compare_versions("2.32.0", "2.31.0") == 1

def test_parse_package_json(tmp_path: Path):
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text(json.dumps({
        "dependencies": {
            "axios": "^0.21.1",
            "lodash": "~4.17.20"
        }
    }), encoding="utf-8")
    
    deps = parse_package_json(pkg_file)
    assert ("axios", "0.21.1") in deps
    assert ("lodash", "4.17.20") in deps

def test_parse_requirements_txt(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.30.0\n# comment\npyyaml>=5.3\n", encoding="utf-8")
    
    deps = parse_requirements_txt(req_file)
    assert ("requests", "2.30.0") in deps
    assert ("pyyaml", "5.3") in deps

def test_parse_composer_json(tmp_path: Path):
    composer_file = tmp_path / "composer.json"
    composer_file.write_text(json.dumps({
        "require": {
            "php": "^8.2.0",
            "guzzlehttp/guzzle": "^7.4.0"
        },
        "require-dev": {
            "phpunit/phpunit": "~9.5.0"
        }
    }), encoding="utf-8")

    deps = parse_composer_json(composer_file)
    assert ("php", "8.2.0") in deps
    assert ("guzzlehttp/guzzle", "7.4.0") in deps
    assert ("phpunit/phpunit", "9.5.0") in deps

def test_scan_dependencies_sca_php2shell(tmp_path: Path):
    # Test October 2026 PHP2Shell vulnerabilities (CVE-2026-109618 and CVE-2026-109619)
    composer_file = tmp_path / "composer.json"
    composer_file.write_text(json.dumps({
        "require": {
            "php": "8.2.10",
            "guzzlehttp/guzzle": "7.4.0"
        }
    }), encoding="utf-8")

    findings = scan_dependencies_sca(tmp_path)
    cves = [f.cve_id for f in findings]
    assert "CVE-2026-109618" in cves # PHP2Shell Out-of-memory uninitialized state
    assert "CVE-2026-109619" in cves # PHP2Shell Stale global state UAF
    assert "CVE-2024-4577" in cves    # PHP-CGI Windows argument injection (8.2.10 < 8.2.20)
    assert "CVE-2022-31090" in cves   # Guzzle header redirect leak

    # Verify patched version is NOT vulnerable to PHP2Shell
    tmp_patched = tmp_path / "patched"
    tmp_patched.mkdir()
    (tmp_patched / "composer.json").write_text(json.dumps({
        "require": {
            "php": "8.2.35"
        }
    }), encoding="utf-8")

    patched_findings = scan_dependencies_sca(tmp_patched)
    patched_cves = [f.cve_id for f in patched_findings]
    assert "CVE-2026-109618" not in patched_cves
    assert "CVE-2026-109619" not in patched_cves

def test_scan_dependencies_sca(tmp_path: Path):
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text(json.dumps({
        "dependencies": {
            "jsonwebtoken": "8.5.1"
        }
    }), encoding="utf-8")

    req_file = tmp_path / "requirements.txt"
    req_file.write_text("pyyaml==5.3.1\n", encoding="utf-8")

    findings = scan_dependencies_sca(tmp_path)
    assert len(findings) == 2
    cves = [f.cve_id for f in findings]
    assert "CVE-2022-23529" in cves # jsonwebtoken
    assert "CVE-2020-14343" in cves # pyyaml
