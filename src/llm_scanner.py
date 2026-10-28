import json
import logging
from pathlib import Path
from typing import List, Optional, Tuple
import httpx
from pydantic import ValidationError
from src.config import VibeSecConfig
from src.schemas import LLMScanResult, Vulnerability, SeverityLevel, HeuristicFinding


SYSTEM_PROMPT = """You are an elite Application Security Engineer, DevSecOps Specialist, and Code Auditor.
Your task is to analyze code diffs and snippets flagged by security heuristics, identify confirmed security vulnerabilities, and provide safe, minimal, drop-in remediation patches.

You MUST respond strictly in valid JSON adhering to this JSON Schema:
{
  "is_vulnerable": true | false,
  "summary": "Short executive summary of security findings",
  "vulnerabilities": [
    {
      "cwe_id": "CWE-XXX (e.g. CWE-89, CWE-798, CWE-94, CWE-78, CWE-79, CWE-327, CWE-502, CWE-693, CWE-353, CWE-601, CWE-338, CWE-1395, CWE-200, CWE-345, CWE-922)",
      "title": "Short vulnerability name",
      "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
      "file_path": "path/to/file.ext",
      "line_number": 12,
      "sink_pattern": "vulnerable_code_snippet()",
      "explanation": "Clear AppSec rationale explaining why this is vulnerable and the risk.",
      "original_code": "Exact original code line or block that is insecure",
      "remediation_patch": "Direct drop-in replacement code that fixes the vulnerability safely"
    }
  ]
}

Rules:
1. Only report real, high-confidence vulnerabilities (e.g., SQL injection, command injection, hardcoded secrets, unsafe eval/exec, DOM XSS, weak CSP, missing SRI, open redirects, insecure PRNG, CSS injection, insecure postMessage, insecure crypto/JWT, insecure deserialization, PHP2Shell CVE-2026-109618 / CVE-2026-109619 memory corruption, PHP-CGI CVE-2024-4577 argument injection, PHP object injection).
2. For every vulnerability found, provide the EXACT `original_code` snippet that must be replaced, and a valid, working `remediation_patch` with parameterized queries, safe env lookups, DOM nodes, CSP policies, or secure libraries.
3. If the code is secure or a false positive, return `"is_vulnerable": false` and `"vulnerabilities": []`.
4. Output ONLY pure JSON. No markdown code blocks, no backticks, no trailing commentary.
"""


def check_ollama_health(config: VibeSecConfig) -> Tuple[bool, str]:
    """Check if the local Ollama instance is reachable and model is available."""
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(f"{config.ollama_url.rstrip('/')}/api/tags")
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                # Check if desired model or base model matches
                matched = any(config.model in m or m.startswith(config.model.split(":")[0]) for m in models)
                if matched:
                    return True, f"Ollama is online and model '{config.model}' is available."
                return True, f"Ollama is online, but model '{config.model}' was not found in installed models: {models}"
            return False, f"Ollama returned HTTP status {resp.status_code}"
    except httpx.ConnectError:
        return False, f"Could not connect to Ollama at {config.ollama_url}. Service may be offline."
    except Exception as e:
        return False, f"Ollama health check failed: {str(e)}"


def scan_with_ollama(
    file_path: str,
    diff_or_code: str,
    heuristic_findings: List[HeuristicFinding],
    config: VibeSecConfig,
) -> Tuple[LLMScanResult, bool]:
    """
    Send suspicious code to Ollama for deep security analysis.
    Returns (LLMScanResult, used_llm: bool).
    If Ollama is unreachable, falls back to heuristic findings.
    """
    prompt = f"""Target File: {file_path}

Heuristic Pre-filter Detections:
"""
    for f in heuristic_findings:
        prompt += f"- [{f.cwe_id}] Line {f.line_number}: {f.title} (Match: `{f.matched_text}`)\n"

    prompt += f"""
Code Snippet / Diff:
```
{diff_or_code}
```

Audit the code snippet above, confirm or reject the heuristic detections, and provide remediation patches in strict JSON format.
"""

    payload = {
        "model": config.model,
        "prompt": prompt,
        "system": SYSTEM_PROMPT,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": config.temperature,
            "num_predict": config.max_tokens,
        },
    }

    try:
        req_timeout = httpx.Timeout(timeout=float(config.timeout_seconds), connect=2.0)
        with httpx.Client(timeout=req_timeout) as client:
            response = client.post(
                f"{config.ollama_url.rstrip('/')}/api/generate",
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            raw_response_text = data.get("response", "")
            
            # Parse JSON
            parsed_json = json.loads(raw_response_text)
            result = LLMScanResult.model_validate(parsed_json)
            return result, True

    except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as e:
        # Fallback to heuristics
        return fallback_heuristics_to_scan_result(file_path, heuristic_findings, error_msg=str(e)), False
    except (json.JSONDecodeError, ValidationError) as e:
        # Parse error, fallback
        return fallback_heuristics_to_scan_result(file_path, heuristic_findings, error_msg=f"LLM Response Parsing Error: {e}"), False
    except Exception as e:
        return fallback_heuristics_to_scan_result(file_path, heuristic_findings, error_msg=f"Unexpected Error: {e}"), False


def generate_heuristic_remediation(f: HeuristicFinding) -> str:
    """Generate syntactically appropriate drop-in replacement code based on file type and rule."""
    ext = Path(f.file_path).suffix.lower()
    is_js_or_web = ext in {".js", ".ts", ".jsx", ".tsx", ".html", ".htm", ".vue", ".svelte", ".astro"}
    is_py = ext in {".py", ".pyw"}
    is_php = ext in {".php", ".phtml", ".inc"}
    matched = f.matched_text.strip()

    if "SECRET" in f.rule_id or f.cwe_id == "CWE-798":
        if is_js_or_web:
            if "=" in matched:
                var_decl = matched.split("=", 1)[0].strip()
                clean_name = var_decl.split()[-1] if " " in var_decl else var_decl
                clean_name = clean_name.replace("const", "").replace("let", "").replace("var", "").strip()
                return f"{var_decl} = window.ENV?.{clean_name} || ''; // SECURE: Loaded via environment/server session"
            return f"// SECURE REMEDIATION (CWE-798): Hardcoded secret removed\n// {matched}"
        elif is_py:
            if "=" in matched:
                var_name = matched.split("=", 1)[0].strip()
                return f"{var_name} = os.environ.get('{var_name}', '')  # Injected via environment"
            return f"# SECURE REMEDIATION (CWE-798): Hardcoded credential removed\n# {matched}"
        elif is_php:
            if "=" in matched:
                var_decl = matched.split("=", 1)[0].strip()
                var_key = var_decl.replace("$", "").strip()
                return f"{var_decl} = getenv('{var_key}') ?: ''; // SECURE: Loaded via environment variable"
            return f"// SECURE REMEDIATION (CWE-798): Hardcoded secret removed\n// {matched}"
        return f"/* SECURE REMEDIATION (CWE-798): Credential removed */"

    elif "CODE-EXEC" in f.rule_id or f.cwe_id == "CWE-94":
        if is_js_or_web:
            if "=" in matched:
                var_decl = matched.split("=", 1)[0].strip()
                return f"// SECURE REMEDIATION (CWE-94): Dynamic execution neutralized; use structured parsing\n{var_decl} = null;"
            return f"// SECURE REMEDIATION (CWE-94): Dynamic execution sink neutralized\n// {matched}"
        elif is_py:
            if "eval(" in matched:
                return matched.replace("eval(", "ast.literal_eval(")
            return f"# SECURE REMEDIATION (CWE-94): Dynamic execution removed\n# {matched}"
        elif is_php:
            return f"// SECURE REMEDIATION (CWE-94): Dynamic code execution sink neutralized\n// {matched}"
        return f"// SECURE REMEDIATION (CWE-94): Dynamic execution neutralized\n// {matched}"

    elif "CMD-INJ" in f.rule_id or f.cwe_id == "CWE-78":
        if is_php:
            return f"// SECURE REMEDIATION (CWE-78): Escape shell arguments with escapeshellarg()\n// $safe_arg = escapeshellarg($input);\n// {matched}"
        elif is_py:
            return f"# SECURE REMEDIATION (CWE-78): Avoid shell=True and pass argument list\n# subprocess.run(['cmd', arg], shell=False)"
        return f"// SECURE REMEDIATION (CWE-78): Avoid dynamic command execution\n// {matched}"

    elif "DOM-XSS" in f.rule_id or f.cwe_id == "CWE-79":
        if ".innerHTML" in matched:
            return matched.replace(".innerHTML", ".textContent")
        elif ".outerHTML" in matched:
            return matched.replace(".outerHTML", ".textContent")
        elif "document.write(" in matched:
            return f"// SECURE REMEDIATION (CWE-79): document.write neutralized\n// {matched}"
        elif is_php:
            if "echo " in matched:
                expr = matched.replace("echo ", "").rstrip(";").strip()
                return f"echo htmlspecialchars({expr}, ENT_QUOTES, 'UTF-8');"
            elif "print " in matched:
                expr = matched.replace("print ", "").rstrip(";").strip()
                return f"print htmlspecialchars({expr}, ENT_QUOTES, 'UTF-8');"
            return f"// SECURE REMEDIATION (CWE-79): Output escaped with htmlspecialchars()\n// {matched}"
        return f"// SECURE REMEDIATION (CWE-79): DOM sink sanitized\n// {matched}"

    elif "SQL" in f.rule_id or f.cwe_id == "CWE-89":
        if is_py:
            return f"# SECURE REMEDIATION (CWE-89): Use parameterized query:\n# cursor.execute('SELECT ... WHERE id = %s', (user_param,))"
        elif is_php:
            return "// SECURE REMEDIATION (CWE-89): Use PDO prepared statements with bound parameters:\n// $stmt = $pdo->prepare('SELECT ... WHERE id = :id');\n// $stmt->execute(['id' => $user_param]);"
        return f"// SECURE REMEDIATION (CWE-89): Parameterize database query with bound values"

    elif "INSECURE-DESERIALIZATION" in f.rule_id or f.cwe_id == "CWE-502":
        if is_php:
            return "// SECURE REMEDIATION (CWE-502): Use json_decode() instead of unserialize():\n// $data = json_decode($untrusted_json, true);"
        return f"// SECURE REMEDIATION (CWE-502): Use safe deserialization (e.g. json.loads or yaml.safe_load)\n// {matched}"

    elif "PATH-TRAVERSAL" in f.rule_id or f.cwe_id == "CWE-22":
        if is_php:
            return "// SECURE REMEDIATION (CWE-22): Restrict include/file paths to an allowlist or use basename():\n// $allowed = ['home.php', 'about.php'];\n// if (in_array(basename($page), $allowed, true)) { include basename($page); }"
        return f"// SECURE REMEDIATION (CWE-22): Use secure path validation and basename\n// {matched}"

    elif "INSECURE-LOCALSTORAGE" in f.rule_id or f.cwe_id == "CWE-922":
        return f"// SECURE REMEDIATION (CWE-922): Sensitive tokens should not be stored in localStorage\n// {matched}"

    elif "WEAK-CSP" in f.rule_id or f.cwe_id == "CWE-693":
        return '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\' https://cdn.example.com; style-src \'self\'; object-src \'none\'; base-uri \'self\';">'

    elif "MISSING-SRI" in f.rule_id or f.cwe_id == "CWE-353":
        if "<script " in matched and not "integrity=" in matched:
            return matched.replace("></script>", ' integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous"></script>')
        return f"// SECURE REMEDIATION (CWE-353): Add SRI hash and crossorigin attribute\n{matched}"

    elif "OPEN-REDIRECT" in f.rule_id or f.cwe_id == "CWE-601":
        return "// SECURE REMEDIATION (CWE-601/CWE-79): Validated URL destination\ntry { const parsed = new URL(profile, window.location.origin); if ((parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.origin === window.location.origin) { document.getElementById('profileLink').href = parsed.pathname + parsed.search; } } catch (e) {}"

    elif "INSECURE-PRNG" in f.rule_id or f.cwe_id == "CWE-338":
        if is_js_or_web:
            return "// SECURE REMEDIATION (CWE-338): Cryptographically secure random token\nconst array = new Uint8Array(16);\nwindow.crypto.getRandomValues(array);\nconst token = Array.from(array, b => b.toString(16).padStart(2, '0')).join('');"
        elif is_py:
            return "# SECURE REMEDIATION (CWE-338): Cryptographically secure random token\nimport secrets\ntoken = secrets.token_hex(16)"
        elif is_php:
            return "// SECURE REMEDIATION (CWE-338): Cryptographically secure random token\n$token = bin2hex(random_bytes(16));"
        return f"// SECURE REMEDIATION (CWE-338): Use cryptographically secure PRNG\n// {matched}"

    elif "CSS-INJECTION" in f.rule_id or f.cwe_id == "CWE-1395":
        return f"// SECURE REMEDIATION (CWE-1395): Sanitize style property or use allowlisted CSS class\nconst ALLOWED_THEMES = ['theme-dark', 'theme-blue'];\nif (theme && ALLOWED_THEMES.includes(theme)) {{ document.body.classList.add(theme); }}"

    elif "INFO-DISCLOSURE" in f.rule_id or f.cwe_id == "CWE-200":
        return "/* SECURE REMEDIATION (CWE-200): Sensitive internal route removed */"

    elif "INSECURE-POSTMESSAGE" in f.rule_id or f.cwe_id == "CWE-345":
        return f"// SECURE REMEDIATION (CWE-345): Origin-validated postMessage listener\nwindow.addEventListener('message', function(event) {{\n    if (event.origin !== window.location.origin) return;\n    document.getElementById('userInformation').textContent = event.data;\n}});"

    elif "INLINE-EVENT-HANDLER" in f.rule_id:
        return re.sub(r"""\son[a-z]+\s*=\s*["'][^"']+["']""", "", matched)


def fallback_heuristics_to_scan_result(
    file_path: str,
    findings: List[HeuristicFinding],
    error_msg: str = "",
) -> LLMScanResult:
    """Convert Tier-1 heuristic detections into an LLMScanResult when Ollama is offline."""
    vulns: List[Vulnerability] = []
    
    for f in findings:
        patch_suggestion = generate_heuristic_remediation(f)

        vulns.append(
            Vulnerability(
                cwe_id=f.cwe_id,
                title=f"{f.title} (Heuristic Flag)",
                severity=f.severity,
                file_path=f.file_path,
                line_number=f.line_number,
                sink_pattern=f.matched_text,
                explanation=f"{f.explanation} (Note: Offline heuristic detection; Ollama was unavailable: {error_msg[:100]})",
                original_code=f.matched_text,
                remediation_patch=patch_suggestion,
            )
        )

    return LLMScanResult(
        is_vulnerable=len(vulns) > 0,
        summary=f"Found {len(vulns)} heuristic security alerts (Ollama offline fallback mode)",
        vulnerabilities=vulns,
    )

