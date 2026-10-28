import pytest
from src.heuristics import scan_text_heuristics, should_trigger_llm_scan
from src.schemas import SeverityLevel


def test_detect_sqli_fstring():
    code = """
def get_user(user_id):
    cursor.execute(f"SELECT * FROM accounts WHERE id = {user_id}")
    return cursor.fetchone()
"""
    findings = scan_text_heuristics("db.py", code)
    assert should_trigger_llm_scan(findings) is True
    assert any(f.cwe_id == "CWE-89" for f in findings)


def test_detect_eval_code_exec():
    code = """
def run_dynamic(user_payload):
    result = eval(user_payload)
    return result
"""
    findings = scan_text_heuristics("handler.py", code)
    assert should_trigger_llm_scan(findings) is True
    assert any(f.cwe_id == "CWE-94" for f in findings)


def test_detect_hardcoded_secret():
    code = """
AWS_KEY = "AKIA1234567890ABCDEF"
AUTH_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeak"
"""
    findings = scan_text_heuristics("secrets.py", code)
    assert should_trigger_llm_scan(findings) is True
    assert any(f.cwe_id == "CWE-798" for f in findings)


def test_detect_jwt_alg_none():
    code = """
decoded = jwt.decode(token, algorithms=['none'])
"""
    findings = scan_text_heuristics("auth.py", code)
    assert should_trigger_llm_scan(findings) is True
    assert any(f.cwe_id == "CWE-327" for f in findings)


def test_detect_web_vulnerabilities():
    html_code = """
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="Content-Security-Policy" content="default-src * 'unsafe-inline' 'unsafe-eval'">
    <script src="https://cdn.example.com/library.js"></script>
</head>
<body>
    <button onclick="searchProducts()">Search</button>
</body>
</html>
"""
    findings_html = scan_text_heuristics("index.html", html_code)
    assert should_trigger_llm_scan(findings_html) is True
    assert any(f.cwe_id == "CWE-693" for f in findings_html)
    assert any(f.cwe_id == "CWE-353" for f in findings_html)

    js_code = """
const ADMIN_TOKEN = "admin-demo-token-987654";
const token = Math.random().toString(36).substring(2);
document.getElementById("profileLink").href = profile;
document.body.style = "background:" + theme;
localStorage.setItem("passwordResetToken", token);
window.addEventListener("message", function(event) {
    document.getElementById("userInformation").innerHTML = event.data;
});
"""
    findings_js = scan_text_heuristics("app.js", js_code)
    assert should_trigger_llm_scan(findings_js) is True
    assert any(f.cwe_id == "CWE-798" for f in findings_js)
    assert any(f.cwe_id == "CWE-338" for f in findings_js)
    assert any(f.cwe_id == "CWE-601" for f in findings_js)
    assert any(f.cwe_id == "CWE-1395" for f in findings_js)
    assert any(f.cwe_id == "CWE-922" for f in findings_js)
    assert any(f.cwe_id == "CWE-345" for f in findings_js)
    assert any(f.cwe_id == "CWE-79" for f in findings_js)

    css_code = """
.debug-info::after {
    content: "API endpoint: /api/internal/admin";
    display: none;
}
"""
    findings_css = scan_text_heuristics("style.css", css_code)
    assert should_trigger_llm_scan(findings_css) is True
    assert any(f.cwe_id == "CWE-200" for f in findings_css)


def test_remediated_code_not_flagged():
    remediated_js = """
// SECURE REMEDIATION (CWE-798): Loaded via env
const ADMIN_TOKEN = window.ENV?.ADMIN_TOKEN || '';

// SECURE REMEDIATION (CWE-338): Cryptographically secure random token
const array = new Uint8Array(16);
window.crypto.getRandomValues(array);
const token = Array.from(array, b => b.toString(16).padStart(2, '0')).join('');

// SECURE REMEDIATION (CWE-601/CWE-79): Validated URL destination
try {
    const parsedUrl = new URL(profile, window.location.origin);
    if ((parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:') && parsedUrl.origin === window.location.origin) {
        document.getElementById('profileLink').href = parsedUrl.pathname + parsedUrl.search;
    }
} catch (e) {}

// SECURE REMEDIATION (CWE-1395): Sanitize style property or use allowlisted CSS class
const ALLOWED_THEMES = ['theme-dark', 'theme-blue'];
if (theme && ALLOWED_THEMES.includes(theme)) {
    document.body.classList.add(theme);
}

// SECURE REMEDIATION (CWE-345): Origin-validated postMessage listener
window.addEventListener('message', function(event) {
    if (event.origin !== window.location.origin) return;
    document.getElementById('userInformation').textContent = event.data;
});
"""
    findings = scan_text_heuristics("app.js", remediated_js)
    assert should_trigger_llm_scan(findings) is False
    assert len(findings) == 0


def test_remediated_csp_html():
    remediated_html = """
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self'; object-src 'none'; base-uri 'self';">
    <script src="https://cdn.example.com/library.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous"></script>
</head>
<body>
    <button id="searchBtn">Search</button>
</body>
</html>
"""
    findings = scan_text_heuristics("index.html", remediated_html)
    assert should_trigger_llm_scan(findings) is False
    assert len(findings) == 0


def test_detect_php_vulnerabilities():
    php_code = """<?php
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $user_id;
$db->query($query);

$cmd = $_POST['command'];
$output = shell_exec("ls -la " . $cmd);

$payload = $_GET['payload'];
assert($payload);

$obj = unserialize($_COOKIE['user_session']);

$page = $_GET['page'];
include($page);

echo $_GET['message'];
"""
    findings = scan_text_heuristics("index.php", php_code)
    assert should_trigger_llm_scan(findings) is True
    cwe_ids = [f.cwe_id for f in findings]
    assert "CWE-89" in cwe_ids   # SQL Injection
    assert "CWE-78" in cwe_ids   # Command Injection
    assert "CWE-94" in cwe_ids   # Code Execution / assert
    assert "CWE-502" in cwe_ids  # Insecure Deserialization / unserialize
    assert "CWE-22" in cwe_ids   # Path Traversal / LFI
    assert "CWE-79" in cwe_ids   # Reflected XSS / echo $_GET


def test_remediated_php_code_not_flagged():
    remediated_php = """<?php
// SECURE: PDO prepared statements with bound parameters
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $user_id]);

// SECURE: Escaped shell arguments
$safe_cmd = escapeshellarg($cmd);
shell_exec("ls -la " . $safe_cmd);

// SECURE: JSON decoding instead of unserialize
$obj = json_decode($user_session_json, true);

// SECURE: Basename validation for path inclusion
$safe_page = basename($page);
include($safe_page);

// SECURE: Output encoded with htmlspecialchars
echo htmlspecialchars($_GET['message'], ENT_QUOTES, 'UTF-8');
"""
    findings = scan_text_heuristics("index.php", remediated_php)
    assert should_trigger_llm_scan(findings) is False
    assert len(findings) == 0


