# 🛡️ VibeSec-Local: Founder & Innovator User Guide
### *Zero-Telemetry, AI-Powered Application Security & Supply-Chain Shield for Startups*

---

## 📌 1. Executive Summary & The Problem

As startups and engineering teams increasingly rely on AI coding assistants (e.g., Cursor, Copilot, ChatGPT, Claude) to accelerate development ("vibe coding"), **shipping speed has multiplied by 10x—but so has the introduction of critical security vulnerabilities**.

AI models frequently hallucinate:
* Unparameterized SQL queries (`f"SELECT * FROM users WHERE id = {user_id}"`)
* Insecure dynamic execution (`eval()`, `exec()`, `Function()`)
* Hardcoded private API keys and database credentials
* Outdated or vulnerable open-source packages
* Weak cryptography and permissive security headers

**VibeSec-Local** solves this crisis by providing a **100% offline, privacy-preserving, dual-engine AppSec platform** that acts as an automated security engineer on every founder's laptop.

---

## 🏗️ 2. Architectural Overview

```
                                  [Developer Writes Code / AI Generates Feature]
                                                         │
                                                         ▼
                                                [git commit / Save]
                                                         │
                                 ┌───────────────────────┴───────────────────────┐
                                 ▼                                               ▼
                     [Tier-1 Fast Filter]                            [Software Composition (SCA)]
                  Microsecond Regex Engine                         Audits package.json / requirements.txt
                 (SQLi, Secrets, Eval, JWT)                                against Offline CVE DB
                                 │                                               │
                                 ▼                                               │
                     [Suspicious Sinks Flagged?]                                 │
                                 │                                               │
                        YES ─────┼───── NO (Clean -> Pass)                       │
                        │                                                        │
                        ▼                                                        │
         [Tier-2 Deep Local LLM Auditor]                                         │
        (Ollama: qwen2.5-coder / deepseek-coder)                                 │
         - Contextual Risk Verification                                          │
         - Synthesizes Minimal Safe Patch                                        │
                        │                                                        │
                        ▼                                                        │
         [🧪 Test-Driven Sandbox Verifier]                                       │
        Executes pytest / npm test / cargo test                                  │
         - Passed? -> Ready for Deployment                                       │
         - Failed? -> Alerts Developer                                           │
                        │                                                        │
                        └───────────────────────┬────────────────────────────────┘
                                                ▼
                                   [Interactive Web HUD & Reports]
                                   - Visual Diff Staging Modal
                                   - OASIS SARIF 2.1.0 Export (CI/CD)
                                   - NIST / OWASP Compliance Markdown
```

### 🔒 Zero-Telemetry Guarantee
* **No Code Leaves Your Machine:** Intellectual property, proprietary algorithms, and sensitive codebase context are never transmitted to external cloud APIs.
* **Compliance-Ready:** Safe for HIPAA, SOC2, PCI-DSS, and GDPR-governed applications.

---

## 🚀 3. Quick Start (3-Minute Setup)

### Option A: Running from Pre-Compiled Standalone Binary (Recommended for Fast Onboarding)
No Python installation required:
```bash
# Navigate to project root
cd VibeSec-Local

# Run CLI commands directly
.\dist\vibesec\vibesec.exe --help

# Launch Web Dashboard
.\dist\vibesec\vibesec.exe ui
```

### Option B: Running from Source / Virtual Environment
```bash
# 1. Create and activate Python virtual environment
python -m venv venv
.\venv\Scripts\activate   # Windows (or source venv/bin/activate on macOS/Linux)

# 2. Install dependencies in editable mode
pip install -e .

# 3. (Optional) Start Ollama for Tier-2 Deep LLM Analysis
ollama run qwen2.5-coder:7b
```

---

## 🧭 4. Core Workflows for Founders & Tech Innovators

### Workflow 1: Install Pre-Commit Gatekeeper
Prevent vulnerable code from ever reaching GitHub or GitLab:
```bash
vibesec install
```
* Every `git commit` automatically triggers a scan.
* Clean code commits instantly (`Exit code 0`).
* If vulnerabilities are found, the commit is safely blocked (`Exit code 1`), and you are prompted with an interactive `[Y/n]` to apply verified security patches.

---

### Workflow 2: Interactive Web HUD & Visual Diff Staging
Launch a modern, dark-mode cybersecurity cockpit directly in your browser:
```bash
vibesec ui
# Or specify custom port:
vibesec ui --port 9000
```

#### Key Dashboard Capabilities:
1. **🛡️ SAST Source Code Tab:**
   * View live health scores (0–100%).
   * Filter vulnerabilities by severity (**CRITICAL**, **HIGH**, **MEDIUM**, **LOW**).
   * Click educational mitigation links (direct MITRE CWE taxonomy references).
2. **🔍 Interactive Staging Modal:**
   * Click **Inspect Diff** on any vulnerability.
   * View side-by-side unified code diffs.
   * Edit patches directly in the modal textarea before applying.
   * Click **🧪 Verify with Test Suite** to run local automated test suites in a temporary sandbox before committing.
3. **📦 Supply Chain & SCA Tab:**
   * Audits `package.json` and `requirements.txt` against known CVEs.
   * 1-click copy for safe package upgrade commands (`npm install`, `pip install`).
4. **📑 Compliance Report Tab:**
   * Generate real-time executive summaries mapped to OWASP Top 10 and MITRE CWE Top 25.
   * Export **SARIF 2.1.0** for CI/CD pipelines.
   * Export formal **Markdown Audit Reports** for investors, security audits, and compliance documentation.

---

### Workflow 3: Background Auto-Pilot (`vibesec watch`)
For rapid "vibe coding" sessions where you want passive background protection:
```bash
vibesec watch
```
* Silently monitors your workspace files for save events.
* Instantly intercepts flaws as you write or paste AI-generated code.
* Automatically patches syntax errors or security sinks in real time.

---

### Workflow 4: Software Composition Analysis (SCA)
Audit all third-party dependencies across NPM, Python, and PHP/Composer manifests:
```bash
vibesec sca
```
Example Output:
```
📦 VibeSec Software Supply Chain Audit:
 ⚠️  CRITICAL: php@8.2.10 in composer.json (CVE-2026-109618) -> Upgrade: Upgrade PHP runtime to >=8.5.12, >=8.4.27, >=8.3.36, or >=8.2.35
 ⚠️  CRITICAL: php@8.2.10 in composer.json (CVE-2026-109619) -> Upgrade: Upgrade PHP runtime to >=8.5.12, >=8.4.27, >=8.3.36, or >=8.2.35
 ⚠️  CRITICAL: jsonwebtoken@8.5.1 in package.json (CVE-2022-23529) -> Upgrade: npm install jsonwebtoken@^9.0.2
 ⚠️  HIGH: pyyaml@5.3.1 in requirements.txt (CVE-2020-14343) -> Upgrade: pip install --upgrade pyyaml>=6.0.1
```

---

### Workflow 5: Generating Compliance & Investor Security Reports
Produce board-ready audit reports to prove cybersecurity diligence to enterprise customers, grant reviewers, or investors:
```bash
# Generate Academic & Executive Markdown Audit Report:
vibesec report --format=markdown --out AUDIT_REPORT.md

# Generate OASIS SARIF 2.1.0 for CI/CD Integration:
vibesec report --format=sarif --out vibesec-results.sarif
```

---

## 🧪 5. Test-Driven Verification Architecture

Blindly accepting AI code fixes can introduce regressions. VibeSec implements a **non-destructive sandbox test harness**:

```
[Candidate Patch] ─► [Target Source File Backup]
                           │
                           ▼
                    [Apply Patch Temporarily]
                           │
                           ▼
               [Execute Test Suite (15s Timeout)]
               (pytest / npm test / cargo test / go test)
                           │
                           ▼
                    [Always Restore Original File in finally: block]
                           │
                           ▼
               [Return Test Result: Passed / Failed]
```

---

## 🛡️ 6. Common Vulnerabilities Detected & Mitigated

| Vulnerability | MITRE CWE | Risk in AI Codebases | VibeSec Remediation Pattern |
| :--- | :--- | :--- | :--- |
| **SQL Injection** | `CWE-89` | AI inserts raw variables into SQL queries | Replaces with parameterized `?` or `%s` bindings |
| **Code Injection / Eval** | `CWE-94` / `CWE-95` | AI uses `eval()` or `exec()` for parsing | Replaces with `ast.literal_eval()` or `json.loads()` |
| **Hardcoded Secrets** | `CWE-798` | API keys / tokens left in code | Moves secrets to `os.environ.get()` / `.env` |
| **Insecure JWT (alg: none)** | `CWE-347` | AI accepts unsigned authentication tokens | Enforces explicit cryptographic algorithms (`HS256`, `RS256`) |
| **Cross-Site Scripting (XSS)** | `CWE-79` | Unescaped user input rendered in templates | Replaces with auto-escaped DOM APIs |
| **Supply Chain CVEs** | `CWE-1395` | Vulnerable library versions in manifest | Automatically calculates minimum safe upgrade version |

---

## ⚙️ 7. Configuration File (`.vibesec.yaml`)

Create a custom `.vibesec.yaml` in your project root using:
```bash
vibesec init-config
```

Sample configuration:
```yaml
# LLM & Local Model Settings
model: "qwen2.5-coder:7b"
ollama_url: "http://localhost:11434"
timeout_seconds: 30
max_tokens: 2048
temperature: 0.0

# Pre-Commit & Scanner Rules
min_severity_to_block: "MEDIUM"     # Options: LOW, MEDIUM, HIGH, CRITICAL
auto_patch_prompt: true             # Prompt developer to auto-apply fixes
offline_fallback_to_heuristics: true # Use regex filter if Ollama is unreachable

# Test Verification Settings
custom_test_command: "pytest -q"    # Optional custom test runner override
test_timeout_seconds: 15
```

---

## 🔄 8. GitHub Actions CI/CD Integration

To upload VibeSec security findings directly to GitHub Advanced Security:

Create `.github/workflows/security.yml`:
```yaml
name: VibeSec Security Gate

on:
  push:
    branches: [ "main", "dev" ]
  pull_request:
    branches: [ "main" ]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install VibeSec
        run: |
          pip install -e .

      - name: Run VibeSec SARIF Audit
        run: |
          vibesec report --format=sarif --out vibesec.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: vibesec.sarif
```

---

## ❓ 9. Frequently Asked Questions (FAQ) & Troubleshooting

### Q: Why does VibeSec display "Offline Heuristics" instead of "Ollama"?
**A:** If the Ollama background daemon is not running or the model is still downloading, VibeSec automatically falls back to Tier-1 heuristic regex scanning so your commits are never blocked.  
To activate Tier-2 Deep LLM analysis:
1. Ensure Ollama is installed and running (`http://localhost:11434`).
2. Run `ollama pull qwen2.5-coder:7b`.
3. Verify connection with `vibesec check-health`.

### Q: Will VibeSec break my build if tests fail?
**A:** No. The test-driven verification feature operates non-destructively in an atomic sandbox. It always restores your files to their exact initial state and reports the pass/fail result to you before any permanent changes are written.

### Q: Can I use VibeSec with PHP / TypeScript / Next.js / Rust / Go?
**A:** Yes! VibeSec supports multi-language projects. It automatically recognizes `composer.json` / `.php-version` (PHP), `package.json` (Node/TypeScript), `Cargo.toml` (Rust), `go.mod` (Go), and `requirements.txt` (Python) for both test detection (PHPUnit, pytest, npm test, cargo test, go test) and supply-chain auditing.

---

### 📄 License & Attribution
* Built for founders, tech innovators, and academic cybersecurity research.
* Aligned with **OWASP Top 10 (2021)**, **MITRE CWE Top 25**, and **NIST SP 800-218 (Secure Software Development Framework)**.
