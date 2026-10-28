from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        ranks = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        return ranks.get(self.value, 0)


class Vulnerability(BaseModel):
    cwe_id: str = Field(
        ...,
        description="Standard CWE identifier (e.g., 'CWE-89' for SQL Injection, 'CWE-798' for Hardcoded Credentials).",
    )
    title: str = Field(
        ...,
        description="Short, human-readable vulnerability title.",
    )
    severity: SeverityLevel = Field(
        ...,
        description="Severity level: LOW, MEDIUM, HIGH, or CRITICAL.",
    )
    file_path: str = Field(
        ...,
        description="Target file relative path.",
    )
    line_number: Optional[int] = Field(
        None,
        description="Line number in the target file where the vulnerability is located.",
    )
    sink_pattern: Optional[str] = Field(
        None,
        description="The dangerous sink or function call detected (e.g., 'cursor.execute', 'eval').",
    )
    explanation: str = Field(
        ...,
        description="Concise AppSec explanation of the security risk and exploit mechanism.",
    )
    original_code: str = Field(
        ...,
        description="The exact vulnerable snippet of code to be replaced.",
    )
    remediation_patch: str = Field(
        ...,
        description="The secure drop-in replacement code that fixes the vulnerability.",
    )


class LLMScanResult(BaseModel):
    is_vulnerable: bool = Field(
        ...,
        description="True if any security vulnerabilities were confirmed.",
    )
    summary: str = Field(
        ...,
        description="Brief summary of the security audit results.",
    )
    vulnerabilities: List[Vulnerability] = Field(
        default_factory=list,
        description="List of detected vulnerabilities and their auto-remediation patches.",
    )


class HeuristicFinding(BaseModel):
    rule_id: str
    cwe_id: str
    title: str
    severity: SeverityLevel
    file_path: str
    line_number: int
    matched_text: str
    explanation: str
    context_lines: str
