import os
from pathlib import Path
from typing import Optional, List
import yaml
from pydantic import BaseModel, Field
from src.schemas import SeverityLevel


class HeuristicRuleConfig(BaseModel):
    enabled: bool = True
    custom_patterns: List[str] = Field(default_factory=list)


class VibeSecConfig(BaseModel):
    model: str = "qwen2.5-coder:7b"
    ollama_url: str = "http://localhost:11434"
    timeout_seconds: int = 30
    min_severity_to_block: SeverityLevel = SeverityLevel.MEDIUM
    auto_patch_prompt: bool = True
    offline_fallback_to_heuristics: bool = True
    max_tokens: int = 2048
    temperature: float = 0.0
    rules: HeuristicRuleConfig = Field(default_factory=HeuristicRuleConfig)

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "VibeSecConfig":
        """Load configuration from .vibesec.yaml in current repo root or parent directories, or return defaults."""
        search_paths = []
        if config_path:
            search_paths.append(config_path)
        
        # Search upwards from cwd
        current = Path.cwd().resolve()
        search_paths.append(current / ".vibesec.yaml")
        search_paths.append(current / ".vibesec.yml")
        for parent in current.parents:
            search_paths.append(parent / ".vibesec.yaml")
            search_paths.append(parent / ".vibesec.yml")
            if (parent / ".git").exists():
                break

        for path in search_paths:
            if path and path.is_file():
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f) or {}
                        return cls(**data)
                except Exception as e:
                    # In case of malformed YAML, return default config
                    break

        return cls()

    def save(self, path: Path) -> None:
        """Save configuration to a YAML file."""
        data = self.model_dump(mode="json")
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
