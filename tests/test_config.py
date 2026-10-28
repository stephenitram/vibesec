import os
from pathlib import Path
from src.config import VibeSecConfig
from src.schemas import SeverityLevel


def test_default_config():
    config = VibeSecConfig()
    assert config.model == "qwen2.5-coder:7b"
    assert config.ollama_url == "http://localhost:11434"
    assert config.min_severity_to_block == SeverityLevel.MEDIUM


def test_save_and_load_config(tmp_path: Path):
    cfg_file = tmp_path / ".vibesec.yaml"
    config = VibeSecConfig(
        model="custom-sec-model:14b",
        timeout_seconds=45,
        min_severity_to_block=SeverityLevel.HIGH,
    )
    config.save(cfg_file)

    loaded = VibeSecConfig.load(cfg_file)
    assert loaded.model == "custom-sec-model:14b"
    assert loaded.timeout_seconds == 45
    assert loaded.min_severity_to_block == SeverityLevel.HIGH
