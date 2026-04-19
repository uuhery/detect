"""Application configuration.

Loads settings from environment variables, with support for
environment-specific .env files (matches template pattern).
"""

import os
from enum import Enum
from pathlib import Path

from dotenv import load_dotenv


class Environment(str, Enum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"
    TEST = "test"


def get_environment() -> Environment:
    match os.getenv("APP_ENV", "development").lower():
        case "production" | "prod":
            return Environment.PRODUCTION
        case "test":
            return Environment.TEST
        case _:
            return Environment.DEVELOPMENT


def load_env_file() -> Path | None:
    env = get_environment()
    # switch_audit/core/config.py -> detection/
    base_dir = Path(__file__).parent.parent.parent

    for candidate in [
        base_dir / f".env.{env.value}.local",
        base_dir / f".env.{env.value}",
        base_dir / ".env.local",
        base_dir / ".env",
    ]:
        if candidate.is_file():
            load_dotenv(dotenv_path=candidate)
            return candidate
    return None


ENV_FILE = load_env_file()


class Settings:
    def __init__(self) -> None:
        self.ENVIRONMENT = get_environment()
        self.PROJECT_NAME = os.getenv("PROJECT_NAME", "switch-audit")
        self.DEBUG = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")

        # LLM — supports any OpenAI-compatible endpoint
        self.OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
        self.OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "") or None
        self.DEFAULT_LLM_MODEL = os.getenv("DEFAULT_LLM_MODEL", "gpt-4o-mini")
        self.DEFAULT_LLM_TEMPERATURE = float(os.getenv("DEFAULT_LLM_TEMPERATURE", "0.1"))

        # LangSmith tracing (auto-activated when LANGCHAIN_TRACING_V2=true)
        self.LANGCHAIN_TRACING_V2 = os.getenv("LANGCHAIN_TRACING_V2", "false")
        self.LANGCHAIN_API_KEY = os.getenv("LANGCHAIN_API_KEY", "")
        self.LANGCHAIN_PROJECT = os.getenv("LANGCHAIN_PROJECT", self.PROJECT_NAME)

        # SSH — target device credentials
        self.SSH_PORT = int(os.getenv("SSH_PORT", "22"))
        self.SSH_USERNAME = os.getenv("SSH_USERNAME", "admin")
        self.SSH_PASSWORD = os.getenv("SSH_PASSWORD", "admin")
        self.SSH_TIMEOUT = int(os.getenv("SSH_TIMEOUT", "30"))
        # netmiko device_type: cisco_xe | cisco_ios | cisco_nxos | ...
        self.SSH_DEVICE_TYPE = os.getenv("SSH_DEVICE_TYPE", "cisco_xe")

        # eAPI — NAPALM EOS driver (separate from SSH tunnel)
        self.EAPI_PORT = int(os.getenv("EAPI_PORT", "443"))
        self.EAPI_TRANSPORT = os.getenv("EAPI_TRANSPORT", "https")

        # Logging
        self.LOG_DIR = Path(os.getenv("LOG_DIR", "logs"))
        self.LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
        self.LOG_FORMAT = os.getenv("LOG_FORMAT", "json")

        self._apply_environment_overrides()

    def _apply_environment_overrides(self) -> None:
        overrides: dict[Environment, dict] = {
            Environment.DEVELOPMENT: {
                "DEBUG": True,
                "LOG_LEVEL": "DEBUG",
                "LOG_FORMAT": "console",
            },
            Environment.TEST: {
                "DEBUG": True,
                "LOG_LEVEL": "DEBUG",
                "LOG_FORMAT": "console",
            },
        }
        for key, value in overrides.get(self.ENVIRONMENT, {}).items():
            if key.upper() not in os.environ:
                setattr(self, key, value)


settings = Settings()
