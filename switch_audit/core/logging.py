"""Structured logging configuration.

Development: pretty console output via structlog.
Production:  JSON lines written to daily log files.
Mirrors the template's logging pattern, trimmed to essentials.
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

from switch_audit.core.config import Environment, settings

# Ensure log directory exists
settings.LOG_DIR.mkdir(parents=True, exist_ok=True)


class JsonlFileHandler(logging.Handler):
    """Appends structured JSON lines to a daily log file."""

    def __init__(self, file_path: Path) -> None:
        super().__init__()
        self.file_path = file_path

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry = {
                "timestamp": datetime.fromtimestamp(record.created).isoformat(),
                "level": record.levelname,
                "message": record.getMessage(),
                "module": record.module,
                "line": record.lineno,
                "environment": settings.ENVIRONMENT.value,
            }
            with open(self.file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            self.handleError(record)


def _get_log_file_path() -> Path:
    prefix = settings.ENVIRONMENT.value
    return settings.LOG_DIR / f"{prefix}-{datetime.now().strftime('%Y-%m-%d')}.jsonl"


def _setup_logging() -> None:
    log_level = logging.DEBUG if settings.DEBUG else logging.INFO

    file_handler = JsonlFileHandler(_get_log_file_path())
    file_handler.setLevel(log_level)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)

    shared_processors: list[Any] = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    logging.basicConfig(
        format="%(message)s",
        level=log_level,
        handlers=[file_handler, console_handler],
    )

    if settings.LOG_FORMAT == "console":
        structlog.configure(
            processors=[*shared_processors, structlog.dev.ConsoleRenderer()],
            wrapper_class=structlog.stdlib.BoundLogger,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )
    else:
        structlog.configure(
            processors=[*shared_processors, structlog.processors.JSONRenderer()],
            wrapper_class=structlog.stdlib.BoundLogger,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )


_setup_logging()

logger = structlog.get_logger()
logger.info(
    "logging_initialized",
    environment=settings.ENVIRONMENT.value,
    log_format=settings.LOG_FORMAT,
    debug=settings.DEBUG,
)
