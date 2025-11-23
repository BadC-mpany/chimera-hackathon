"""
Centralized logging configuration for CHIMERA.
Provides structured logging to both console and timestamped log files.
"""
import logging
import sys
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from src.config import load_settings


class JsonFormatter(logging.Formatter):
    """Formats log records as JSON strings."""

    def format(self, record: logging.LogRecord) -> str:
        log_object = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "source": record.name,
        }
        # If the log call includes extra data, add it to the JSON object.
        if hasattr(record, "extra_data") and isinstance(record.extra_data, dict):
            log_object.update(record.extra_data)

        return json.dumps(log_object)


class ChimeraFormatter(logging.Formatter):
    """Custom formatter with color support for console and structured output."""
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'
    }
    
    def __init__(self, use_colors: bool = True, detailed: bool = False):
        self.use_colors = use_colors
        self.detailed = detailed
        
        if detailed:
            fmt = '[%(asctime)s] [%(levelname)-8s] [%(name)s:%(lineno)d] %(message)s'
        else:
            fmt = '[%(asctime)s] [%(levelname)-8s] %(message)s'
            
        super().__init__(fmt, datefmt='%Y-%m-%d %H:%M:%S')
    
    def format(self, record):
        if self.use_colors and hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
            levelname = record.levelname
            if levelname in self.COLORS:
                record.levelname = f"{self.COLORS[levelname]}{levelname}{self.COLORS['RESET']}"
        return super().format(record)


def setup_logging(debug: bool = False, log_dir: Optional[Path] = None) -> Path:
    """
    Configure logging for CHIMERA with both console and file handlers.
    
    Args:
        debug: If True, sets log level to DEBUG and enables detailed logging
        log_dir: Directory for log files. Defaults to workspace_root/logs
        
    Returns:
        Path to the created log file
    """
    settings = load_settings()
    
    # Determine if debug mode is enabled
    if debug is None:
        debug = settings.get("agent", {}).get("debug", False)
    
    # Set log directory
    if log_dir is None:
        log_dir = Path("logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Create timestamped log file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"chimera_{timestamp}.log"
    
    # Set root logger level
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if debug else logging.INFO)
    
    # Remove existing handlers to avoid duplicates
    root_logger.handlers.clear()
    
    # Suppress noisy third-party library loggers
    logging.getLogger('httpcore').setLevel(logging.WARNING)
    logging.getLogger('httpx').setLevel(logging.WARNING)
    logging.getLogger('openai').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    # Console Handler (with colors, less detailed)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    console_handler.setFormatter(ChimeraFormatter(use_colors=True, detailed=False))
    root_logger.addHandler(console_handler)
    
    # File Handler (no colors, detailed with line numbers)
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)  # Always DEBUG for file
    file_handler.setFormatter(ChimeraFormatter(use_colors=False, detailed=True))
    root_logger.addHandler(file_handler)

    # Dashboard JSONL Handler (structured logs for dashboards)
    dashboard_log_file = log_dir.parent / "data" / "dashboard_events.jsonl"
    dashboard_log_file.parent.mkdir(exist_ok=True)
    dashboard_handler = logging.FileHandler(dashboard_log_file, encoding='utf-8')
    dashboard_handler.setLevel(logging.INFO)
    dashboard_handler.setFormatter(JsonFormatter())
    
    # Create a dedicated logger for dashboard events
    dashboard_logger = logging.getLogger("dashboard")
    dashboard_logger.setLevel(logging.INFO)
    dashboard_logger.propagate = False # Do not forward to root logger
    dashboard_logger.addHandler(dashboard_handler)
    
    # Log startup message
    logger = logging.getLogger(__name__)
    logger.info("="*80)
    logger.info(f"CHIMERA Logging Initialized")
    logger.info(f"Debug Mode: {debug}")
    logger.info(f"Log File: {log_file}")
    logger.info(f"Dashboard Log: {dashboard_log_file}")
    logger.info(f"Timestamp: {timestamp}")
    logger.info("="*80)
    
    return log_file


def log_dashboard_event(message: str, data: dict):
    """
    Logs a structured event to the dashboard logger.

    Args:
        message: A human-readable log message.
        data: A dictionary of structured data to include in the log.
    """
    dashboard_logger = logging.getLogger("dashboard")
    dashboard_logger.info(message, extra={'extra_data': data})


def log_separator(logger: logging.Logger, message: str = "", level: str = "INFO"):
    """Log a visual separator for better readability."""
    getattr(logger, level.lower())("")
    getattr(logger, level.lower())("=" * 80)
    if message:
        getattr(logger, level.lower())(f"  {message}")
        getattr(logger, level.lower())("=" * 80)
    getattr(logger, level.lower())("")


def log_dict(logger: logging.Logger, title: str, data: dict, level: str = "DEBUG"):
    """Pretty-print a dictionary to logs."""
    import json
    log_method = getattr(logger, level.lower())
    log_method(f"{title}:")
    try:
        formatted = json.dumps(data, indent=2, default=str)
        for line in formatted.split('\n'):
            log_method(f"  {line}")
    except Exception:
        log_method(f"  {data}")
