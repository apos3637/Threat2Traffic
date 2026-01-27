import logging
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime


def get_logger(
    name: str,
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
) -> logging.Logger:
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(level)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_task_logger(task_name: str, log_dir: Optional[Path] = None) -> logging.Logger:
    if log_dir is None:
        log_dir = Path(__file__).parent.parent / "logs"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"{task_name}_{timestamp}.log"

    return get_logger(task_name, log_file=log_file)
