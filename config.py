import os
import logging
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-soc-secret-key-replace-me")
    HOST = os.getenv("HOST", "127.0.0.1")
    PORT = int(os.getenv("PORT", "5000"))
    DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"

    # Paths
    DATA_DIR = BASE_DIR / "data"
    REPORTS_DIR = BASE_DIR / os.getenv("REPORTS_DIR", "reports")
    DATABASE_PATH = BASE_DIR / os.getenv("DATABASE_PATH", "data/vuln_assessment.db")
    LOG_FILE = BASE_DIR / os.getenv("LOG_FILE", "data/scanner_audit.log")

    # Authorization Scope Guardrails
    ALLOWED_TARGET_CIDRS = [
        cidr.strip()
        for cidr in os.getenv(
            "ALLOWED_TARGET_CIDRS",
            "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
        ).split(",")
        if cidr.strip()
    ]
    NMAP_BINARY_PATH = os.getenv("NMAP_BINARY_PATH", "nmap")
    NMAP_TIMEOUT_SECONDS = int(os.getenv("NMAP_TIMEOUT_SECONDS", "180"))

    # NVD API v2.0 Settings
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
    NVD_CACHE_TTL_HOURS = int(os.getenv("NVD_CACHE_TTL_HOURS", "24"))

    # Optional Nessus Integration
    NESSUS_URL = os.getenv("NESSUS_URL", "").strip()
    NESSUS_ACCESS_KEY = os.getenv("NESSUS_ACCESS_KEY", "").strip()
    NESSUS_SECRET_KEY = os.getenv("NESSUS_SECRET_KEY", "").strip()
    NESSUS_VERIFY_SSL = os.getenv("NESSUS_VERIFY_SSL", "false").lower() == "true"

    @classmethod
    def ensure_directories(cls):
        cls.DATA_DIR.mkdir(parents=True, exist_ok=True)
        cls.REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def setup_logging() -> logging.Logger:
    Config.ensure_directories()
    logger = logging.getLogger("AegisVuln")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(module)s | %(message)s"
        )
        file_handler = logging.FileHandler(Config.LOG_FILE, encoding="utf-8")
        file_handler.setFormatter(formatter)
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)
    return logger
