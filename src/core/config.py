"""
Lab 11 — Configuration & API Key Setup
"""

import os
from pathlib import Path


def load_env_file():
    """Load .env file if exists."""
    env_path = Path(__file__).resolve().parent.parent.parent / ".env"
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and "=" in line and not line.startswith("#"):
                    key, value = line.split("=", 1)
                    os.environ.setdefault(key.strip(), value.strip())


def setup_api_key():
    """Load OpenAI API key from environment or .env file."""
    load_env_file()
    if "OPENAI_API_KEY" not in os.environ:
        env_path = Path(__file__).resolve().parent.parent.parent / ".env"
        if env_path.exists():
            load_env_file()
    if "OPENAI_API_KEY" not in os.environ:
        raise ValueError("OPENAI_API_KEY not set. Set it in .env file or environment.")
    print("OpenAI API key loaded.")


# Allowed software supply chain security topics (used by topic_filter)
ALLOWED_TOPICS = [
    "supply chain",
    "software",
    "security",
    "vulnerability",
    "dependency",
    "package",
    "npm",
    "pip",
    "docker",
    "container",
    "sbom",
    "sca",
    "sast",
    "dast",
    "secret",
    "api key",
    "token",
    "credential",
    "encryption",
    "signature",
    "certificate",
    "tls",
    "ssl",
    "malware",
    "ransomware",
    "phishing",
    "patch",
    "update",
    "cve",
    "exploit",
    "penetration",
    "audit",
    "compliance",
    "soc2",
    "iso27001",
    "gdpr",
    "devsecops",
    "ci cd",
    "pipeline",
    "github",
    "gitlab",
    "jenkins",
    "artifact",
    "repository",
    "registry",
    "open source",
    "license",
    "fork",
    "pull request",
    "build",
    "deploy",
    "infrastructure",
]

# Blocked topics (immediate reject)
BLOCKED_TOPICS = [
    "hack",
    "weapon",
    "drug",
    "illegal",
    "violence",
    "gambling",
    "bomb",
    "kill",
    "steal",
    "create malware",
]
