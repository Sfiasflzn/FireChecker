
import re
from pathlib import Path


def read_config(file_path):
    """
    Read a Cisco IOS ACL configuration file.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {file_path}")

    if not path.is_file():
        raise ValueError("The provided path is not a file.")

    content = path.read_text(encoding="utf-8")

    if not content.strip():
        raise ValueError("Configuration file is empty.")

    return content.splitlines()


def parse_acl_rules(config_lines):
    """
    Extract ACL rules from Cisco IOS configuration.
    """

    rules = []

    for line_number, line in enumerate(config_lines, start=1):
        line = line.strip()

        if not line or line.startswith("!"):
            continue

        if re.match(r"^(?:\d+\s+)?(?:permit|deny)\s+", line):
            rules.append({
                "line_number": line_number,
                "raw_rule": line
            })

    return rules
