
import re
from pathlib import Path


def read_config(file_path):
    """
    Read a Cisco IOS ACL configuration file.
    Supports UTF-8 and UTF-8 with BOM encoding.
    """

    path = Path(file_path)

    # Check whether the file exists
    if not path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {file_path}"
        )

    # Check whether the path is a file
    if not path.is_file():
        raise ValueError(
            "The provided path is not a file."
        )

    # Read configuration file
    try:
        content = path.read_text(encoding="utf-8-sig")

    except UnicodeDecodeError:
        raise ValueError(
            "Unable to read configuration file. "
            "Please use UTF-8 encoding."
        )

    except OSError as error:
        raise OSError(
            f"Unable to read configuration file: {error}"
        )

    # Check whether the file is empty
    if not content.strip():
        raise ValueError(
            "Configuration file is empty."
        )

    return content.splitlines()


def parse_acl_rules(config_lines):
    """
    Extract Cisco IOS ACL rules from configuration lines.
    Supports numbered and non-numbered ACL entries.
    """

    rules = []

    for line_number, line in enumerate(config_lines, start=1):

        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("!"):
            continue

        # Identify permit and deny ACL rules
        if re.match(
            r"^(?:\d+\s+)?(?:permit|deny)\s+",
            line,
            re.IGNORECASE
        ):
            rules.append({
                "line_number": line_number,
                "raw_rule": line
            })

    return rules
