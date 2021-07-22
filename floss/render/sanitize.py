import string


def sanitize_string_for_printing(s: str) -> str:
    """
    Return sanitized string for printing to cli.
    """
    sanitized_string = s.replace("\\\\", "\\")  # print single backslashes
    sanitized_string = "".join(c for c in sanitized_string if c in string.printable)
    return sanitized_string


def sanitize_string_for_script(s: str) -> str:
    """
    Return sanitized string that is added to IDA script source.
    """
    sanitized_string = sanitize_string_for_printing(s)
    sanitized_string = sanitized_string.replace("\\", "\\\\")
    sanitized_string = sanitized_string.replace('"', '\\"')
    return sanitized_string
