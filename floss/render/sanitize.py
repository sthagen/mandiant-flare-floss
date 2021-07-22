import string


def sanitize_string_for_printing(s: str) -> str:
    """
    Return sanitized string for printing to cli.
    """
    sanitized_string = s.replace("\\\\", "\\")  # print single backslashes
    sanitized_string = "".join(c for c in sanitized_string if c in string.printable)
    return sanitized_string