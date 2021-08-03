import logging

GREY = "\x1b[38;21m"
CYAN = "\x1b[36;21m"
YELLOW = "\x1b[33;21m"
RED = "\x1b[31;21m"
BOLD_RED = "\x1b[31;1m"
RESET = "\x1b[0m"


def make_format(color):
    return f"{color}%(levelname)s{RESET}: %(name)s: %(message)s"


FORMATS = {
    logging.DEBUG: make_format(GREY),
    logging.INFO: make_format(CYAN),
    logging.WARNING: make_format(YELLOW),
    logging.ERROR: make_format(RED),
    logging.CRITICAL: make_format(BOLD_RED),
}

FORMATTERS = {level: logging.Formatter(FORMATS[level]) for level in FORMATS.keys()}


class ColorFormatter(logging.Formatter):
    """
    Logging Formatter to add colors and count warning / errors

    via: https://stackoverflow.com/a/56944256/87207
    """

    def format(self, record):
        return FORMATTERS[record.levelno].format(record)


logging.TRACE = logging.DEBUG - 1
logging.addLevelName(logging.TRACE, "TRACE")


class LoggerWithTrace(logging.getLoggerClass()):
    def trace(self, msg, *args, **kwargs):
        self.log(logging.TRACE, msg, *args, **kwargs)


logging.setLoggerClass(LoggerWithTrace)


def getLogger(name) -> LoggerWithTrace:
    """
    a logging constructor that guarantees that the TRACE level is available.
    use this just like `logging.getLogger`.

    note: this code must come after the registration of the TRACE level.
    """
    return logging.getLogger(name)
