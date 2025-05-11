import logging
import sys

from typing import Optional


COLOR_RED_INTENSE = "\033[1;31m"
COLOR_RED = "\033[31m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW_INTENSE = "\033[1;33m"
COLOR_YELLOW = "\033[33m"
COLOR_BLUE = "\033[34m"
COLOR_PURPLE = "\033[35m"
COLOR_CYAN = "\033[36m"
COLOR_WHITE_INTENSE = "\033[1;37m"
COLOR_WHITE = "\033[37m"

COLOR_DEFAULT = "\033[0m"

COLOR_MAP = {
    logging.INFO: COLOR_WHITE_INTENSE,
    logging.ERROR: COLOR_RED_INTENSE,
    logging.WARNING: COLOR_YELLOW_INTENSE,
    logging.CRITICAL: COLOR_RED_INTENSE,
}

LEVEL_NAME = {
    logging.INFO: "INFO",
    logging.ERROR: "ERROR",
    logging.WARNING: "WARN",
    logging.CRITICAL: "CRIT",
}


def setup_logging(
        debug: bool = False,
        enable_colors: bool = False,
        angr_loglevel: Optional[str] = None,
        firmwire_loglevel: Optional[str] = None,
        show_package: bool = False,
        stderr: bool = False,
):
    if debug:
        level = logging.DEBUG
    else:
        level = logging.INFO

    angr_log = logging.getLogger("angr")
    if angr_loglevel:
        angr_log.setLevel(angr_loglevel)
    else:
        angr_log.propagate = False

    firmwire_log = logging.getLogger("firmwire")
    if firmwire_loglevel:
        firmwire_log.setLevel(firmwire_loglevel)
    else:
        firmwire_log.propagate = False

    if show_package:
        fmt = "[%(levelname)s] %(name)s: %(message)s"
    else:
        fmt = "[%(levelname)s] %(message)s"

    la_log = logging.getLogger("loris_analyzer")
    la_log.setLevel(level)

    if stderr:
        handler = logging.StreamHandler(sys.stderr)
    else:
        handler = logging.StreamHandler(sys.stdout)

    formatter = logging.Formatter(fmt)
    handler.setFormatter(formatter)

    la_log.addHandler(handler)
    la_log.propagate = False

    for k, v in LEVEL_NAME.items():
        if enable_colors:
            logging.addLevelName(k, COLOR_MAP[k] + v + COLOR_DEFAULT)
        else:
            logging.addLevelName(k, v)
