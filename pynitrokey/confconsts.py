import logging
import os
import tempfile
from enum import IntEnum


class Verbosity(IntEnum):
    """regular lvls from `logging` & `machine` for machine-readable output only"""

    machine = 100
    silent = logging.CRITICAL
    minimal = logging.WARNING
    user = logging.INFO
    debug = logging.DEBUG
    unset = logging.NOTSET


ENV_DEBUG_VAR = "PYNK_DEBUG"
DEFAULT_VERBOSE = Verbosity.user
VERBOSE = DEFAULT_VERBOSE

# set global debug/verbosity -> search for environment variable: ENV_DEBUG_VAR
_env_dbg_lvl = os.environ.get(ENV_DEBUG_VAR)
if _env_dbg_lvl:
    try:
        # env-var only set w/o contents equals 'Verbosity.debug'
        if _env_dbg_lvl.strip() == "":
            VERBOSE = Verbosity.debug
        # non-empty env-var shall be a number, representing a level
        else:
            VERBOSE = Verbosity(int(_env_dbg_lvl))
    except ValueError as e:
        VERBOSE = DEFAULT_VERBOSE
        print(f"exception: {e}")
        print(
            f"environment variable: '{ENV_DEBUG_VAR}' invalid, "
            f"setting default: {VERBOSE.name} = {VERBOSE.value}"
        )
    print(f"Found {ENV_DEBUG_VAR}='{_env_dbg_lvl}'. Setting VERBOSE={VERBOSE}")


LOG_FN = tempfile.NamedTemporaryFile(prefix="nitropy.log.").name
LOG_FORMAT_STDOUT = "%(asctime)-15s %(levelname)6s %(name)10s %(message)s"
LOG_FORMAT = "%(relativeCreated)-8d %(levelname)6s %(name)10s %(message)s"

GH_ISSUES_URL = "https://github.com/Nitrokey/pynitrokey/issues/"
SUPPORT_URL = "https://support.nitrokey.com/"
SUPPORT_EMAIL = "support@nitrokey.com"
UDEV_URL = (
    "https://docs.nitrokey.com/nitrokey3/linux/firmware-update.html#troubleshooting"
)


logger = logging.getLogger(__name__)
stream_handler = logging.StreamHandler()
stream_handler.setLevel(VERBOSE)
stream_handler.setFormatter(logging.Formatter(LOG_FORMAT_STDOUT))
logger.addHandler(stream_handler)
