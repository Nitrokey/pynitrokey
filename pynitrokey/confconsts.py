# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import logging
import os
import tempfile
from datetime import datetime
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

LOG_FN = tempfile.NamedTemporaryFile(
    prefix=f"nitropy-{datetime.now().strftime('%Y%m%dT%H%M%S')}-", suffix=".log"
).name
LOG_FORMAT_STDOUT = "%(asctime)-15s %(levelname)6s %(name)10s %(message)s"
LOG_FORMAT = "%(relativeCreated)-8d %(levelname)6s %(name)10s %(message)s"

CLI_LOG_BLACKLIST: dict[str, int] = {
    # dict of {name: lenght} mapping to exclude from cli parameter logging
    # name: name of the parameter
    # length: number of arguments the parameter has
    # nitropy start kdf-details
    "--passwd": 1,
    # nitropy start update
    # nitropy pro enable-update
    # nitropy nethsm
    "-p": 1,
    # nitropy pro enable-update
    # nitropy nk3 secrets set-pin
    # nitropy nethsm
    "--password": 1,
    # nitropy nk3 test
    # nitropy fido2 verify
    # nitropy fido2 make-credential
    # nitropy fido2 list-credentials
    # nitropy fido2 delete-credential
    # nitropy fido2 challenge-response
    "--pin": 1,
}

GH_ISSUES_URL = "https://github.com/Nitrokey/pynitrokey/issues/"
SUPPORT_URL = "https://support.nitrokey.com/"
SUPPORT_EMAIL = "support@nitrokey.com"
UDEV_URL = "https://docs.nitrokey.com/nitrokeys/nitrokey3/firmware-update#troubleshooting-linux"
