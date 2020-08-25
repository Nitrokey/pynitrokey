
from enum import IntEnum
import tempfile


class Verbosity(IntEnum):
    unset = 0
    silent = 1
    machine = 2
    user = 3
    full = 4
    debug = 5


#VERBOSE = Verbosity.user
VERBOSE = Verbosity.debug

LOG_FN = tempfile.NamedTemporaryFile(prefix="nitropy.log.").name
LOG_FORMAT_STDOUT = '*** %(asctime)-15s %(levelname)6s %(name)10s %(message)s'
LOG_FORMAT = '%(relativeCreated)-8d %(levelname)6s %(name)10s %(message)s'

ISSUES_URL = "https://github.com/Nitrokey/pynitrokey/issues/"
