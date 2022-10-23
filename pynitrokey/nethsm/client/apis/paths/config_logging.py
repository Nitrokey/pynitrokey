from pynitrokey.nethsm.client.paths.config_logging.get import ApiForget
from pynitrokey.nethsm.client.paths.config_logging.put import ApiForput


class ConfigLogging(
    ApiForget,
    ApiForput,
):
    pass
