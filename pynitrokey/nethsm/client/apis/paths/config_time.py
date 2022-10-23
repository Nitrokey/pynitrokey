from pynitrokey.nethsm.client.paths.config_time.get import ApiForget
from pynitrokey.nethsm.client.paths.config_time.put import ApiForput


class ConfigTime(
    ApiForget,
    ApiForput,
):
    pass
