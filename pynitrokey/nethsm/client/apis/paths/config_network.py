from pynitrokey.nethsm.client.paths.config_network.get import ApiForget
from pynitrokey.nethsm.client.paths.config_network.put import ApiForput


class ConfigNetwork(
    ApiForget,
    ApiForput,
):
    pass
