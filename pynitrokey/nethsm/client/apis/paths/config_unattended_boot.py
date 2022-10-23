from pynitrokey.nethsm.client.paths.config_unattended_boot.get import ApiForget
from pynitrokey.nethsm.client.paths.config_unattended_boot.put import ApiForput


class ConfigUnattendedBoot(
    ApiForget,
    ApiForput,
):
    pass
