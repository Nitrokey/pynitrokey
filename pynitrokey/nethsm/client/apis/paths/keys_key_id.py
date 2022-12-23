from pynitrokey.nethsm.client.paths.keys_key_id.get import ApiForget
from pynitrokey.nethsm.client.paths.keys_key_id.put import ApiForput
from pynitrokey.nethsm.client.paths.keys_key_id.delete import ApiFordelete


class KeysKeyID(
    ApiForget,
    ApiForput,
    ApiFordelete,
):
    pass
