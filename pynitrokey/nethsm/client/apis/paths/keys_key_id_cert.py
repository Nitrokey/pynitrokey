from pynitrokey.nethsm.client.paths.keys_key_id_cert.get import ApiForget
from pynitrokey.nethsm.client.paths.keys_key_id_cert.put import ApiForput
from pynitrokey.nethsm.client.paths.keys_key_id_cert.delete import ApiFordelete


class KeysKeyIDCert(
    ApiForget,
    ApiForput,
    ApiFordelete,
):
    pass
