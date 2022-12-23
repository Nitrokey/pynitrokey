# do not import all endpoints into this module because that uses a lot of memory and stack frames
# if you need the ability to import all endpoints from this module, import them with
# from pynitrokey.nethsm.client.paths.keys_key_id_public_pem import Api

from pynitrokey.nethsm.client.paths import PathValues

path = PathValues.KEYS_KEY_ID_PUBLIC_PEM