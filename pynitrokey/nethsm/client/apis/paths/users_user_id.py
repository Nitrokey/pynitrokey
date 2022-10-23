from pynitrokey.nethsm.client.paths.users_user_id.get import ApiForget
from pynitrokey.nethsm.client.paths.users_user_id.put import ApiForput
from pynitrokey.nethsm.client.paths.users_user_id.delete import ApiFordelete


class UsersUserID(
    ApiForget,
    ApiForput,
    ApiFordelete,
):
    pass
