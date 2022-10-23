import typing_extensions

from pynitrokey.nethsm.client.paths import PathValues
from pynitrokey.nethsm.client.apis.paths.info import Info
from pynitrokey.nethsm.client.apis.paths.health_alive import HealthAlive
from pynitrokey.nethsm.client.apis.paths.health_ready import HealthReady
from pynitrokey.nethsm.client.apis.paths.health_state import HealthState
from pynitrokey.nethsm.client.apis.paths.metrics import Metrics
from pynitrokey.nethsm.client.apis.paths.provision import Provision
from pynitrokey.nethsm.client.apis.paths.unlock import Unlock
from pynitrokey.nethsm.client.apis.paths.lock import Lock
from pynitrokey.nethsm.client.apis.paths.random import Random
from pynitrokey.nethsm.client.apis.paths.keys import Keys
from pynitrokey.nethsm.client.apis.paths.keys_generate import KeysGenerate
from pynitrokey.nethsm.client.apis.paths.keys_key_id import KeysKeyID
from pynitrokey.nethsm.client.apis.paths.keys_key_id_public_pem import KeysKeyIDPublicPem
from pynitrokey.nethsm.client.apis.paths.keys_key_id_csr_pem import KeysKeyIDCsrPem
from pynitrokey.nethsm.client.apis.paths.keys_key_id_decrypt import KeysKeyIDDecrypt
from pynitrokey.nethsm.client.apis.paths.keys_key_id_encrypt import KeysKeyIDEncrypt
from pynitrokey.nethsm.client.apis.paths.keys_key_id_sign import KeysKeyIDSign
from pynitrokey.nethsm.client.apis.paths.keys_key_id_cert import KeysKeyIDCert
from pynitrokey.nethsm.client.apis.paths.keys_key_id_restrictions_tags_tag import KeysKeyIDRestrictionsTagsTag
from pynitrokey.nethsm.client.apis.paths.users import Users
from pynitrokey.nethsm.client.apis.paths.users_user_id import UsersUserID
from pynitrokey.nethsm.client.apis.paths.users_user_id_passphrase import UsersUserIDPassphrase
from pynitrokey.nethsm.client.apis.paths.users_user_id_tags import UsersUserIDTags
from pynitrokey.nethsm.client.apis.paths.users_user_id_tags_tag import UsersUserIDTagsTag
from pynitrokey.nethsm.client.apis.paths.config_unlock_passphrase import ConfigUnlockPassphrase
from pynitrokey.nethsm.client.apis.paths.config_unattended_boot import ConfigUnattendedBoot
from pynitrokey.nethsm.client.apis.paths.config_tls_public_pem import ConfigTlsPublicPem
from pynitrokey.nethsm.client.apis.paths.config_tls_cert_pem import ConfigTlsCertPem
from pynitrokey.nethsm.client.apis.paths.config_tls_csr_pem import ConfigTlsCsrPem
from pynitrokey.nethsm.client.apis.paths.config_tls_generate import ConfigTlsGenerate
from pynitrokey.nethsm.client.apis.paths.config_network import ConfigNetwork
from pynitrokey.nethsm.client.apis.paths.config_logging import ConfigLogging
from pynitrokey.nethsm.client.apis.paths.config_backup_passphrase import ConfigBackupPassphrase
from pynitrokey.nethsm.client.apis.paths.config_time import ConfigTime
from pynitrokey.nethsm.client.apis.paths.system_info import SystemInfo
from pynitrokey.nethsm.client.apis.paths.system_reboot import SystemReboot
from pynitrokey.nethsm.client.apis.paths.system_shutdown import SystemShutdown
from pynitrokey.nethsm.client.apis.paths.system_factory_reset import SystemFactoryReset
from pynitrokey.nethsm.client.apis.paths.system_update import SystemUpdate
from pynitrokey.nethsm.client.apis.paths.system_commit_update import SystemCommitUpdate
from pynitrokey.nethsm.client.apis.paths.system_cancel_update import SystemCancelUpdate
from pynitrokey.nethsm.client.apis.paths.system_backup import SystemBackup
from pynitrokey.nethsm.client.apis.paths.system_restore import SystemRestore

PathToApi = typing_extensions.TypedDict(
    'PathToApi',
    {
        PathValues.INFO: Info,
        PathValues.HEALTH_ALIVE: HealthAlive,
        PathValues.HEALTH_READY: HealthReady,
        PathValues.HEALTH_STATE: HealthState,
        PathValues.METRICS: Metrics,
        PathValues.PROVISION: Provision,
        PathValues.UNLOCK: Unlock,
        PathValues.LOCK: Lock,
        PathValues.RANDOM: Random,
        PathValues.KEYS: Keys,
        PathValues.KEYS_GENERATE: KeysGenerate,
        PathValues.KEYS_KEY_ID: KeysKeyID,
        PathValues.KEYS_KEY_ID_PUBLIC_PEM: KeysKeyIDPublicPem,
        PathValues.KEYS_KEY_ID_CSR_PEM: KeysKeyIDCsrPem,
        PathValues.KEYS_KEY_ID_DECRYPT: KeysKeyIDDecrypt,
        PathValues.KEYS_KEY_ID_ENCRYPT: KeysKeyIDEncrypt,
        PathValues.KEYS_KEY_ID_SIGN: KeysKeyIDSign,
        PathValues.KEYS_KEY_ID_CERT: KeysKeyIDCert,
        PathValues.KEYS_KEY_ID_RESTRICTIONS_TAGS_TAG: KeysKeyIDRestrictionsTagsTag,
        PathValues.USERS: Users,
        PathValues.USERS_USER_ID: UsersUserID,
        PathValues.USERS_USER_ID_PASSPHRASE: UsersUserIDPassphrase,
        PathValues.USERS_USER_ID_TAGS: UsersUserIDTags,
        PathValues.USERS_USER_ID_TAGS_TAG: UsersUserIDTagsTag,
        PathValues.CONFIG_UNLOCKPASSPHRASE: ConfigUnlockPassphrase,
        PathValues.CONFIG_UNATTENDEDBOOT: ConfigUnattendedBoot,
        PathValues.CONFIG_TLS_PUBLIC_PEM: ConfigTlsPublicPem,
        PathValues.CONFIG_TLS_CERT_PEM: ConfigTlsCertPem,
        PathValues.CONFIG_TLS_CSR_PEM: ConfigTlsCsrPem,
        PathValues.CONFIG_TLS_GENERATE: ConfigTlsGenerate,
        PathValues.CONFIG_NETWORK: ConfigNetwork,
        PathValues.CONFIG_LOGGING: ConfigLogging,
        PathValues.CONFIG_BACKUPPASSPHRASE: ConfigBackupPassphrase,
        PathValues.CONFIG_TIME: ConfigTime,
        PathValues.SYSTEM_INFO: SystemInfo,
        PathValues.SYSTEM_REBOOT: SystemReboot,
        PathValues.SYSTEM_SHUTDOWN: SystemShutdown,
        PathValues.SYSTEM_FACTORYRESET: SystemFactoryReset,
        PathValues.SYSTEM_UPDATE: SystemUpdate,
        PathValues.SYSTEM_COMMITUPDATE: SystemCommitUpdate,
        PathValues.SYSTEM_CANCELUPDATE: SystemCancelUpdate,
        PathValues.SYSTEM_BACKUP: SystemBackup,
        PathValues.SYSTEM_RESTORE: SystemRestore,
    }
)

path_to_api = PathToApi(
    {
        PathValues.INFO: Info,
        PathValues.HEALTH_ALIVE: HealthAlive,
        PathValues.HEALTH_READY: HealthReady,
        PathValues.HEALTH_STATE: HealthState,
        PathValues.METRICS: Metrics,
        PathValues.PROVISION: Provision,
        PathValues.UNLOCK: Unlock,
        PathValues.LOCK: Lock,
        PathValues.RANDOM: Random,
        PathValues.KEYS: Keys,
        PathValues.KEYS_GENERATE: KeysGenerate,
        PathValues.KEYS_KEY_ID: KeysKeyID,
        PathValues.KEYS_KEY_ID_PUBLIC_PEM: KeysKeyIDPublicPem,
        PathValues.KEYS_KEY_ID_CSR_PEM: KeysKeyIDCsrPem,
        PathValues.KEYS_KEY_ID_DECRYPT: KeysKeyIDDecrypt,
        PathValues.KEYS_KEY_ID_ENCRYPT: KeysKeyIDEncrypt,
        PathValues.KEYS_KEY_ID_SIGN: KeysKeyIDSign,
        PathValues.KEYS_KEY_ID_CERT: KeysKeyIDCert,
        PathValues.KEYS_KEY_ID_RESTRICTIONS_TAGS_TAG: KeysKeyIDRestrictionsTagsTag,
        PathValues.USERS: Users,
        PathValues.USERS_USER_ID: UsersUserID,
        PathValues.USERS_USER_ID_PASSPHRASE: UsersUserIDPassphrase,
        PathValues.USERS_USER_ID_TAGS: UsersUserIDTags,
        PathValues.USERS_USER_ID_TAGS_TAG: UsersUserIDTagsTag,
        PathValues.CONFIG_UNLOCKPASSPHRASE: ConfigUnlockPassphrase,
        PathValues.CONFIG_UNATTENDEDBOOT: ConfigUnattendedBoot,
        PathValues.CONFIG_TLS_PUBLIC_PEM: ConfigTlsPublicPem,
        PathValues.CONFIG_TLS_CERT_PEM: ConfigTlsCertPem,
        PathValues.CONFIG_TLS_CSR_PEM: ConfigTlsCsrPem,
        PathValues.CONFIG_TLS_GENERATE: ConfigTlsGenerate,
        PathValues.CONFIG_NETWORK: ConfigNetwork,
        PathValues.CONFIG_LOGGING: ConfigLogging,
        PathValues.CONFIG_BACKUPPASSPHRASE: ConfigBackupPassphrase,
        PathValues.CONFIG_TIME: ConfigTime,
        PathValues.SYSTEM_INFO: SystemInfo,
        PathValues.SYSTEM_REBOOT: SystemReboot,
        PathValues.SYSTEM_SHUTDOWN: SystemShutdown,
        PathValues.SYSTEM_FACTORYRESET: SystemFactoryReset,
        PathValues.SYSTEM_UPDATE: SystemUpdate,
        PathValues.SYSTEM_COMMITUPDATE: SystemCommitUpdate,
        PathValues.SYSTEM_CANCELUPDATE: SystemCancelUpdate,
        PathValues.SYSTEM_BACKUP: SystemBackup,
        PathValues.SYSTEM_RESTORE: SystemRestore,
    }
)
