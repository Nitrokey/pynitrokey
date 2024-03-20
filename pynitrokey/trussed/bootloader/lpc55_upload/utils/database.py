#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module to manage used databases in SPSDK."""

import atexit
import logging
import os
import pickle
import shutil
from copy import copy, deepcopy
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

import platformdirs
from typing_extensions import Self

import spsdk
from spsdk import SPSDK_CACHE_DISABLED, SPSDK_DATA_FOLDER
from spsdk.crypto.hash import EnumHashAlgorithm, Hash, get_hash
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.misc import (
    deep_update,
    find_first,
    load_configuration,
    value_to_bool,
    value_to_int,
)

logger = logging.getLogger(__name__)


class SPSDKErrorMissingDevice(SPSDKError):
    """Missing device in database."""


class Features:
    """Features dataclass represents a single device revision."""

    def __init__(
        self, name: str, is_latest: bool, device: "Device", features: Dict[str, Dict[str, Any]]
    ) -> None:
        """Constructor of revision.

        :param name: Revision name
        :param is_latest: Mark if this revision is latest.
        :param device: Reference to its device
        :param features: Features
        """
        self.name = name
        self.is_latest = is_latest
        self.device = device
        self.features = features

    def check_key(self, feature: str, key: Union[List[str], str]) -> bool:
        """Check if the key exist in database.

        :param feature: Feature name
        :param key: Item key or key path in list like ['grp1', 'grp2', 'key']
        :raises SPSDKValueError: Unsupported feature
        :return: True if exist False otherwise
        """
        if feature not in self.features:
            raise SPSDKValueError(f"Unsupported feature: '{feature}'")
        db_dict = self.features[feature]

        if isinstance(key, list):
            while len(key) > 1:
                act_key = key.pop(0)
                if act_key not in db_dict or not isinstance(db_dict[act_key], dict):
                    return False
                db_dict = db_dict[act_key]
            key = key[0]

        assert isinstance(key, str)
        return key in db_dict

    def get_value(self, feature: str, key: Union[List[str], str], default: Any = None) -> Any:
        """Get value.

        :param feature: Feature name
        :param key: Item key or key path in list like ['grp1', 'grp2', 'key']
        :param default: Default value in case of missing key
        :raises SPSDKValueError: Unsupported feature
        :raises SPSDKValueError: Unavailable item in feature
        :return: Value from the feature
        """
        if feature not in self.features:
            raise SPSDKValueError(f"Unsupported feature: '{feature}'")
        db_dict = self.features[feature]

        if isinstance(key, list):
            while len(key) > 1:
                act_key = key.pop(0)
                if act_key not in db_dict or not isinstance(db_dict[act_key], dict):
                    raise SPSDKValueError(f"Non-existing nested group: '{act_key}'")
                db_dict = db_dict[act_key]
            key = key[0]

        assert isinstance(key, str)
        val = db_dict.get(key, default)

        if val is None:
            raise SPSDKValueError(f"Unavailable item '{key}' in feature '{feature}'")
        return val

    def get_bool(
        self, feature: str, key: Union[List[str], str], default: Optional[bool] = None
    ) -> bool:
        """Get Boolean value.

        :param feature: Feature name
        :param key: Item key or key path in list like ['grp1', 'grp2', 'key']
        :param default: Default value in case of missing key
        :return: Boolean value from the feature
        """
        val = self.get_value(feature, key, default)
        return value_to_bool(val)

    def get_int(
        self, feature: str, key: Union[List[str], str], default: Optional[int] = None
    ) -> int:
        """Get Integer value.

        :param feature: Feature name
        :param key: Item key or key path in list like ['grp1', 'grp2', 'key']
        :param default: Default value in case of missing key
        :return: Integer value from the feature
        """
        val = self.get_value(feature, key, default)
        return value_to_int(val)

    def get_str(
        self, feature: str, key: Union[List[str], str], default: Optional[str] = None
    ) -> str:
        """Get String value.

        :param feature: Feature name
        :param key: Item key or key path in list like ['grp1', 'grp2', 'key']
        :param default: Default value in case of missing key
        :return: String value from the feature
        """
        val = self.get_value(feature, key, default)
        assert isinstance(val, str)
        return val

    def get_list(
        self, feature: str, key: Union[List[str], str], default: Optional[List] = None
    ) -> List[Any]:
        """Get List value.

        :param feature: Feature name
        :param key: Item key or key path in list like ['grp1', 'grp2', 'key']
        :param default: Default value in case of missing key
        :return: List value from the feature
        """
        val = self.get_value(feature, key, default)
        assert isinstance(val, list)
        return val

    def get_dict(
        self, feature: str, key: Union[List[str], str], default: Optional[Dict] = None
    ) -> Dict:
        """Get Dictionary value.

        :param feature: Feature name
        :param key: Item key or key path in list like ['grp1', 'grp2', 'key']
        :param default: Default value in case of missing key
        :return: Dictionary value from the feature
        """
        val = self.get_value(feature, key, default)
        assert isinstance(val, dict)
        return val

    def get_file_path(
        self, feature: str, key: Union[List[str], str], default: Optional[str] = None
    ) -> str:
        """Get File path value.

        :param feature: Feature name
        :param key: Item key or key path in list like ['grp1', 'grp2', 'key']
        :param default: Default value in case of missing key
        :return: File path value from the feature
        """
        file_name = self.get_str(feature, key, default)
        return self.device.create_file_path(file_name)


class Revisions(List[Features]):
    """List of device revisions."""

    def revision_names(self, append_latest: bool = False) -> List[str]:
        """Get list of revisions.

        :param append_latest: Add to list also "latest" string
        :return: List of all supported device version.
        """
        ret = [rev.name for rev in self]
        if append_latest:
            ret.append("latest")
        return ret

    def get(self, name: Optional[str] = None) -> Features:
        """Get the revision by its name.

        If name is not specified, or equal to 'latest', then the latest revision is returned.

        :param name: The revision name.
        :return: The Revision object.
        """
        if name is None or name == "latest":
            return self.get_latest()
        return self.get_by_name(name)

    def get_by_name(self, name: str) -> Features:
        """Get the required revision.

        :param name: Required revision name
        :raises SPSDKValueError: Incase of invalid device or revision value.
        :return: The Revision object.
        """
        revision = find_first(self, lambda rev: rev.name == name)
        if not revision:
            raise SPSDKValueError(f"Requested revision {name} is not supported.")
        return revision

    def get_latest(self) -> Features:
        """Get latest revision for device.

        :raises SPSDKValueError: Incase of there is no latest revision defined.
        :return: The Features object.
        """
        revision = find_first(self, lambda rev: rev.is_latest)
        if not revision:
            raise SPSDKValueError("No latest revision has been defined.")
        return revision


class DeviceInfo:
    """Device information dataclass."""

    def __init__(
        self,
        purpose: str,
        web: str,
        memory_map: Dict[str, Dict[str, Union[int, bool]]],
        isp: Dict[str, Any],
    ) -> None:
        """Constructor of device information class.

        :param purpose: String description of purpose of MCU (in fact the device group)
        :param web: Web page with device info
        :param memory_map: Basic memory map of device
        :param isp: Information regarding ISP mode
        """
        self.purpose = purpose
        self.web = web
        self.memory_map = memory_map
        self.isp = isp

    @staticmethod
    def load(config: Dict[str, Any], defaults: Dict[str, Any]) -> "DeviceInfo":
        """Loads the device from folder.

        :param config: The name of device.
        :param defaults: Device data defaults.
        :return: The Device object.
        """
        data = deepcopy(defaults)
        deep_update(data, config)
        return DeviceInfo(
            purpose=data["purpose"], web=data["web"], memory_map=data["memory_map"], isp=data["isp"]
        )

    def update(self, config: Dict[str, Any]) -> None:
        """Updates Device info by new configuration.

        :param config: The new Device Info configuration
        """
        self.purpose = config.get("purpose", self.purpose)
        self.web = config.get("web", self.web)
        self.memory_map = config.get("memory_map", self.memory_map)
        self.isp = config.get("isp", self.isp)


class Device:
    """Device dataclass represents a single device."""

    def __init__(
        self,
        name: str,
        path: str,
        latest_rev: str,
        info: DeviceInfo,
        device_alias: Optional["Device"] = None,
        revisions: Revisions = Revisions(),
    ) -> None:
        """Constructor of SPSDK Device.

        :param name: Device name
        :param path: Data path
        :param latest_rev: latest revision name
        :param device_alias: Device alias, defaults to None
        :param revisions: Device revisions, defaults to Revisions()
        """
        self.name = name
        self.path = path
        self.latest_rev = latest_rev
        self.device_alias = device_alias
        self.revisions = revisions
        self.info = info

    @property
    def features_list(self) -> List[str]:
        """Get the list of device features."""
        return [str(k) for k in self.revisions.get().features.keys()]

    @staticmethod
    def _load_alias(
        name: str, path: str, dev_cfg: Dict[str, Any], other_devices: "Devices"
    ) -> "Device":
        """Loads the device from folder.

        :param name: The name of device.
        :param path: Device data path.
        :param dev_cfg: Already loaded configuration.
        :param other_devices: Other devices used to allow aliases.
        :return: The Device object.
        """
        dev_cfg = load_configuration(os.path.join(path, "database.yaml"))
        dev_alias_name = dev_cfg["alias"]
        # Let get() function raise exception in case that device not exists in database
        ret = deepcopy(other_devices.get(dev_alias_name))
        ret.name = name
        ret.path = path
        ret.device_alias = other_devices.get(dev_alias_name)
        dev_features: Dict[str, Dict] = dev_cfg.get("features", {})
        dev_revisions: Dict[str, Dict] = dev_cfg.get("revisions", {})
        assert isinstance(dev_features, Dict)
        assert isinstance(dev_revisions, Dict)
        ret.latest_rev = dev_cfg.get("latest", ret.latest_rev)
        # First off all update general changes in features
        if dev_features:
            for rev in ret.revisions:
                deep_update(rev.features, dev_features)

        for rev_name, rev_updates in dev_revisions.items():
            try:
                dev_rev = ret.revisions.get_by_name(rev_name)
            except SPSDKValueError as exc:
                # In case of newly defined revision, there must be defined alias
                alias_rev = rev_updates.get("alias")
                if not alias_rev:
                    raise SPSDKError(
                        f"There is missing alias key in new revision ({rev_name}) of aliased device {ret.name}"
                    ) from exc
                dev_rev = deepcopy(ret.revisions.get_by_name(alias_rev))
                dev_rev.name = rev_name
                dev_rev.is_latest = bool(ret.latest_rev == rev_name)
                ret.revisions.append(dev_rev)

            # Update just same rev
            rev_specific_features = rev_updates.get("features")
            if rev_specific_features:
                deep_update(dev_rev.features, rev_specific_features)

        if "info" in dev_cfg:
            ret.info.update(dev_cfg["info"])

        return ret

    @staticmethod
    def load(name: str, path: str, defaults: Dict[str, Any], other_devices: "Devices") -> "Device":
        """Loads the device from folder.

        :param name: The name of device.
        :param path: Device data path.
        :param defaults: Device data defaults.
        :param other_devices: Other devices used to allow aliases.
        :return: The Device object.
        """
        dev_cfg = load_configuration(os.path.join(path, "database.yaml"))
        dev_alias_name = dev_cfg.get("alias")
        if dev_alias_name:
            return Device._load_alias(
                name=name, path=path, dev_cfg=dev_cfg, other_devices=other_devices
            )

        dev_features: Dict[str, Dict] = dev_cfg["features"]
        features_defaults: Dict[str, Dict] = deepcopy(defaults["features"])

        dev_info = DeviceInfo.load(dev_cfg["info"], defaults["info"])

        # Get defaults and update them by device specific data set
        for feature_name in dev_features:
            deep_update(features_defaults[feature_name], dev_features[feature_name])
            dev_features[feature_name] = features_defaults[feature_name]

        revisions = Revisions()
        dev_revisions: Dict[str, Dict] = dev_cfg["revisions"]
        latest: str = dev_cfg["latest"]
        if latest not in dev_revisions:
            raise SPSDKError(
                f"The latest revision defined in database for {name} is not in supported revisions"
            )

        ret = Device(name=name, path=path, info=dev_info, latest_rev=latest, device_alias=None)

        for rev, rev_updates in dev_revisions.items():
            features = deepcopy(dev_features)
            rev_specific_features = rev_updates.get("features")
            if rev_specific_features:
                deep_update(features, rev_specific_features)
            revisions.append(
                Features(name=rev, is_latest=bool(rev == latest), features=features, device=ret)
            )

        ret.revisions = revisions

        return ret

    def create_file_path(self, file_name: str) -> str:
        """Create File path value for this device.

        :param file_name: File name to be enriched by device path
        :return: File path value for the device
        """
        path = os.path.abspath(os.path.join(self.path, file_name))
        if not os.path.exists(path) and self.device_alias:
            path = self.device_alias.create_file_path(file_name)

        if not os.path.exists(path):
            raise SPSDKValueError(f"Non existing file ({file_name}) in database")
        return path


class Devices(List[Device]):
    """List of devices."""

    def get(self, name: str) -> Device:
        """Return database device structure.

        :param name: String Key with device name.
        :raises SPSDKErrorMissingDevice: In case the device with given name does not exist
        :return: Dictionary device configuration structure or None:
        """
        dev = find_first(self, lambda dev: dev.name == name)
        if not dev:
            raise SPSDKErrorMissingDevice(f"The device with name {name} is not in the database.")
        return dev

    @property
    def devices_names(self) -> List[str]:
        """Get the list of devices names."""
        return [dev.name for dev in self]

    def feature_items(self, feature: str, key: str) -> Iterator[Tuple[str, str, Any]]:
        """Iter the whole database for the feature items.

        :return: Tuple of Device name, revision name and items value.
        """
        for device in self:
            if not feature in device.features_list:
                continue
            for rev in device.revisions:
                value = rev.features[feature].get(key)
                if value is None:
                    raise SPSDKValueError(f"Missing item '{key}' in feature '{feature}'!")
                yield (device.name, rev.name, value)

    @staticmethod
    def load(devices_path: str, defaults: Dict[str, Any]) -> "Devices":
        """Loads the devices from SPSDK database path.

        :param devices_path: Devices data path.
        :param defaults: Devices defaults data.
        :return: The Devices object.
        """
        devices = Devices()
        uncompleted_aliases: List[os.DirEntry] = []
        for dev in os.scandir(devices_path):
            if dev.is_dir():
                try:
                    try:
                        devices.append(
                            Device.load(
                                name=dev.name,
                                path=dev.path,
                                defaults=defaults,
                                other_devices=devices,
                            )
                        )
                    except SPSDKErrorMissingDevice:
                        uncompleted_aliases.append(dev)
                except SPSDKError as exc:
                    logger.error(
                        f"Failed loading device '{dev.name}' into SPSDK database. Details:\n{str(exc)}"
                    )
        while uncompleted_aliases:
            prev_len = len(uncompleted_aliases)
            for dev in copy(uncompleted_aliases):
                try:
                    devices.append(
                        Device.load(
                            name=dev.name, path=dev.path, defaults=defaults, other_devices=devices
                        )
                    )
                    uncompleted_aliases.remove(dev)
                except SPSDKErrorMissingDevice:
                    pass
            if prev_len == len(uncompleted_aliases):
                raise SPSDKError("Cannot load all alias devices in database.")
        return devices


class Database:
    """Class that helps manage used databases in SPSDK."""

    def __init__(self, path: str) -> None:
        """Register Configuration class constructor.

        :param path: The path to configuration JSON file.
        """
        self._cfg_cache: Dict[str, Dict[str, Any]] = {}
        self.path = path
        self.common_folder_path = os.path.join(path, "common")
        self.devices_folder_path = os.path.join(path, "devices")
        self._defaults = load_configuration(
            os.path.join(self.common_folder_path, "database_defaults.yaml")
        )
        self._devices = Devices.load(devices_path=self.devices_folder_path, defaults=self._defaults)

        # optional Database hash that could be used for identification of consistency
        self.db_hash = bytes()

    @property
    def devices(self) -> Devices:
        """Get the list of devices stored in the database."""
        return self._devices

    def get_feature_list(self, dev_name: Optional[str] = None) -> List[str]:
        """Get features list.

        If device is not used, the whole list of SPSDK features is returned

        :param dev_name: Device name, defaults to None
        :returns: List of features.
        """
        if dev_name:
            return self.devices.get(dev_name).features_list

        default_features: Dict[str, Dict] = self._defaults["features"]
        return [str(k) for k in default_features.keys()]

    def get_defaults(self, feature: str) -> Dict[str, Any]:
        """Gets feature defaults.

        :param feature: Feature name
        :return: Dictionary with feature defaults.
        """
        features = self._defaults["features"]
        if feature not in features:
            raise SPSDKValueError(f"Invalid feature requested: {feature}")

        return deepcopy(features[feature])

    def get_device_features(
        self,
        device: str,
        revision: str = "latest",
    ) -> Features:
        """Get device features database.

        :param device: The device name.
        :param revision: The revision of the silicon.
        :raises SPSDKValueError: Unsupported feature
        :return: The feature data.
        """
        dev = self.devices.get(device)
        return dev.revisions.get(revision)

    def get_schema_file(self, feature: str) -> Dict[str, Any]:
        """Get JSON Schema file name for the requested feature.

        :param feature: Requested feature.
        :return: Loaded dictionary of JSON Schema file.
        """
        filename = os.path.join(SPSDK_DATA_FOLDER, "jsonschemas", f"sch_{feature}.yaml")
        return self.load_db_cfg_file(filename)

    def load_db_cfg_file(self, filename: str) -> Dict[str, Any]:
        """Return load database config file (JSON/YAML). Use SingleTon behavior.

        :param filename: Path to config file.
        :raises SPSDKError: Invalid config file.
        :return: Loaded file in dictionary.
        """
        abs_path = os.path.abspath(filename)
        if abs_path not in self._cfg_cache:
            try:
                cfg = load_configuration(abs_path)
            except SPSDKError as exc:
                raise SPSDKError(f"Invalid configuration file. {str(exc)}") from exc
            self._cfg_cache[abs_path] = cfg

        return deepcopy(self._cfg_cache[abs_path])

    def get_devices_with_feature(
        self, feature: str, sub_keys: Optional[List[str]] = None
    ) -> List[str]:
        """Get the list of all device names that supports requested feature.

        :param feature: Name of feature
        :param sub_keys: Optional sub keys to specify the nested dictionaries that feature needs to has to be counted
        :returns: List of devices that supports requested feature.
        """

        def check_sub_keys(d: dict, sub_keys: List[str]) -> bool:
            key = sub_keys.pop(0)
            if not key in d:
                return False

            if len(sub_keys) == 0:
                return True

            nested = d[key]
            if not isinstance(nested, dict):
                return False
            return check_sub_keys(nested, sub_keys)

        devices = []
        for device in self.devices:
            if feature in device.features_list:
                if sub_keys and not check_sub_keys(
                    device.revisions.get_latest().features[feature], copy(sub_keys)
                ):
                    continue
                devices.append(device.name)

        devices.sort()
        return devices

    def __hash__(self) -> int:
        """Hash function of the database."""
        return hash(len(self._cfg_cache))


class DatabaseManager:
    """Main SPSDK database manager."""

    _instance = None
    _db: Optional[Database] = None
    _db_hash: int = 0
    _db_cache_file_name = ""

    @staticmethod
    def get_cache_filename() -> Tuple[str, str]:
        """Get database cache folder and file name.

        :return: Tuple of cache path and database file name.
        """
        data_folder = SPSDK_DATA_FOLDER.lower()
        cache_name = (
            "db_"
            + get_hash(data_folder.encode(), algorithm=EnumHashAlgorithm.SHA1)[:6].hex()
            + ".cache"
        )
        cache_path = platformdirs.user_cache_dir(appname="spsdk", version=spsdk.version)
        return (cache_path, os.path.join(cache_path, cache_name))

    @staticmethod
    def clear_cache() -> None:
        """Clear SPSDK cache."""
        path, _ = DatabaseManager.get_cache_filename()
        shutil.rmtree(path)

    @classmethod
    def _get_database(cls) -> Database:
        """Get database and count with cache."""
        if SPSDK_CACHE_DISABLED:
            DatabaseManager.clear_cache()
            return Database(SPSDK_DATA_FOLDER)

        db_hash = DatabaseManager.get_db_hash(SPSDK_DATA_FOLDER)

        if os.path.exists(cls._db_cache_file_name):
            try:
                with open(cls._db_cache_file_name, mode="rb") as f:
                    loaded_db = pickle.load(f)
                    assert isinstance(loaded_db, Database)
                    if db_hash == loaded_db.db_hash:
                        logger.debug(f"Loaded database from cache: {cls._db_cache_file_name}")
                        return loaded_db
                    # if the hash is not same clear cache and make a new one
                    logger.debug(f"Existing cached DB ({cls._db_cache_file_name}) has invalid hash")
                    DatabaseManager.clear_cache()
            except Exception as exc:
                logger.debug(f"Cannot load database cache: {str(exc)}")

        db = Database(SPSDK_DATA_FOLDER)
        db.db_hash = db_hash
        try:
            os.makedirs(cls._db_cache_folder_name, exist_ok=True)
            with open(cls._db_cache_file_name, mode="wb") as f:
                pickle.dump(db, f, pickle.HIGHEST_PROTOCOL)
                logger.debug(f"Created database cache: {cls._db_cache_file_name}")
        except Exception as exc:
            logger.debug(f"Cannot store database cache: {str(exc)}")
        return db

    def __new__(cls) -> Self:
        """Manage SPSDK Database as a singleton class.

        :return: SPSDK_Database object
        """
        if cls._instance:
            return cls._instance
        cls._instance = super(DatabaseManager, cls).__new__(cls)
        cls._db_cache_folder_name, cls._db_cache_file_name = DatabaseManager.get_cache_filename()
        cls._db = cls._instance._get_database()
        cls._db_hash = hash(cls._db)
        return cls._instance

    @staticmethod
    def get_db_hash(path: str) -> bytes:
        """Get the real db hash."""
        hash_obj = Hash(EnumHashAlgorithm.SHA1)
        for root, dirs, files in os.walk(path):
            for _dir in dirs:
                hash_obj.update(DatabaseManager.get_db_hash(os.path.join(root, _dir)))
            for file in files:
                if os.path.splitext(file)[1] in [".json", ".yaml"]:
                    stat = os.stat(os.path.join(root, file))
                    hash_obj.update_int(stat.st_mtime_ns)
                    hash_obj.update_int(stat.st_ctime_ns)
                    hash_obj.update_int(stat.st_size)

        return hash_obj.finalize()

    @property
    def db(self) -> Database:
        """Get Database."""
        db = type(self)._db
        assert isinstance(db, Database)
        return db

    # """List all SPSDK supported features"""
    COMM_BUFFER = "comm_buffer"
    # BLHOST = "blhost"
    CERT_BLOCK = "cert_block"
    DAT = "dat"
    MBI = "mbi"
    HAB = "hab"
    AHAB = "ahab"
    SIGNED_MSG = "signed_msg"
    PFR = "pfr"
    IFR = "ifr"
    BOOTABLE_IMAGE = "bootable_image"
    FCB = "fcb"
    XMCD = "xmcd"
    BEE = "bee"
    IEE = "iee"
    OTFAD = "otfad"
    SB21 = "sb21"
    SB31 = "sb31"
    SBX = "sbx"
    SHADOW_REGS = "shadow_regs"
    DEVHSM = "devhsm"
    TP = "tp"
    TZ = "tz"
    ELE = "ele"
    MEMCFG = "memcfg"
    WPC = "wpc"


@atexit.register
def on_delete() -> None:
    """Delete method of SPSDK database.

    The exit method is used to update cache in case it has been changed.
    """
    if SPSDK_CACHE_DISABLED:
        return
    if DatabaseManager._db_hash != hash(DatabaseManager._db):
        try:
            with open(DatabaseManager._db_cache_file_name, mode="wb") as f:
                logger.debug(f"Updating cache: {DatabaseManager._db_cache_file_name}")
                pickle.dump(DatabaseManager().db, f, pickle.HIGHEST_PROTOCOL)
        except FileNotFoundError:
            pass


def get_db(
    device: str,
    revision: str = "latest",
) -> Features:
    """Get device feature database.

    :param device: The device name.
    :param revision: The revision of the silicon.
    :return: The feature data.
    """
    return DatabaseManager().db.get_device_features(device, revision)


def get_device(device: str) -> Device:
    """Get device database object.

    :param device: The device name.
    :return: The device data.
    """
    return DatabaseManager().db.devices.get(device)


def get_families(feature: str, sub_keys: Optional[List[str]] = None) -> List[str]:
    """Get the list of all family names that supports requested feature.

    :param feature: Name of feature
    :param sub_keys: Optional sub keys to specify the nested dictionaries that feature needs to has to be counted
    :returns: List of devices that supports requested feature.
    """
    return DatabaseManager().db.get_devices_with_feature(feature, sub_keys)


def get_schema_file(feature: str) -> Dict[str, Any]:
    """Get JSON Schema file name for the requested feature.

    :param feature: Requested feature.
    :return: Loaded dictionary of JSON Schema file.
    """
    return DatabaseManager().db.get_schema_file(feature)
