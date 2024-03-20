#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK plugins manager."""

import logging
import os
import sys
from importlib.machinery import ModuleSpec
from importlib.util import find_spec, module_from_spec, spec_from_file_location
from types import ModuleType
from typing import Dict, List, Optional

import importlib_metadata

from spsdk.exceptions import SPSDKError, SPSDKTypeError
from spsdk.utils.misc import SingletonMeta
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class PluginType(SpsdkEnum):
    """Contains commands tags."""

    SIGNATURE_PROVIDER = (0, "spsdk.sp", "Signature provider")
    DEVICE_INTERFACE = (1, "spsdk.device.interface", "Device interface")
    DEBUG_PROBE = (2, "spsdk.debug_probe", "Debug Probe")
    WPC_SERVICE = (3, "spsdk.wpc.service", "WPC Service")


class PluginsManager(metaclass=SingletonMeta):
    """Plugin manager."""

    def __init__(self) -> None:
        """Plugin manager constructor."""
        self.plugins: Dict[str, ModuleType] = {}

    def load_from_entrypoints(self, group_name: Optional[str] = None) -> int:
        """Load modules from given setuptools group.

        :param group_name: Entry point group to load plugins

        :return: The number of loaded plugins.
        """
        if group_name is not None and not isinstance(group_name, str):
            raise SPSDKTypeError("Group name must be of string type.")
        group_names = (
            [group_name]
            if group_name is not None
            else [PluginType.get_label(tag) for tag in PluginType.tags()]
        )

        entry_points: List[importlib_metadata.EntryPoint] = []
        for group_name in group_names:
            eps = importlib_metadata.entry_points(group=group_name)
            entry_points.extend(eps)

        count = 0
        for ep in entry_points:
            try:
                plugin = ep.load()
            except (ModuleNotFoundError, ImportError) as exc:
                logger.warning(f"Module {ep.module} could not be loaded: {exc}")
                continue
            logger.info(f"Plugin {ep.name} has been loaded.")
            self.register(plugin)
            count += 1
        return count

    def load_from_source_file(self, source_file: str, module_name: Optional[str] = None) -> None:
        """Import Python source file directly.

        :param source_file: Path to python source file: absolute or relative to cwd
        :param module_name: Name for the new module, default is basename of the source file
        :raises SPSDKError: If importing of source file failed
        """
        name = module_name or os.path.splitext(os.path.basename(source_file))[0]
        spec = spec_from_file_location(name=name, location=source_file)
        if not spec:
            raise SPSDKError(
                f"Source '{source_file}' does not exist. Check if it is valid file path name"
            )

        module = self._import_module_spec(spec)
        self.register(module)

    def load_from_module_name(self, module_name: str) -> None:
        """Import Python module directly.

        :param module_name: Module name to be imported
        :raises SPSDKError: If importing of source file failed
        """
        spec = find_spec(name=module_name)
        if not spec:
            raise SPSDKError(
                f"Source '{module_name}' does not exist.Check if it is valid file module name"
            )
        module = self._import_module_spec(spec)
        self.register(module)

    def _import_module_spec(self, spec: ModuleSpec) -> ModuleType:
        """Import module from module specification.

        :param spec: Module specification
        :return: Imported module type
        """
        module = module_from_spec(spec)
        try:
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)  # type: ignore
            logger.debug(f"A module spec {spec.name} has been loaded.")
        except Exception as e:
            raise SPSDKError(f"Failed to load module spec {spec.name}: {e}") from e
        return module

    def register(self, plugin: ModuleType) -> None:
        """Register a plugin with the given name.

        :param plugin: Plugin as a module
        """
        plugin_name = self.get_plugin_name(plugin)
        if plugin_name in self.plugins:
            logger.debug(f"Plugin {plugin_name} has been already registered.")
            return
        self.plugins[plugin_name] = plugin
        logger.debug(f"A plugin {plugin_name} has been registered.")

    def get_plugin(self, name: str) -> Optional[ModuleType]:
        """Return a plugin for the given name.

        :param name: Plugin name
        :return: Plugin or None if plugin with name is not registered
        """
        return self.plugins.get(name)

    def get_plugin_name(self, plugin: ModuleType) -> str:
        """Get canonical name of plugin.

        :param plugin: Plugin as a module
        :return: String with plugin name
        """
        name = getattr(plugin, "__name__", None)
        if name is None:
            raise SPSDKError("Plugin name could not be determined.")
        return name


def load_plugin_from_source(source: str, name: Optional[str] = None) -> None:
    """Load plugin from source.

    :param source: The source to be loaded
        Accepted values:
            - Path to source file
            - Existing module name
            - Existing entrypoint
    :param name: Name for the new module/plugin
    """
    manager = PluginsManager()
    if name and name in manager.plugins:
        logger.debug(f"Plugin {name} has been already registered.")
        return
    try:
        return manager.load_from_source_file(source)
    except SPSDKError:
        pass
    try:
        manager.load_from_module_name(source)
        return
    except SPSDKError:
        pass
    try:
        manager.load_from_entrypoints(source)
        return
    except SPSDKError:
        pass
    raise SPSDKError(f"Unable to load from source '{source}'.")
