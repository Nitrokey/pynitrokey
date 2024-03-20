#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for schema-based configuration validation."""

import copy
import io
import logging
import os
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional, Union

import fastjsonschema
from deepmerge import Merger, always_merger
from deepmerge.strategy.dict import DictStrategies
from deepmerge.strategy.list import ListStrategies
from deepmerge.strategy.set import SetStrategies
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap as CMap
from ruamel.yaml.comments import CommentedSeq as CSeq

from spsdk import SPSDK_YML_INDENT
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import (
    find_dir,
    find_file,
    load_configuration,
    value_to_int,
    wrap_text,
    write_file,
)
from spsdk.utils.spsdk_enum import SpsdkEnum

ENABLE_DEBUG = False

logger = logging.getLogger(__name__)


def cmap_update(cmap: CMap, updater: CMap) -> None:
    """Update CMap including comments.

    :param cmap: Original CMap to be updated.
    :param updater: CMap updater.
    """
    cmap.update(updater)
    cmap.ca.items.update(updater.ca.items)


class PropertyRequired(SpsdkEnum):
    """Enum describing if the property is required or optional."""

    REQUIRED = (0, "REQUIRED", "Required")
    CONDITIONALLY_REQUIRED = (1, "CONDITIONALLY_REQUIRED", "Conditionally required")
    OPTIONAL = (2, "OPTIONAL", "Optional")


class SPSDKListStrategies(ListStrategies):
    """Extended List Strategies."""

    # pylint: disable=unused-argument   # because of the base class
    @staticmethod
    def strategy_set(_config, _path, base, nxt):  # type: ignore
        """Use the set of both as a output."""
        try:
            ret = list(set(base + nxt))
            ret.sort()
        except TypeError:
            try:
                ret = base + nxt
            except TypeError:
                logger.warning(
                    "Found unhashable object in List 'set' strategy during merge."
                    " It was used 'override' method instead of 'set'."
                )
                ret = nxt
        return ret


class SPSDKMerger(Merger):
    """Modified Merger to add new list strategy 'set'."""

    PROVIDED_TYPE_STRATEGIES = {
        list: SPSDKListStrategies,
        dict: DictStrategies,
        set: SetStrategies,
    }


def _is_number(param: Any) -> bool:
    """Checks whether the input represents a number.

    :param param: Input to analyze
    :raises SPSDKError: Input doesn't represent a number
    :return: True if input represents a number
    """
    try:
        value_to_int(param)
        return True
    except SPSDKError:
        return False


def _is_hex_number(param: Any) -> bool:
    """Checks whether the input represents a hexnumber.

    :param param: Input to analyze
    :raises SPSDKError: Input doesn't represent a hexnumber
    :return: True if input represents a hexnumber
    """
    try:
        bytes.fromhex(param)
        return True
    except (TypeError, ValueError):
        return False


def _print_validation_fail_reason(
    exc: fastjsonschema.JsonSchemaValueException,
    extra_formatters: Optional[Dict[str, Callable[[str], bool]]] = None,
) -> str:
    """Print formatted and easy to read reason why the  validation failed.

    :param exc: Original exception.
    :param extra_formatters: Additional custom formatters
    :return: String explaining the reason of fail.
    """

    def process_nested_rule(
        exception: fastjsonschema.JsonSchemaValueException,
        extra_formatters: Optional[Dict[str, Callable[[str], bool]]],
    ) -> str:
        message = ""
        for rule_def_ix, rule_def in enumerate(exception.rule_definition):
            try:
                validator = fastjsonschema.compile(rule_def, formats=extra_formatters)
                validator(exception.value)
                message += f"\nRule#{rule_def_ix} passed.\n"
            except fastjsonschema.JsonSchemaValueException as _exc:
                message += (
                    f"\nReason of fail for {exception.rule} rule#{rule_def_ix}: "
                    f"\n {_print_validation_fail_reason(_exc , extra_formatters)}\n"
                )
        if all(rule_def.get("required") for rule_def in exception.rule_definition):
            message += f"\nYou need to define {exception.rule} of the following sets:"
            for rule_def in exc.rule_definition:
                message += f" {rule_def['required']}"
        return message

    message = str(exc)
    if exc.rule == "required":
        missing = filter(lambda x: x not in exc.value.keys(), exc.rule_definition)
        message += f"; Missing field(s): {', '.join(missing)}"
    elif exc.rule == "format":
        if exc.rule_definition == "file":
            message += f"; Non-existing file: {exc.value}"
            message += "; The file must exists even if the key is NOT used in configuration."
    elif exc.rule == "anyOf":
        message += process_nested_rule(exc, extra_formatters=extra_formatters)
    elif exc.rule == "oneOf":
        message += process_nested_rule(exc, extra_formatters=extra_formatters)
    return message


def check_config(
    config: Union[str, Dict[str, Any]],
    schemas: List[Dict[str, Any]],
    extra_formatters: Optional[Dict[str, Callable[[str], bool]]] = None,
    search_paths: Optional[List[str]] = None,
) -> None:
    """Check the configuration by provided list of validation schemas.

    :param config: Configuration to check
    :param schemas: List of validation schemas
    :param extra_formatters: Additional custom formatters
    :param search_paths: List of paths where to search for the file, defaults to None
    :raises SPSDKError: Invalid validation schema or configuration
    """
    custom_formatters: Dict[str, Callable[[str], bool]] = {
        "dir": lambda x: bool(find_dir(x, search_paths=search_paths, raise_exc=False)),
        "file": lambda x: bool(find_file(x, search_paths=search_paths, raise_exc=False)),
        "file_name": lambda x: os.path.basename(x.replace("\\", "/")) not in ("", None),
        "optional_file": lambda x: not x
        or bool(find_file(x, search_paths=search_paths, raise_exc=False)),
        "number": _is_number,
        "hex_value": _is_hex_number,
    }
    if isinstance(config, str):
        config_to_check = load_configuration(config)
        config_dir = os.path.dirname(config)
        if search_paths:
            search_paths.append(config_dir)
        else:
            search_paths = [config_dir]
    else:
        config_to_check = copy.deepcopy(config)

    schema: Dict[str, Any] = {}
    for sch in schemas:
        always_merger.merge(schema, copy.deepcopy(sch))
    validator = None
    formats = always_merger.merge(custom_formatters, extra_formatters or {})
    try:
        if ENABLE_DEBUG:
            validator_code = fastjsonschema.compile_to_code(schema, formats=formats)
            write_file(validator_code, "validator_file.py")
        else:
            validator = fastjsonschema.compile(schema, formats=formats)
    except (TypeError, fastjsonschema.JsonSchemaDefinitionException) as exc:
        raise SPSDKError(f"Invalid validation schema to check config: {str(exc)}") from exc
    try:
        if ENABLE_DEBUG:
            # pylint: disable=import-error,import-outside-toplevel
            import validator_file

            validator_file.validate(config_to_check, formats)
        else:
            assert validator is not None
            validator(config_to_check)
    except fastjsonschema.JsonSchemaValueException as exc:
        message = _print_validation_fail_reason(exc, formats)
        raise SPSDKError(f"Configuration validation failed: {message}") from exc


class CommentedConfig:
    """Class for generating commented config templates or custom configurations."""

    MAX_LINE_LENGTH = 120 - 2  # Minus '# '

    def __init__(
        self,
        main_title: str,
        schemas: List[Dict[str, Any]],
        note: Optional[str] = None,
    ):
        """Constructor for Config templates.

        :param main_title: Main title of final template.
        :param schemas: Main description of final template.
        :param note: Additional Note after title test.
        """
        self.main_title = main_title
        self.schemas = schemas
        self.indent = 0
        self.note = note
        self.creating_configuration = False

    @property
    def max_line(self) -> int:
        """Maximal line with current indent."""
        return self.MAX_LINE_LENGTH - max(SPSDK_YML_INDENT * (self.indent - 1), 0)

    def _get_title_block(self, title: str, description: Optional[str] = None) -> str:
        """Get unified title blob.

        :param title: Simple title of block
        :param description: Description of block
        :return: ASCII art block
        """
        delimiter = "=" * self.max_line
        title_str = f" == {title} == "
        title_str = title_str.center(self.max_line)

        ret = delimiter + "\n" + title_str + "\n"
        if description:
            wrapped_description = wrap_text(description, self.max_line)
            lines = wrapped_description.splitlines()
            ret += "\n".join([line.center(self.max_line) for line in lines])
            ret += "\n"
        ret += delimiter
        return ret

    @staticmethod
    def get_property_optional_required(key: str, block: Dict[str, Any]) -> PropertyRequired:
        """Function to determine if the config property is required or not.

        :param key: Name of config record
        :param block: Source data block
        :return: Final description.
        """
        schema_kws = ["allOf", "anyOf", "oneOf", "if", "then", "else"]

        def _find_required(d_in: Dict[str, Any]) -> Optional[List[str]]:
            if "required" in d_in:
                return d_in["required"]

            for d_v in d_in.values():
                if isinstance(d_v, dict):
                    ret = _find_required(d_v)
                    if ret:
                        return ret
            return None

        def _find_required_in_schema_kws(schema_node: Union[List, Dict[str, Any]]) -> List[str]:
            """Find all required properties in structure composed of nested properties."""
            all_props: List[str] = []
            if isinstance(schema_node, dict):
                for k, v in schema_node.items():
                    if k == "required":
                        all_props.extend(v)
                    elif k in schema_kws:
                        req_props = _find_required_in_schema_kws(v)
                        all_props.extend(req_props)
            if isinstance(schema_node, list):
                for item in schema_node:
                    req_props = _find_required_in_schema_kws(item)
                    all_props.extend(req_props)
            return list(set(all_props))

        if "required" in block and key in block["required"]:
            return PropertyRequired.REQUIRED

        for val in block.values():
            if isinstance(val, dict):
                ret = _find_required(val)
                if ret and key in ret:
                    return PropertyRequired.CONDITIONALLY_REQUIRED

        actual_kws = {k: v for k, v in block.items() if k in schema_kws}
        ret = _find_required_in_schema_kws(actual_kws)
        if key in ret:
            return PropertyRequired.CONDITIONALLY_REQUIRED

        return PropertyRequired.OPTIONAL

    def _create_object_block(
        self,
        block: Dict[str, Dict[str, Any]],
        custom_value: Optional[Union[Dict[str, Any], List[Any]]] = None,
    ) -> CMap:
        """Private function used to create object block with data.

        :param block: Source block with data
        :param custom_value:
            Optional dictionary or List of properties to be exported.
        It is recommended to pass OrderedDict to preserve the key order.
            - key is property ID to be exported
            - value is its value; or None if default value shall be used
        :return: CMap or CSeq base configuration object
        :raises SPSDKError: In case of invalid data pattern.
        """
        assert block.get("type") == "object"
        self.indent += 1

        assert "properties" in block.keys()

        cfg_m = CMap()
        for key in self._get_schema_block_keys(block):
            assert (
                key in block["properties"].keys()
            ), f"Missing key ({key}, in block properties. Block title: {block.get('title', 'Unknown')})"

            # Skip the record in case that custom value key is defined,
            # but it has None value as a mark to not use this record
            value = custom_value.get(key, None) if custom_value else None  # type: ignore
            if custom_value and value is None:
                continue

            val_p: Dict = block["properties"][key]
            value_to_add = self._get_schema_value(val_p, value)
            if value_to_add is None:
                raise SPSDKError(f"Cannot create the value for {key}")

            cfg_m[key] = value_to_add
            required = self.get_property_optional_required(key, block).description
            assert required
            self._add_comment(
                cfg_m,
                val_p,
                key,
                value_to_add,
                required,
            )

        self.indent -= 1
        return cfg_m

    def _create_array_block(
        self, block: Dict[str, Dict[str, Any]], custom_value: Optional[List[Any]]
    ) -> CSeq:
        """Private function used to create array block with data.

        :param block: Source block with data
        :return: CS base configuration object
        :raises SPSDKError: In case of invalid data pattern.
        """
        assert block.get("type") == "array"
        assert "items" in block.keys()
        self.indent += 1
        val_i: Dict = block["items"]

        cfg_s = CSeq()
        if custom_value is not None:
            for cust_val in custom_value:
                value = self._get_schema_value(val_i, cust_val)
                if isinstance(value, (CSeq, List)):
                    cfg_s.extend(value)
                else:
                    cfg_s.append(value)
        else:
            value = self._get_schema_value(val_i, None)
            # the template_value can be the actual list(not only one element)
            if isinstance(value, (CSeq, List)):
                cfg_s.extend(value)
            else:
                cfg_s.append(value)
        self.indent -= 1
        return cfg_s

    @staticmethod
    def _check_matching_oneof_option(one_of: Dict[str, Any], cust_val: Any) -> bool:
        """Find matching given custom value to "oneOf" schema.

        :param one_of:oneOf schema
        :param cust_val: custom value
        :raises SPSDKError: if not found
        """

        def check_type(option: Dict, t: str) -> bool:
            option_type = option.get("type")
            if isinstance(option_type, list):
                return t in option_type
            return t == option_type

        if cust_val:
            if isinstance(cust_val, dict) and check_type(one_of, "object"):
                properties = one_of.get("properties")
                assert properties, "non-empty properties must be defined"
                if all([key in properties for key in cust_val.keys()]):
                    return True

            if isinstance(cust_val, str) and check_type(one_of, "string"):
                return True

            if isinstance(cust_val, int) and check_type(one_of, "number"):
                return True

        return False

    def _handle_one_of_block(
        self,
        block: Dict[str, Any],
        custom_value: Optional[Union[Dict[str, Any], List[Any]]] = None,
    ) -> CMap:
        """Private function used to create oneOf block with data, and return as an array that contains all values.

        :param block: Source block with data
        :param custom_value: custom value to fill the array
        :return: CS base configuration object
        """

        def get_help_name(schema: Dict) -> str:
            if schema.get("type") == "object":
                options = list(schema["properties"].keys())
                if len(options) == 1:
                    return options[0]
                return str(options)
            return str(schema.get("title", schema.get("type", "Unknown")))

        ret = CMap()
        one_of = block
        assert isinstance(one_of, list)
        if custom_value is not None:
            for i, one_option in enumerate(one_of):
                if not self._check_matching_oneof_option(one_option, custom_value):
                    continue
                return self._get_schema_value(one_option, custom_value)
            raise SPSDKError("Any allowed option matching the configuration data")

        # Check the restriction into templates in oneOf block
        one_of_mod = []
        for x in one_of:
            skip = x.get("skip_in_template", False)
            if not skip:
                one_of_mod.append(x)

        # In case that only one oneOf option left just return simple value
        if len(one_of_mod) == 1:
            return self._get_schema_value(one_of_mod[0], custom_value)

        option_types = ", ".join([get_help_name(x) for x in one_of_mod])
        title = f"List of possible {len(one_of_mod)} options."
        for i, option in enumerate(one_of_mod):
            if option.get("type") != "object":
                continue
            value = self._get_schema_value(option, None)
            assert isinstance(value, CMap)
            cmap_update(ret, value)

            key = list(value.keys())[0]
            comment = ""
            if i == 0:
                comment = self._get_title_block(title, f"Options [{option_types}]") + "\n"
            comment += "\n " + (
                f" [Example of possible configuration #{i}] ".center(self.max_line, "=")
            )
            self._update_before_comment(cfg=ret, key=key, comment=comment)
        return ret

    def _get_schema_value(
        self, block: Dict[str, Any], custom_value: Any
    ) -> Union[CMap, CSeq, str, int, float, List]:
        """Private function used to fill up configuration block with data.

        :param block: Source block with data
        :param custom_value: value to be saved instead of default value
        :return: CM/CS base configuration object with comment
        :raises SPSDKError: In case of invalid data pattern.
        """

        def get_custom_or_template() -> Any:
            assert (
                custom_value or "template_value" in block.keys()
            ), f"Template value not provided in {block}"
            return (
                custom_value
                if (custom_value is not None)
                else block.get("template_value", "Unknown")
            )

        ret: Optional[Union[CMap, CSeq, str, int, float]] = None
        if "oneOf" in block and not "properties" in block:
            ret = self._handle_one_of_block(block["oneOf"], custom_value)
            if not ret:
                ret = get_custom_or_template()
        else:
            schema_type = block.get("type")
            if not schema_type:
                raise SPSDKError(f"Type not available in block: {block}")
            assert schema_type, f"Type not available in block: {block}"

            if schema_type == "object":
                assert (custom_value is None) or isinstance(custom_value, dict)
                ret = self._create_object_block(block, custom_value)
            elif schema_type == "array":
                assert (custom_value is None) or isinstance(custom_value, list)
                ret = self._create_array_block(block, custom_value)
            else:
                ret = get_custom_or_template()

        assert isinstance(ret, (CMap, CSeq, str, int, float, list))

        return ret

    def _add_comment(
        self,
        cfg: Union[CMap, CSeq],
        schema: Dict[str, Any],
        key: Union[str, int],
        value: Optional[Union[CMap, CSeq, str, int, float, List]],
        required: str,
    ) -> None:
        """Private function used to create comment for block.

        :param cfg: Target configuration where the comment should be stored
        :param schema: Object configuration JSON SCHEMA
        :param key: Config key
        :param value: Value of config key
        :param required: Required text description
        """
        value_len = len(str(key) + ": ")
        if value and isinstance(value, (str, int)):
            value_len += len(str(value))
        template_title = schema.get("template_title")
        title = schema.get("title", "")
        descr = schema.get("description", "")
        enum_list = schema.get("enum", schema.get("enum_template", []))
        enum = ""

        if len(enum_list):
            enum = "Possible options: <" + ", ".join([str(x) for x in enum_list]) + ">"
        if title:
            # one_line_comment = (
            #     f"[{required}] {title}{'; ' if descr else ''}{descr}{';'+enum if enum else ''}"
            # )
            # TODO This feature will be disabled since the issue
            # https://sourceforge.net/p/ruamel-yaml/tickets/475/ will be solved
            # if True:  # len(one_line_comment) > self.max_line - value_len:
            # Too long comment split it into comment block
            comment = f"===== {title} [{required}] =====".center(self.max_line, "-")
            if descr:
                comment += wrap_text("\nDescription: " + descr, max_line=self.max_line)
            if enum:
                comment += wrap_text("\n" + enum, max_line=self.max_line)
            cfg.yaml_set_comment_before_after_key(
                key, comment, indent=SPSDK_YML_INDENT * (self.indent - 1)
            )
            # else:
            #     cfg.yaml_add_eol_comment(
            #         one_line_comment,
            #         key=key,
            #         column=SPSDK_YML_INDENT * (self.indent - 1),
            #     )

        if template_title:
            self._update_before_comment(cfg, key, "\n" + self._get_title_block(template_title))

    @staticmethod
    def _get_schema_block_keys(schema: Dict[str, Dict[str, Any]]) -> List[str]:
        """Creates list of property keys in given schema.

        :param schema: Input schema piece.
        :return: List of all property keys.
        """
        if "properties" not in schema:
            return []
        return [
            key
            for key in schema["properties"]
            if schema["properties"][key].get("skip_in_template", False) == False
        ]

    def _update_before_comment(
        self, cfg: Union[CMap, CSeq], key: Union[str, int], comment: str
    ) -> None:
        """Update comment to add new comment before current one.

        :param sfg: Commented map / Commented Sequence
        :param key: Key name
        :param comment: Comment that should be place before current one.
        """
        from ruamel.yaml.error import CommentMark
        from ruamel.yaml.tokens import CommentToken

        def comment_token(s: str, mark: CommentMark) -> CommentToken:
            # handle empty lines as having no comment
            return CommentToken(("# " if s else "") + s + "\n", mark)

        comments = cfg.ca.items.setdefault(key, [None, None, None, None])
        if not isinstance(comments[1], list):
            comments[1] = []
        new_lines = comment.splitlines()
        new_lines.reverse()
        start_mark = CommentMark(SPSDK_YML_INDENT * (self.indent - 1))
        for c in new_lines:
            comments[1].insert(0, comment_token(c, start_mark))

    def export(self, config: Optional[Dict[str, Any]] = None) -> CMap:
        """Export configuration template into CommentedMap.

        :param config: Configuration to be applied to template.
        :raises SPSDKError: Error
        :return: Configuration template in CM.
        """
        self.indent = 0
        self.creating_configuration = bool(config)
        loc_schemas = copy.deepcopy(self.schemas)
        # 1. Get blocks with their titles and lists of their keys
        block_list: Dict[str, Any] = {}
        for schema in loc_schemas:
            if schema.get("skip_in_template", False):
                continue
            title = schema.get("title", "General Options")
            if title in block_list:
                property_list = block_list[title]["properties"]
                assert isinstance(property_list, list)
                property_list.extend(
                    [
                        x
                        for x in self._get_schema_block_keys(schema)
                        if x not in block_list[title]["properties"]
                    ]
                )
            else:
                block_list[title] = {}
                block_list[title]["properties"] = self._get_schema_block_keys(schema)
                block_list[title]["description"] = schema.get("description", "")

        # 2. Merge all schemas together to get whole single schema
        schemas_merger = SPSDKMerger(
            [(list, ["set"]), (dict, ["merge"]), (set, ["union"])],
            ["override"],
            ["override"],
        )

        merged: Dict[str, Any] = {}
        for schema in loc_schemas:
            schemas_merger.merge(merged, copy.deepcopy(schema))

        # 3. Create order of individual settings

        order_dict: Dict[str, Any] = OrderedDict()
        properties_for_template = self._get_schema_block_keys(merged)
        for block in block_list.values():
            block_properties: list = block["properties"]
            # block_properties.sort()
            for block_property in block_properties:
                if block_property in properties_for_template:
                    order_dict[block_property] = merged["properties"][block_property]
        merged["properties"] = order_dict

        try:
            self.indent = 0
            # 4. Go through all individual logic blocks
            cfg = self._create_object_block(merged, config)
            assert isinstance(cfg, CMap)
            # 5. Add main title of configuration
            title = f"  {self.main_title}  ".center(self.MAX_LINE_LENGTH, "=") + "\n\n"
            if self.note:
                title += f"\n{' Note '.center(self.MAX_LINE_LENGTH, '-')}\n"
                title += wrap_text(self.note, self.max_line) + "\n"
            cfg.yaml_set_start_comment(title)
            for title, info in block_list.items():
                description = info["description"]
                assert isinstance(description, str) or description is None

                first_key = None
                for info_key in info["properties"]:
                    if info_key in cfg.keys():
                        first_key = info_key
                        break

                if first_key:
                    self._update_before_comment(
                        cfg, first_key, self._get_title_block(title, description)
                    )

            self.creating_configuration = False
            return cfg

        except Exception as exc:
            self.creating_configuration = False
            raise SPSDKError(f"Template generation failed: {str(exc)}") from exc

    def get_template(self) -> str:
        """Export Configuration template directly into YAML string format.

        :return: YAML string.
        """
        return self.convert_cm_to_yaml(self.export())

    def get_config(self, config: Dict[str, Any]) -> str:
        """Export Configuration directly into YAML string format.

        :return: YAML string.
        """
        return self.convert_cm_to_yaml(self.export(config))

    @staticmethod
    def convert_cm_to_yaml(config: CMap) -> str:
        """Convert Commented Map for into final YAML string.

        :param config: Configuration in CM format.
        :raises SPSDKError: If configuration is empty
        :return: YAML string with configuration to use to store in file.
        """
        if not config:
            raise SPSDKError("Configuration cannot be empty")
        yaml = YAML(pure=True)
        yaml.indent(sequence=SPSDK_YML_INDENT * 2, offset=SPSDK_YML_INDENT)
        stream = io.StringIO()
        yaml.dump(config, stream)
        yaml_data = stream.getvalue()

        return yaml_data
