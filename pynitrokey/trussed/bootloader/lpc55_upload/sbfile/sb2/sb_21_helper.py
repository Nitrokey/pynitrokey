#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module containing helper functions for nxpimage."""

import logging
import struct
from numbers import Number
from typing import Callable, Dict, List, Optional, Union

from ...exceptions import SPSDKError
from ...mboot.memories import ExtMemId, MemId
from ...sbfile.sb2.commands import (
    CmdBaseClass,
    CmdErase,
    CmdFill,
    CmdJump,
    CmdKeyStoreBackup,
    CmdKeyStoreRestore,
    CmdLoad,
    CmdMemEnable,
    CmdProg,
    CmdVersionCheck,
    VersionCheckType,
)
from ...utils.crypto.otfad import KeyBlob
from ...utils.misc import (
    align_block,
    get_bytes_cnt_of_int,
    load_binary,
    swap32,
    value_to_bytes,
    value_to_int,
)

logger = logging.getLogger(__name__)


class SB21Helper:
    """SB21 Helper class."""

    def __init__(self, search_paths: Optional[List[str]] = None):
        """SB21 helper constructor."""
        self.search_paths = search_paths
        self.cmds = {
            "load": self._load,
            "fill": self._fill_memory,
            "erase": self._erase_cmd_handler,
            "enable": self._enable,
            "encrypt": self._encrypt,
            "keywrap": self._keywrap,
            "keystore_to_nv": self._keystore_to_nv,
            "keystore_from_nv": self._keystore_from_nv,
            "version_check": self._version_check,
            "jump": self._jump,
            "programFuses": self._prog,
        }

    @staticmethod
    def get_mem_id(mem_opt: Union[int, str]) -> int:
        """Get memory ID from str or int in BD file.

        :param mem_opt: memory option in BD file
        :raises SPSDKError: if memory option is not supported
        :return: int memory ID
        """
        if isinstance(mem_opt, int):
            return mem_opt
        if isinstance(mem_opt, str):
            try:
                return int(mem_opt, 0)
            except ValueError:
                mem_id = MemId.get_legacy_str(mem_opt)
                if mem_id:
                    return mem_id
        raise SPSDKError(f"Unsupported memory option: {mem_opt}")

    def get_command(self, cmd_name: str) -> Callable[[Dict], CmdBaseClass]:
        """Returns a function based on input argument name.

        The json file generated by bd file parser uses command names (load, fill,
        etc.). These names are used to get the proper function name, which creates
        corresponding object.

        :param cmd_name: one of 'load', 'fill', 'erase', 'enable', 'reset', 'encrypt',
        'keywrap'
        :return: appropriate Command object
        """
        command_object = self.cmds[cmd_name]
        return command_object

    def _fill_memory(self, cmd_args: dict) -> CmdFill:
        """Returns a CmdFill object initialized based on cmd_args.

        Fill is a type of load command used for filling a region of memory with pattern.

        Example:
        section(0) {
            // pattern fill
            load 0x55.b > 0x2000..0x3000;
            // load two bytes at an address
            load 0x1122.h > 0xf00;
        }

        :param cmd_args: dictionary holding address and pattern
        :return: CmdFill object
        """
        address = value_to_int(cmd_args["address"])
        pattern = value_to_int(cmd_args["pattern"])
        return CmdFill(address=address, pattern=pattern)

    def _load(self, cmd_args: dict) -> Union[CmdLoad, CmdProg]:
        """Returns a CmdLoad object initialized based on cmd_args.

        The load statement is used to store data into the memory.
        The load command is also used to write to the flash memory.
        When loading to the flash memory, the region being loaded to must be erased before to the load operation.
        The most common form of a load statement is loading a source file by name.
        Only plain binary images are supported.

        Example:
        section (0) {
            // load an entire binary file to an address
            load myBinFile > 0x70000000;
            // load an eight byte blob
            load {{ ff 2e 90 07 77 5f 1d 20 }} > 0xa0000000;
            // 4 byte load IFR statement
            load ifr 0x1234567 > 0x30;
            // Program fuse statement
            load fuse {{00 00 00 01}} > 0x01000188;
            // load to sdcard
            load sdcard {{aa bb cc dd}} > 0x08000188;
            load @288 {{aa bb cc dd}} > 0x08000188;
        }

        :param cmd_args: dictionary holding path to file or values and address
        :raises SPSDKError: If dict doesn't contain 'file' or 'values' key
        :return: CmdLoad object
        """
        prog_mem_id = 4
        address = value_to_int(cmd_args["address"])
        load_opt = cmd_args.get("load_opt")
        mem_id = 0
        if load_opt:
            mem_id = self.get_mem_id(load_opt)

        # general non-authenticated load command
        if cmd_args.get("file"):
            data = load_binary(cmd_args["file"], self.search_paths)
            return CmdLoad(address=address, data=data, mem_id=mem_id)
        if cmd_args.get("values"):
            # if the memory ID is fuse or IFR change load command to program command
            if mem_id == prog_mem_id:
                return self._prog(cmd_args)

            values = [int(s, 16) for s in cmd_args["values"].split(",")]
            if max(values) > 0xFFFFFFFF or min(values) < 0:
                raise SPSDKError(
                    f"Invalid values for load command, values: {(values)}"
                    + ", expected unsigned 32bit comma separated values"
                )
            data = struct.pack(f"<{len(values)}L", *values)
            return CmdLoad(address=address, data=data, mem_id=mem_id)
        if cmd_args.get("pattern"):
            # if the memory ID is fuse or IFR change load command to program command
            # pattern in this case represents 32b int data word 1
            if mem_id == prog_mem_id:
                return self._prog(cmd_args)

        raise SPSDKError(f"Unsupported LOAD command args: {cmd_args}")

    def _prog(self, cmd_args: dict) -> CmdProg:
        """Returns a CmdProg object initialized based on cmd_args.

        :param cmd_args: dictionary holding path to file or values and address
        :raises SPSDKError: If data words are wrong
        :return: CmdProg object
        """
        address = value_to_int(cmd_args["address"])
        mem_id = self.get_mem_id(cmd_args.get("load_opt", 4))
        data_word1 = 0
        data_word2 = 0
        # values provided as binary blob {{aa bb cc dd}} either 4 or 8 bytes:
        if cmd_args.get("values"):
            int_value = int(cmd_args["values"], 16)
            byte_count = get_bytes_cnt_of_int(int_value)

            if byte_count <= 4:
                data_word1 = int_value
            elif byte_count <= 8:
                data_words = value_to_bytes(int_value, byte_cnt=8)
                data_word1 = value_to_int(data_words[:4])
                data_word2 = value_to_int(data_words[4:])
            else:
                raise SPSDKError("Program operation requires 4 or 8 byte segment")

            # swap byte order
            data_word1 = swap32(data_word1)
            data_word2 = swap32(data_word2)

        # values provided as integer e.g. 0x1000 represents data_word1
        elif cmd_args.get("pattern"):
            int_value = value_to_int(cmd_args["pattern"])
            byte_count = get_bytes_cnt_of_int(int_value)

            if byte_count <= 4:
                data_word1 = int_value
            else:
                raise SPSDKError("Data word 1 must be 4 bytes long")
        else:
            raise SPSDKError("Unsupported program command arguments")

        return CmdProg(address=address, data_word1=data_word1, data_word2=data_word2, mem_id=mem_id)

    def _erase_cmd_handler(self, cmd_args: dict) -> CmdErase:
        """Returns a CmdErase object initialized based on cmd_args.

        The erase statement inserts a bootloader command to erase the flash memory.
        There are two forms of the erase statement. The simplest form (erase all)
        creates a command that erases the available flash memory.
        The actual effect of this command depends on the runtime settings
        of the bootloader and whether
        the bootloader resides in the flash, ROM, or RAM.

        Example:
        section (0){
            // Erase all
            erase all;
            // Erase unsecure all
            erase unsecure all;
            // erase statements specifying memory ID and range
            erase @8 all;
            erase @288 0x8001000..0x80074A4;
            erase sdcard 0x8001000..0x80074A4;
            erase mmccard 0x8001000..0x80074A4;
        }

        :param cmd_args: dictionary holding path to address, length and flags
        :return: CmdErase object
        """
        address = value_to_int(cmd_args["address"])
        length = value_to_int(cmd_args.get("length", 0))
        flags = cmd_args.get("flags", 0)

        mem_opt = cmd_args.get("mem_opt")
        mem_id = 0
        if mem_opt:
            mem_id = self.get_mem_id(mem_opt)

        return CmdErase(address=address, length=length, flags=flags, mem_id=mem_id)

    def _enable(self, cmd_args: dict) -> CmdMemEnable:
        """Returns a CmdEnable object initialized based on cmd_args.

        Enable statement is used for initialization of external memories
        using a parameter block that was previously loaded to RAM.

        Example:
        section (0){
            # Load quadspi config block bin file to RAM, use it to enable QSPI.
            load myBinFile > 0x20001000;
            enable qspi 0x20001000;
        }

        :param cmd_args: dictionary holding address, size and memory type
        :return: CmdEnable object
        """
        address = value_to_int(cmd_args["address"])
        size = cmd_args.get("size", 4)
        mem_opt = cmd_args.get("mem_opt")
        mem_id = 0
        if mem_opt:
            mem_id = self.get_mem_id(mem_opt)
        return CmdMemEnable(address=address, size=size, mem_id=mem_id)

    def _encrypt(self, cmd_args: dict) -> CmdLoad:
        """Returns a CmdLoad object initialized based on cmd_args.

        Encrypt holds an ID, which is a reference to keyblob to be used for
        encryption. So the encrypt command requires a list of keyblobs, the keyblob
        ID and load command.

        e.g.
        encrypt (0){
            load myImage > 0x0810000;
        }

        :param cmd_args: dictionary holding list of keyblobs, keyblob ID and load dict
        :raises SPSDKError: If keyblob to be used is not in the list or is invalid
        :return: CmdLoad object
        """
        keyblob_id = cmd_args["keyblob_id"]
        keyblobs = cmd_args.get("keyblobs", [])

        address = value_to_int(cmd_args["address"])

        if cmd_args.get("file"):
            data = load_binary(cmd_args["file"], self.search_paths)
        if cmd_args.get("values"):
            values = [int(s, 16) for s in cmd_args["values"].split(",")]
            data = struct.pack(f"<{len(values)}L", *values)

        try:
            valid_keyblob = self._validate_keyblob(keyblobs, keyblob_id)
        except SPSDKError as exc:
            raise SPSDKError(f"Invalid key blob {str(exc)}") from exc

        if valid_keyblob is None:
            raise SPSDKError(f"Missing keyblob {keyblob_id} for encryption.")

        start_addr = value_to_int(valid_keyblob["keyblob_content"][0]["start"])
        end_addr = value_to_int(valid_keyblob["keyblob_content"][0]["end"])
        key = bytes.fromhex(valid_keyblob["keyblob_content"][0]["key"])
        counter = bytes.fromhex(valid_keyblob["keyblob_content"][0]["counter"])
        byte_swap = valid_keyblob["keyblob_content"][0].get("byte_swap", False)

        keyblob = KeyBlob(start_addr=start_addr, end_addr=end_addr, key=key, counter_iv=counter)

        # Encrypt only if the ADE and VLD flags are set
        if bool(end_addr & keyblob.KEY_FLAG_ADE) and bool(end_addr & keyblob.KEY_FLAG_VLD):
            encoded_data = keyblob.encrypt_image(
                base_address=address, data=align_block(data, 512), byte_swap=byte_swap
            )
        else:
            encoded_data = data

        return CmdLoad(address, encoded_data)

    def _keywrap(self, cmd_args: dict) -> CmdLoad:
        """Returns a CmdLoad object initialized based on cmd_args.

        Keywrap holds keyblob ID to be encoded by a value stored in load command and
        stored to address defined in the load command.

        Example:
        keywrap (0) {
            load {{ 00000000 }} > 0x08000000;
        }

        :param cmd_args: dictionary holding list of keyblobs, keyblob ID and load dict
        :raises SPSDKError: If keyblob to be used is not in the list or is invalid
        :return: CmdLoad object
        """
        # iterate over keyblobs
        keyblobs = cmd_args.get("keyblobs", None)
        keyblob_id = cmd_args.get("keyblob_id", None)

        address = value_to_int(cmd_args["address"])
        otfad_key = cmd_args["values"]

        try:
            valid_keyblob = self._validate_keyblob(keyblobs, keyblob_id)
        except SPSDKError as exc:
            raise SPSDKError(f" Key blob validation failed: {str(exc)}") from exc
        if valid_keyblob is None:
            raise SPSDKError(f"Missing keyblob {keyblob_id} for given keywrap")

        start_addr = value_to_int(valid_keyblob["keyblob_content"][0]["start"])
        end_addr = value_to_int(valid_keyblob["keyblob_content"][0]["end"])
        key = bytes.fromhex(valid_keyblob["keyblob_content"][0]["key"])
        counter = bytes.fromhex(valid_keyblob["keyblob_content"][0]["counter"])

        blob = KeyBlob(start_addr=start_addr, end_addr=end_addr, key=key, counter_iv=counter)

        encoded_keyblob = blob.export(kek=otfad_key)
        logger.info(f"Creating wrapped keyblob: \n{str(blob)}")

        return CmdLoad(address=address, data=encoded_keyblob)

    def _keystore_to_nv(self, cmd_args: dict) -> CmdKeyStoreRestore:
        """Returns a CmdKeyStoreRestore object initialized with memory type and address.

        The keystore_to_nv statement instructs the bootloader to load the backed up
        keystore values back into keystore memory region on non-volatile memory.

        Example:
        section (0) {
            keystore_to_nv @9 0x8000800;

        :param cmd_args: dictionary holding the memory type and address.
        :return: CmdKeyStoreRestore object.
        """
        mem_opt = cmd_args["mem_opt"]
        address = value_to_int(cmd_args["address"])
        return CmdKeyStoreRestore(address, ExtMemId.from_tag(mem_opt))

    def _keystore_from_nv(self, cmd_args: dict) -> CmdKeyStoreBackup:
        """Returns a CmdKeyStoreRestore object initialized with memory type and address.

        The keystore_to_nv statement instructs the bootloader to load the backed up
        keystore values back into keystore memory region on non-volatile memory.

        Example:
        section (0) {
            keystore_from_nv @9 0x8000800;

        :param cmd_args: dictionary holding the memory type and address.
        :return: CmdKeyStoreRestore object.
        """
        mem_opt = cmd_args["mem_opt"]
        address = value_to_int(cmd_args["address"])
        return CmdKeyStoreBackup(address, ExtMemId.from_tag(mem_opt))

    def _version_check(self, cmd_args: dict) -> CmdVersionCheck:
        """Returns a CmdVersionCheck object initialized with version check type and version.

        Validates version of secure or non-secure firmware version with the value stored in the OTP or PFR,
        to prevent the FW rollback.
        The command fails if version provided in command is lower than version stored in the OTP/PFR.

        Example:
        section (0) {
            version_check sec 0x2;
            version_check nsec 2;
        }

        :param cmd_args: dictionary holding the version type and fw version.
        :return: CmdKeyStoreRestore object.
        """
        ver_type = cmd_args["ver_type"]
        fw_version = cmd_args["fw_version"]
        return CmdVersionCheck(VersionCheckType.from_tag(ver_type), fw_version)

    def _validate_keyblob(self, keyblobs: List, keyblob_id: Number) -> Optional[Dict]:
        """Checks, whether a keyblob is valid.

        Parser returns a list of dicts which contains keyblob definitions. These
        definitions should contain a 'start', 'end', 'key' & 'counter' keys with
        appropriate values. To be able to create a keyblob, we need these for
        values. Otherwise we throw an exception that the keyblob is invalid.

        :param keyblobs: list of dicts defining keyblobs
        :param keyblob_id: id of keyblob we want to check
        :raises SPSDKError: If the keyblob definition is empty
        :raises SPSDKError: If the keyblob definition is missing one key
        :return: keyblob If exists and is valid, None otherwise
        """
        for keyblob in keyblobs:
            if keyblob_id == keyblob["keyblob_id"]:
                kb_content = keyblob["keyblob_content"]
                if len(kb_content) == 0:
                    raise SPSDKError(f"Keyblob {keyblob_id} definition is empty!")

                for key in ["start", "end", "key", "counter"]:
                    if key not in kb_content[0]:
                        raise SPSDKError(f"Keyblob {keyblob_id} is missing '{key}' definition!")

                return keyblob

        return None

    def _jump(self, cmd_args: dict) -> CmdJump:
        """Returns a CmdJump object initialized with memory type and address.

        The "jump" command produces the ROM_JUMP_CMD.
        See the boot image format design document for specific details about these commands,
        such as the function prototypes they expect.
        Jump to entrypoint is not supported. Only fixed address is supported.

        Example:
        section (0) {
            # jump to a fixed address
            jump 0xffff0000;
        }

        :param cmd_args: dictionary holding the argument and address.
        :return: CmdJump object.
        """
        argument = cmd_args.get("argument", 0)
        address = value_to_int(cmd_args["address"])
        spreg = cmd_args.get("spreg")

        return CmdJump(address, argument, spreg)
