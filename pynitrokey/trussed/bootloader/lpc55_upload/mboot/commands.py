#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Commands and responses used by MBOOT module."""

from struct import pack, unpack, unpack_from
from typing import Dict, List, Optional, Type

from spsdk.utils.interfaces.commands import CmdPacketBase, CmdResponseBase
from spsdk.utils.spsdk_enum import SpsdkEnum

from .error_codes import StatusCode
from .exceptions import McuBootError

########################################################################################################################
# McuBoot Commands and Responses Tags
########################################################################################################################

# fmt: off
class CommandTag(SpsdkEnum):
    """McuBoot Commands."""

    NO_COMMAND                  = (0x00, "NoCommand", "No Command")
    FLASH_ERASE_ALL             = (0x01, "FlashEraseAll", "Erase Complete Flash")
    FLASH_ERASE_REGION          = (0x02, "FlashEraseRegion", "Erase Flash Region")
    READ_MEMORY                 = (0x03, "ReadMemory", "Read Memory")
    WRITE_MEMORY                = (0x04, "WriteMemory", "Write Memory")
    FILL_MEMORY                 = (0x05, "FillMemory", "Fill Memory")
    FLASH_SECURITY_DISABLE      = (0x06, "FlashSecurityDisable", "Disable Flash Security")
    GET_PROPERTY                = (0x07, "GetProperty", "Get Property")
    RECEIVE_SB_FILE             = (0x08, "ReceiveSBFile", "Receive SB File")
    EXECUTE                     = (0x09, "Execute", "Execute")
    CALL                        = (0x0A, "Call", "Call")
    RESET                       = (0x0B, "Reset", "Reset MCU")
    SET_PROPERTY                = (0x0C, "SetProperty", "Set Property")
    FLASH_ERASE_ALL_UNSECURE    = (0x0D, "FlashEraseAllUnsecure", "Erase Complete Flash and Unlock")
    FLASH_PROGRAM_ONCE          = (0x0E, "FlashProgramOnce", "Flash Program Once")
    FLASH_READ_ONCE             = (0x0F, "FlashReadOnce", "Flash Read Once")
    FLASH_READ_RESOURCE         = (0x10, "FlashReadResource", "Flash Read Resource")
    CONFIGURE_MEMORY            = (0x11, "ConfigureMemory", "Configure Quad-SPI Memory")
    RELIABLE_UPDATE             = (0x12, "ReliableUpdate", "Reliable Update")
    GENERATE_KEY_BLOB           = (0x13, "GenerateKeyBlob", "Generate Key Blob")
    FUSE_PROGRAM                = (0x14, "ProgramFuse", "Program Fuse")
    KEY_PROVISIONING            = (0x15, "KeyProvisioning", "Key Provisioning")
    TRUST_PROVISIONING          = (0x16, "TrustProvisioning", "Trust Provisioning")
    FUSE_READ                   = (0x17, "ReadFuse", "Read Fuse")
    UPDATE_LIFE_CYCLE           = (0x18, "UpdateLifeCycle", "Update Life Cycle")
    ELE_MESSAGE                 = (0x19, "EleMessage", "Send EdgeLock Enclave Message")

    # reserved commands
    CONFIGURE_I2C = (0xC1, "ConfigureI2c", "Configure I2C")
    CONFIGURE_SPI = (0xC2, "ConfigureSpi", "Configure SPI")
    CONFIGURE_CAN = (0xC3, "ConfigureCan", "Configure CAN")



class CommandFlag(SpsdkEnum):
    """Flags for McuBoot commands."""

    NONE           = (0, "NoFlags", "No flags specified")
    HAS_DATA_PHASE = (1, "DataPhase", "Command has a data phase")



class ResponseTag(SpsdkEnum):
    """McuBoot Responses to Commands."""

    GENERIC                     = (0xA0, "GenericResponse", "Generic Response")
    READ_MEMORY                 = (0xA3, "ReadMemoryResponse", "Read Memory Response")
    GET_PROPERTY                = (0xA7, "GetPropertyResponse", "Get Property Response")
    FLASH_READ_ONCE             = (0xAF, "FlashReadOnceResponse", "Flash Read Once Response")
    FLASH_READ_RESOURCE         = (0xB0, "FlashReadResourceResponse", "Flash Read Resource Response")
    KEY_BLOB_RESPONSE           = (0xB3, "CreateKeyBlobResponse", "Create Key Blob")
    KEY_PROVISIONING_RESPONSE   = (0xB5, "KeyProvisioningResponse", "Key Provisioning Response")
    TRUST_PROVISIONING_RESPONSE = (0xB6, "TrustProvisioningResponse", "Trust Provisioning Response")


class KeyProvOperation(SpsdkEnum):
    """Type of key provisioning operation."""

    ENROLL              = (0, "Enroll", "Enroll Operation")
    SET_USER_KEY        = (1, "SetUserKey", "Set User Key Operation")
    SET_INTRINSIC_KEY   = (2, "SetIntrinsicKey", "Set Intrinsic Key Operation")
    WRITE_NON_VOLATILE  = (3, "WriteNonVolatile", "Write Non Volatile Operation")
    READ_NON_VOLATILE   = (4, "ReadNonVolatile", "Read Non Volatile Operation")
    WRITE_KEY_STORE     = (5, "WriteKeyStore", "Write Key Store Operation")
    READ_KEY_STORE      = (6, "ReadKeyStore", "Read Key Store Operation")


class KeyProvUserKeyType(SpsdkEnum):
    """Enumeration of supported user keys in PUF. Keys are SoC specific, not all will be supported for the processor."""

    OTFADKEK        = (2, "OTFADKEK", "Key for OTFAD encryption")
    SBKEK           = (3, "SBKEK", "Key for SB file encryption")
    PRINCE_REGION_0 = (7, "PRINCE0", "Key for Prince region 0")
    PRINCE_REGION_1 = (8, "PRINCE1", "Key for Prince region 1")
    PRINCE_REGION_2 = (9, "PRINCE2", "Key for Prince region 2")
    PRINCE_REGION_3 = (10, "PRINCE3", "Key for Prince region 3")

    USERKEK         = (11, "USERKEK", "Encrypted boot image key")
    UDS             = (12, "UDS", "Universal Device Secret for DICE")


class GenerateKeyBlobSelect(SpsdkEnum):
    """Key selector for the generate-key-blob function.

    For devices with SNVS, valid options of [key_sel] are
    0, 1 or OTPMK: OTPMK from FUSE or OTP(default),
    2 or ZMK: ZMK from SNVS,
    3 or CMK: CMK from SNVS,
    For devices without SNVS, this option will be ignored.
    """

    OPTMK   = (0, "OPTMK", "OTPMK from FUSE or OTP(default)")
    ZMK     = (2, "ZMK", "ZMK from SNVS")
    CMK     = (3, "CMK", "CMK from SNVS")


class TrustProvOperation(SpsdkEnum):
    """Operations supported by Trust Provisioning flow."""

    PROVE_GENUINITY = (0xF4, "ProveGenuinity", "Start the proving genuinity process")
    ISP_SET_WRAPPED_DATA = (0xF0, "SetWrappedData", "Start processing Wrapped data")
    """Type of trust provisioning operation."""

    OEM_GEN_MASTER_SHARE        = (0, "OemGenMasterShare", "Enroll Operation")
    OEM_SET_MASTER_SHARE        = (1, "SetUserKey", "Set User Key Operation")
    OEM_GET_CUST_CERT_DICE_PUK  = (2, "SetIntrinsicKey", "Set Intrinsic Key Operation")
    HSM_GEN_KEY                 = (3, "HsmGenKey", "HSM gen key")
    HSM_STORE_KEY               = (4, "HsmStoreKey", "HSM store key")
    HSM_ENC_BLOCK               = (5, "HsmEncBlock", "HSM Enc block")
    HSM_ENC_SIGN                = (6, "HsnEncSign", "HSM enc sign")


class TrustProvOemKeyType(SpsdkEnum):
    """Type of oem key type definition."""

    MFWISK      = (0xC3A5, "MFWISK", "ECDSA Manufacturing Firmware Signing Key")
    MFWENCK     = (0xA5C3, "MFWENCK", "CKDF Master Key for Manufacturing Firmware Encryption Key")
    GENSIGNK    = (0x5A3C, "GENSIGNK", "Generic ECDSA Signing Key")
    GETCUSTMKSK = (0x3C5A, "GETCUSTMKSK", "CKDF Master Key for Production Firmware Encryption Key")


class TrustProvKeyType(SpsdkEnum):
    """Type of key type definition."""

    CKDFK = (1, "CKDFK", "CKDF Master Key")
    HKDFK = (2, "HKDFK", "HKDF Master Key")
    HMACK = (3, "HMACK", "HMAC Key")
    CMACK = (4, "CMACK", "CMAC Key")
    AESK  = (5, "AESK", "AES Key")
    KUOK  = (6, "KUOK", "Key Unwrap Only Key")


class TrustProvWrappingKeyType(SpsdkEnum):
    """Type of wrapping key type definition."""

    INT_SK = (0x10, "INT_SK", "The wrapping key for wrapping of MFG_CUST_MK_SK0_BLOB")
    EXT_SK = (0x11, "EXT_SK", "The wrapping key for wrapping of MFG_CUST_MK_SK0_BLOB")

class TrustProvWpc(SpsdkEnum):
    """Type of WPC trusted facility commands for DSC."""

    WPC_GET_ID              = (0x5000000, "wpc_get_id", "WPC get ID")
    NXP_GET_ID              = (0x5000001, "nxp_get_id", "NXP get ID")
    WPC_INSERT_CERT         = (0x5000002, "wpc_insert_cert", "WPC insert certificate")
    WPC_SIGN_CSR            = (0x5000003, "wpc_sign_csr", "WPC sign CSR")

class TrustProvDevHsmDsc(SpsdkEnum):
    """Type of DSC Device HSM."""

    DSC_HSM_CREATE_SESSION  = (0x6000000, "dsc_hsm_create_session", "DSC HSM create session")
    DSC_HSM_ENC_BLK         = (0x6000001, "dsc_hsm_enc_blk", "DSC HSM encrypt bulk")
    DSC_HSM_ENC_SIGN        = (0x6000002, "dsc_hsm_enc_sign", "DSC HSM sign")

# fmt: on

########################################################################################################################
# McuBoot Command and Response packet classes
########################################################################################################################


class CmdHeader:
    """McuBoot command/response header."""

    SIZE = 4

    def __init__(self, tag: int, flags: int, reserved: int, params_count: int) -> None:
        """Initialize the Command Header.

        :param tag: Tag indicating the command, see: `CommandTag` class
        :param flags: Flags for the command
        :param reserved: Reserved?
        :param params_count: Number of parameter for the command
        """
        self.tag = tag
        self.flags = flags
        self.reserved = reserved
        self.params_count = params_count

    def __eq__(self, obj: object) -> bool:
        return isinstance(obj, CmdHeader) and vars(obj) == vars(self)

    def __ne__(self, obj: object) -> bool:
        return not self.__eq__(obj)

    def __repr__(self) -> str:
        return f"<Tag=0x{self.tag:02X}, Flags=0x{self.flags:02X}, ParamsCount={self.params_count}>"

    def __str__(self) -> str:
        return (
            f"CmdHeader(tag=0x{self.tag:02X}, flags=0x{self.flags:02X}, "
            f"reserved={self.reserved}, params_count={self.params_count})"
        )

    def to_bytes(self) -> bytes:
        """Serialize header into bytes."""
        return pack("4B", self.tag, self.flags, self.reserved, self.params_count)

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> "CmdHeader":
        """Deserialize header from bytes.

        :param data: Input data in bytes
        :param offset: The offset of input data
        :return: De-serialized CmdHeader object
        :raises McuBootError: Invalid data format
        """
        if len(data) < 4:
            raise McuBootError(f"Invalid format of RX packet (data length is {len(data)} bytes)")
        return cls(*unpack_from("4B", data, offset))


class CmdPacket(CmdPacketBase):
    """McuBoot command packet format class."""

    SIZE = 32
    EMPTY_VALUE = 0x00

    def __init__(
        self, tag: CommandTag, flags: int, *args: int, data: Optional[bytes] = None
    ) -> None:
        """Initialize the Command Packet object.

        :param tag: Tag identifying the command
        :param flags: Flags used by the command
        :param args: Arguments used by the command
        :param data: Additional data, defaults to None
        """
        self.header = CmdHeader(tag.tag, flags, 0, len(args))
        self.params = list(args)
        if data is not None:
            if len(data) % 4:
                data += b"\0" * (4 - len(data) % 4)
            self.params.extend(unpack_from(f"<{len(data) // 4}I", data))
            self.header.params_count = len(self.params)

    def __eq__(self, obj: object) -> bool:
        return isinstance(obj, CmdPacket) and vars(obj) == vars(self)

    def __ne__(self, obj: object) -> bool:
        return not self.__eq__(obj)

    def __str__(self) -> str:
        """Get object info."""
        tag = (
            CommandTag.get_label(self.header.tag)
            if self.header.tag in CommandTag.tags()
            else f"0x{self.header.tag:02X}"
        )
        return f"Tag={tag}, Flags=0x{self.header.flags:02X}" + "".join(
            f", P[{n}]=0x{param:08X}" for n, param in enumerate(self.params)
        )

    def to_bytes(self, padding: bool = True) -> bytes:
        """Serialize CmdPacket into bytes.

        :param padding: If True, add padding to specific size
        :return: Serialized object into bytes
        """
        self.header.params_count = len(self.params)
        data = self.header.to_bytes()
        data += pack(f"<{self.header.params_count}I", *self.params)
        if padding and len(data) < self.SIZE:
            data += bytes([self.EMPTY_VALUE] * (self.SIZE - len(data)))
        return data


class CmdResponse(CmdResponseBase):
    """McuBoot response base format class."""

    def __init__(self, header: CmdHeader, raw_data: bytes) -> None:
        """Initialize the Command Response object.

        :param header: Header for the response
        :param raw_data: Response data
        """
        assert isinstance(header, CmdHeader)
        assert isinstance(raw_data, (bytes, bytearray))
        self.header = header
        self.raw_data = raw_data
        (status,) = unpack_from("<L", raw_data)
        self.status: int = status

    @property
    def value(self) -> int:
        """Return a integer representation of the response."""
        return unpack_from(">I", self.raw_data)[0]

    def _get_status_label(self) -> str:
        return (
            StatusCode.get_label(self.status)
            if self.status in StatusCode.tags()
            else f"Unknown[0x{self.status:08X}]"
        )

    def __eq__(self, obj: object) -> bool:
        return isinstance(obj, CmdResponse) and vars(obj) == vars(self)

    def __ne__(self, obj: object) -> bool:
        return not self.__eq__(obj)

    def __str__(self) -> str:
        """Get object info."""
        return (
            f"Tag=0x{self.header.tag:02X}, Flags=0x{self.header.flags:02X}"
            + " ["
            + ", ".join(f"{b:02X}" for b in self.raw_data)
            + "]"
        )


class GenericResponse(CmdResponse):
    """McuBoot generic response format class."""

    def __init__(self, header: CmdHeader, raw_data: bytes) -> None:
        """Initialize the Generic response object.

        :param header: Header for the response
        :param raw_data: Response data
        """
        super().__init__(header, raw_data)
        _, tag = unpack_from("<2I", raw_data)
        self.cmd_tag: int = tag

    def __str__(self) -> str:
        """Get object info."""
        tag = ResponseTag.get_label(self.header.tag)
        status = self._get_status_label()
        cmd = (
            CommandTag.get_label(self.cmd_tag)
            if self.cmd_tag in CommandTag.tags()
            else f"Unknown[0x{self.cmd_tag:02X}]"
        )
        return f"Tag={tag}, Status={status}, Cmd={cmd}"


class GetPropertyResponse(CmdResponse):
    """McuBoot get property response format class."""

    def __init__(self, header: CmdHeader, raw_data: bytes) -> None:
        """Initialize the Get-Property response object.

        :param header: Header for the response
        :param raw_data: Response data
        """
        super().__init__(header, raw_data)
        _, *values = unpack_from(f"<{self.header.params_count}I", raw_data)
        self.values: List[int] = list(values)

    def __str__(self) -> str:
        """Get object info."""
        tag = ResponseTag.get_label(self.header.tag)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}" + "".join(
            f", v{n}=0x{value:08X}" for n, value in enumerate(self.values)
        )


class ReadMemoryResponse(CmdResponse):
    """McuBoot read memory response format class."""

    def __init__(self, header: CmdHeader, raw_data: bytes) -> None:
        """Initialize the Read-Memory response object.

        :param header: Header for the response
        :param raw_data: Response data
        """
        super().__init__(header, raw_data)
        _, length = unpack_from("<2I", raw_data)
        self.length: int = length

    def __str__(self) -> str:
        """Get object info."""
        tag = ResponseTag.get_label(self.header.tag)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}, Length={self.length}"


class FlashReadOnceResponse(CmdResponse):
    """McuBoot flash read once response format class."""

    def __init__(self, header: CmdHeader, raw_data: bytes) -> None:
        """Initialize the Flash-Read-Once response object.

        :param header: Header for the response
        :param raw_data: Response data
        """
        super().__init__(header, raw_data)
        _, length, *values = unpack_from(f"<{self.header.params_count}I", raw_data)
        self.length: int = length
        self.values: List[int] = list(values)
        self.data = raw_data[8 : 8 + self.length] if self.length > 0 else b""

    def __str__(self) -> str:
        """Get object info."""
        tag = ResponseTag.get_label(self.header.tag)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}, Length={self.length}"


class FlashReadResourceResponse(CmdResponse):
    """McuBoot flash read resource response format class."""

    def __init__(self, header: CmdHeader, raw_data: bytes) -> None:
        """Initialize the Flash-Read-Resource response object.

        :param header: Header for the response
        :param raw_data: Response data
        """
        super().__init__(header, raw_data)
        _, length = unpack_from("<2I", raw_data)
        self.length: int = length

    def __str__(self) -> str:
        """Get object info."""
        tag = ResponseTag.get_label(self.header.tag)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}, Length={self.length}"


class KeyProvisioningResponse(CmdResponse):
    """McuBoot Key Provisioning response format class."""

    def __init__(self, header: CmdHeader, raw_data: bytes) -> None:
        """Initialize the Key-Provisioning response object.

        :param header: Header for the response
        :param raw_data: Response data
        """
        super().__init__(header, raw_data)
        _, length = unpack_from("<2I", raw_data)
        self.length: int = length

    def __str__(self) -> str:
        """Get object info."""
        tag = ResponseTag.get_label(self.header.tag)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}, Length={self.length}"


class TrustProvisioningResponse(CmdResponse):
    """McuBoot Trust Provisioning response format class."""

    def __init__(self, header: CmdHeader, raw_data: bytes) -> None:
        """Initialize the Trust-Provisioning response object.

        :param header: Header for the response
        :param raw_data: Response data
        """
        super().__init__(header, raw_data)
        _, *values = unpack(f"<{self.header.params_count}I", raw_data)
        self.values: List[int] = list(values)

    def __str__(self) -> str:
        """Get object info."""
        tag = ResponseTag.get_label(self.header.tag)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}"


class NoResponse(CmdResponse):
    """Special internal case when no response is provided by the target."""

    def __init__(self, cmd_tag: int) -> None:
        """Create a NoResponse to an command that was issued, indicated by its tag.

        :param cmd_tag: Tag of the command that preceded the no-response from target
        """
        header = CmdHeader(tag=cmd_tag, flags=0, reserved=0, params_count=0)
        raw_data = pack("<L", StatusCode.NO_RESPONSE.tag)
        super().__init__(header, raw_data)


def parse_cmd_response(data: bytes, offset: int = 0) -> CmdResponse:
    """Parse command response.

    :param data: Input data in bytes
    :param offset: The offset of input data
    :return: De-serialized object from data
    """
    known_response: Dict[int, Type[CmdResponse]] = {
        ResponseTag.GENERIC.tag: GenericResponse,
        ResponseTag.GET_PROPERTY.tag: GetPropertyResponse,
        ResponseTag.READ_MEMORY.tag: ReadMemoryResponse,
        ResponseTag.FLASH_READ_RESOURCE.tag: FlashReadResourceResponse,
        ResponseTag.FLASH_READ_ONCE.tag: FlashReadOnceResponse,
        ResponseTag.KEY_BLOB_RESPONSE.tag: ReadMemoryResponse,
        ResponseTag.KEY_PROVISIONING_RESPONSE.tag: KeyProvisioningResponse,
        ResponseTag.TRUST_PROVISIONING_RESPONSE.tag: TrustProvisioningResponse,
    }
    header = CmdHeader.from_bytes(data, offset)
    if header.tag in known_response:
        return known_response[header.tag](header, data[CmdHeader.SIZE :])

    return CmdResponse(header, data[CmdHeader.SIZE :])
