#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""EdgeLock Enclave Message constants."""

from ..utils.spsdk_enum import SpsdkEnum, SpsdkSoftEnum


class MessageIDs(SpsdkSoftEnum):
    """ELE Messages ID."""

    PING_REQ = (0x01, "PING_REQ", "Ping request.")
    ELE_FW_AUTH_REQ = (0x02, "ELE_FW_AUTH_REQ", "ELE firmware authenticate request.")
    ELE_DUMP_DEBUG_BUFFER_REQ = (0x21, "ELE_DUMP_DEBUG_BUFFER_REQ", "Dump the ELE logs")
    ELE_OEM_CNTN_AUTH_REQ = (
        0x87,
        "ELE_OEM_CNTN_AUTH_REQ",
        "OEM Container authenticate",
    )
    ELE_VERIFY_IMAGE_REQ = (0x88, "ELE_VERIFY_IMAGE_REQ", "Verify Image")
    ELE_RELEASE_CONTAINER_REQ = (
        0x89,
        "ELE_RELEASE_CONTAINER_REQ",
        "Release Container.",
    )
    WRITE_SEC_FUSE_REQ = (0x91, "WRITE_SEC_FUSE_REQ", "Write secure fuse request.")
    ELE_FWD_LIFECYCLE_UP_REQ = (
        0x95,
        "ELE_FWD_LIFECYCLE_UP_REQ",
        "Forward Lifecycle update",
    )
    READ_COMMON_FUSE = (0x97, "READ_COMMON_FUSE", "Read common fuse request.")
    GET_FW_VERSION_REQ = (0x9D, "GET_FW_VERSION_REQ", "Get firmware version request.")
    RETURN_LIFECYCLE_UPDATE_REQ = (
        0xA0,
        "RETURN_LIFECYCLE_UPDATE_REQ",
        "Return lifecycle update request.",
    )
    ELE_GET_EVENTS_REQ = (0xA2, "ELE_GET_EVENTS_REQ", "Get Events")
    LOAD_KEY_BLOB_REQ = (0xA7, "LOAD_KEY_BLOB_REQ", "Load KeyBlob request.")
    ELE_COMMIT_REQ = (0xA8, "ELE_COMMIT_REQ", "EdgeLock Enclave commit request.")
    ELE_DERIVE_KEY_REQ = (0xA9, "ELE_DERIVE_KEY_REQ", "Derive key")
    GENERATE_KEY_BLOB_REQ = (0xAF, "GENERATE_KEY_BLOB_REQ", "Generate KeyBlob request.")
    GET_FW_STATUS_REQ = (0xC5, "GET_FW_STATUS_REQ", "Get ELE FW status request.")
    ELE_ENABLE_APC_REQ = (
        0xD2,
        "ELE_ENABLE_APC_REQ",
        "Enable APC (Application processor)",
    )
    ELE_ENABLE_RTC_REQ = (0xD3, "ELE_ENABLE_RTC_REQ", "Enable RTC (Runtime processor)")
    GET_INFO_REQ = (0xDA, "GET_INFO_REQ", "Get ELE Information request.")
    ELE_RESET_APC_CTX_REQ = (0xD8, "ELE_RESET_APC_CTX_REQ", "Reset APC Context")
    START_RNG_REQ = (0xA3, "START_RNG_REQ", "Start True Random Generator request.")
    GET_TRNG_STATE_REQ = (
        0xA3,
        "GET_TRNG_STATE_REQ",
        "Get True Random Generator state request.",
    )
    RESET_REQ = (0xC7, "RESET_REQ", "System reset request.")
    WRITE_FUSE = (0xD6, "WRITE_FUSE", "Write fuse")
    WRITE_SHADOW_FUSE = (0xF2, "WRITE_SHADOW_FUSE", "Write shadow fuse")
    READ_SHADOW_FUSE = (0xF3, "READ_SHADOW_FUSE", "Read shadow fuse request.")


class LifeCycle(SpsdkSoftEnum):
    """ELE life cycles."""

    LC_BLANK = (0x002, "BLANK", "Blank device")
    LC_FAB = (0x004, "FAB", "Fab mode")
    LC_NXP_PROV = (0x008, "NXP_PROV", "NXP Provisioned")
    LC_OEM_OPEN = (0x010, "OEM_OPEN", "OEM Open")
    LC_OEM_SWC = (0x020, "OEM_SWC", "OEM Secure World Closed")
    LC_OEM_CLSD = (0x040, "OEM_CLSD", "OEM Closed")
    LC_OEM_FR = (0x080, "OEM_FR", "Field Return OEM")
    LC_NXP_FR = (0x100, "NXP_FR", "Field Return NXP")
    LC_OEM_LCKD = (0x200, "OEM_LCKD", "OEM Locked")
    LC_BRICKED = (0x400, "BRICKED", "BRICKED")


class LifeCycleToSwitch(SpsdkSoftEnum):
    """ELE life cycles to switch request."""

    OEM_CLOSED = (0x08, "OEM_CLOSED", "OEM Closed")
    OEM_LOCKED = (0x80, "OEM_LOCKED", "OEM Locked")


class MessageUnitId(SpsdkSoftEnum):
    """Message Unit ID."""

    RTD_MU = (0x01, "RTD_MU", "Real Time Device message unit")
    APD_MU = (0x02, "APD_MU", "Application Processor message unit")


class ResponseStatus(SpsdkEnum):
    """ELE Message Response status."""

    ELE_SUCCESS_IND = (0xD6, "Success", "The request was successful")
    ELE_FAILURE_IND = (0x29, "Failure", "The request failed")


class ResponseIndication(SpsdkSoftEnum):
    """ELE Message Response indication."""

    ELE_ROM_PING_FAILURE_IND = (0x0A, "ELE_ROM_PING_FAILURE_IND", "ROM ping failure")
    ELE_FW_PING_FAILURE_IND = (0x1A, "ELE_FW_PING_FAILURE_IND", "Firmware ping failure")
    ELE_UNALIGNED_PAYLOAD_FAILURE_IND = (
        0xA6,
        "ELE_UNALIGNED_PAYLOAD_FAILURE_IND",
        "Un-aligned payload failure",
    )
    ELE_WRONG_SIZE_FAILURE_IND = (
        0xA7,
        "ELE_WRONG_SIZE_FAILURE_IND",
        "Wrong size failure",
    )
    ELE_ENCRYPTION_FAILURE_IND = (
        0xA8,
        "ELE_ENCRYPTION_FAILURE_IND",
        "Encryption failure",
    )
    ELE_DECRYPTION_FAILURE_IND = (
        0xA9,
        "ELE_DECRYPTION_FAILURE_IND",
        "Decryption failure",
    )
    ELE_OTP_PROGFAIL_FAILURE_IND = (
        0xAA,
        "ELE_OTP_PROGFAIL_FAILURE_IND",
        "OTP program fail failure",
    )
    ELE_OTP_LOCKED_FAILURE_IND = (
        0xAB,
        "ELE_OTP_LOCKED_FAILURE_IND",
        "OTP locked failure",
    )
    ELE_OTP_INVALID_IDX_FAILURE_IND = (
        0xAD,
        "ELE_OTP_INVALID_IDX_FAILURE_IND",
        "OTP Invalid IDX failure",
    )
    ELE_TIME_OUT_FAILURE_IND = (0xB0, "ELE_TIME_OUT_FAILURE_IND", "Timeout  failure")
    ELE_BAD_PAYLOAD_FAILURE_IND = (
        0xB1,
        "ELE_BAD_PAYLOAD_FAILURE_IND",
        "Bad payload failure",
    )
    ELE_WRONG_ADDRESS_FAILURE_IND = (
        0xB4,
        "ELE_WRONG_ADDRESS_FAILURE_IND",
        "Wrong address failure",
    )
    ELE_DMA_FAILURE_IND = (0xB5, "ELE_DMA_FAILURE_IND", "DMA failure")
    ELE_DISABLED_FEATURE_FAILURE_IND = (
        0xB6,
        "ELE_DISABLED_FEATURE_FAILURE_IND",
        "Disabled feature failure",
    )
    ELE_MUST_ATTEST_FAILURE_IND = (
        0xB7,
        "ELE_MUST_ATTEST_FAILURE_IND",
        "Must attest failure",
    )
    ELE_RNG_NOT_STARTED_FAILURE_IND = (
        0xB8,
        "ELE_RNG_NOT_STARTED_FAILURE_IND",
        "Random number generator not started failure",
    )
    ELE_CRC_ERROR_IND = (0xB9, "ELE_CRC_ERROR_IND", "CRC error")
    ELE_AUTH_SKIPPED_OR_FAILED_FAILURE_IND = (
        0xBB,
        "ELE_AUTH_SKIPPED_OR_FAILED_FAILURE_IND",
        "Authentication skipped or failed failure",
    )
    ELE_INCONSISTENT_PAR_FAILURE_IND = (
        0xBC,
        "ELE_INCONSISTENT_PAR_FAILURE_IND",
        "Inconsistent parameter failure",
    )
    ELE_RNG_INST_FAILURE_IND = (
        0xBD,
        "ELE_RNG_INST_FAILURE_IND",
        "Random number generator instantiation failure",
    )
    ELE_LOCKED_REG_FAILURE_IND = (
        0xBE,
        "ELE_LOCKED_REG_FAILURE_IND",
        "Locked register failure",
    )
    ELE_BAD_ID_FAILURE_IND = (0xBF, "ELE_BAD_ID_FAILURE_IND", "Bad ID failure")
    ELE_INVALID_OPERATION_FAILURE_IND = (
        0xC0,
        "ELE_INVALID_OPERATION_FAILURE_IND",
        "Invalid operation failure",
    )
    ELE_NON_SECURE_STATE_FAILURE_IND = (
        0xC1,
        "ELE_NON_SECURE_STATE_FAILURE_IND",
        "Non secure state failure",
    )
    ELE_MSG_TRUNCATED_IND = (0xC2, "ELE_MSG_TRUNCATED_IND", "Message truncated failure")
    ELE_BAD_IMAGE_NUM_FAILURE_IND = (
        0xC3,
        "ELE_BAD_IMAGE_NUM_FAILURE_IND",
        "Bad image number failure",
    )
    ELE_BAD_IMAGE_ADDR_FAILURE_IND = (
        0xC4,
        "ELE_BAD_IMAGE_ADDR_FAILURE_IND",
        "Bad image address failure",
    )
    ELE_BAD_IMAGE_PARAM_FAILURE_IND = (
        0xC5,
        "ELE_BAD_IMAGE_PARAM_FAILURE_IND",
        "Bad image parameters failure",
    )
    ELE_BAD_IMAGE_TYPE_FAILURE_IND = (
        0xC6,
        "ELE_BAD_IMAGE_TYPE_FAILURE_IND",
        "Bad image type failure",
    )
    ELE_APC_ALREADY_ENABLED_FAILURE_IND = (
        0xCB,
        "ELE_APC_ALREADY_ENABLED_FAILURE_IND",
        "APC already enabled failure",
    )
    ELE_RTC_ALREADY_ENABLED_FAILURE_IND = (
        0xCC,
        "ELE_RTC_ALREADY_ENABLED_FAILURE_IND",
        "RTC already enabled failure",
    )
    ELE_WRONG_BOOT_MODE_FAILURE_IND = (
        0xCD,
        "ELE_WRONG_BOOT_MODE_FAILURE_IND",
        "Wrong boot mode failure",
    )
    ELE_OLD_VERSION_FAILURE_IND = (
        0xCE,
        "ELE_OLD_VERSION_FAILURE_IND",
        "Old version failure",
    )
    ELE_CSTM_FAILURE_IND = (0xCF, "ELE_CSTM_FAILURE_IND", "CSTM failure")
    ELE_CORRUPTED_SRK_FAILURE_IND = (
        0xD0,
        "ELE_CORRUPTED_SRK_FAILURE_IND",
        "Corrupted SRK failure",
    )
    ELE_OUT_OF_MEMORY_IND = (0xD1, "ELE_OUT_OF_MEMORY_IND", "Out of memory failure")

    ELE_MUST_SIGNED_FAILURE_IND = (
        0xE0,
        "ELE_MUST_SIGNED_FAILURE_IND",
        "Must be signed failure",
    )
    ELE_NO_AUTHENTICATION_FAILURE_IND = (
        0xEE,
        "ELE_NO_AUTHENTICATION_FAILURE_IND",
        "No authentication failure",
    )
    ELE_BAD_SRK_SET_FAILURE_IND = (
        0xEF,
        "ELE_BAD_SRK_SET_FAILURE_IND",
        "Bad SRK set failure",
    )
    ELE_BAD_SIGNATURE_FAILURE_IND = (
        0xF0,
        "ELE_BAD_SIGNATURE_FAILURE_IND",
        "Bad signature failure",
    )
    ELE_BAD_HASH_FAILURE_IND = (0xF1, "ELE_BAD_HASH_FAILURE_IND", "Bad hash failure")
    ELE_INVALID_LIFECYCLE_IND = (0xF2, "ELE_INVALID_LIFECYCLE_IND", "Invalid lifecycle")
    ELE_PERMISSION_DENIED_FAILURE_IND = (
        0xF3,
        "ELE_PERMISSION_DENIED_FAILURE_IND",
        "Permission denied failure",
    )
    ELE_INVALID_MESSAGE_FAILURE_IND = (
        0xF4,
        "ELE_INVALID_MESSAGE_FAILURE_IND",
        "Invalid message failure",
    )
    ELE_BAD_VALUE_FAILURE_IND = (0xF5, "ELE_BAD_VALUE_FAILURE_IND", "Bad value failure")
    ELE_BAD_FUSE_ID_FAILURE_IND = (
        0xF6,
        "ELE_BAD_FUSE_ID_FAILURE_IND",
        "Bad fuse ID failure",
    )
    ELE_BAD_CONTAINER_FAILURE_IND = (
        0xF7,
        "ELE_BAD_CONTAINER_FAILURE_IND",
        "Bad container failure",
    )
    ELE_BAD_VERSION_FAILURE_IND = (
        0xF8,
        "ELE_BAD_VERSION_FAILURE_IND",
        "Bad version failure",
    )
    ELE_INVALID_KEY_FAILURE_IND = (
        0xF9,
        "ELE_INVALID_KEY_FAILURE_IND",
        "The key in the container is invalid",
    )
    ELE_BAD_KEY_HASH_FAILURE_IND = (
        0xFA,
        "ELE_BAD_KEY_HASH_FAILURE_IND",
        "The key hash verification does not match OTP",
    )
    ELE_NO_VALID_CONTAINER_FAILURE_IND = (
        0xFB,
        "ELE_NO_VALID_CONTAINER_FAILURE_IND",
        "No valid container failure",
    )
    ELE_BAD_CERTIFICATE_FAILURE_IND = (
        0xFC,
        "ELE_BAD_CERTIFICATE_FAILURE_IND",
        "Bad certificate failure",
    )
    ELE_BAD_UID_FAILURE_IND = (0xFD, "ELE_BAD_UID_FAILURE_IND", "Bad UID failure")
    ELE_BAD_MONOTONIC_COUNTER_FAILURE_IND = (
        0xFE,
        "ELE_BAD_MONOTONIC_COUNTER_FAILURE_IND",
        "Bad monotonic counter failure",
    )
    ELE_ABORT_IND = (0xFF, "ELE_ABORT_IND", "Abort")


class EleFwStatus(SpsdkSoftEnum):
    """ELE Firmware status."""

    ELE_FW_STATUS_NOT_IN_PLACE = (0, "ELE_FW_STATUS_NOT_IN_PLACE", "Not in place")
    ELE_FW_STATUS_IN_PLACE = (
        1,
        "ELE_FW_STATUS_IN_PLACE",
        "Authenticated and operational",
    )


class EleInfo2Commit(SpsdkSoftEnum):
    """ELE Information type to be committed."""

    NXP_SRK_REVOCATION = (
        0x1 << 0,
        "NXP_SRK_REVOCATION",
        "SRK revocation of the NXP container",
    )
    NXP_FW_FUSE = (0x1 << 1, "NXP_FW_FUSE", "FW fuse version of the NXP container")
    OEM_SRK_REVOCATION = (
        0x1 << 4,
        "OEM_SRK_REVOCATION",
        "SRK revocation of the OEM container",
    )
    OEM_FW_FUSE = (0x1 << 5, "OEM_FW_FUSE", "FW fuse version of the OEM container")


class KeyBlobEncryptionAlgorithm(SpsdkSoftEnum):
    """ELE KeyBlob encryption algorithms."""

    AES_CBC = (0x03, "AES_CBC", "KeyBlob encryption algorithm AES CBC")
    AES_CTR = (0x04, "AES_CTR", "KeyBlob encryption algorithm AES CTR")
    AES_XTS = (0x37, "AES_XTS", "KeyBlob encryption algorithm AES XTS")
    SM4_CBC = (0x2B, "SM4_CBC", "KeyBlob encryption algorithm SM4 CBC")


class KeyBlobEncryptionIeeCtrModes(SpsdkSoftEnum):
    """IEE Keyblob mode attributes."""

    AesCTRWAddress = (0x02, "CTR_WITH_ADDRESS", " AES CTR w address binding mode")
    AesCTRWOAddress = (0x03, "CTR_WITHOUT_ADDRESS", " AES CTR w/o address binding mode")
    AesCTRkeystream = (0x04, "CTR_KEY_STREAM", "AES CTR keystream only")


class EleTrngState(SpsdkSoftEnum):
    """ELE TRNG state."""

    ELE_TRNG_NOT_READY = (
        0x0,
        "ELE_TRNG_NOT_READY",
        "True random generator not started yet. Use 'start-trng' command",
    )
    ELE_TRNG_PROGRAM = (0x1, "ELE_TRNG_PROGRAM", "TRNG is in program mode")
    ELE_TRNG_GENERATING_ENTROPY = (
        0x2,
        "ELE_TRNG_GENERATING_ENTROPY",
        "TRNG is still generating entropy",
    )
    ELE_TRNG_READY = (
        0x3,
        "ELE_TRNG_READY",
        "TRNG entropy is valid and ready to be read",
    )
    ELE_TRNG_ERROR = (
        0x4,
        "ELE_TRNG_ERROR",
        "TRNG encounter an error while generating entropy",
    )


class EleCsalState(SpsdkSoftEnum):
    """ELE CSAL state."""

    ELE_CSAL_NOT_READY = (
        0x0,
        "ELE_CSAL_NOT_READY",
        "Crypto Lib random context initialization is not done yet",
    )
    ELE_CSAL_ON_GOING = (
        0x1,
        "ELE_CSAL_ON_GOING",
        "Crypto Lib random context initialization is on-going",
    )
    ELE_CSAL_READY = (
        0x2,
        "ELE_CSAL_READY",
        "Crypto Lib random context initialization succeed",
    )
    ELE_CSAL_ERROR = (
        0x3,
        "ELE_CSAL_ERROR",
        "Crypto Lib random context initialization failed",
    )
    ELE_CSAL_PAUSE = (
        0x4,
        "ELE_CSAL_PAUSE",
        "Crypto Lib random context initialization is in 'pause' mode",
    )
