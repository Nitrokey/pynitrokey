# Copyright 2019 SoloKeys Developers
# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT


class SoloExtension:
    version = 0x14
    rng = 0x15


class SoloBootloader:
    write = 0x40
    done = 0x41
    check = 0x42
    erase = 0x43
    version = 0x44
    reboot = 0x45
    st_dfu = 0x46
    disable = 0x47
    boot_pubkey = 0x48

    HIDCommandBoot = 0x50
    HIDCommandEnterBoot = 0x51
    HIDCommandEnterSTBoot = 0x52
    HIDCommandRNG = 0x60
    HIDCommandProbe = 0x70
    HIDCommandStatus = 0x71

    TAG = b"\x8c\x27\x90\xf6"
