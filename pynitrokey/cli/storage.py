# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import logging
import platform
import string
import subprocess
import time
from shutil import which
from typing import Optional

import click
import usb1
from intelhex import IntelHex
from tqdm import tqdm

from pynitrokey.cli.exceptions import CliException
from pynitrokey.helpers import (
    AskUser,
    check_pynitrokey_version,
    confirm,
    local_critical,
    local_print,
    prompt,
)
from pynitrokey.libnk import DeviceNotFound, NitrokeyStorage, RetCode


def connect_nkstorage():
    try:
        nks = NitrokeyStorage()
        nks.connect()
        return nks
    except DeviceNotFound:
        raise CliException("No Nitrokey Storage device found", support_hint=False)


logger = logging.getLogger(__name__)


@click.group()
def storage():
    """Interact with Nitrokey Storage devices, see subcommands."""
    pass


def process_runner(c: str, args: Optional[dict[str, str]] = None) -> str:
    """Wrapper for running command and returning output, both logged"""
    cmd = c.split()
    if args and any(f"${key}" in c for key in args.keys()):
        for i, _ in enumerate(cmd):
            template = string.Template(cmd[i])
            cmd[i] = template.substitute(args)

    logger.debug(f"Running {c}")
    local_print(f'* Running \t"{c}"')
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
    except subprocess.CalledProcessError as e:
        logger.error(f'Output for "{c}": {e.output}')
        local_print(f'\tOutput for "{c}": "{e.output.strip().decode()}"')
        raise
    logger.debug(f'Output for "{c}": {output}')
    return output


class DfuTool:
    name = "dfu-programmer"

    @classmethod
    def is_available(cls) -> bool:
        """Check whether `name` is on PATH and marked as executable."""
        return which(cls.name) is not None

    @classmethod
    def get_version(cls) -> str:
        c = f"{cls.name} --version"
        output = process_runner(c).strip()
        return output

    @classmethod
    def check_version(cls) -> bool:
        # todo choose and use specialized package for version strings management, e.g:
        #   from packaging import version
        ver_string = cls.get_version()
        ver = ver_string.split()[1]
        ver_found = (*map(int, ver.split(".")),)
        ver_required = (0, 6, 1)
        local_print(f"Tool found: {ver_string}")
        return ver_found >= ver_required

    @classmethod
    def self_check(cls) -> bool:
        if not cls.is_available():
            local_print(
                f"{cls.name} is not available. Please install it or use another tool for update."
            )
            raise click.Abort()

        local_print("")
        cls.check_version()
        local_print("")
        return True


class ConnectedDevices:
    application_mode: int
    update_mode: int

    def __init__(self, application_mode: int, update_mode: int) -> None:
        self.application_mode = application_mode
        self.update_mode = update_mode


class UsbId:
    vid: int
    pid: int

    def __init__(self, vid: int, pid: int) -> None:
        self.vid = vid
        self.pid = pid


def is_connected() -> ConnectedDevices:
    devs = {}
    usb_id = {
        "update_mode": UsbId(0x03EB, 0x2FF1),
        "application_mode": UsbId(0x20A0, 0x4109),
    }
    with usb1.USBContext() as context:
        for k, v in usb_id.items():
            res = context.getByVendorIDAndProductID(vendor_id=v.vid, product_id=v.pid)
            devs[k] = 1 if res else 0
    return ConnectedDevices(
        application_mode=devs["application_mode"], update_mode=devs["update_mode"]
    )


@click.command()
@click.argument("firmware", type=click.Path(exists=True, readable=True))
@click.option(
    "--experimental",
    default=False,
    is_flag=True,
    help="Allow to execute experimental features",
)
def update(firmware: str, experimental):
    """experimental: run assisted update through dfu-programmer tool"""
    check_pynitrokey_version()

    if platform.system() != "Linux" or not experimental:
        local_print(
            "This feature is Linux only and experimental, which means it was not tested thoroughly.\n"
            "Please pass --experimental switch to force running it anyway."
        )
        raise click.Abort()
    assert firmware.endswith(".hex")

    DfuTool.self_check()

    commands = """
        dfu-programmer at32uc3a3256s erase
        dfu-programmer at32uc3a3256s flash --suppress-bootloader-mem $FIRMWARE
        dfu-programmer at32uc3a3256s start
        """

    local_print(
        "Note: During the execution update program will try to connect to the device. "
        "Check your udev rules in case of connection issues."
    )
    local_print(f"Using firmware path: {firmware}")
    # note: this is just for presentation - actual argument replacement is done in process_runner
    # the string form cannot be used, as it could contain space which would break dfu-programmer's call
    args = {"FIRMWARE": firmware}
    local_print(
        f"Commands to be executed: {string.Template(commands).substitute(args)}"
    )
    if not confirm("Do you want to perform the firmware update now?"):
        logger.info("Update cancelled by user")
        raise click.Abort()

    check_for_update_mode()

    commands_clean = commands.strip().split("\n")
    for c in commands_clean:
        c = c.strip()
        if not c:
            continue
        try:
            output = process_runner(c, args)
            if output:
                local_print(output)
        except subprocess.CalledProcessError as e:
            linux = "linux" in platform.platform().lower()
            local_critical(
                e, "Note: make sure you have the udev rules installed." if linux else ""
            )

    local_print("")
    local_print("Finished!")

    for _ in tqdm(range(10), leave=False):
        if is_connected().application_mode != 0:
            break
        time.sleep(1)

    list_cmd = storage.commands["list"]
    assert list_cmd.callback
    list_cmd.callback()


def check_for_update_mode() -> None:
    connected = is_connected()
    assert (
        connected.application_mode + connected.update_mode > 0
    ), "No connected Nitrokey Storage devices found"
    if connected.application_mode and not connected.update_mode:
        # execute bootloader
        storage.commands["enable-update"].callback()  # type: ignore[misc]
        for _ in tqdm(range(10), leave=False):
            if is_connected().update_mode != 0:
                break
            time.sleep(1)
        time.sleep(1)
    else:
        local_print(
            "Nitrokey Storage in update mode found in the USB list (not connected yet)"
        )


@click.command()
def list():
    """List connected devices"""

    local_print(":: 'Nitrokey Storage' keys:")
    devices = NitrokeyStorage.list_devices()
    for dct in devices:
        local_print(f" - {dct}")
    if len(devices) == 1:
        nks = NitrokeyStorage()
        nks.connect()
        local_print(f"Found libnitrokey version: {nks.library_version()}")
        local_print(f"Firmware version: {nks.fw_version}")
        local_print(f"Admin PIN retries: {nks.admin_pin_retries}")
        local_print(f"User PIN retries: {nks.user_pin_retries}")


@click.command()
def enable_update():
    """Enable firmware update for NK Storage device

    If the Firmware Password is not in the environment variable NITROPY_FIRMWARE_PASSWORD, it will be prompted from stdin
    """
    password = AskUser(
        "Firmware Password", envvar="NITROPY_FIRMWARE_PASSWORD", hide_input=True
    ).ask()
    local_print("Enabling firmware update mode")
    nks = connect_nkstorage()
    if nks.enable_firmware_update(password) == 0:
        local_print("setting firmware update mode - success!")
    else:
        local_critical(
            "Enabling firmware update has failed. Check your firmware password."
        )


@click.command()
def change_firmware_password():
    """
    Change the firmware update password.

    The user is prompted for the old and the new firmware update password.  Per
    default, the firmware update password is 12345678.
    """
    nk = connect_nkstorage()

    old_password = prompt(
        "Old firmware update password", default="12345678", hide_input=True
    )
    new_password = prompt(
        "New firmware update password", hide_input=True, confirmation_prompt=True
    )
    ret = nk.change_firmware_password(old_password, new_password)
    if ret.ok:
        local_print("Successfully updated the firmware password")
    elif ret == RetCode.WRONG_PASSWORD:
        local_critical("Wrong firmware update password", support_hint=False)
    elif ret == RetCode.TooLongStringException:
        local_critical(
            "The new firmware update password is too long", support_hint=False
        )
    else:
        local_critical(f"Failed to update the firmware password ({ret.name})")


@click.command()
def open_encrypted():
    """Unlock the encrypted volume

    If the User PIN is not in the environment variable NITROPY_USER_PIN, it will be prompted from stdin
    """
    password = AskUser("User PIN", envvar="NITROPY_USER_PIN", hide_input=True).ask()
    nks = connect_nkstorage()
    ret = nks.unlock_encrypted_volume(password)
    if not ret.ok:
        if ret == RetCode.WRONG_PASSWORD:
            raise CliException("Wrong user PIN", support_hint=False)
        else:
            raise CliException(
                "Unexpected error unlocking the encrypted volume {}".format(str(ret))
            )


@click.command()
def close_encrypted():
    """Lock the encrypted volume"""
    nks = connect_nkstorage()
    ret = nks.lock_encrypted_volume()
    if not ret.ok:
        raise CliException("Error closing the encrypted volume: {}".format(str(ret)))


@click.command()
def open_hidden():
    """Unlock a hidden volume

    If the hidden volume passphrase is not in the environment variable NITROPY_HIDDEN_PASSPHRASE, it will be prompted from stdin
    """
    password = AskUser(
        "Hidden volume passphrase", envvar="NITROPY_HIDDEN_PASSPHRASE", hide_input=True
    ).ask()
    nks = connect_nkstorage()
    ret = nks.unlock_hidden_volume(password)
    if not ret.ok:
        if ret == RetCode.WRONG_PASSWORD:
            raise CliException("Wrong hidden volume passphrase", support_hint=False)
        else:
            raise CliException(
                "Unexpected error unlocking the hidden volume: {}".format(str(ret))
            )


@click.command()
def close_hidden():
    """Lock the hidden volumes"""
    nks = connect_nkstorage()
    ret = nks.lock_hidden_volume()
    if not ret.ok:
        raise CliException("Error closing the hidden volume: {}".format(str(ret)))


@click.command()
@click.argument(
    "slot",
    type=int,
)
@click.argument(
    "begin",
    type=int,
)
@click.argument("end", type=int)
def create_hidden(slot, begin, end):
    """Create a hidden volume

    SLOT is the slot used for the hidden volume (1-4)\n
    START is where the volume begins expressed in percent of total available storage (0-99)\n
    END is where the volume ends expressed in percent of total available storage (1-100)\n
    If the hidden volume passphrase is not in the environment variable NITROPY_HIDDEN_PASSPHRASE, it will be prompted from stdin
    """
    if not slot in [1, 2, 3, 4]:
        raise CliException("Error: Slot must be between 1 and 4", support_hint=False)
    elif begin > 99 or begin < 0:
        raise CliException("Error: Begin must be between 0 and 99", support_hint=False)
    elif end < 1 or end > 100:
        raise CliException("Error: End must be between 1 and 100", support_hint=False)
    elif begin >= end:
        raise CliException(
            "Error: END must be strictly superior than START", support_hint=False
        )

    password = AskUser(
        "Hidden volume passphrase", envvar="NITROPY_HIDDEN_PASSPHRASE", hide_input=True
    ).ask()

    nks = connect_nkstorage()
    ret = nks.create_hidden_volume(slot - 1, begin, end, password)
    if not ret.ok:
        raise CliException("Error creating the hidden volume: {}".format(str(ret)))


class MemoryConstants:
    HEX_OFFSET = 0x80000000
    APPLICATION_DATA_START = 0x2000
    USER_DATA_START = 495 * 512  # 0x3DE00
    # user data end, last page is for the bootloader data (as per dfu-programmer manual)
    USER_DATA_END = 511 * 512  # 0x3FE00


def input_format(x: str):
    return "hex" if x.endswith("hex") else "bin"


def empty_check_user_data(ih: IntelHex):
    empty = 0
    for i in range(MemoryConstants.USER_DATA_START, MemoryConstants.USER_DATA_END):
        empty += ih[i] not in [0xFF, 0x00]
    return empty == 0


@click.command()
@click.argument("firmware", type=click.Path(exists=True))
def check(firmware: str):
    """Check if provided binary image contains user data in the proper region

    Use it on downloaded full image with `--force` flag, as in: \n
    $ dfu-programmer at32uc3a3256s read --bin --force > dump.bin
    """
    current_firmware_read = IntelHex()
    current_firmware_read.loadfile(firmware, format=input_format(firmware))

    if empty_check_user_data(current_firmware_read):
        raise click.ClickException(
            f"{firmware}: Provided dumped binary image does not contain user data"
        )
    click.echo(f"{firmware}: User data seem to be present")


@click.command()
@click.argument("fw1_path", type=click.Path(exists=True))
@click.argument("fw2_path", type=click.Path(exists=True))
@click.argument("region", type=click.Choice(["application", "user"]))
@click.option("--max-diff", type=int, default=10)
def compare(fw1_path: str, fw2_path: str, region: str, max_diff: int):
    """Compare two binary images"""

    fw1 = IntelHex()
    fw1.loadfile(fw1_path, format=input_format(fw1_path))
    fw2 = IntelHex()
    fw2.loadfile(fw2_path, format=input_format(fw2_path))

    offset = {}
    for f in [fw1, fw2]:
        offset[f] = 0
        if f.minaddr() >= MemoryConstants.HEX_OFFSET:
            offset[f] = MemoryConstants.HEX_OFFSET

    if fw1.minaddr() != fw2.minaddr():
        click.echo(
            f"Warning: different offsets found - this could make the operation fail: {hex(fw1.minaddr())} {hex(fw2.minaddr())}"
        )

    diff_count = 0
    non_empty_count = 0
    if region == "application":
        data_start = MemoryConstants.APPLICATION_DATA_START
        data_stop = MemoryConstants.USER_DATA_START
    elif region == "user":
        data_start = MemoryConstants.USER_DATA_START
        data_stop = MemoryConstants.USER_DATA_END
    else:
        raise click.ClickException(f"Wrong type")

    def geti(f: IntelHex, i: int) -> int:
        return f[i + offset[f]]

    click.echo(f"Checking binary images in range {hex(data_start)}:{hex(data_stop)}")
    for i in range(data_start, data_stop):
        fw1_i = geti(fw1, i)
        fw2_i = geti(fw2, i)
        data_equal = fw1_i == fw2_i or fw1_i in [0xFF, 0x00] and fw2_i in [0xFF, 0x00]
        diff_count += not data_equal
        non_empty_count += fw1_i not in [0xFF, 0x00]
        if not data_equal:
            click.echo(
                f"Binaries differ at {hex(i)} (page {i // 512}): {hex(fw1_i)} {hex(fw2_i)}"
            )
        if diff_count > max_diff:
            raise click.ClickException(f"Maximum diff count reached")

    if diff_count > 0:
        raise click.ClickException(f"Binaries differ")
    if non_empty_count == 0:
        raise click.ClickException(f"Binaries contain no data")
    click.echo(f"Non-empty bytes count: {non_empty_count}")
    click.echo("Binary images are identical")


@click.command()
@click.argument("dumped_firmware", type=click.Path(exists=True))
@click.argument("new_firmware_file", type=click.Path(exists=True))
@click.argument("output", type=click.File("w"))
@click.option("--overlap", type=click.Choice(["error", "ignore"]), default="error")
def merge(
    dumped_firmware: str,
    new_firmware_file: str,
    output: click.File,
    overlap: str,
):
    """Simple tool to merge user data into the new firmware binary"""
    if not output.name.endswith("hex"):
        raise click.ClickException("Provided output path has to end in .hex")

    current_firmware_read = IntelHex()
    current_firmware_read.loadfile(
        dumped_firmware, format=input_format(dumped_firmware)
    )

    if empty_check_user_data(current_firmware_read):
        raise click.ClickException(
            "Provided dumped binary image does not contain user data"
        )

    new_firmware = IntelHex()
    new_firmware.loadfile(new_firmware_file, format=input_format(new_firmware_file))
    new_firmware.merge(
        current_firmware_read[
            MemoryConstants.USER_DATA_START : MemoryConstants.USER_DATA_END
        ],
        overlap=overlap,
    )
    new_firmware.write_hex_file(output)
    click.echo(f'Done. Results written to "{output.name}".')


@click.group()
def user_data():
    """experimental: commands to check and manipulate user data in the downloaded binary images"""
    pass


user_data.add_command(merge)
user_data.add_command(check)
user_data.add_command(compare)

storage.add_command(list)
storage.add_command(enable_update)
storage.add_command(change_firmware_password)
storage.add_command(open_encrypted)
storage.add_command(close_encrypted)
storage.add_command(open_hidden)
storage.add_command(close_hidden)
storage.add_command(create_hidden)
storage.add_command(update)
storage.add_command(user_data)
