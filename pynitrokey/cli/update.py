# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import os
import platform
from datetime import datetime

import click
import requests
import sys
import tempfile
import json
import time

import pynitrokey

from pynitrokey.helpers import local_print, local_critical, LOG_FN, logger
from pynitrokey.helpers import AskUser



@click.command()
@click.option("-s", "--serial", help="Serial number of Nitrokey key to target",
              default=None)
@click.option('-y', 'yes', default=False, is_flag=True, help='agree to everything')
def update(serial, yes):
    """Update Nitrokey key to latest firmware version."""

    # @fixme: print this and allow user to cancel (if not -y is active)
    #update_url = 'https://update.nitrokey.com/'
    #print('Please use {} to run the firmware update'.format(update_url))
    #return

    IS_LINUX = platform.system() == "Linux"

    logger.debug(f"Start session {datetime.now()}")

    # @fixme: move to generic startup stuff logged into file exclusively!
    local_print("Nitrokey FIDO2 firmware update tool",
                f"Platform: {platform.platform()}",
                f"System: {platform.system()}, is_linux: {IS_LINUX}",
                f"Python: {platform.python_version()}",
                f"Saving run log to: {LOG_FN}", "",
                f"Starting update procedure for Nitrokey FIDO2...")

    from pynitrokey.fido2 import find

    # Determine target key
    client = None
    try:
        client = find(serial)

    except pynitrokey.exceptions.NoSoloFoundError as e:
        local_critical(None,
            "No Nitrokey key found!", e, None,
            "If you are on Linux, are your udev rules up to date?",
            "For more, see: ",
            "  https://www.nitrokey.com/documentation/installation#os:linux",
            None)

    except pynitrokey.exceptions.NonUniqueDeviceError as e:
        local_critical(None,
            "Multiple Nitrokey keys are plugged in!", e, None,
            "Please unplug all but one key", None)

    except Exception as e:
        local_critical(None, "Unhandled error connecting to key", e, None)

    # determine asset url: we want the (signed) json file
    # @fixme: move to confconsts.py ...
    api_base_url = "https://api.github.com/repos"
    api_url = f"{api_base_url}/Nitrokey/nitrokey-fido2-firmware/releases/latest"
    try:
        gh_release_data = json.loads(requests.get(api_url).text)
    except Exception as e:
        local_critical("Failed downloading firmware", e)

    # search asset with `fn` suffix being .json and take its url
    assets = [(x["name"], x["browser_download_url"]) \
              for x in gh_release_data["assets"]]
    download_url = None
    for fn, url in assets:
        if fn.endswith(".json"):
            download_url = url
            break
    if not download_url:
        local_critical("Failed to determine latest release (url)",
                       "assets:", *map(str, assets))

    # download asset url
    # @fixme: move to confconsts.py ...
    local_print(f"Downloading latest firmware: {gh_release_data['tag_name']} "
                f"(published at {gh_release_data['published_at']})")
    tmp_dir = tempfile.gettempdir()
    fw_fn = os.path.join(tmp_dir, "fido2_firmware.json")
    try:
        with open(fw_fn, "wb") as fd:
            firmware = requests.get(download_url)
            fd.write(firmware.content)
    except Exception as e:
        local_critical("Failed downloading firmware", e)

    local_print(f"Firmware saved to {fw_fn}",
                f"Downloaded firmware version: {gh_release_data['tag_name']}")

    # @fixme: whyyyyy is this here, move away... (maybe directly next to `fido2.find()`)
    def get_dev_details():

        # @fixme: why not use `find` here...
        from pynitrokey.fido2 import find_all
        c = find_all()[0]

        _props = c.dev.descriptor
        local_print(f"Device connected:")
        if "serial_number" in _props:
            local_print(f"{_props['serial_number']}: {_props['product_string']}")
        else:
            local_print(f"{_props['path']}: {_props['product_string']}")

        version_raw = c.solo_version()
        major, minor, patch = version_raw[:3]
        locked = "" if len(version_raw) > 3 and version_raw[3] else "unlocked"

        local_print(f"Firmware version: {major}.{minor}.{patch} {locked}", None)

    get_dev_details()

    # ask for permission
    if not yes:
        local_print("This will update your Nitrokey FIDO2")
        if not AskUser.strict_yes_no("Do you want to continue?"):
            local_critical("exiting due to user input...", support_hint=False)

    # Ensure we are in bootloader mode
    if client.is_solo_bootloader():
        local_print("Key already in bootloader mode, continuing...")
    else:
        try:
            local_print("Entering bootloader mode, please confirm with button on key!")
            client.enter_bootloader_or_die()
            time.sleep(0.5)
        except Exception as e:
            local_critical("problem switching to bootloader mode:", e)

    # reconnect and actually flash it...
    try:
        from pynitrokey.fido2 import find
        client = find(serial)
        client.use_hid()
        client.program_file(fw_fn)

    except Exception as e:
        local_critical("problem flashing firmware:", e)

    local_print(None, "After update check")
    tries = 100
    for i in range(tries):
        try:
            get_dev_details()
            break
        except Exception as e:
            if i > tries-1:
                local_critical("Could not connect to device after update", e)
                raise
            time.sleep(0.5)

    local_print("Congratulations, your key was updated to the latest firmware.")
    logger.debug("Finishing session {}".format(datetime.now()))
    local_print("Log saved to: {}".format(LOG_FN))





