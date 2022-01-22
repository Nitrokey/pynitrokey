# pynitrokey

A command line interface for the Nitrokey FIDO2, Nitrokey Start, Nitrokey 3 and NetHSM.

## Current state
Update to the latest firmware versions on the Nitrokey Start and Nitrokey FIDO2 devices was tested. Windows support for Nitrokey Start is not added yet.

Additional features:
- handle `status` command for displaying touch button status (2.0.0 firmware and later);
- firmware signing adjusted for Nitrokey FIDO2 bootloader
- monitor command with timestamps

## Installation

### Linux, Unix

```bash
sudo apt install python3-pip
pip3 install --user pynitrokey
```

If you want to use the `nk3` command for accessing Nitrokey 3 devices, you also have to install the `nk3` extra:

```
pip3 install --user pynitrokey[nk3]
```

To access Nitrokey Start, FIDO2 and Nitrokey 3 devices without superuser rights, you need to install the Nitrokey udev rules that are shipped with `libnitrokey`.  You can also install them manually:

```
wget https://raw.githubusercontent.com/Nitrokey/libnitrokey/master/data/41-nitrokey.rules
sudo mv 41-nitrokey.rules /etc/udev/rules.d/
```

### Windows
*Generally Windows support and the installer are experimental - please use with caution.*

Known issues:
* Support for Nitrokey Start under Windows 10 is not working without installing libusb libraries (to be described).
* The installer does not remove a previous installation (manually remove it using `settings -> programs and apps`)

How to install:
1. Download the latest `.msi` installer from [releases](https://github.com/Nitrokey/pynitrokey/releases/)
1. Double-click the installer and click through (`Next` and `Finish`)
1. Open the command console in the administrator mode (Windows 10: press the right mouse button on the Menu Start and select "Windows PowerShell (Admin)" from the menu).
1. Enter `nitropy`

Without administrator privileges `nitropy` might not be able to communicate to device.

### MacOS

*To install nitropy on MacOS*
```
pip3 install pynitrokey
```

If you want to use the `nk3` command for accessing Nitrokey 3 devices, you also have to install the `nk3` extra:

```
pip3 install pynitrokey[nk3]
```

1. Without `penv`: `nitropy` can be found here: `/usr/local/bin/nitropy`
2. With `penv`: `/Users/[USER_NAME]/.pyenv/versions/[PYENV_NAME]/bin/nitropy`

Make sure you have libnitrokey installed to connect *Nitrokey Pro* and *Nitrokey Storage* devices.


## Nitrokey FIDO2
### Firmware Update
Automatic firmware update is recommended via https://update.nitrokey.com. Alternatively, it is also possible to update the Nitrokey FIDO2 using:
```bash
nitropy fido2 update
```

Your Nitrokey FIDO2 is now updated to the latest firmware.

## Nitrokey Start
### Firmware Update

Verify device connection

```bash
nitropy start list
FSIJ-1.2.15-87042524: Nitrokey Nitrokey Start (RTM.10)
```
Start update process, logs saved to upgrade.log, handy in case of failure

```bash
nitropy start update
```

Does not ask for confirmation nor the default Admin PIN, handy for batch calls
```
nitropy start update -p 12345678 -y
```

Following will flash files from the local disk, instead of downloading them
```
nitropy start update --regnual $(FIRMWARE_DIR)/regnual.bin --gnuk ${FIRMWARE_DIR}/gnuk.bin
```

### Switching ID

```
nitropy start set-identity [0,1,2]
```

Where 0, 1 and 2 are the available IDs.

#### Alternative MI switching method

`pynitrokey` installation is not always possible, hence describing below alternative method to change the Identity on the Nitrokey Start. It suffices to have any CCID application installed, and send the following APDU `00 85 00 {ID}` (hex), where `ID` is in range `[0;2]`. After receiving this command Nitrokey Start will reboot with the selected identity.

Here is how to do it using GnuPG:
```text
# Setting ID to 2
$ gpg-connect-agent --hex "scd apdu  00 85 00 02" /bye
ERR 65539 Unknown version in packet <Unspecified source>

# Alternative error messsage
ERR 65572 Bad certificate <Unspecified source>
```

The error message here is expected due to immediate reboot of the device, and with losing the connection.

When the ID change is attempted to be done immediately, the following response could be received:
```
ERR 100663406 Card removed <SCD>
```
To restore the communication, either kill the `gpg-agent` or run `gpg --card-status` again.

Tip: alternative `gpg-connect-agent reloadagent /bye` is not sufficient.

## NetHSM

A guide on how to use `nitropy` to access a NetHSM is available on
[docs.nitrokey.com](https://docs.nitrokey.com/nethsm/cli.html).

## Nitrokey 3

A guide on how to use `nitropy` with Nitrokey 3 device is available on [docs.nitrokey.com](https://docs.nitrokey.com/nitrokey3/linux/nitropy.html).

## Maintainers

Current maintainers can be found in [MAINTAINERS.md](MAINTAINERS.md) file.

## License

Licensed similarly to upstream, under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
