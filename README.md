# pynitrokey

A command line interface for the Nitrokey FIDO2, Nitrokey Start and NetHSM.

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

## Maintainers

Current maintainers can be found in [MAINTAINERS.MD](MAINTAINERS.MD) file.

## License

Licensed similarly to upstream, under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
