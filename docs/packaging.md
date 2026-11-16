<!--
Copyright Nitrokey GmbH
SPDX-License-Identifier: Apache-2.0 OR MIT
-->

# Packaging pynitrokey

When `pynitrokey` is packaged for a distribution or a package manager, the `nitropy` executable should always be included.
Optionally, the package can also provide `pynitrokey` as a Python library.

Shell completions for Bash, Zsh and Fish can be generated from the `nitropy` script:

```
$ _NITROPY_COMPLETE=bash_source nitropy > nitropy.bash
$ _NITROPY_COMPLETE=zsh_source nitropy > nitropy.zsh
$ _NITROPY_COMPLETE=fish_source nitropy > nitropy.fish
```

For more information, see the [click documentation](https://click.palletsprojects.com/en/8.1.x/shell-completion/).

Unfortunately, man pages for `nitropy` are currently not available and cannot be generated automatically.

## Optional dependencies

To limit the need to install pyscard, it is made optional.
If you make it an optional dependency of your package, please patch `pynitrokey/cli/nk3/pcsc_absent.py` to indicate users how they can install it.

## udev rules

Users need the appropriate permissions to be able to communicate with Nitrokey devices.
The easiest way to configure these permissions is through the udev rules provided in the [`nitrokey-udev-rules` repository](https://github.com/Nitrokey/nitrokey-udev-rules).
We recommend to provide these rules in a separate package and make the `pynitrokey` package depend on it.

> [!NOTE]
> `libnitrokey` also includes udev rules.
> These rules are no longer updated and don’t include the latest changes provided by `nitrokey-udev-rules`.
> We recommend to use `nitrokey-udev-rules` instead.
