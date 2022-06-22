# pynitrokey

A command line interface for the Nitrokey FIDO2, Nitrokey Start, Nitrokey 3 and NetHSM.

## Quickstart

```
$ pipx install pynitrokey
$ nitropy --help
```

## Documentation

The user documentation for the `nitropy` CLI is available on [docs.nitrokey.com](https://docs.nitrokey.com/software/nitropy/index.html). See also the product documentation for more information on the available commands:
- [Nitrokey 3](https://docs.nitrokey.com/nitrokey3/index.html)
- [Nitrokey FIDO2](https://docs.nitrokey.com/fido2/index.html)
- [Nitrokey Start](https://docs.nitrokey.com/start/index.html)
- [NetHSM](https://docs.nitrokey.com/nethsm/index.html)

### Switching Nitrokey Start identities

#### Alternative MI switching method

<details>

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
</details>

## Compatibility

`nitropy` requires Python 3.9 or later.

## Development

Information for developers and contributors can be found in the [Developer Guide](./docs/developer-guide.rst).

## Maintainers

Current maintainers can be found in [MAINTAINERS.md](MAINTAINERS.md) file.

## License

Licensed similarly to upstream, under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
