# Copyright 2019 SoloKeys Developers
# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import ctypes
import functools
import logging
import os
import platform
import sys
import time
from collections.abc import Sequence
from getpass import getpass
from importlib.metadata import version
from itertools import chain
from threading import Event, Timer
from typing import Any, Callable, List, Optional, Tuple, TypeVar, Union

import click
from nitrokey.updates import Repository
from semver.version import Version
from tqdm import tqdm

from pynitrokey.confconsts import (
    CLI_LOG_BLACKLIST,
    LOG_FN,
    SUPPORT_EMAIL,
    SUPPORT_URL,
    UDEV_URL,
    VERBOSE,
    Verbosity,
)

STDOUT_PRINT = True


def normalize_parameters(s: str) -> list[str]:
    """Helper function to normalize different writing of parameters

    `s`: `str` parameter to normalize

    Returns:
        `list of str`: normalized form of `parameter`
    """
    if s.startswith("--"):
        return s.split("=", maxsplit=1)
    else:
        return [s]


def filter_sensitive_parameters(parameters: list[str]) -> list[str]:
    """Helper function to remove sensitive parameters

    `parameters`: `list of str`

    Returns:
        `list of str`: `parameters` without sensitive values listed
                       in `pynitrokey.confconsts.CLI_LOG_BLACKLIST`
    """
    parameters = list(
        chain.from_iterable(
            [normalize_parameters(parameter) for parameter in parameters]
        )
    )

    redact_count = 0
    for i in range(len(parameters)):
        if redact_count > 0:
            parameters[i] = "[redacted]"
            redact_count -= 1
        elif parameters[i] in CLI_LOG_BLACKLIST:
            redact_count = CLI_LOG_BLACKLIST[parameters[i]]
    return parameters


def to_websafe(data: str) -> str:
    data = data.replace("+", "-")
    data = data.replace("/", "_")
    data = data.replace("=", "")
    return data


def from_websafe(data: str) -> str:
    data = data.replace("-", "+")
    data = data.replace("_", "/")
    return data + "=="[: (3 * len(data)) % 4]


def b32padding(data: str) -> str:
    """Helper function to pad base32 strings correctly, as some services
    provide OTP secrets as base32 strings without the necessary padding

    `s`: `str` base32 input string

    Returns:
        `str`: string padded to full base32 character blocks

    >>> b32padding("")
    ''
    >>> b32padding("AA")
    'AA======'
    >>> b32padding("AAAA")
    'AAAA===='
    >>> b32padding("AAAAA")
    'AAAAA==='
    >>> b32padding("AAAAAAA")
    'AAAAAAA='
    >>> b32padding("AAAAAAAA")
    'AAAAAAAA'
    >>> b32padding("AAAAAAAABB")
    'AAAAAAAABB======'
    """
    padding_needed = -len(data) % 8
    return data + (padding_needed * "=")


class Table:
    def __init__(self, headers: Sequence[str]) -> None:
        self._headers = headers
        self._rows: list[list[str]] = []
        self._widths = [len(header) for header in headers]

    def add_row(self, row: Sequence[Any]) -> None:
        assert len(row) == len(self._headers)
        str_row = []
        for i, item in enumerate(row):
            s = str(item)
            self._widths[i] = max(self._widths[i], len(s))
            str_row.append(s)
        self._rows.append(str_row)

    def __str__(self) -> str:
        def format_row(items: Sequence[str]) -> str:
            row = [item.ljust(width) for (item, width) in zip(items, self._widths)]
            return "\t".join(row)

        lines = []
        lines.append(format_row(self._headers))
        lines.append(format_row(["-" * width for width in self._widths]))
        for row in self._rows:
            lines.append(format_row(row))
        return "\n".join(lines)


class ProgressBar:
    """
    Helper class for progress bars where the total length of the progress bar
    is not available before the first iteration.
    """

    def __init__(self, **kwargs: Any) -> None:
        self.bar: Optional[tqdm[Any]] = None
        self.kwargs = kwargs
        self.sum = 0

    def __enter__(self) -> "ProgressBar":
        return self

    def __exit__(self, exc_type: None, exc_val: None, exc_tb: None) -> None:
        self.close()

    def update(self, n: int, total: int) -> None:
        if not self.bar:
            self.bar = tqdm(total=total, **self.kwargs)
        self.bar.update(n)
        self.sum += n

    def update_sum(self, n: int, total: int) -> None:
        if not self.bar:
            self.bar = tqdm(total=total, **self.kwargs)
        if n > self.sum:
            self.bar.update(n - self.sum)
            self.sum = n

    def close(self) -> None:
        if self.bar:
            self.bar.close()


class DownloadProgressBar(ProgressBar):
    """
    Helper class for progress bars for downloading a file.
    """

    def __init__(self, desc: str) -> None:
        super().__init__(desc=f"Download {desc}", unit="B", unit_scale=True)


class Timeout(object):
    """
    Utility class for adding a timeout to an event.
    :param time_or_event: A number, in seconds, or a threading.Event object.
    :ivar event: The Event associated with the Timeout.
    :ivar timer: The Timer associated with the Timeout, if any.
    """

    def __init__(self, time_or_event: Union[float, Event]) -> None:
        if isinstance(time_or_event, float):
            self.event = Event()
            self.timer: Optional[Timer] = Timer(float(time_or_event), self.event.set)
        else:
            self.event = time_or_event
            self.timer = None

    def __enter__(self) -> Event:
        if self.timer:
            self.timer.start()
        return self.event

    def __exit__(self, exc_type: None, exc_val: None, exc_tb: None) -> None:
        if self.timer:
            self.timer.join()
            self.timer.cancel()


class Try:
    """Utility class for an execution of a repeated action with Retries."""

    def __init__(self, i: int, retries: int) -> None:
        self.i = i
        self.retries = retries

    def __str__(self) -> str:
        return f"try {self.i + 1} of {self.retries}"

    def __repr__(self) -> str:
        return f"Try(i={self.i}, retries={self.retries})"


class Retries:
    """Utility class for repeating an action multiple times until it succeeds."""

    def __init__(self, retries: int, timeout: float = 0.5) -> None:
        self.retries = retries
        self.i = 0
        self.timeout = timeout

    def __iter__(self) -> "Retries":
        return self

    def __next__(self) -> Try:
        if self.i >= self.retries:
            raise StopIteration
        if self.i > 0:
            time.sleep(self.timeout)
        t = Try(self.i, self.retries)
        self.i += 1
        return t


# @todo: introduce granularization: dbg, info, err (warn?)
#        + machine-readable
#        + logfile-only (partly solved)
def local_print(*messages: Any, **kwargs: Any) -> None:
    """Application-wide logging function"""

    passed_exc = None
    logger = logging.getLogger()

    for item in messages:
        # handle exception in order as, if it is a regular message
        if isinstance(item, Exception):
            logger.exception(item)
            passed_exc = item
            item = repr(item)
            item = "\tException encountered: " + item

        # just a newline, don't log to file...
        elif item is None or item == "":
            item = ""

        # logfile debug output
        else:
            whereto = "print: " if STDOUT_PRINT else ""
            logger.debug(f"{whereto}{str(item).strip()}")

        # to stdout
        if STDOUT_PRINT:
            print(item, **kwargs)

    # handle `passed_exc`: re-raise on debug verbosity!
    if VERBOSE == Verbosity.debug and passed_exc:
        raise passed_exc


def local_critical(
    *messages: Any, support_hint: bool = True, ret_code: int = 1, **kwargs: Any
) -> None:

    global STDOUT_PRINT
    messages = ("Critical error:",) + tuple(messages)
    local_print(*messages, **kwargs)

    if support_hint:

        # list all connected devices to logfile
        # @fixme: not the best solution
        STDOUT_PRINT = False
        local_print("listing all connected devices:")

        try:
            from pynitrokey.cli import nitropy

            nitropy.commands["list"].callback()  # type: ignore

        except Exception:
            local_print("Unable to list devices. See log for the details.")
            logger = logging.getLogger()
            logger.exception("Unable to list devices")

        STDOUT_PRINT = True

        linux = "linux" in platform.platform().lower()
        local_print(
            "",
            "-" * 80,
            "Critical error occurred, exiting now",
            "Unexpected? Is this a bug? Would you like to get support/help?",
            f"- You can report issues at: {SUPPORT_URL}",
            f"- Writing an e-mail to {SUPPORT_EMAIL} is also possible",
            f"- Please attach the log: '{LOG_FN}' with any support/help request!",
            (
                f"- Please check if you have udev rules installed: {UDEV_URL}"
                if linux
                else "" "-" * 80
            ),
            "",
        )
    sys.exit(ret_code)


# @fixme: consider using/wrapping click.confirm() instead of this...
class AskUser:
    """
    Asking user for input:
        `question`:       printed user question
        `options`:        `[]`        -> we want some data input
                          `List[str]` -> only allow items inside iterable
        `strict`:         if `options` are used, force full match
        `repeat`:         ask `question` up to `repeat` times, if `options` are provided
        `adapt_question`: adapt user-provided `question` (add options, whitespace...),
                          set to `False`, if strictly `question` shall be used
        `hide_input`:     use 'getpass' instead of regular `input`
    """

    def __init__(
        self,
        question: str,
        options: List[str] = [],
        strict: bool = False,
        repeat: int = 3,
        adapt_question: bool = True,
        hide_input: bool = False,
        envvar: Optional[str] = None,
    ) -> None:

        self.data: Optional[str] = None

        self.question = question
        self.adapt_question = adapt_question
        self.final_question = question
        if self.adapt_question:
            _q = self.final_question
            # strip ending colon(s) ':' or whitespace(s) ' '
            _q = _q.strip(" ").strip(":").strip(" ").strip(":")
            if options:
                _q += (
                    f" [{'/'.join(options)}]"
                    if strict
                    else f" [{'/'.join(f'({o[0]}){o[1:]}' for o in options)}]"
                )
            _q += ": "
            self.final_question = _q

        self.options = options
        self.strict = strict
        self.repeat = repeat or 1
        self.hide_input = hide_input
        self.envvar = envvar

    @classmethod
    def yes_no(cls, what: str, strict: bool = False) -> bool:
        opts = ["yes", "no"]
        return cls(what, options=opts, strict=strict).ask() == opts[0]

    @classmethod
    def strict_yes_no(cls, what: str) -> bool:
        return cls.yes_no(what, strict=True)

    @classmethod
    def plain(cls, what: str) -> str:
        return cls(what).ask()

    @classmethod
    def hidden(cls, what: str) -> str:
        return cls(what, hide_input=True).ask()

    def get_input(
        self,
        pre_str: Optional[str] = None,
        hide_input: Optional[Union[str, bool]] = None,
    ) -> str:
        pre_input_string = pre_str or self.final_question
        hide_input = hide_input if hide_input is not None else self.hide_input
        if hide_input:
            return getpass(pre_input_string)
        else:
            print(pre_input_string, end="", file=sys.stderr)
            return input().strip()

    def ask(self) -> str:
        answer = None
        if self.envvar is not None:
            fromvar = os.environ.get(self.envvar)
            if fromvar is not None:
                answer = fromvar

        if answer is None:
            answer = self.get_input()

        # handle plain input request first
        if not self.options:
            self.data = answer
            return self.data

        # now `options` based
        retries = self.repeat
        while retries:
            if answer in self.options:
                self.data = answer
                return self.data

            if not self.strict:
                short_opts = {c[0].lower(): c for c in self.options}
                if len(answer) > 0:
                    self.data = short_opts.get(answer[0].lower())

                if self.data:
                    local_print(f"choosing: {self.data}")
                    return self.data

            answer = self.get_input()
            retries -= 1

        if retries == 0:
            local_critical("max tries exceeded - exiting...")

        assert self.data is None, "expecting `self.data` to be None at this point!"
        return self.data or ""


confirm = functools.partial(click.confirm, err=True)
prompt = functools.partial(click.prompt, err=True)


def require_windows_admin() -> None:
    if os.name == "nt":
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:  # type: ignore
            local_print(
                "Warning: It is recommended to execute nitropy with admin privileges "
                "to be able to access Nitrokey 3 and Nitrokey FIDO 2 devices."
            )


def check_pynitrokey_version() -> None:
    """Checks wether the used pynitrokey version is the latest available version and warns the user if the used version is outdated"""

    latest_release = Repository("Nitrokey", "pynitrokey").get_latest_release()
    latest_version = Version.parse(latest_release.tag[1:])

    current_version = Version.parse(version("pynitrokey"))

    if current_version < latest_version:
        local_print(
            f"You are using an outdated version ({current_version}) of pynitrokey."
        )
        local_print(f"Latest pynitrokey version is {latest_version}")
        local_print("Updating with an outdated version is discouraged.")

        if not confirm("Do you still want to continue?", default=False):
            raise click.Abort()


def check_experimental_flag(experimental: bool) -> None:
    """Helper function to show common warning for the experimental features"""
    if not experimental:
        local_print(" ")
        local_print(
            "This feature is experimental, which means it was not tested thoroughly.\n"
            "Note: data stored with it can be lost in the next firmware update.\n"
            "Please pass --experimental switch to force running it anyway."
        )
        local_print(" ")
        raise click.Abort()
