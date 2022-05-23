# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import functools
import logging
import os
import platform
import sys
import time
from getpass import getpass
from numbers import Number
from threading import Event, Timer
from typing import List, Optional

import click
from tqdm import tqdm

from pynitrokey.confconsts import (
    LOG_FN,
    SUPPORT_EMAIL,
    SUPPORT_URL,
    UDEV_URL,
    VERBOSE,
    Verbosity,
)

STDOUT_PRINT = True


def to_websafe(data):
    data = data.replace("+", "-")
    data = data.replace("/", "_")
    data = data.replace("=", "")
    return data


def from_websafe(data):
    data = data.replace("-", "+")
    data = data.replace("_", "/")
    return data + "=="[: (3 * len(data)) % 4]


class ProgressBar:
    """
    Helper class for progress bars where the total length of the progress bar
    is not available before the first iteration.
    """

    def __init__(self, **kwargs) -> None:
        self.bar: Optional[tqdm] = None
        self.kwargs = kwargs
        self.sum = 0

    def __enter__(self) -> "ProgressBar":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
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

    def __init__(self, time_or_event):
        if isinstance(time_or_event, Number):
            self.event = Event()
            self.timer = Timer(time_or_event, self.event.set)
        else:
            self.event = time_or_event
            self.timer = None

    def __enter__(self):
        if self.timer:
            self.timer.start()
        return self.event

    def __exit__(self, exc_type, exc_val, exc_tb):
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
def local_print(*messages, **kwargs):
    """
    application-wide logging function
    `messages`:   `str`         -> log single string
                  `Exception`   -> log exception
                  `list of ...` -> list of either `str` or `Exception` handle serialized
    """
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


def local_critical(*messages, support_hint=True, ret_code=1, **kwargs):
    global STDOUT_PRINT
    messages = ["Critical error:"] + list(messages)
    local_print(*messages, **kwargs)
    if support_hint:

        # list all connected devices to logfile
        # @fixme: not the best solution
        STDOUT_PRINT = False
        local_print("listing all connected devices:")

        try:
            from pynitrokey.cli import nitropy

            nitropy.commands["list"].callback()
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
            f"- Please check if you have udev rules installed: {UDEV_URL}"
            if linux
            else "" "-" * 80,
            "",
        )
    sys.exit(ret_code)


# @fixme: consider using/wrapping click.confirm() instead of this...
class AskUser:
    """
    Asking user for input:
        `question`:       printed user question
        `options`:        `None`        -> we want some data input
                          `iter of str` -> only allow items inside iterable
        `strict`:         if `options` are used, force full match
        `repeat`:         ask `question` up to `repeat` times, if `options` are provided
        `adapt_question`: adapt user-provided `question` (add options, whitespace...),
                          set to `False`, if strictly `question` shall be used
        `hide_input`:     use 'getpass' instead of regular `input`
    """

    def __init__(
        self,
        question: str,
        options: List[str] = None,
        strict: bool = False,
        repeat: int = 3,
        adapt_question=True,
        hide_input=False,
        envvar: str = None,
    ):

        self.data = None

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
    def yes_no(cls, what: str, strict: bool = False):
        opts = ["yes", "no"]
        return cls(what, options=opts, strict=strict).ask() == opts[0]

    @classmethod
    def strict_yes_no(cls, what: str):
        return cls.yes_no(what, strict=True)

    @classmethod
    def plain(cls, what):
        return cls(what).ask()

    @classmethod
    def hidden(cls, what):
        return cls(what, hide_input=True).ask()

    def get_input(self, pre_str=None, hide_input=None):
        pre_input_string = pre_str or self.final_question
        hide_input = hide_input if hide_input is not None else self.hide_input
        if hide_input:
            return getpass(pre_input_string)
        else:
            print(pre_input_string, end="", file=sys.stderr)
            return input(pre_input_string).strip()

    def ask(self):
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
        return self.data


confirm = functools.partial(click.confirm, err=True)
prompt = functools.partial(click.prompt, err=True)
