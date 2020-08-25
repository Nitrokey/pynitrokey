# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import logging
import sys

from numbers import Number
from threading import Event, Timer
from typing import List

from pynitrokey.confconsts import LOG_FN, LOG_FORMAT, ISSUES_URL, VERBOSE, Verbosity

def to_websafe(data):
    data = data.replace("+", "-")
    data = data.replace("/", "_")
    data = data.replace("=", "")
    return data


def from_websafe(data):
    data = data.replace("-", "+")
    data = data.replace("_", "/")
    return data + "=="[: (3 * len(data)) % 4]


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


logging.basicConfig(format=LOG_FORMAT, level=logging.DEBUG, filename=LOG_FN)
logger = logging.getLogger()


def local_print(*messages, **kwargs):
    """
    Convenience logging function
    `messages`:   `str`         -> log single string
                  `Exception`   -> log exception
                  `list of ...` -> list of either `str` or `Exception` handle serialized
    """
    passed_exc = None

    for item in messages:
        # append exception print to last message
        if isinstance(item, Exception):
            logger.exception("EXCEPTION", exc_info=item)
            passed_exc = item

        # just a newline, don't log to file...
        elif item is None or item == "":
            item = ""

        # logfile debug output
        else:
            logger.debug(f"print: {item.strip()}")

        # to stdout
        print(item, **kwargs)

    # handle `passed_exc`: re-raise on debug verbosity!
    if VERBOSE == Verbosity.debug and passed_exc:
        raise passed_exc


def local_critical(*messages, support_hint=True, **kwargs):
    messages = ["ERROR:"] + list(messages)
    local_print(*messages, **kwargs)
    if support_hint:
        local_print("",
             "#" * 40,
             "Critical error occurred, exiting now",
             "Unexpected? Is this a bug? Do you would like to get support/help?",
             f"- You can report issues at: {ISSUES_URL}",
             f"- Please attach the log: '{LOG_FN}' with any support/help request!",
             "#" * 40, ""
        )
    sys.exit(1)


# @fixme: consider exchanging/wrapping click.confirm() instead of this...
class AskUser:
    """
    Asking user for input:
        `question`:     printed user question
        `options`:      `None`        -> we want some data input
                        `iter of str` -> only allow items inside iterable
        `title`:        additionally print this string before the question
        `strict`:       if `options` are used, force full match
        `repeat`:       ask questions up to `repeat` times if `options` and not matched
    """
    def __init__(self, question: str,
                 options: List[str]=None,
                 title: str=None,
                 strict: bool=False,
                 repeat: int=3):

        self.data = None

        self.question = question
        self.options = options
        self.title = title
        self.strict = strict
        self.repeat = repeat or 1

    @classmethod
    def yes_no(cls, what: str, title: str=None, strict: bool=False):
        opts = ["yes", "no"]
        return cls(what, options=opts, title=title, strict=strict).ask() == opts[0]

    @classmethod
    def strict_yes_no(cls, what: str, title: str=None):
        return cls.yes_no(what, title=title, strict=True)

    @classmethod
    def plain(cls, what, title=None):
        return cls(what, title=title).ask()

    def ask(self):
        if self.title:
            local_print(self.title)

        answer = input(self.question).strip()

        # handle plain input request first
        if not self.options:
            self.data = answer
            return self.data

        # now `options` based
        retries = self.repeat
        while retries:
            if self.strict:
                if answer in self.options:
                    self.data = answer
                    return self.data
            else:
                short_opts = {c[0].lower(): c for c in self.options}
                if len(answer) > 0:
                    self.data = short_opts.get(answer[0].lower())
                if self.data:
                    local_print(f"choosing: {self.data}")
                    return self.data

            answer = input(self.question).strip()
            retries -= 1

        if retries == 0:
            local_critical("max tries exceeded - exiting...")

        assert self.data is None, "expecting `self.data` to be None at this point!"
        return self.data
