# -*- coding: utf-8 -*-
#
# Copyright 2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import re

from pynitrokey.updates import Asset, Release, Repository

REPOSITORY_OWNER = "Nitrokey"
REPOSITORY_NAME = "nitrokey-3-firmware"
REPOSITORY = Repository(owner=REPOSITORY_OWNER, name=REPOSITORY_NAME)
UPDATE_PATTERN = re.compile("\\.sb2$")


def get_firmware_update(release: Release) -> Asset:
    return release.require_asset(UPDATE_PATTERN)
