<!--
Copyright Nitrokey GmbH
SPDX-License-Identifier: Apache-2.0 OR MIT
-->

# Release Process
1. Bump version in `pyproject.toml`. Use `0.x.y` format.
2. Create a release in the Github UI with the tag in format `v0.x.y`. The CD pipeline will run automatically on a new release.
3. Wait for the deployment action to run and approve the deployment to [PyPI](https://pypi.org/p/pynitrokey).
