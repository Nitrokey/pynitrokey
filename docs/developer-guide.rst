pynitrokey Developer Guide
==========================

Setting Up The Environment
--------------------------

Use ``make init`` to install ``pynitrokey``, its dependencies and the development tools inside a virtual environment in the ``venv`` folder.  This virtual environment is also used by other targets in the Makefile like ``make check``.  ``pynitrokey`` is installed in editable mode so that all changes to the source code also apply to the ``nitropy`` executable in the virtual environment.  If dependencies are changed, run ``make update-venv`` to update the virtual environment.


By default the development environment is isolated using venv, when set up using ``make init``. To run the ``nitropy`` from there call ``./venv/bin/nitropy``. This can be used as a shortcut ``make run ARGS="nk3 list"``, where ``ARGS`` is an optional argument to pass to ``nitropy``.


Containerized Environment
--------------------

Setting up a proper environment, matching the exact Python version, or having a newer one than it is supported, might be problematic for the development.
For such cases it is handy to have development/test environment containerized, so it does not affect nor need changes in the host OS internals.
For that Earthly tool is used, but any Docker-like tool will work.

The common targets are listed in the main Makefile with the ``e`` suffix:

- ``make builde`` - executes Earthly build process for the pynitrokey container image;
- ``make rune`` - runs Docker container based on the pynitrokey image for a quick tests. Use ``DOCKER=podman`` to call ``podman`` binary instead of the default Docker.

See https://earthly.dev/ for the Earthly setup instructions. Mind, that their binaries currently are not signed and cannot be verified, thus installation to the root directory of the host OS is not advised (on contrary to the claims on their main page). Use Dockerfile directly instead if in doubt.


Linters
-------

We use `flake8`_ for style checks, `black`_ for code formatting, `isort`_ for import sorting and `mypy`_ for static type analysis.  To run all checks, execute ``make check``. Before using it for the first time, you have to call ``make init`` to setup a virtual environment and install the required dependencies.

.. _flake8: https://flake8.pycqa.org/en/latest/
.. _black: https://github.com/psf/black
.. _isort: https://github.com/PyCQA/isort
.. _mypy: https://github.com/python/mypy

mypy is configured to only check annotated code.  If you add new code, please consider adding type annotations and enabling strict checks for your modules in ``pyproject.toml``.

Please make sure that all checks pass for your code before opening a PR.

Signed Commits
--------------

If you have an OpenPGP key, please sign all your commits with it.  We require all commits on the master branch to be signed.  If you don’t have an OpenPGP key, a developer that reviewed your commits will sign them for you.

Supported Python Versions
-------------------------

The current minimum required Python version is documented in the readme.  Make sure that your code works with this Python version.  The minimum required Python version is selected to be compatible with the latest Ubuntu LTS and regular releases and with the latest Debian stable release. If there has not been a point release for the latest Ubuntu LTS release yet, we also support the second-latest Ubuntu LTS release. Raising the required Python version requires adapting the CI to this new minimum too.

Commit Hooks
--------------

For local quick checks of the formatting you can use `pre-commit`_.

.. _pre-commit: https://pre-commit.com/

Setup::

   $ pip install pre-commit -U
   $ pre-commit install

Usage:

- https://pre-commit.com/#usage

Checks configured in ``.pre-commit-config.yaml`` will be executed before each commit, and on-demand when calling ``pre-commit`` from the command line.


Design Patterns
---------------

Output and Error Handling
~~~~~~~~~~~~~~~~~~~~~~~~~

Use ``pynitrokey.helpers.local_print`` for printing messages to the user.  This helper method also adds the output to the log file.

To report an error, use ``pynitrokey.helpers.local_critical`` or raise a ``pynitrokey.cli.exceptions.CliException`` (that uses ``local_critical`` internally).  Per default, this adds a support hint to the output that points the user to the log file.

Password Input
~~~~~~~~~~~~~~

Commands that require a password should first try to read the password from an environment variable.  If the environment variable is not set, they should prompt the user to enter the password.  Passwords must not be passed as a command-line argument.
