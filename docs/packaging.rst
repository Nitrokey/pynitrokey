Packaging pynitrokey
====================

When ``pynitrokey`` is packaged for a distribution or a package manager, we recommend that the package provides both the ``pynitrokey`` Python library and the ``nitropy`` executable.
Alternatively, the Python library can be packaged as ``pynitrokey`` and the executable as ``nitropy``.
(Note that we consider splitting ``pynitrokey`` into a library and an executable in a future release.)

Shell completions for Bash, Zsh and Fish can be generated from the ``nitropy`` script::

    $ _NITROPY_COMPLETE=bash_source nitropy > nitropy.bash
    $ _NITROPY_COMPLETE=zsh_source nitropy > nitropy.zsh
    $ _NITROPY_COMPLETE=fish_source nitropy > nitropy.fish

For more information, see the `click documentation`_.

.. _click documentation: https://click.palletsprojects.com/en/8.1.x/shell-completion/

Unfortunately, man pages for ``nitropy`` are currently not available and cannot be generated automatically.

Optional dependencies
--------------------

To limit the need to install pyscard, it is made optional.
If you make it an optional dependency of your package, please patch ``pynitrokey/cli/nk3/pcsc_absent.py`` to indicate users how they can install it.
