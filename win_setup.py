import pathlib
from cx_Freeze import setup, Executable

buildOptions = dict(packages = [], excludes = [])

msiOptions = dict(
    add_to_path = True,
    all_users = True
)

base = 'Console'

executables = [
    Executable('nitropy.py', base=base)
]

__version_path__ = pathlib.Path(__file__).parent.resolve().absolute() / "pynitrokey" / "VERSION"
__version__ = open(__version_path__).read().strip()

setup(name='pynitrokey',
      version = __version__,
      description = 'Nitrokey Python Tools',
      options = dict(build_exe = buildOptions,
                     bdist_msi = msiOptions),
      executables = executables)
