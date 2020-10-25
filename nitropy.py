import sys

## Windows ensure libusb-1.0.dll is in PATH
#if sys.platform.startswith("win32"):
#    import usb
#    from pathlib import Path
#    usb_dll_path = Path(usb.__file__).parent / "backend"
#    import os
#    os.environ["PATH"] = os.environ["PATH"] + f";{usb_dll_path}"
#    #print (os.environ["PATH"])


from pynitrokey.cli import nitropy

nitropy()


