VERSION 0.6
FROM ubuntu:latest
WORKDIR /workdir

build:
    ENV FLIT_ROOT_INSTALL=1
    RUN apt update && apt install python3 python3-dev make python3-pip python3.10-venv libpcsclite-dev swig  -qy
    RUN apt install libusb-1.0-0-dev  -qy
    RUN python3 -m pip install -U pip
    RUN python3 -m pip install -U flit pyusb cffi ecdsa intelhex nkdfu python-dateutil requests tqdm urllib3 tlv8
    RUN python3 -m pip install -U "nrfutil >=6.1.4,<7"
    RUN python3 -m pip install -U "spsdk >=1.7.0,<1.8.0"
    RUN python3 -m pip install -U  "cryptography >=3.4.4,<37"


    # COPY Makefile pynitrokey/ pyproject.toml README.md .
    COPY . .
    RUN make clean
    RUN make init
    ENTRYPOINT ["/workdir/venv/bin/nitropy"]
    ENV ALLOW_ROOT=1
    ENV PATH /workdir/venv/bin:$PATH
    SAVE IMAGE pynitrokey:latest
