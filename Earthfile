VERSION 0.6
FROM ubuntu:latest
WORKDIR /workdir

build:
    ENV FLIT_ROOT_INSTALL=1
    RUN apt update && apt install python3 python3-dev make python3-pip python3.10-venv libpcsclite-dev swig  -qy
    RUN apt install libusb-1.0-0-dev  -qy
    RUN python3 -m pip install -U pip
    RUN python3 -m pip install -U flit
    RUN mkdir pynitrokey
    COPY pyproject.toml README.md .
    RUN python3 -m flit install --only-deps
    COPY . .
    RUN make clean
    RUN make init
    ENTRYPOINT ["/workdir/venv/bin/nitropy"]
    ENV ALLOW_ROOT=1
    ENV PATH /workdir/venv/bin:$PATH
    SAVE IMAGE pynitrokey:latest
