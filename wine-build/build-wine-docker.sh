#!/bin/bash

set -x

pwd=$(pwd)

export WINEPREFIX=${pwd}/wine_base
#export WINEARCH=win32

PY_VERSION=3.6.8
PY_BASE_URL=https://www.python.org/ftp/python/${PY_VERSION}/win32
PY_DIR=python${PY_VERSION}
PY_WINE_HOME=c:/${PY_DIR}
PY_HOME=${WINEPREFIX}/drive_c/${PY_DIR}

WINE_BUILD_DIR=${WINEPREFIX}/drive_c/build
CACHE_DIR=${WINE_BUILD_DIR}/cache

PYNITROKEY_DIR=${WINE_BUILD_DIR}/pynitrokey
PYNITROKEY_VERSION=$(cat ${PYNITROKEY_DIR}/pynitrokey/VERSION)


BIN_LIBUSB=${CACHE_DIR}/libusb/libusb.git/libusb/.libs/libusb-1.0.dll
LIBUSB=${WINE_BUILD_DIR}/libusb-1.0.dll

#BIN_PYBOOTLOADER=${CACHE_DIR}/SomberNight/pyinstaller.git/PyInstaller/bootloader/Windows-64bit/run.exe
#PYBOOTLOADER=${WINE_BUILD_DIR}/run.exe


cat ${PYNITROKEY_DIR}/wine-build/nitropy.spec.tmpl | \
	sed -e "s/%%PYTHON_VERSION%%/${PY_VERSION}/g" | \
	sed -e "s/%%PYNITROKEY_VERSION%%/${PYNITROKEY_VERSION}/g" \
	> ${PYNITROKEY_DIR}/wine-build/nitropy.spec


export WINEPREFIX

function py
{
	#WINEDEBUG=+all wine ${PY_WINE_HOME}/python.exe -O -B "$@"
	wine ${PY_WINE_HOME}/python.exe -O -B "$@"
}


# boot wineprefix
mkdir -p ${CACHE_DIR} ${WINE_BUILD_DIR} ${WINEPREFIX}
#WINEPREFIX=${pwd}/${WINEPREFIX} wineboot

#WINEDEBUG=+all wineboot
wineboot


# wine python install 
for msi_part in core dev exe lib pip tools; do 
	wget ${PY_BASE_URL}/${msi_part}.msi
	#WINEDEBUG=+all msiexec /i ${msi_part}.msi /qb TARGETDIR=${PY_WINE_HOME}
	msiexec /i ${msi_part}.msi /qb TARGETDIR=${PY_WINE_HOME}
done

for repo in SomberNight/pyinstaller libusb/libusb; do
    git clone https://github.com/${repo}.git $(basename ${repo})
done

#### @fixme: obsolete?
#pushd ${CACHE_DIR}/libusb/libusb
#echo "libusb_1_0_la_LDFLAGS += -Wc,-static" >> libusb/Makefile.am
#./bootstrap.sh
#./configure --host=i686-w64-mingw32 --build=x86_64-pc-linux-gnu
#make -j4 \
#cp ${BIN_LIBUSB} ${LIBUSB}
#popd


# install pyinstaller
pushd pyinstaller
git reset --hard
git checkout develop
py -m pip install .
popd

# install usb stuff for win32
py -m pip install pyusb libusb 

# ok let's hack the right libusb version into it...
#mkdir libusb-1.0.24
#pushd libusb-1.0.24
#wget https://github.com/libusb/libusb/releases/download/v1.0.24/libusb-1.0.24.7z
#7z x libusb-1.0.24.7z
#cp VS2019/MS32/dll/libusb-1.0.dll ${PY_HOME}/Lib/site-packages/libusb/_platform/_windows/x86/libusb-1.0.dll
#popd


# now actually run pynitrokey build(s)
pushd ${WINE_BUILD_DIR}/pynitrokey

# upgrade pip to enable 'cryptography' install
py -m pip install -U pip
py -m pip install cryptography

# @fixme: obsolete?!
#cp /build/${LIBUSB} /build/${PY_HOME}/Lib/site-packages/usb/backend/

# install all requirements using pip
py -m pip install --no-warn-script-location -r dev-requirements.txt 
py -m pip install --no-warn-script-location -r ci-requirements.txt

# install pynitrokey 
py -m flit install 

# build msi
py win_setup.py bdist_msi 
cp wine-build/nitropy.spec .

# build single-exe
py -m PyInstaller --noconfirm --clean --name nitropy-${PYNITROKEY_VERSION} --onefile nitropy.spec

cp dist/pynitrokey-${PYNITROKEY_VERSION}-win32.msi /build/wine_base/drive_c/build
cp dist/pynitrokey-${PYNITROKEY_VERSION}-win32.msi /build/wine_base/drive_c/build/pynitrokey.msi 
cp dist/nitropy-${PYNITROKEY_VERSION}.exe /build/wine_base/drive_c/build


popd


