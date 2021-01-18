pwd=$(pwd)


export WINEPREFIX=${pwd}/wine_base

PY_VERSION=3.7.7
PY_BASE_URL=https://www.python.org/ftp/python/${PY_VERSION}/win32
PY_DIR=python${PY_VERSION}
PY_WINE_HOME=c:/${PY_DIR}
PY_HOME=${WINEPREFIX}/drive_c/${PY_DIR}



WINE_BUILD_DIR=${WINEPREFIX}/drive_c/build
CACHE_DIR=${WINE_BUILD_DIR}/cache

BIN_LIBUSB=${CACHE_DIR}/libusb/libusb.git/libusb/.libs/libusb-1.0.dll
LIBUSB=${WINE_BUILD_DIR}/libusb-1.0.dll

#BIN_PYBOOTLOADER=${CACHE_DIR}/SomberNight/pyinstaller.git/PyInstaller/bootloader/Windows-64bit/run.exe
#PYBOOTLOADER=${WINE_BUILD_DIR}/run.exe

#PYNK_DIR=${CACHE_DIR}/Nitrokey/pynitrokey.git
#PYNK_MSI=${WINE_BUILD_DIR}/pynitrokey.msi
#PYNK_EXE=${WINE_BUILD_DIR}/nitropy.exe

export WINEPREFIX

function py
{
	wine ${PY_WINE_HOME}/python.exe -O -B "$@"
}


# boot wineprefix
mkdir -p ${CACHE_DIR} ${WINE_BUILD_DIR} ${WINEPREFIX}
WINEPREFIX=${pwd}/${WINEPREFIX} wineboot

# wine python install 
for msi_part in core dev exe lib pip tools; do 
	wget ${PY_BASE_URL}/${msi_part}.msi
	#mv ${msi_path}.msi ${CACHE_DIR}
	wine msiexec /i ${msi_part}.msi /qb TARGETDIR=${PY_WINE_HOME}
done


for repo in SomberNight/pyinstaller libusb/libusb; do
    git clone https://github.com/${repo}.git $(basename ${repo})
done

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

pushd ${WINE_BUILD_DIR}/pynitrokey

cp /build/${LIBUSB} /build/${PY_HOME}/Lib/site-packages/usb/backend/
py -m pip install --no-warn-script-location -r dev-requirements.txt 
py -m pip install --no-warn-script-location -r ci-requirements.txt
py -m flit install 
py win_setup.py bdist_msi 
cp wine-build/nitropy.spec .
py -m PyInstaller --noconfirm --clean --name nitropy-0.4.1 --onefile nitropy.spec

cp dist/pynitrokey-*-win32.msi /build/wine_base/drive_c/build
cp dist/pynitrokey-*-win32.msi /build/wine_base/drive_c/build/pynitrokey.msi 
cp dist/nitropy-0.4.1.exe /build/wine_base/drive_c/build


popd


