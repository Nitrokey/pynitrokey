pwd=$(shell pwd)
WINEPREFIX=wine_base
WINE=WINEPREFIX=$(pwd)/$(WINEPREFIX) wine

PY_VERSION=3.7.7
PY_BASE_URL=https://www.python.org/ftp/python/$(PY_VERSION)/win32
PY_DIR=python$(PY_VERSION)
PY_WINE_HOME=c:/$(PY_DIR)
PY_HOME=$(WINEPREFIX)/drive_c/$(PY_DIR)
PY=$(WINE) $(PY_WINE_HOME)/python.exe -O -B


WINE_BUILD_DIR=$(WINEPREFIX)/drive_c/build
CACHE_DIR=$(WINE_BUILD_DIR)/cache
WORKDIRS=$(WINEPREFIX) $(CACHE_DIR) $(WINE_BUILD_DIR)

PY_PARTS=core dev exe lib pip tools
PY_PARTS_PATHS=$(addsuffix .msi,$(addprefix $(CACHE_DIR)/,$(PY_PARTS)))

REPOS=SomberNight/pyinstaller Nitrokey/pynitrokey libusb/libusb
REPO_PATHS=$(addsuffix .git,$(addprefix $(CACHE_DIR)/,$(REPOS)))

BIN_LIBUSB=$(CACHE_DIR)/libusb/libusb.git/libusb/.libs/libusb-1.0.dll
LIBUSB=$(WINE_BUILD_DIR)/libusb-1.0.dll

BIN_PYBOOTLOADER=$(CACHE_DIR)/SomberNight/pyinstaller.git/PyInstaller/bootloader/Windows-64bit/run.exe
PYBOOTLOADER=$(WINE_BUILD_DIR)/run.exe

PYNK_DIR=$(CACHE_DIR)/Nitrokey/pynitrokey.git
PYNK_MSI=$(WINE_BUILD_DIR)/pynitrokey.msi
PYNK_EXE=$(WINE_BUILD_DIR)/nitropy.exe

BUILDS=$(LIBUSB) $(PYBOOTLOADER) exe #$(PYNK_MSI) $(PYNK_EXE)

.PHONY: all sources builds clean msi exe

all: sources builds
	echo "all"

sources: $(WORKDIRS) $(PY_PARTS_PATHS) $(REPO_PATHS) $(PY_HOME)
	echo "sources"

builds: $(BUILDS)

clean:
	rm -rf $(WORKDIRS)

$(CACHE_DIR):
	mkdir -p $(CACHE_DIR)

$(WINE_BUILD_DIR):
	mkdir -p $(WINE_BUILD_DIR)

$(WINEPREFIX):
	mkdir -p $(WINEPREFIX)
	WINEPREFIX=$(pwd)/$(WINEPREFIX) wineboot

$(CACHE_DIR)/%.msi: 
	wget $(PY_BASE_URL)/$*.msi
	mv $*.msi $(CACHE_DIR)

$(PY_HOME): $(PY_PARTS_PATHS)
	for msi_path in $?; \
	do \
		$(WINE) msiexec /i $$msi_path /qb TARGETDIR=$(PY_WINE_HOME); \
	done

$(CACHE_DIR)/%.git:
	git clone https://github.com/$*.git	$@ 


$(LIBUSB): $(CACHE_DIR)/libusb/libusb.git
	cd $(CACHE_DIR)/libusb/libusb.git && ( \
 		echo "libusb_1_0_la_LDFLAGS += -Wc,-static" >> libusb/Makefile.am && \
		./bootstrap.sh && \
		./configure --host=i686-w64-mingw32 --build=x86_64-pc-linux-gnu && \
		make -j4 \
	)
	cp $(BIN_LIBUSB) $(LIBUSB)

$(PYBOOTLOADER): $(CACHE_DIR)/SomberNight/pyinstaller.git
	#rm -f $(BIN_PYBOOTLOADER)
	cd $< && git reset --hard && git checkout develop
	# this might help against false-positives from malware-scanners
	#echo "const char *random_tag = \"tagged by me\";" >> $</bootloader/src/pyi_main.c
	#cd $</bootloader && python3 ./waf all CC=i686-w64-mingw32-gcc CFLAGS="-static -Wno-dangling-else -Wno-error=unused-value"
	$(PY) -m pip install $<
	#$(PY) -m pip install pyinstaller
	cp $(BIN_PYBOOTLOADER) $(PYBOOTLOADER)

msi: $(PYNK_MSI)
exe: $(PYNK_EXE)

#$(PYNK_MSI) $(PYNK_EXE): $(CACHE_DIR)/Nitrokey/pynitrokey.git
$(PYNK_EXE): $(CACHE_DIR)/Nitrokey/pynitrokey.git
	cp nitropy.spec $<
	cd $< && ( \
		$(PY) -m pip install --no-warn-script-location -r dev-requirements.txt && \
		$(PY) -m pip install --no-warn-script-location -r ci-requirements.txt && \
		$(PY) -m flit install && \
		$(PY) win_setup.py bdist_msi && \
		$(PY) -m PyInstaller --noconfirm --clean --name nitropy-0.4.1 --onefile nitropy.spec \
	)
	cp $</dist/pynitrokey-*-win32.msi $(PYNK_MSI)
	cp $</dist/pynitrokey-*-win32.msi $(WINE_BUILD_DIR) 
	cp $</dist/nitropy-0.4.1.exe $(WINE_BUILD_DIR)


#### nsis ??





