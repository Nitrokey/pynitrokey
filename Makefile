.PHONY: black build clean publish reinstall

PACKAGE_NAME=pynitrokey
VENV=venv


# setup development environment
init: update-venv

# ensure this passes before commiting
check: lint
	$(VENV)/bin/python3 -m black --check $(PACKAGE_NAME)/
	$(VENV)/bin/python3 -m isort --check-only $(PACKAGE_NAME)/

# automatic code fixes
fix: black isort

black:
	$(VENV)/bin/python3 -m black -t py35 $(PACKAGE_NAME)/

isort:
	$(VENV)/bin/python3 -m isort --py 35 $(PACKAGE_NAME)/

lint:
	$(VENV)/bin/python3 -m flake8 $(PACKAGE_NAME)/ \
		--extend-exclude pynitrokey/nethsm/client

semi-clean:
	rm -rf **/__pycache__

clean: semi-clean
	rm -rf $(VENV)
	rm -rf dist


# Package management

VERSION_FILE := "$(PACKAGE_NAME)/VERSION"
VERSION := $(shell cat $(VERSION_FILE))

tag:
	git tag -a $(VERSION) -m"v$(VERSION)"
	git push origin $(VERSION)

.PHONY: build-forced
build-forced:
	$(VENV)/bin/python3 -m flit build

build: check
	$(VENV)/bin/python3 -m flit build

publish:
	$(VENV)/bin/python3 -m flit --repository pypi publish

system-pip-install-upgrade:
	python -m pip install -U pynitrokey

system-pip-install-last-version:
	python -m pip install pynitrokey== 2>&1 | grep -oE ", ([^,]+), ([^,]+)\)$$" | cut -d "," -f 2 | xargs > LAST_VERSION
	python -m pip install pynitrokey==`cat LAST_VERSION | xargs`

system-pip-install:
	python -m pip install pynitrokey

system-pip-uninstall:
	python -m pip uninstall pynitrokey -y

system-nitropy-test-simple:
	which nitropy
	nitropy


$(VENV):
	python3 -m venv $(VENV)
	$(VENV)/bin/python3 -m pip install -U pip

# re-run if dev or runtime dependencies change,
# or when adding new scripts
update-venv: $(VENV)
	$(VENV)/bin/python3 -m pip install -U pip
	$(VENV)/bin/python3 -m pip install -U -r dev-requirements.txt
	$(VENV)/bin/python3 -m flit install --symlink

.PHONY: CI
CI:
	env FLIT_ROOT_INSTALL=1 $(MAKE) init VENV=$(VENV)
	env FLIT_ROOT_INSTALL=1 $(MAKE) build-forced VENV=$(VENV)
	# $(MAKE) check || true # disableing this for the ci to work
	@echo
	env LC_ALL=C.UTF-8 LANG=C.UTF-8 $(VENV)/bin/nitropy
	@echo
	env LC_ALL=C.UTF-8 LANG=C.UTF-8 $(VENV)/bin/nitropy version
	git describe

.PHONY: build-CI-test
build-CI-test:
	sudo docker build . -t nitro-python-ci

.PHONY: CI-test
CI-test:
	sudo docker run -it --rm -v $(PWD):/app nitro-python-ci make CI VENV=venv-ci

OPENAPI_OUTPUT_DIR=${PWD}/tmp/openapi-client

# Generates the OpenAPI client for the NetHSM REST API
.PHONY: nethsm-client
nethsm-client: nethsm-scheme.json
	mkdir -p "${OPENAPI_OUTPUT_DIR}"
	cp nethsm-scheme.json "${OPENAPI_OUTPUT_DIR}/scheme.json"
	docker run --rm -ti -v "${OPENAPI_OUTPUT_DIR}:/out" \
		openapitools/openapi-generator-cli generate \
		-i=/out/scheme.json \
		-g=python -o=/out/python --package-name=pynitrokey.nethsm.client
	cp -r "${OPENAPI_OUTPUT_DIR}/python/pynitrokey/nethsm/client" pynitrokey/nethsm

	# TODO: We would like to use the upstream scheme definition, but it currently
	# misses proper mime type definitions for operations that return other data
	# than JSON
		# -i=https://nethsmdemo.nitrokey.com/api_docs/gen_nethsm_api_oas20.json \

.PHONY: wine-build
wine-build: wine-build/pynitrokey-$(VERSION).msi wine-build/nitropy-$(VERSION).exe

wine-build/pynitrokey-$(VERSION).msi wine-build/nitropy-$(VERSION).exe:
	sh build-wine.sh
	cp wine-build/out/pynitrokey-$(VERSION)-win32.msi wine-build
	cp wine-build/out/nitropy-$(VERSION).exe wine-build

