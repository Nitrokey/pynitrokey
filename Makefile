.PHONY: black build clean publish reinstall

PACKAGE_NAME=pynitrokey
VENV=venv
PYTHON3=python3

BLACK_FLAGS=-t py39 --extend-exclude pynitrokey/nethsm/client
FLAKE8_FLAGS=--extend-exclude pynitrokey/nethsm/client,pynitrokey/nk3/bootloader/nrf52_upload
ISORT_FLAGS=--py 39 --extend-skip pynitrokey/nethsm/client

# whitelist of directories for flake8
FLAKE8_DIRS=pynitrokey/nethsm pynitrokey/cli/nk3 pynitrokey/nk3

.PHONY: init-fedora37
init-fedora37:
	sudo dnf install -y swig pcsc-lite-devel
	$(MAKE) init

# setup development environment
init: update-venv

ARGS=
.PHONY: run rune builde
run:
	./venv/bin/nitropy $(ARGS)

DOCKER=docker
IMAGE=pynitrokey
CMD=/bin/bash
rune:
	$(DOCKER) run --privileged --rm -it -v $(PWD):/app --entrypoint= $(IMAGE) $(CMD)

builde:
	earthly +build

# ensure this passes before committing
check: lint
	@echo "Note: run semi-clean target in case this fails without any proper reason"
	$(VENV)/bin/python3 -m black $(BLACK_FLAGS) --check $(PACKAGE_NAME)/
	$(VENV)/bin/python3 -m isort $(ISORT_FLAGS) --check-only $(PACKAGE_NAME)/
	$(VENV)/bin/python3 -m doctest pynitrokey/nk3/utils.py
	@echo All good!

# automatic code fixes
fix: black isort

black:
	$(VENV)/bin/python3 -m black $(BLACK_FLAGS) $(PACKAGE_NAME)/

isort:
	$(VENV)/bin/python3 -m isort $(ISORT_FLAGS) $(PACKAGE_NAME)/

lint:
	$(VENV)/bin/python3 -m flake8 $(FLAKE8_FLAGS) $(FLAKE8_DIRS)
	$(VENV)/bin/python3 -m mypy $(PACKAGE_NAME)

semi-clean:
	rm -rf ./**/__pycache__
	rm -rf ./.mypy_cache

clean: semi-clean
	rm -rf ./$(VENV)
	rm -rf ./dist


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
	$(PYTHON3) -m pip install -U pynitrokey

system-pip-install-last-version:
	$(PYTHON3) -m pip install pynitrokey==$(VERSION)

system-pip-install:
	$(PYTHON3) -m pip install pynitrokey

system-pip-uninstall:
	$(PYTHON3) -m pip uninstall pynitrokey -y

system-nitropy-test-simple:
	which nitropy
	nitropy


$(VENV):
	$(PYTHON3) -m venv $(VENV)
	$(VENV)/bin/python3 -m pip install -U pip


# re-run if dev or runtime dependencies change,
# or when adding new scripts
update-venv: $(VENV)
	$(VENV)/bin/python3 -m pip install -U pip
	$(VENV)/bin/python3 -m pip install flit
	$(VENV)/bin/python3 -m flit install --symlink

.PHONY: CI
CI:
	env FLIT_ROOT_INSTALL=1 $(MAKE) init VENV=$(VENV)
	env FLIT_ROOT_INSTALL=1 $(MAKE) build-forced VENV=$(VENV)
	$(MAKE) check
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

nethsm-api.yaml:
	curl "https://nethsmdemo.nitrokey.com/api_docs/nethsm-api.yaml" --output nethsm-api.yaml

# Generates the OpenAPI client for the NetHSM REST API
.PHONY: nethsm-client
nethsm-client: nethsm-api.yaml
	mkdir -p "${OPENAPI_OUTPUT_DIR}"
	cp nethsm-api.yaml "${OPENAPI_OUTPUT_DIR}/nethsm-api.yaml"
	docker run --rm -ti -v "${OPENAPI_OUTPUT_DIR}:/out" \
		openapitools/openapi-generator-cli:latest-release generate \
		-i=/out/nethsm-api.yaml \
		-g=python -o=/out/python --package-name=pynitrokey.nethsm.client
	cp -r "${OPENAPI_OUTPUT_DIR}/python/pynitrokey/nethsm/client" pynitrokey/nethsm

.PHONY: secrets-test-all secrets-test
TESTPARAM=-x -s -o log_cli=true
secrets-test-all: init
	./venv/bin/pytest  -v pynitrokey/test_secrets_app.py --durations=0 $(TESTPARAM)

secrets-test: init
	@echo "Skipping slow tests. Run secrets-test-all target for all tests."
	./venv/bin/pytest  -v pynitrokey/test_secrets_app.py --durations=0 -m "not slow" $(TESTPARAM)
