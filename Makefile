.PHONY: all black build clean publish reinstall

PACKAGE_NAME=pynitrokey
VENV=venv
PYTHON3=python3
PYTHON3_VENV=venv/bin/python3

# whitelist of directories for flake8
FLAKE8_DIRS=pynitrokey/cli/fido2.py pynitrokey/cli/nk3 pynitrokey/cli/nkfido2.py pynitrokey/cli/nkpk.py pynitrokey/cli/trussed

all: init

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

# code checks
check-format:
	$(PYTHON3_VENV) -m black --check $(PACKAGE_NAME)/

check-import-sorting:
	$(PYTHON3_VENV) -m isort --check-only $(PACKAGE_NAME)/

check-style:
	$(PYTHON3_VENV) -m flake8 $(FLAKE8_DIRS)

check-typing:
	@echo "Note: run semi-clean target in case this fails without any proper reason"
	$(PYTHON3_VENV) -m mypy $(PACKAGE_NAME)/

check: check-format check-import-sorting check-style check-typing

# automatic code fixes
fix:
	$(PYTHON3_VENV) -m black $(BLACK_FLAGS) $(PACKAGE_NAME)/
	$(PYTHON3_VENV) -m isort $(ISORT_FLAGS) $(PACKAGE_NAME)/

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
	$(PYTHON3_VENV) -m flit build

build: check
	$(PYTHON3_VENV) -m flit build

publish:
	$(PYTHON3_VENV) -m flit --repository pypi publish

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
	$(PYTHON3_VENV) -m pip install -U pip


# re-run if dev or runtime dependencies change,
# or when adding new scripts
update-venv: $(VENV)
	$(PYTHON3_VENV) -m pip install -U pip
	$(PYTHON3_VENV) -m pip install flit
	$(PYTHON3_VENV) -m flit install --symlink

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

.PHONY: secrets-test-all secrets-test secrets-test-report secrets-test-report-CI
LOG=info
TESTADD=
TESTPARAM=-x -s -o log_cli=true -o log_cli_level=$(LOG) -W ignore::DeprecationWarning $(TESTADD)
secrets-test-all: init
	./venv/bin/pytest  -v pynitrokey/test_secrets_app.py --durations=20 $(TESTPARAM)

secrets-test:
	@echo "Skipping slow tests. Run secrets-test-all target for all tests."
	./venv/bin/pytest  -v pynitrokey/test_secrets_app.py --durations=20 -m "not slow" $(TESTPARAM)

REPORT=report.html
secrets-test-report:
	./venv/bin/pytest  -v pynitrokey/test_secrets_app.py --durations=0 -o log_cli=false -o log_cli_level=debug -W ignore::DeprecationWarning --template=html1/index.html --report $(REPORT)
	@echo "Report written to $(REPORT)"


REPORT=report.html
secrets-test-report-CI:
	./venv/bin/pytest  -v pynitrokey/test_secrets_app.py --durations=0  -m "not slow" -o log_cli=false -o log_cli_level=debug -W ignore::DeprecationWarning --template=html1/index.html --report $(REPORT) --junitxml=report-junit.xml $(TESTADD)
	@echo "Report written to $(REPORT)"


CORPUS_PATH=$(shell mktemp -d)
secrets-test-generate-corpus:
	./venv/bin/pytest  -v pynitrokey/test_secrets_app.py --durations=0 $(TESTPARAM) --generate-fuzzing-corpus --fuzzing-corpus-path=$(CORPUS_PATH)
	@echo "Corpus written to $(CORPUS_PATH)"
