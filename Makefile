# Copyright 2019 SoloKeys Developers
# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

PACKAGE_NAME=pynitrokey

# whitelist of directories for flake8
FLAKE8_DIRS=\
	pynitrokey/cli/fido2.py \
	pynitrokey/cli/nk3 \
	pynitrokey/cli/nkfido2.py \
	pynitrokey/cli/nkpk \
	pynitrokey/cli/trussed \
	pynitrokey/fido2

MYPY ?= poetry run mypy

.PHONY: all
all: install

.PHONY: install
install:
	poetry sync --all-extras --with dev

.PHONY: lock
lock:
	poetry lock

.PHONY: update
update:
	poetry update

# code checks
.PHONY: check-format
check-format:
	poetry run black --check $(PACKAGE_NAME)/ stubs

.PHONY: check-import-sorting
check-import-sorting:
	poetry run isort --check-only $(PACKAGE_NAME)/ stubs

.PHONY: check-style
check-style:
	poetry run flake8 $(FLAKE8_DIRS) stubs

.PHONY: check-typing
check-typing:
	$(MYPY) $(PACKAGE_NAME)/

.PHONY: check
check: check-format check-import-sorting check-style check-typing

.PHONY: test
test:
	$(PYTHON3_VENV) -m doctest pynitrokey/helpers.py

# automatic code fixes
.PHONY: fix
fix:
	poetry run black $(BLACK_FLAGS) $(PACKAGE_NAME)/ stubs
	poetry run isort $(ISORT_FLAGS) $(PACKAGE_NAME)/ stubs

.PHONY: clean
clean:
	rm -rf ./dist
	rm -rf ./**/__pycache__
	rm -rf ./.mypy_cache


# Package management

.PHONY: tag
tag: VERSION := $(shell poetry version --short)
tag:
	git tag -a $(VERSION) -m"v$(VERSION)"
	git push origin $(VERSION)

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
