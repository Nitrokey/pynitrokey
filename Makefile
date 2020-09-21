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
	$(VENV)/bin/python3 -m flake8 $(PACKAGE_NAME)/

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

system-pip-install-test:
	python -m pip install -U pynitrokey
	which nitropy
	nitropy

system-pip-uninstall:
	python -m pip uninstall pynitrokey -y
  
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
	$(MAKE) check || true
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
