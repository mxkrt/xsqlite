SHELL := /bin/bash

.PHONY: help
help:
	@echo
	@echo "makefile targets"
	@echo "----------------"
	@echo "  make install     - install in virtualenv ~/.virtualenvs/xsqlite"
	@echo "  make uninstall   - uninstall in virtualenv ~/.virtualenvs/xsqlite"
	@echo "  make purge       - remove ~/.virtualenvs/xsqlite"
	@echo "  make dev_install - create editable install in ~/.virtualenvs/xsqlite_dev"
	@echo "  make dev_purge   - remove ~/.virtualenvs/xsqlite_dev"
	@echo "  make clean       - remove temporary files from working dir"

.PHONY: install
install:
	@echo "Creating new virtualenv ~/.virtualenvs/xsqlite"
	@python3 -m venv ~/.virtualenvs/xsqlite
	@echo "Installing in virtualenv ~/.virtualenvs/xsqlite"
	@. ~/.virtualenvs/xsqlite/bin/activate && pip3 install .
	@echo "Activate xsqlite virtualenv as follows:"
	@echo
	@echo ". ~/.virtualenvs/xsqlite/bin/activate"
	@echo

.PHONY: uninstall
uninstall:
	@echo "Uninstalling from virtualenv ~/.virtualenvs/xsqlite"
	@. ~/.virtualenvs/xsqlite/bin/activate && pip3 uninstall xsqlite
	@echo


.PHONY: purge
purge:
	@echo "removing virtualenv ~/.virtualenvs/xsqlite"
	rm -rf ~/.virtualenvs/xsqlite

.PHONY: dev_install
dev_install:
	@echo "Creating new virtualenv ~/.virtualenvs/xsqlite_dev"
	@python3 -m venv ~/.virtualenvs/xsqlite_dev
	@echo "Perform editable install in virtualenv ~/.virtualenvs/xsqlite_dev"
	@. ~/.virtualenvs/xsqlite_dev/bin/activate && pip3 install --editable .
	@echo "Activate xsqlite development virtualenv as follows:"
	@echo
	@echo ". ~/.virtualenvs/xsqlite_dev/bin/activate"
	@echo

.PHONY: dev_purge
dev_purge:
	@echo "removing virtualenv ~/.virtualenvs/xsqlite_dev"
	rm -rf ~/.virtualenvs/xsqlite_dev

.PHONY: clean
clean:
	rm -rf build
	rm -rf xsqlite.egg-info
