PYTHON ?= python3

.PHONY: test build publish

test:
	$(PYTHON) -m unittest discover -s tests

build:
	$(PYTHON) -m build

publish:
	$(PYTHON) -m twine upload dist/*
