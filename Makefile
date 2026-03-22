PYTHON ?= python3

.PHONY: test build publish release-check release-build release-publish version-packages

test:
	$(PYTHON) -m unittest discover -s tests

build:
	$(PYTHON) -m build

publish:
	$(PYTHON) -m twine upload dist/*

release-check: test

release-build: build

release-publish: publish

version-packages:
	@echo "Python versioning is managed by release-please via .github/workflows/release.yml"
