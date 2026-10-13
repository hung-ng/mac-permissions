.PHONY: build test start controller
build:
	bash scripts/build.sh
test: build
	/usr/bin/python3 -m unittest discover -s Tests -p 'test_*.py' -v
start:
	bash scripts/start.sh --state-dir "$$PWD/build/runtime"
controller:
	/usr/bin/env python3 client/controller.py --token-file build/runtime/owner.token --open
