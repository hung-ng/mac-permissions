.PHONY: build test start controller connection-build connection-test macbook-package macbook-tailscale-test
build:
	bash scripts/build.sh
test: build
	/usr/bin/python3 -m unittest discover -s Tests -p 'test_*.py' -v
start:
	bash scripts/start.sh --state-dir "$$PWD/build/runtime"
controller:
	/usr/bin/env python3 client/controller.py --token-file build/runtime/owner.token --open
connection-build:
	bash scripts/build-connection.sh
connection-test:
	/usr/bin/python3 -m unittest discover -s Tests -p 'test_native_connection.py' -v
macbook-package: connection-build
	bash scripts/package-controller.sh
macbook-tailscale-test:
	bash scripts/macbook-tailscale-test.sh
