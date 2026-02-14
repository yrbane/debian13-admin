.PHONY: test lint check-syntax

test:
	bats tests/

lint:
	shellcheck lib/domain-manager.sh

check-syntax:
	bash -n lib/domain-manager.sh
	bash -n lib/install-web.sh
	bash -n lib/verify.sh
	bash -n debian13-server.sh
