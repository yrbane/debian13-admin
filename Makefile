.PHONY: test lint check-syntax docker-test

test:
	bats tests/

lint:
	shellcheck lib/*.sh || true

check-syntax:
	@for f in lib/*.sh debian13-server.sh; do \
		bash -n "$$f" || exit 1; \
	done
	@echo "All syntax OK"

docker-test:
	docker build -f Dockerfile.test -t debian13-test .
	docker run --rm debian13-test
