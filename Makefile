COMMANDS       = notation-local-signer
LDFLAGS        =
GO_BUILD_FLAGS = --ldflags="$(LDFLAGS)"

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'

.PHONY: all
all: build

.PHONY: FORCE
FORCE:

bin/%: cmd/% FORCE
	go build $(GO_BUILD_FLAGS) -o $@ ./$<

.PHONY: download
download: ## download dependencies via go mod
	go mod download

.PHONY: build
build: $(addprefix bin/,$(COMMANDS)) ## builds binaries

.PHONY: test
test: ## run unit test
	go test -race -v -coverprofile=coverage.txt -covermode=atomic ./...

.PHONY: install
install: bin/notation-local-signer ## installs the plugin
	mkdir -p  ~/.config/notation/plugins/local-signer/
	cp bin/notation-local-signer ~/.config/notation/plugins/local-signer/

.PHONY: rotate-key
rotate-key: ## generate a new key pair for notation signing
	scripts/rotate-key.sh
