PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64
DIST ?= dist
VERSION ?= dev
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Client binaries + skill, as served by tokd at /dl/ (TOKD_DOWNLOADS).
dist:
	mkdir -p $(DIST)
	for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags="-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)" -o $(DIST)/tok-$$os-$$arch$$ext ./cmd/tok || exit 1; \
	done
	cp skills/tok/SKILL.md $(DIST)/SKILL.md
	echo $(VERSION) > $(DIST)/TOK_VERSION

test:
	go test ./...

.PHONY: dist test
