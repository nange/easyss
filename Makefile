PROJECT=Easyss

LDFLAGS += -X "github.com/nange/easyss/v3/version.Name=${PROJECT}"
LDFLAGS += -X "github.com/nange/easyss/v3/version.BuildDate=$(shell date '+%Y-%m-%d %H:%M:%S')"
LDFLAGS += -X "github.com/nange/easyss/v3/version.GitTag=$(shell git describe --tags 2>/dev/null)"

GO := go
GO_BUILD := CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)'
WIN_ARCH ?= amd64
GO_BUILD_WIN := GOOS=windows GOARCH=$(WIN_ARCH) CGO_ENABLED=0 go build -ldflags '-H windowsgui $(LDFLAGS)'
GOMOBILE := $(shell go env GOPATH)/bin/gomobile
# Android 15+ / Google Play 要求原生库 16KB 对齐（16KB page size 支持），
# 通过外部链接器将 ELF LOAD 段对齐到 16384 字节，消除 AGP 的 Aligned16KB 警告
ANDROID_ALIGN_LDFLAGS := -extldflags=-Wl,-z,max-page-size=16384
GOMOBILE_BIND := $(GOMOBILE) bind -target=android/arm64,android/amd64 -androidapi 29 -ldflags '$(LDFLAGS) $(ANDROID_ALIGN_LDFLAGS)'

.PHONY: format lint test easyss easyss-headless easyss-windows easyss-server easyss-server-windows easyss-android-aar

echo:
	@echo "${PROJECT}"

easyss:
	cd cmd/easyss; \
	$(GO_BUILD) -o ../../bin/easyss

easyss-windows:
	cd cmd/easyss; \
	$(GO_BUILD_WIN) -o ../../bin/easyss.exe

easyss-mac-app:
	cd cmd/easyss; \
	GOOS=darwin $(GO_BUILD) -o ../../bin/easyss
	bash scripts/app-bundle.sh bin/easyss icon/Easyss.icns cmd/easyss/Info.plist

easyss-headless:
		cd cmd/easyss; \
    $(GO_BUILD) -tags "headless" -o ../../bin/easyss-headless

easyss-server:
	cd cmd/easyss-server; \
	$(GO_BUILD) -o ../../bin/easyss-server

easyss-server-windows:
	cd cmd/easyss-server; \
	GOOS=windows GOARCH=$(WIN_ARCH) $(GO_BUILD) -o ../../bin/easyss-server.exe

easyss-android-aar:
	@if ! command -v javac >/dev/null 2>&1; then \
		echo "Error: javac not found in PATH, please add JDK bin directory to PATH"; \
		exit 1; \
	fi
	$(GOMOBILE_BIND) -javapkg io.github.nange.easyss -o bin/libeasyss.aar ./mobile/ ./config/

format:
	$(GO) fmt ./...

test:
	$(GO) test -timeout 15m -v ./...

test-race:
	$(GO) test -race -v ./...

lint:
	go tool golangci-lint run --timeout 10m --verbose
