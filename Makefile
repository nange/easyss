PROJECT=Easyss

LDFLAGS += -X "github.com/nange/easyss/v3/version.Name=${PROJECT}"
LDFLAGS += -X "github.com/nange/easyss/v3/version.BuildDate=$(shell date '+%Y-%m-%d %H:%M:%S')"
LDFLAGS += -X "github.com/nange/easyss/v3/version.GitTag=$(shell git describe --tags)"

GO := go
GO_BUILD := go build -ldflags '$(LDFLAGS)'
GO_BUILD_WIN := GOOS=windows GOARCH=amd64 CGO_ENABLED=1 go build -ldflags '-H=windowsgui $(LDFLAGS)'
GO_BUILD_ANDROID := GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC=${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang go build -ldflags '$(LDFLAGS)'

.PHONY: easyss easyss-with-notray easyss-windows easyss-server easyss-server-windows

echo:
	@echo "${PROJECT}"

easyss:
	cd cmd/easyss; \
	$(GO_BUILD) -o ../../bin/easyss

easyss-windows:
	cd cmd/easyss; \
	$(GO_BUILD_WIN) -o ../../bin/easyss.exe

easyss-with-notray:
	cd cmd/easyss; \
    $(GO_BUILD) -tags "with_notray " -o ../../bin/easyss-with-notray

easyss-server:
	cd cmd/easyss-server; \
	$(GO_BUILD) -o ../../bin/easyss-server

easyss-server-windows:
	cd cmd/easyss-server; \
	$(GO_BUILD_WIN) -o ../../bin/easyss-server.exe

easyss-android:
	cd cmd/easyss; \
	$(GO_BUILD_ANDROID) -tags "with_notray " -o ../../bin/easyss-android

test:
	$(GO) test -v ./...

lint:
	golangci-lint run
