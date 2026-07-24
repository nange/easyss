PROJECT=Easyss

LDFLAGS += -X "github.com/nange/easyss/v3/version.Name=${PROJECT}"
LDFLAGS += -X "github.com/nange/easyss/v3/version.BuildDate=$(shell date '+%Y-%m-%d %H:%M:%S')"
LDFLAGS += -X "github.com/nange/easyss/v3/version.GitTag=$(shell git describe --tags)"

GO := go
GO_BUILD := go build -ldflags '$(LDFLAGS)'
GO_BUILD_WIN := GOOS=windows GOARCH=amd64 CGO_ENABLED=1 go build -ldflags '-H windowsgui $(LDFLAGS)'
GOMOBILE := $(shell go env GOPATH)/bin/gomobile
GOMOBILE_BIND := $(GOMOBILE) bind -target=android/arm64,android/amd64 -androidapi 29 -ldflags '$(LDFLAGS)'

.PHONY: easyss easyss-without-tray easyss-windows easyss-mac-app easyss-server easyss-server-windows easyss-android-aar format test lint

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
		$(GO_BUILD) -o ../../bin/easyss
		bash scripts/app-bundle.sh bin/easyss icon/icon_1024_1024.png cmd/easyss/Info.plist

easyss-without-tray:
		cd cmd/easyss; \
	    $(GO_BUILD) -tags "without_tray " -o ../../bin/easyss-without-tray

easyss-server:
	cd cmd/easyss-server; \
	CGO_ENABLED=0 $(GO_BUILD) -o ../../bin/easyss-server

easyss-server-windows:
	cd cmd/easyss-server; \
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o ../../bin/easyss-server.exe

easyss-android-aar:
	@if ! command -v javac >/dev/null 2>&1; then \
		echo "Error: javac not found in PATH, please add JDK bin directory to PATH"; \
		exit 1; \
	fi
	$(GOMOBILE_BIND) -javapkg io.github.nange.easyss -o bin/libeasyss.aar ./mobile/ ./config/

format:
	$(GO) fmt ./...

test:
	$(GO) test -v ./...

lint:
	go tool golangci-lint run --timeout 10m --verbose
