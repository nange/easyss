PROJECT=Easyss

LDFLAGS += -X "github.com/nange/easyss/v3/version.Name=${PROJECT}"
LDFLAGS += -X "github.com/nange/easyss/v3/version.BuildDate=$(shell date '+%Y-%m-%d %H:%M:%S')"
LDFLAGS += -X "github.com/nange/easyss/v3/version.GitTag=$(shell git describe --tags)"

GO := go
GO_BUILD := go build -ldflags '$(LDFLAGS)'
GO_BUILD_WIN := GOOS=windows GOARCH=amd64 CGO_ENABLED=1 go build -ldflags '-H windowsgui $(LDFLAGS)'
GOMOBILE := gomobile
GOMOBILE_BIND_BASE := $(GOMOBILE) bind -target=android/arm64,android/amd64 -androidapi 29 -ldflags '$(LDFLAGS)'

GOMOBILE_JBR_PATH := $(shell cygpath -d "C:/Program Files/Android/Android Studio/jbr/bin" 2>/dev/null)
ifneq ($(GOMOBILE_JBR_PATH),)
  GOMOBILE_BIND := PATH="$(GOMOBILE_JBR_PATH):$$PATH" $(GOMOBILE_BIND_BASE)
else
  GOMOBILE_BIND := $(GOMOBILE_BIND_BASE)
endif

.PHONY: easyss easyss-without-tray easyss-windows easyss-server easyss-server-windows format test lint

echo:
	@echo "${PROJECT}"

easyss:
	cd cmd/easyss; \
	$(GO_BUILD) -o ../../bin/easyss

easyss-windows:
	cd cmd/easyss; \
	$(GO_BUILD_WIN) -o ../../bin/easyss.exe

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
	$(GOMOBILE_BIND) -javapkg io.github.nange.easyss -o bin/libeasyss.aar ./mobile/ ./config/

format:
	$(GO) fmt ./...

test:
	$(GO) test -v ./...

lint:
	go tool golangci-lint run --timeout 10m --verbose
