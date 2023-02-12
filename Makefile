PROJECT=Easyss

LDFLAGS += -X "github.com/nange/easyss/v2/version.Name=${PROJECT}"
LDFLAGS += -X "github.com/nange/easyss/v2/version.BuildDate=$(shell date '+%Y-%m-%d %H:%M:%S')"
LDFLAGS += -X "github.com/nange/easyss/v2/version.GitTag=$(shell git describe --tags)"

GO := go
GO_BUILD := go build -ldflags '$(LDFLAGS)'
GO_BUILD_WIN := GOOS=windows GOARCH=amd64 CGO_ENABLED=1 go build -ldflags '-H=windowsgui $(LDFLAGS)'

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

test:
	$(GO) test -v ./...

lint:
	golangci-lint run
