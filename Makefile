PROJECT=Easyss

GO := go

LDFLAGS += -X "github.com/nange/easyss/v2/version.Name=${PROJECT}"
LDFLAGS += -X "github.com/nange/easyss/v2/version.BuildDate=$(shell date '+%Y-%m-%d %H:%M:%S')"
LDFLAGS += -X "github.com/nange/easyss/v2/version.GitTag=$(shell git describe --tags)"

.PHONY: easyss easyss-with-notray easyss-windows easyss-server easyss-server-windows

echo:
	@echo "${PROJECT}"

easyss:
	cd cmd/easyss; \
	$(GO) build -o ../../bin/easyss -ldflags '$(LDFLAGS)'

easyss-windows:
	cd cmd/easyss; \
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 $(GO) build -o ../../bin/easyss.exe -ldflags '-H=windowsgui $(LDFLAGS)'

easyss-with-notray:
	cd cmd/easyss; \
    $(GO) build -tags "with_notray " -o ../../bin/easyss-with-notray -ldflags '$(LDFLAGS)' main.go start_withnotray.go

easyss-server:
	cd cmd/easyss-server; \
	$(GO) build -o ../../bin/easyss-server -ldflags '$(LDFLAGS)'

easyss-server-windows:
	cd cmd/easyss-server; \
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 $(GO) build -o ../../bin/easyss-server.exe -ldflags '$(LDFLAGS)'

test:
	$(GO) test -v ./...

lint:
	golangci-lint run
