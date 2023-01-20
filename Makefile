PROJECT=Easyss

GO := go

LDFLAGS += -X "github.com/nange/easyss/v2/version.Name=${PROJECT}"
LDFLAGS += -X "github.com/nange/easyss/v2/version.BuildDate=$(shell date '+%Y-%m-%d %H:%M:%S')"
LDFLAGS += -X "github.com/nange/easyss/v2/version.GitTag=$(shell git describe --tags)"

.PHONY: easyss easyss-with-notray easyss-server

echo:
	@echo "${PROJECT}"

easyss:
	cd cmd/easyss; \
	$(GO) build -o easyss -ldflags '$(LDFLAGS)'

easyss-windows:
	cd cmd/easyss; \
	$(GO) build -o easyss.exe -ldflags '-H=windowsgui $(LDFLAGS)'

easyss-with-notray:
	cd cmd/easyss; \
    $(GO) build -tags "with_notray " -o easyss-with-notray -ldflags '$(LDFLAGS)'

easyss-server:
	cd cmd/easyss-server; \
	$(GO) build -o easyss-server -ldflags '$(LDFLAGS)'

test:
	$(GO) test -v ./...

lint:
	golangci-lint run
