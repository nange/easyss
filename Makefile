PROJECT=easyss

GO := go

.PHONY: vet easyss easyss-with-notray easyss-server

echo:
	@echo "${PROJECT}"

easyss:
	cd cmd/easyss; \
	$(GO) build -o easyss main.go start.go pac.go tray.go

easyss-windows:
	cd cmd/easyss; \
	$(GO) build -ldflags -H=windowsgui -o easyss.exe

easyss-with-notray:
	cd cmd/easyss; \
    $(GO) build -tags "with_notray " -o easyss-with-notray main.go start_withnotray.go

easyss-server:
	cd cmd/easyss-server; \
	$(GO) build -o easyss-server

vet:
	$(GO) vet ./...; \
	$(GO) vet -tags "with_notray " ./...
