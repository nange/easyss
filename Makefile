PROJECT=easyss

GO := go

.PHONY: vet client-server client-server-with-notray remote-server

echo:
	@echo "${PROJECT}"

client-server:
	cd cmd/client-server; \
	$(GO) build -o client-server main.go start.go pac.go tray.go

client-server-windows:
	cd cmd/client-server; \
	$(GO) build -ldflags -H=windowsgui -o client-server-with-tray

client-server-with-notray:
	cd cmd/client-server; \
    $(GO) build -tags "with_notray " -o client-server-with-notray main.go start_withnotray.go pac.go

remote-server:
	cd cmd/remote-server; \
	$(GO) build -o remote-server

easyss-android:
	cd cmd/easyss; \
	fyne package -appID easyss -os android

vet:
	$(GO) vet ./...; \
	$(GO) vet -tags "with_notray " ./...
