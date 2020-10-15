PROJECT=easyss

GO := GO111MODULE=on go

.PHONY: vet client-server-with-tray client-server-with-notray remote-server

echo:
	@echo "${PROJECT}"

client-server-with-tray:
	cd cmd/client-server; \
	$(GO) build -tags "with_tray " -o client-server-with-tray main.go start.go pac.go tray.go

client-server-with-tray-windows:
	cd cmd/client-server; \
	$(GO) build -ldflags -H=windowsgui -tags "with_tray " -o client-server-with-tray

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
	$(GO) vet -tags "with_tray " ./...; \
	$(GO) vet -tags "with_notray " ./...
