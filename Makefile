PROJECT=tidb

GO := GO111MODULE=on go

client-server-with-tray:
	cd cmd/client-server; \
	$(GO) build -tags "with_tray " -o client-server-with-tray

client-server-with-notray:
	cd cmd/client-server; \
    $(GO) build -tags "with_notray " -o client-server-with-notray

remote-server:
	cd cmd/remote-server; \
	$(GO) build -o remote-server

vet:
	$(GO) vet -tags "with_tray " ./...; \
	$(GO) vet -tags "with_notray " ./...

.PHONY: vet client-server-with-tray client-server-with-notray remote-server
