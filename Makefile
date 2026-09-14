PROJECT=Easyss

LDFLAGS += -X "github.com/nange/easyss/v3/version.Name=${PROJECT}"
LDFLAGS += -X "github.com/nange/easyss/v3/version.BuildDate=$(shell date '+%Y-%m-%d %H:%M:%S')"
LDFLAGS += -X "github.com/nange/easyss/v3/version.GitTag=$(shell git describe --tags 2>/dev/null)"

GO := go
GO_BUILD := CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)'
WIN_ARCH ?= amd64
GO_BUILD_WIN := GOOS=windows GOARCH=$(WIN_ARCH) CGO_ENABLED=0 go build -ldflags '-H windowsgui $(LDFLAGS)'
GOMOBILE := $(shell go env GOPATH)/bin/gomobile
# Android 15+ / Google Play 要求原生库 16KB 对齐（16KB page size 支持），
# 通过外部链接器将 ELF LOAD 段对齐到 16384 字节，消除 AGP 的 Aligned16KB 警告
ANDROID_ALIGN_LDFLAGS := -extldflags=-Wl,-z,max-page-size=16384
GOMOBILE_BIND := $(GOMOBILE) bind -target=android/arm64,android/amd64 -androidapi 29 -ldflags '$(LDFLAGS) $(ANDROID_ALIGN_LDFLAGS)'

BIN := bin
# CI / 发布产物按平台分目录：不同架构互不覆盖，打包因此与构建顺序无关。
PLATFORM_DIRS := $(BIN)/linux-amd64 $(BIN)/linux-arm64 $(BIN)/windows-amd64 \
                 $(BIN)/windows-arm64 $(BIN)/darwin-arm64 $(BIN)/darwin-amd64

# 注意：本行只是 .PHONY 声明。不要把 `make .PHONY` 当作目标使用——那会把下面
# 所有目标（format/lint/test/全部构建）当成前置目标跑一遍。CI 只调用明确的
# build / verify / dist 目标。
.PHONY: echo format lint test test-race test-headless test-race-headless verify clean \
        easyss easyss-headless easyss-windows easyss-server easyss-server-windows \
        easyss-mac-app easyss-android-aar \
        build build-linux-amd64 build-linux-arm64 build-windows-amd64 build-windows-arm64 \
        build-darwin-arm64 build-darwin-amd64 pack dist

echo:
	@echo "${PROJECT}"

# ---------------------------------------------------------------------------
# 本机开发构建：产物写在 bin/ 根目录
# ---------------------------------------------------------------------------

easyss:
	cd cmd/easyss; \
	$(GO_BUILD) -o ../../bin/easyss

easyss-windows:
	cd cmd/easyss; \
	$(GO_BUILD_WIN) -o ../../bin/easyss.exe

easyss-mac-app:
	cd cmd/easyss; \
	GOOS=darwin $(GO_BUILD) -o ../../bin/easyss
	bash scripts/app-bundle.sh bin/easyss icon/Easyss.icns cmd/easyss/Info.plist

easyss-headless:
		cd cmd/easyss; \
    $(GO_BUILD) -tags "headless" -o ../../bin/easyss-headless

easyss-server:
	cd cmd/easyss-server; \
	$(GO_BUILD) -o ../../bin/easyss-server

easyss-server-windows:
	cd cmd/easyss-server; \
	GOOS=windows GOARCH=$(WIN_ARCH) $(GO_BUILD) -o ../../bin/easyss-server.exe

easyss-android-aar:
	@if ! command -v javac >/dev/null 2>&1; then \
		echo "Error: javac not found in PATH, please add JDK bin directory to PATH"; \
		exit 1; \
	fi
	$(GOMOBILE_BIND) -javapkg io.github.nange.easyss -o bin/libeasyss.aar ./mobile/ ./config/

# ---------------------------------------------------------------------------
# CI / 发布构建：产物写在 bin/<os>-<arch>/ 子目录
# 平台显式写死，不再用命令行传 GOOS/GOARCH/WIN_ARCH，避免同一目标名产出不同架构
# ---------------------------------------------------------------------------

build: build-linux-amd64 build-linux-arm64 build-windows-amd64 build-windows-arm64 build-darwin-arm64 build-darwin-amd64
	@echo "构建完成：$(PLATFORM_DIRS)"

build-linux-amd64:
	@mkdir -p $(BIN)/linux-amd64
	cd cmd/easyss && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o ../../$(BIN)/linux-amd64/easyss
	cd cmd/easyss && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags headless -ldflags '$(LDFLAGS)' -o ../../$(BIN)/linux-amd64/easyss-headless
	cd cmd/easyss-server && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o ../../$(BIN)/linux-amd64/easyss-server

build-linux-arm64:
	@mkdir -p $(BIN)/linux-arm64
	cd cmd/easyss && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o ../../$(BIN)/linux-arm64/easyss
	cd cmd/easyss && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags headless -ldflags '$(LDFLAGS)' -o ../../$(BIN)/linux-arm64/easyss-headless
	cd cmd/easyss-server && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o ../../$(BIN)/linux-arm64/easyss-server

build-windows-amd64:
	@mkdir -p $(BIN)/windows-amd64
	cd cmd/easyss && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags '-H windowsgui $(LDFLAGS)' -o ../../$(BIN)/windows-amd64/easyss.exe
	cd cmd/easyss-server && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o ../../$(BIN)/windows-amd64/easyss-server.exe

build-windows-arm64:
	@mkdir -p $(BIN)/windows-arm64
	cd cmd/easyss && GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -ldflags '-H windowsgui $(LDFLAGS)' -o ../../$(BIN)/windows-arm64/easyss.exe
	cd cmd/easyss-server && GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o ../../$(BIN)/windows-arm64/easyss-server.exe

build-darwin-arm64:
	@mkdir -p $(BIN)/darwin-arm64
	cd cmd/easyss && GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o ../../$(BIN)/darwin-arm64/easyss
	cd cmd/easyss-server && GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o ../../$(BIN)/darwin-arm64/easyss-server
	bash scripts/app-bundle.sh $(BIN)/darwin-arm64/easyss icon/Easyss.icns cmd/easyss/Info.plist $(BIN)/darwin-arm64

build-darwin-amd64:
	@mkdir -p $(BIN)/darwin-amd64
	cd cmd/easyss && GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o ../../$(BIN)/darwin-amd64/easyss
	cd cmd/easyss-server && GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o ../../$(BIN)/darwin-amd64/easyss-server
	bash scripts/app-bundle.sh $(BIN)/darwin-amd64/easyss icon/Easyss.icns cmd/easyss/Info.plist $(BIN)/darwin-amd64

# ---------------------------------------------------------------------------
# 打包：资产名与 zip 内文件名是 selfupdate(<product>-<goos>-<goarch>.zip) 与
# docker/Dockerfile 的对外契约，改名会破坏客户端自更新和镜像构建。
# zip 统一落在 bin/（工作流上传 bin/*.zip 与 bin/*.aar）。
# ---------------------------------------------------------------------------

pack: build
	cd $(BIN)/linux-amd64 && rm -f ../easyss-linux-amd64.zip && zip ../easyss-linux-amd64.zip ./easyss
	cd $(BIN)/linux-amd64 && rm -f ../easyss-headless-linux-amd64.zip && zip ../easyss-headless-linux-amd64.zip ./easyss-headless
	cd $(BIN)/linux-amd64 && rm -f ../easyss-server-linux-amd64.zip && zip ../easyss-server-linux-amd64.zip ./easyss-server
	cd $(BIN)/linux-arm64 && rm -f ../easyss-linux-arm64.zip && zip ../easyss-linux-arm64.zip ./easyss
	cd $(BIN)/linux-arm64 && rm -f ../easyss-headless-linux-arm64.zip && zip ../easyss-headless-linux-arm64.zip ./easyss-headless
	cd $(BIN)/linux-arm64 && rm -f ../easyss-server-linux-arm64.zip && zip ../easyss-server-linux-arm64.zip ./easyss-server
	cd $(BIN)/windows-amd64 && rm -f ../easyss-windows-amd64.zip && zip ../easyss-windows-amd64.zip ./easyss.exe
	cd $(BIN)/windows-amd64 && rm -f ../easyss-server-windows-amd64.zip && zip ../easyss-server-windows-amd64.zip ./easyss-server.exe
	cd $(BIN)/windows-arm64 && rm -f ../easyss-windows-arm64.zip && zip ../easyss-windows-arm64.zip ./easyss.exe
	cd $(BIN)/windows-arm64 && rm -f ../easyss-server-windows-arm64.zip && zip ../easyss-server-windows-arm64.zip ./easyss-server.exe
	cd $(BIN)/darwin-arm64 && rm -f ../easyss-darwin-arm64.zip && zip -r ../easyss-darwin-arm64.zip ./Easyss.app
	cd $(BIN)/darwin-arm64 && rm -f ../easyss-server-darwin-arm64.zip && zip ../easyss-server-darwin-arm64.zip ./easyss-server
	cd $(BIN)/darwin-amd64 && rm -f ../easyss-darwin-amd64.zip && zip -r ../easyss-darwin-amd64.zip ./Easyss.app
	cd $(BIN)/darwin-amd64 && rm -f ../easyss-server-darwin-amd64.zip && zip ../easyss-server-darwin-amd64.zip ./easyss-server

# 发布资产：bin/*.zip + bin/libeasyss.aar
dist: pack easyss-android-aar

# release / nightly 的显式校验入口（CI 的构建步骤不再顺带跑 lint 与测试）
verify: lint test-race

# 只清理 CI/发布产物；本机 bin/ 根目录下的二进制、config.json、日志一概不动
clean:
	rm -rf $(PLATFORM_DIRS) $(BIN)/*.zip $(BIN)/libeasyss.aar

# ---------------------------------------------------------------------------
# 校验
# ---------------------------------------------------------------------------

format:
	$(GO) fmt ./...

test:
	$(GO) test -timeout 15m -v ./...

test-race:
	$(GO) test -race -timeout 20m -v ./...

# headless (Android/无托盘) 下只有 cmd/easyss 的文件集随该标签变化，其余包
# 完全相同，因此测试只跑 cmd/easyss；vet 用同一标签覆盖全部包的编译（含
# _test.go），「测试文件引用了托盘专属符号」这类问题由它拦住。
test-headless:
	$(GO) vet -tags headless ./...
	$(GO) test -tags headless -timeout 15m -v ./cmd/easyss/

test-race-headless:
	$(GO) vet -tags headless ./...
	$(GO) test -tags headless -race -timeout 20m -v ./cmd/easyss/

lint:
	go tool golangci-lint run --timeout 10m --verbose
	@diff="$$(go fix -diff ./...)"; \
	if [ -n "$$diff" ]; then \
		echo "Error: 'go fix ./...' has pending changes, run 'go fix ./...' until the diff is empty:"; \
		echo "$$diff"; \
		exit 1; \
	fi
