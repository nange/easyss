# Easyss

Easyss 是一款兼容 SOCKS5/HTTP 代理的安全上网工具，目标是使访问国外技术网站更流畅、免受干扰。

有报道表明访问国外技术网站正变得越来越困难，即使用了一些常用代理技术也面临被干扰的可能性。为了以防万一提前准备，重新实现了一套协议以加快访问速度和对抗嗅探。

**当前 master 分支对应全新的 v3，内核完全重构，性能与稳定性大幅提升。如需 v2 文档请[点击](https://github.com/nange/easyss/tree/v2)。**

## 特性

* 简单稳定易用，没有复杂的配置项；支持 IPv4/IPv6 双栈网络
* 无流量特征，不易被嗅探：底层基于真实 HTTP/2 (TLS) 传输协议，并通过流量整形、真实网页 fallback、智能连接调度等手段兼顾隐蔽性与稳定性
* 全平台支持（Linux、macOS、Windows、Android 等）
* 支持 SOCKS5（TCP/UDP，thanks [go-socks5](https://github.com/things-go/go-socks5)）与 HTTP 代理协议
* 支持浏览器代理（设置系统代理）与系统全局代理（thanks [tun2socks](https://github.com/xjasonlyu/tun2socks)），支持 `ping`（ICMP Echo）
* 支持系统托盘图标管理客户端（thanks [systray](https://github.com/gogpu/systray)）
* 可配置多服务器切换；自定义直连、代理白名单（IP/域名）
* 支持服务端链式代理

## 下载

在 [release 页面](https://github.com/nange/easyss/releases)直接下载各平台编译好的二进制文件。

**macOS 用户注意：** `Easyss.app` 未经 Apple 公证，首次双击会被 Gatekeeper 拦截（提示无法验证开发者/应用已损坏）。请在首次下载后进入 `Easyss.app` 所在目录执行：

```bash
xattr -cr ./Easyss.app
```

之后即可正常双击运行。配置文件需与程序同目录，建议将 app 放在自选目录而非 `/Applications`。源码编译请参考 `Makefile`。

## 用法

### 客户端

创建配置文件 `config.json` 并放入 `easyss` 二进制所在目录。

Easyss v3 支持两种配置模式，自动识别：

* **简化模式**：扁平 JSON，兼容 v2 配置，适合大多数用户
* **完整模式**：嵌套 JSON，支持多服务器等高级功能，需 `version: 3`

#### 简化模式（推荐，兼容 v2）

仅支持配置单一服务器，最简配置：

```json
{
  "server": "your-domain.com",
  "server_port": 443,
  "password": "your-password",
  "local_port": 4080,
  "log_file_path": "easyss.log"
}
```

**参数说明：**

| 参数 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `server` | 是 | - | 服务器地址（域名或 IP，不含端口） |
| `server_port` | 是 | - | 服务器端口 |
| `password` | 是 | - | 通信加密密钥 |
| `local_port` | 否 | 4080 | 本地 SOCKS5 监听端口。`http_port` 自动设为 `local_port + 1000` |
| `method` | 否 | aes-256-gcm | 加密方式，可选: `aes-256-gcm`, `chacha20-poly1305` |
| `proxy_rule` | 否 | auto | 代理规则，可选: `auto`, `reverse_auto`, `proxy`, `direct`, `auto_block` |
| `timeout` | 否 | 30 | 基础超时时间，单位秒，取值范围 15-60（越界取边界值）；TCP/UDP 空闲、拨号、DNS 响应与连接轮换均由它派生（见下文） |
| `bind_all` | 否 | false | 是否将监听端口绑定到所有本地 IP；开启时监听 `[::]`，系统代理与 TUN 等本机自用端点改用同族回环 `[::1]` 访问本地代理 |
| `outbound_proto` | 否 | native | 出口协议，可选: `native`, `h2`（效果相同，均为 HTTP/2） |
| `log_level` | 否 | info | 日志级别，可选: `debug`, `info`, `warn`, `error` |
| `log_file_path` | 否 | 空 | 日志文件路径，为空则输出到标准输出 |
| `direct_file` | 否 | 空 | 自定义直连文件路径（IP/CIDR/域名/正则混写，每行一条，支持 `regexp:` 和 `*` 通配符） |
| `proxy_file` | 否 | 空 | 自定义代理文件路径（IP/CIDR/域名/正则混写，每行一条，支持 `regexp:` 和 `*` 通配符） |

除 3 个必填参数外其他均为可选。未列出的字段（如 `sn`、`ca_path`、`http_port`、`ipv6_rule`、`enable_quic` 等）同样可在简化模式中使用，加载时会在内存中转换为完整模式（不回写配置文件）。配置项也可用命令行参数覆盖，见 `./easyss --help`。

执行 `./easyss -show-config-example-simple` 可查看简化模式示例。

#### 完整模式

支持所有 v3 高级功能（多服务器、流量整形、传输层调参等），最简配置示例：

```json
{
  "version": 3,
  "servers": [
    {
      "host": "your-domain.com",
      "port": 443,
      "password": "your-password"
    }
  ],
  "local": {
    "socks_port": 4080,
    "http_port": 5080
  },
  "log": {
    "level": "info",
    "file_path": "easyss.log"
  },
  "timeout": 30
}
```

> **注意**：`"version": 3` 且 `servers` 非空是识别完整模式的依据。`local.socks_port` 为 0 时不启动任何本地代理服务器；`local.http_port` 未配置时由它推导（`socks_port + 1000`）。

其余字段（`servers` 的加密方式/SNI/CA、`routing`、`transport`、`shaper`、`auth_username` 等）均有默认值，按需配置；`./easyss -show-config-example` 可查看完整示例。

**servers 参数说明（可配置多个，托盘菜单可切换）：**

| 参数 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `servers[].host` | 是 | - | 服务器主机名或 IP 字面量（不含端口；IPv6 字面量无需方括号，客户端会自动补上） |
| `servers[].port` | 否 | 443 | 服务器端口 |
| `servers[].password` | 是 | - | 通信加密密钥 |
| `servers[].method` | 否 | aes-256-gcm | 加密方式，可选: `aes-256-gcm`, `chacha20-poly1305`；必须在服务端 `allowed_methods` 允许的列表内 |
| `servers[].sn` | 否 | 空 | TLS SNI 覆盖，留空则使用 `host`。服务端用 IP 证书（IP-only 模式）时必须留空；Cloudflare 优选 IP 场景填对应域名（见"配置 Cloudflare 优选 IP"） |
| `servers[].ca_path` | 否 | 空 | 自定义 CA 证书路径（服务端使用自签证书时填写） |
| `servers[].default` | 否 | false | 是否为默认服务器；条目都不填时取列表第一个 |

> **兼容性**：旧键 `servers[].address` 等价于 `host`，新旧键同时出现会报错；`host` 必填且不得包含端口。升级是单向兼容（新二进制可读旧键），升级后请勿再用旧版本运行新配置。

**local 参数说明：**

| 参数 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `local.socks_port` | 否 | - | 本地 SOCKS5 监听端口（如 4080）；为 0 时不启动本地代理服务器，通常需要填写 |
| `local.http_port` | 否 | `socks_port + 1000` | 本地 HTTP 代理监听端口；未配置时由 `socks_port` 推导，显式配置优先。`socks_port` 为 0 时它也是 0；它非 0 而 `socks_port` 为 0 时启动会报错 |
| `local.bind_all` | 否 | false | 是否将监听端口绑定到所有本地 IP；开启时监听 `[::]`，系统代理与 TUN 等本机自用端点改用同族回环 `[::1]` 访问本地代理 |
| `local.disable_sys_proxy` | 否 | false | 是否不设置系统代理（headless 版默认会设置） |
| `local.enable_forward_dns` | 否 | false | 是否在本机所有网卡的 53 端口提供 DNS 转发（供 LAN 设备使用）。仅路由器透明代理场景，需 `socks_port > 0` 才能启动；运行中 TUN 未生效时转发器对所有查询回 REFUSED |
| `local.enable_tun2socks` | 否 | false | 是否启用 TUN 全局透明代理 |
| `local.enable_quic` | 否 | false | 是否允许 QUIC（UDP 443）走代理 |
| `local.tun_mtu` | 否 | 1500 | TUN 设备与 tun2socks 的 MTU，钳制到 [1280, 9000] |
| `local.tun_config` | 否 | 空 | TUN 参数覆盖，目前仅支持 `{"device": "my-tun9"}` 自定义设备名（简化模式下是包含该对象的字符串）；未知键或类型不匹配会报错 |

**routing 参数说明：**

| 参数 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `routing.proxy_rule` | 否 | auto | 代理规则，可选: `auto`, `reverse_auto`, `proxy`, `direct`, `auto_block` |
| `routing.ipv6_rule` | 否 | auto | IPv6 规则，可选: `auto`（网络与服务端都支持时才启用）, `enable`（强制启用）, `disable`（禁用）；填其他值等同 `disable` |
| `routing.direct_file` | 否 | 空 | 自定义直连文件路径（IP/CIDR/域名/正则混写，每行一条，支持 `regexp:` 和 `*` 通配符） |
| `routing.proxy_file` | 否 | 空 | 自定义代理文件路径（同上格式） |

**其他参数说明：**

| 参数 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `version` | 是 | - | 配置版本，完整模式固定为 `3`；字段改名（如 `address`→`host`）不改变该版本号 |
| `log.level` | 否 | info | 日志级别，可选: `debug`, `info`, `warn`, `error` |
| `log.file_path` | 否 | 空 | 日志文件路径，为空则输出到标准输出 |
| `timeout` | 否 | 30 | 基础超时时间，单位秒，取值范围 15-60（越界取边界值）；TCP/UDP 空闲、拨号、DNS 响应与连接轮换均由它派生（见下文） |
| `auth_username` | 否 | 空 | 本地代理的用户名（SOCKS5/HTTP 代理认证），留空表示不校验 |
| `auth_password` | 否 | 空 | 本地代理的密码 |
| `pprof_enabled` | 否 | false | 是否启用 pprof 调试服务（127.0.0.1:6060） |

**高级参数（`transport` / `shaper`）：**

传输层连接数、缓冲与流量整形参数均可配置，默认值适配绝大多数网络；完整字段与默认值见 `./easyss -show-config-example`。

**`timeout`（默认 30，范围 15-60）：** 基础超时，TCP/UDP 空闲、出站拨号与 DNS 响应超时都由它派生。过小会让空闲连接被频繁误杀，过大则让半开连接长时间占用资源；连接轮换到期只影响新流，进行中的流不会被打断。

#### 配置模式自动识别

* 包含 `"version": 3` 且 `servers` 非空 → **完整模式**
* 其他情况 → **简化模式**（加载时在内存中转换为完整模式，不回写配置文件）

保存好配置文件后双击 `easyss`，托盘会出现 Easyss 图标：

![托盘图标](docs/images/tray.png)

**注意：代理对象选择"系统全局流量"时，需要管理员权限。**

**开机自启动与网络尚未就绪：** 开机时 WiFi/网络往往尚未就绪，客户端不会启动失败：服务端域名解析失败只会变成一条启动警告（托盘提示"网络尚未就绪、已在后台重试"），本地代理端口照常监听，后台持续重试解析，网络恢复后自动可用。若配置了系统全局流量（Tun2socks），此时会跳过 TUN，网络恢复后在托盘菜单重新开启即可。

**无托盘（headless）版本的系统代理：** `easyss-headless`（以及 `easyss --disable-tray`）没有托盘菜单，会在本地代理启动成功后直接设置系统代理，并在退出时自动撤销；不需要时配置 `"disable_sys_proxy": true`（完整模式为 `local.disable_sys_proxy`）。

* Linux 上以 root 或 systemd 系统服务方式运行时 `gsettings`/`dbus` 通常不可达，系统代理不会生效，这类部署请改用 TUN 或手动配置代理。
* 进程被 `kill -9` 或崩溃时来不及撤销，系统代理会残留并指向已停止的本地端口，表现为"整机断网"；GNOME 下执行 `gsettings set org.gnome.system.proxy mode 'none'` 即可恢复。

**自定义直连/代理白名单：**

个别国内/国外 IP 或域名可能未被正确识别路由，可用 `direct_file` 和 `proxy_file` 自定义。在 `easyss` 所在目录下新建文本文件（如 `direct.txt`、`proxy.txt`），IP/CIDR/域名可混写，每行一条记录。

简化模式：

```json
{ "direct_file": "direct.txt", "proxy_file": "proxy.txt" }
```

完整模式：

```json
"routing": { "direct_file": "direct.txt", "proxy_file": "proxy.txt" }
```

> 配置中的相对路径（`direct_file`、`proxy_file`、`ca_path` 等）会先按当前工作目录查找，找不到时自动回退到 `easyss` 可执行文件所在目录（macOS 下为 `.app` 旁），因此从 Finder 双击、开机自启等方式启动也能正常读取。

`direct.txt` 示例（匹配到则不走代理）：

```text
39.156.66.10
206.0.68.0/23
baidu.com
# glob：匹配所有包含 "cn-" 的域名
*cn-*
# 正则：匹配 mycdn.com 及其子域名
regexp:^.*\.mycdn\.com$
```

`proxy.txt` 示例（匹配到则强制走代理）：

```text
10.0.0.0/8
google.com
# glob：匹配所有包含 "google" 的域名
*google*
# 正则：匹配包含 .youtube. 的域名
regexp:^.*\.youtube\..*$
```

**匹配规则：**

* 每行按优先级识别：`regexp:` 正则 → 含 `*` 的 glob → CIDR → IP → 域名（支持子域名）。
* 空行与以 `#` 开头的整行注释会被跳过，不支持行尾注释（`#` 可能是正则/glob 的一部分）；匹配大小写不敏感。
* 域名支持子域名匹配；IP 归一化后比较（`::ffff:1.2.3.4` 与 `1.2.3.4` 等价）。
* 路由优先级：自定义直连 > 自定义代理 > auto/geo 规则。
* 无法编译的规则会记启动告警并跳过（服务端 `next_proxy_file` 中的同样错误会让启动失败），告警带行号。

### 手机客户端

手机客户端 [EasyssTun.apk](https://github.com/nange/easyss/releases) 可直接下载，源码见 [nange/EasyssTun](https://github.com/nange/EasyssTun)。

可将常用的国内大流量 APP 勾选为跳过以减少电量消耗；不选也没关系，Easyss 会自动判断该直连还是走代理。

### 服务器端

与客户端一样，创建配置文件 `config.json` 并与二进制 `easyss-server` 放在同一目录。最简配置：

```json
{
  "version": 3,
  "server": {
    "host": "your-domain.com",
    "port": 443,
    "password": "your-password"
  },
  "log": {
    "level": "info",
    "file_path": "easyss.log"
  },
  "timeout": 30
}
```

> **注意**：`server.host` 填**你自己的真实域名**（需已解析到本服务器 IP），或**公网 IPv4 字面量**（即"不用域名"的 IP-only 模式，见下文）；除非同时配置了自定义证书（`cert_path` + `key_path`），否则此项**必填**。留空、填私有/保留地址或 IPv6 字面量都会在启动时报错。

其余字段（fallback、shaper、transport、next_proxy、pprof 等）均有默认值，按需配置；`./easyss-server -show-config-example` 可查看完整示例。

**参数说明：**

| 参数 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `server.host` | 条件必填 | - | 服务器域名或公网 IPv4 字面量，即自动申请证书时提交给 Let's Encrypt 的标识符：域名需已解析到本机 IP，公网 IP 走 IP-only 模式。留空需同时配置 `cert_path` 与 `key_path`；私有/保留地址或 IPv6 字面量会报错 |
| `server.port` | 否 | 443 | 监听端口，默认所有网卡 |
| `server.bind` | 否 | 空 | 可选监听网卡地址（主机名或 IP，不含端口）；旧键 `server.listen` 的主机部分会自动映射到这里 |
| `server.password` | 是 | - | 通信加密密钥 |
| `server.allowed_methods` | 否 | aes-256-gcm, chacha20-poly1305 | 允许的加密方式列表 |
| `server.cert_path` | 否 | - | 自定义证书路径，**必须与 `key_path` 成对配置**，只配一个会报错 |
| `server.key_path` | 否 | - | 自定义证书密钥路径，**必须与 `cert_path` 成对配置** |
| `server.email` | 否 | 随机生成 | 自动申请证书用的邮箱 |
| `fallback.target` | 否 | - | 回落目标，自动识别：空 = 内置主题页面；URL = 反向代理到上游 HTTP 服务；目录 = 按 URL path 匹配 HTML；文件 = 所有路径返回同一页面 |
| `fallback.preserve_host` | 否 | false | 仅 URL 模式生效。false：转发给上游的 Host 为上游主机（适合 GitHub 等校验 Host 的站点）；true：透传客户端原始 Host（适合依赖 `server_name` 的本地 nginx） |
| `fallback.cdn_domains` | 否 | [] | 仅 URL 模式生效。需经代理中转的 CDN 域名列表，HTML/CSP 中这些域名的绝对 URL 会被重写为 `/__cdn__/<host>/...` |
| `pprof_enabled` | 否 | false | 是否启用 pprof 调试服务（127.0.0.1:6060） |
| `timeout` | 否 | 30 | 基础超时时间，秒，范围 15-60；各项空闲/拨号/DNS 超时都由它派生，语义同客户端 |

> **自定义证书**：服务器在私有网络（无公网域名/IP）时可使用自签证书：配置 `server.cert_path` + `server.key_path`（必须成对）。证书 SAN 必须包含客户端要连接的地址，客户端需把 CA 证书填到 `servers[].ca_path`，`sn` 留空；`build/certs` 有 cfssl 示例。

> **兼容性**：旧键 `server.domain` 等价于 `host`，`server.listen`（如 `:443`、`127.0.0.1:443`）会拆成 `port` 与可选的 `bind`；新旧键同时出现会报错。升级是单向兼容。

> **窗口与调优**：服务端 HTTP/2 的 `transport.h2_max_frame_size`、`h2_recv_buf_conn` / `h2_recv_buf_stream`（连接级/流级上行窗口）与 `shaper.*`（流量整形）均可配置，默认值适配绝大多数网络，完整字段见 `-show-config-example`。上传速度上不去时可先调大上行窗口，**连接级窗口应 ≥ 流级窗口**；下载窗口由客户端决定，不可配。

> **fallback 示例**：
>
> ```json
> "fallback": { "target": "" }                                              // 内置主题页面（默认）
> "fallback": { "target": "http://127.0.0.1:8080", "preserve_host": true }  // 反代到本地 nginx
> "fallback": { "target": "https://github.com", "cdn_domains": ["githubassets.com"] } // 反代到公网站点
> "fallback": { "target": "/var/www/fallback/" }                            // 目录：/about → about.html，未匹配 → 404.html
> ```
>
> URL 模式会自动处理上游 Host 头、`Location`/HTML/CSP 中的绝对 URL、`Set-Cookie` 的 `Domain`、`Origin`/`Referer`，以及 `Accept-Encoding` 协商与 gzip 重写，无需额外配置。目录模式优先级：反向代理 > 目录 > 单文件 > 内置主题。

执行：

```sh
./easyss-server                                   # 前台运行
nohup ./easyss-server > easyss-server.log 2>&1    # 后台运行
```

**注意：未使用自定义证书时，服务器的 443 端口必须对外可访问，用于自动签发与续期的 TLS 校验（无论 `server.host` 填的是域名还是公网 IP），且需长期保持可达。`easyss-server` 需要 sudo 权限运行；如需支持 `ping`（ICMP），同样需要 sudo。**

#### 不用域名（IP-only）：用公网 IP 自动申请证书

服务器有**公网 IPv4** 且公网 443 可直接访问时，无需域名：把 `server.host` 填成该 IP，`easyss-server` 会自动向 Let's Encrypt 申请并续期一张 **IP 地址证书**。

```json
{
  "version": 3,
  "server": {
    "host": "203.0.114.1",
    "port": 443,
    "password": "your-password"
  }
}
```

客户端填同一个 IP 即可（完整模式 `servers[].host`、简化模式 `server`），`sn` 留空——证书里就是 IP。

Let's Encrypt 对 IP 证书的几条硬性规定：

* **短生命周期**：有效期约 160 小时，服务端会自动续期，无需干预；但**不要删 `certmagic/` 证书目录**——反复重签会撞速率限制（同一 IP 每 7 天最多 5 张，ARI 协调的续期不计入）。
* **只能用 tls-alpn-01 验证**：公网 443 在首次签发与每次续期时都要能被 Let's Encrypt 访问；`server.port` 不是 443 时需把公网 443 转发到它。
* **必须是公网地址**：私有/保留/CGNAT 地址（如 `10.x`、`192.168.x`、`100.64.0.0/10`）无法签发，这类部署请用自定义证书；`host` 填这类地址会启动报错。IPv6 字面量暂不支持。
* 证书会进入 CT 日志（可用 crt.sh 搜索该 IP）；客户端访问该 IP 时不发送 SNI。

#### Docker 部署

```sh
docker run -d --name easyss --network host nange/docker-easyss:latest -p yourport -k yourpassword -s yourdomain.com
```

## 高级用法

### 服务器部署在反向代理（或 CDN）之后

Easyss v3 以 HTTP/2 作为传输层，天然兼容反向代理和 CDN 部署：把 Nginx、Cloudflare 等反向代理的流量转发到 `easyss-server` 的监听端口，客户端填反向代理的地址和端口即可，无需额外设置。

### 配置 Cloudflare 优选 IP

可将 Cloudflare CDN 作为反向代理并把流量转发给 Easyss，配合优选 IP 通常能改善访问速度。简化模式把 `server` 配为优选 IP、`sn` 配为 Cloudflare 后台的域名；完整模式对应 `servers[].host` 与 `servers[].sn`。

与 IP-only 模式相反：那里 `sn` 必须留空（证书里就是 IP），这里 `sn` 必须是域名（证书是 Cloudflare 为你的域名签发的）。

### 作为透明代理部署在路由器或软路由上

将 Easyss 部署在路由器/软路由上，可让家里或公司网络自动透明代理，无需在终端设备安装客户端。简化模式设置 `enable_tun2socks: true` 和 `enable_forward_dns: true`，完整模式设置 `local.enable_tun2socks` 与 `local.enable_forward_dns`。

两个开关缺一不可，且 `socks_port` 必须有效（`enable_forward_dns` 的查询要靠 TUN 回到本机 SOCKS5 再按域名分流；缺 `socks_port` 时启动直接失败）：

* `enable_tun2socks`：在本机建立全局透明代理（TUN 网卡 + 路由表），让经过这台主机的流量按域名/GeoIP 分流后走代理。
* `enable_forward_dns`：在本机所有网卡的 53 端口提供 DNS 转发（UDP、双栈），供 LAN 设备当解析器使用。

**`enable_forward_dns` 只为"路由器透明代理"存在，运行时必须保持 TUN 开启。** LAN 设备发给路由器自身的 DNS 查询在内核里本地投递，不会进 TUN，所以由这个转发器接住再向上游发一次：上游是公网解析器，地址落在 TUN 的默认路由内，查询因此重新进入 TUN，经代理侧的 DNS 拦截按域名分流（该屏蔽的屏蔽、该直连的直连）。转发器自身不屏蔽、不缓存。转发器逐条读运行期 TUN 状态：TUN 未生效（没开、启动失败、被托盘关掉）时对所有 LAN 查询回 REFUSED，而不是降级成物理网卡上的直连解析（DNS 泄漏）。启动期只校验 `socks_port > 0`；TUN 由运行期闸门把关，因为托盘切换服务器/重启时会先把 TUN 偏好临时置 false 再起核心。

还需在路由器上完成两件事：

1. 把 LAN 侧（DHCP 下发）的 DNS 指向这台路由器的 LAN IP（如 `192.168.1.1`）。只改 DNS 而网关不指向它时，设备能解析域名但连接不经过这台主机，也就不会被代理。
2. 放行 UDP 53（**不要在公网侧放行**，否则就是开放解析器）。

若 53 端口被占用，Easyss 会启动失败，常见占用者是 `dnsmasq` 与 `systemd-resolved`，需先停用它们的 DNS 监听（如 dnsmasq 设 `port=0` 只保留 DHCP）。该转发只监听 UDP 53：LAN 客户端因截断应答改用 TCP 53 重试的查询不会被应答，受影响的环境请让客户端直连上游解析器，或用 dnsmasq 承接 TCP 查询后再转发到本服务。

TUN 网卡的 MTU 由 `tun_mtu` 统一控制（默认 1500，钳制到 [1280, 9000]）；调大（如 8500）可减少包数与系统调用，但会抬高本机 UDP/ICMP 报文的尺寸上限，默认值对绝大多数网络已足够。

视需要开启 IP 转发：

```bash
# /etc/sysctl.conf
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1   # 需要 IPv6 转发时一并开启
sysctl -p
```

### 服务端链式代理

服务端（`easyss-server`）支持把请求再次转发给下一级代理（目前仅支持 SOCKS5），在服务端配置中指定 `next_proxy`：

```json
{
  "next_proxy": {
    "url": "socks5://your-ip:your-port",
    "next_proxy_file": "next_proxy.txt",
    "enable_udp": false,
    "all_host": false
  }
}
```

* `next_proxy.url`：下一级代理地址，格式 `socks5://ip:port`
* `next_proxy.next_proxy_file`：走链式代理的 IP/CIDR/域名列表文件，格式与客户端 `direct_file`/`proxy_file` 一致；区别是无法编译的规则会让服务端**启动失败**（而不是只记告警）
* `next_proxy.enable_udp`：是否转发 UDP（需下一级代理支持 UDP ASSOCIATE）。开启前请确认，否则这些 UDP 目标会全部超时（TUN 模式下表现为所有域名都解析不出来）
* `next_proxy.all_host`：是否对所有请求走链式代理；未指定 `next_proxy_file` 时仅按它决定

## LICENSE

MIT License
