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
* 支持节点组网(VPN)：多个 easyss 节点之间互相访问对端自身的服务端口，DERP 中继由 easyss 服务端内嵌，不依赖任何官方服务

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
| `local.enable_forward_dns` | 否 | false | 是否在本机所有网卡的 53 端口提供 DNS 转发（供 LAN 设备使用） |
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

两个开关缺一不可：

* `enable_tun2socks`：在本机建立全局透明代理（TUN 网卡 + 路由表），让经过这台主机的流量按域名/GeoIP 分流后走代理。
* `enable_forward_dns`：在本机所有网卡的 53 端口提供 DNS 转发（UDP、双栈），供 LAN 设备当解析器使用；只转发，不做屏蔽/缓存。

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

### 节点组网(VPN)

多个 easyss 节点之间可以互相访问**对端自身的服务端口**（sshd 的 22、Web 的 8080、
数据库的 3306 等），从而支持节点间 SSH / HTTP / 数据库互通。DERP 中继由 easyss
服务端内嵌，**不依赖 Tailscale 官方服务**，也不需要在服务端做任何配置之外的部署。

中继本身是**私有端点**：它只接待经 easyss 协议隧道到达的连接，公网上访问 `/derp`
只会看到与其他未知路径一致的伪装页面。因此不存在"拿你的域名当免费中继"的问题，
也不需要为它开放额外端口。

**同一个 region 下可以有多台中继**（多个 `derp: true` 的服务端条目，互为冗余），
它们之间可以组成 mesh：挂在不同中继上的客户端互相发包时，由服务端沿 mesh 连接转发
一跳（不跨 region），因此"同一 region 的两个客户端落在了不同中继上"不会再导致它们
失联。运行上的四条硬约束：

* **同一 region 最多 3 台中继（推荐 1-2 台）**。mesh 是全互联（每台中继都列出其余
  每一台），而节点地址里内嵌的正是这一组中继，因此两侧都把上限当作配置加载阶段的
  硬约束、**超过就报错拒绝启动**（不会带着一个谁也连不上的中继跑起来）：服务端
  `server.vpn.mesh_peers` 最多 2 条（本机 + 2 个对端），节点 `servers[]` 里标记
  `"derp": true` 的条目最多 3 条（规范化去重后，同一个中继写多遍只算一条）。
  节点侧的校验只在 `vpn.enabled=true` 时生效——没启用 VPN 的配置不参与运行期；
  `./easyss vpn identity` 走的是同一份校验，越限时它报的就是这条配置错误。
* **当前服务端必须在声明的中继列表里**。内嵌 DERP 只接待经**本服务端**隧道送达的
  连接，所以节点实际能连上的中继只能是它此刻隧道所落的那台服务端。`vpn.enabled=true`
  时若当前服务端不在列表里，启动日志会给出 `level=ERROR`（提示"服务器不在声明的
  DERP 列表中"），**本会话的 VPN 不工作**（代理照常可用）。托盘版还会弹出系统通知
  （"VPN 功能不生效：当前使用的服务器 … 不在 vpn 声明的中继(DERP)列表里"）——**启动**
  与**切换服务器**两条路径都会弹，判据用的是**运行中会话实际使用**的那台服务器，因此
  在托盘里点了另一台服务器之后立刻按新服务器重新判定。修法是把 `servers[]` 里
  对应该服务端的条目也标上 `"derp": true`，再用 `./easyss vpn identity` 读出
  新的地址（地址由配置推导，改了配置它自己就会变）。
* **所有节点必须声明同一组中继**。对端地址里内嵌的 DERP 节点集合与本节点不一致时
  启动即报错（缺一个节点就可能让某一侧在耗尽列表后彻底连不上）。
* **mesh 是可选的**，且只在服务端之间配置：没配 mesh 时跨中继的客户端收不到对方的
  数据包（包被丢弃并回 `PeerGoneReasonNotHere`），同中继内的客户端不受影响。

地址里内嵌 DERP 节点集合：由 `servers[]` 里全部 `derp: true` 的条目派生；没有任何
条目标记时回退**当前连接的服务端**（因此切换服务端会让地址变化，要对端跟着更新——
要稳定的多节点地址就把每一个中继都标记上）。这里**没有**"显式覆盖"的字段：地址里
那几个 `host:port` 必须与该中继所在服务端的对外地址逐字一致（服务端靠完全匹配把它
认成"来访问我的 DERP"并改拨回环），而那个对外地址只由服务端的 `server.domain` 与
`server.listen` 的端口推导——端口转发/反向代理这类"对外 host:port 与监听不同"的
形态明确不支持。

> **升级说明**：`server.vpn.derp_addr` 与 `vpn.derp_addr` 已移除。老配置里留着它们
> 不影响启动（未知键被忽略），但启动日志里会出现一条 `was removed and is ignored`
> 的 `WARN`：请删掉那一行，并确认 `servers[]` 里对应的条目带 `"derp": true`。

节点的 DERP 连接由一个专门的拨号器送进 easyss 隧道（tailcat 的 `DERPDialer`
选项，见 `go.mod` 里的两个 `replace`：`tailscale.com` 与
`github.com/tailscale/tailcat`）。该选项目前由本地 fork 提供，上游合并前请按
`go.mod` 注释切换 replace 的形态。

#### 1. 服务端（DERP 中继主机 S1）

```jsonc
{
  "server": {
    "listen": ":443",
    "domain": "a.example.com",
    "password": "your-password",
    "vpn": {
      "enabled": true,
      // 没有 derp_addr 这样的字段：本服务端对外通告的 DERP 地址恒等于
      // domain + listen 的端口（这里即 a.example.com:443），节点侧从
      // servers[] 的 "derp": true 标记里拿到同一个值。
      // 可选：同 region 其他中继的互联。两个字段要么都给，要么都不给。
      // mesh 是全互联，所以 mesh_peers 最多 2 条：本机 + 对端 = 同一 region
      // 最多 3 台中继（推荐 1-2 台），超过会让服务端启动失败。
      // mesh_key 是这组中继共享的口令（任意字符串，内部 SHA-256 成 32 字节密钥）。
      "mesh_key": "a-long-shared-passphrase",
      "mesh_peers": [
        // addr 必须等于对端自己的 DERP 地址（它的 domain + listen 端口）。
        // proxy 是把这条连接送进隧道的 SOCKS5——通常是本机上指向该对端的
        // easyss-headless 的 socks 端口；省略时用顶层 next_proxy.url。
        { "addr": "b.example.com:443", "proxy": "socks5://127.0.0.1:1081" }
      ]
    }
  }
}
```

mesh 连接的完整路径是：本机内嵌 DERP → 上面那个 SOCKS5 → easyss-headless 的隧道 →
对端 easyss 服务端（握手目标正是它自己的 DERP 地址）→ 对端回环上的内嵌 DERP。
这不是"优化"，而是唯一可能成功的形态：内嵌 DERP 只接待回环来源，直连对端公网
`host:port` 只会拿到伪装页面。因此每个 mesh 对端都需要**一条指向它的隧道**（
N 台中继的全互联 = 每台 N-1 个 easyss-headless，各自只连一个对端；N ≤ 3），并且该
客户端的
分流规则不能把对端域名判成直连（用 `auto`/`proxy`，别用 `direct`）。

对端使用手工证书/私有 CA 时，用 `mesh_peers[].ca_file` 给出根证书；用 certmagic
（Let's Encrypt）时留空即可。

#### 2. 节点

每个节点都要在 `servers[]` 里为**每一台**运行内嵌 DERP 的服务端各留一条条目，并全部
标记 `derp: true`（DERP 位置从这些条目派生；最多 3 条，推荐 1-2 条，超过 3 条启动
即报错）：

```jsonc
{
  "servers": [
    { "address": "a.example.com", "port": 443, "password": "...", "derp": true, "default": true },
    { "address": "b.example.com", "port": 443, "password": "...", "derp": true }
  ],
  "vpn": {
    "enabled": true,
    "relay_only": true,      // 默认 true：全部经服务端中继，不走节点间直连
    "peer_port": 6080,       // 可省略：socks_port + 2000
    "peers": [
      { "host_name": "b", "address": "tcXXXXXXXX..." }
    ]
  }
}
```

#### 3. 首次配置：两个 key 的收件人不同

在节点 X 上执行 `./easyss vpn identity` 可以拿到两样东西，**它们要填到对端**：

```
client nodekey（填到对端的 vpn.allow_clients）:
  nodekey:1fb017cf...

地址内嵌的 derp 节点（region 901，按此顺序尝试）:
  a.example.com:443, b.example.com:443

node address（填到对端的 vpn.peers[].address；属于秘密）:
  tcpGFwWCAx7-xt-F...
```

| 拿到的东西 | 填到哪里 | 作用 |
|---|---|---|
| `client nodekey`（`nodekey:...`） | 对端的 `vpn.allow_clients` | 对端面据此识别访问侧（可选硬化） |
| `node address`（`tc...`） | 对端的 `vpn.peers[].address` | 内嵌公钥 / DERP 位置 / preshared key |

中继列表那块就是地址里包含的 derp 节点；当前服务端不在该列表里时会额外打印一块
`注意：...`（见上面的第一条硬约束）。地址同时也写在 `<exe>/vpn/peer.txt` 里。

**地址本身是秘密**：它内嵌 preshared key，拿到地址就等于拿到对端面的接入能力。因此
**启动日志刻意不打印地址**（只有 `address_file` 指向那个文件），要分发地址请从
`./easyss vpn identity` 或该文件复制。

地址是 `(身份文件, 当前 servers[] 派生出的中继集合)` 的函数，**不落盘**：改了
`servers[]` 里的 `derp` 标记之后重新执行一次命令就是新地址，不需要"重新生成"。
需要换的是**身份本身**（例如私钥泄漏、想换掉内嵌的 preshared key）：

```bash
./easyss vpn identity                 # 打印 client nodekey 与地址（--json 便于脚本消费）
./easyss vpn regen --dry-run          # 只预览一份新身份，不写任何文件（见下）
./easyss vpn regen                    # 两个都换（= --node --client）
./easyss vpn regen --node             # 只换 node-identity.json：地址变，client nodekey 不变
./easyss vpn regen --client           # 只换 client.key：client nodekey 变，地址不变
```

`--dry-run` 的密钥是每次调用现生成的，因此它只回答"新身份长什么样"，预览出来的地址
**不会**与随后真写的那次相同——不要把 dry-run 打印的地址分发给对端，真写完再抄。
真写时（含 `--node`）会同步刷新 `<exe>/vpn/peer.txt`，那个文件始终是当前身份的地址。

被替换掉的旧身份备份为 `<file>.bak`，**每次重新生成都覆盖它**，因此每个文件最多只留
一份备份——它就是"上一次生效的身份"，也是回滚点：把 `.bak` 拷回原名即完成回滚。因此
**换完必须更新每个对端**：地址变了要改对端的 `vpn.peers[].address`，nodekey 变了要改
对端的 `vpn.allow_clients`（没配白名单则无感）。`./easyss vpn identity` 在检测到当前
身份与备份不同（即还没回滚、也没重新分发）时会额外打一块 `提示：...`，提醒手上的
地址还是旧的，并说明如何用备份回滚。

#### 4. 访问对端

```bash
# 非 TUN：用现有代理 SOCKS5 端口
curl --socks5-hostname 127.0.0.1:4080 http://b:8080/
ssh -o ProxyCommand="nc -X 5 -x 127.0.0.1:4080 b 22" user@b

# TUN 模式（系统全局流量）：不需要任何代理参数
curl http://b:8080/
ssh user@b
```

非 TUN 时请显式使用 SOCKS5 端口：HTTP 代理入口（系统代理里配置的那个）不参与
节点组网的分流，访问对端名字需要走 SOCKS5。

#### 5. 边界与注意事项

* **只能访问对端自身的服务**：对端面只接受字面 loopback 目标，因此对端不可能成为
  内网跳板；只绑在某个内网 IP 上的服务不可达。
* TUN 模式（系统全局流量）与 `relay_only=false` 不兼容：TUN 会把节点间直连的 UDP
  报文捕获并送回 easyss 自己。配置里 `relay_only` 默认就是 `true`；若显式关掉它，
  启动时若已启用 TUN 会被强制置回（并打警告），运行中再打开 TUN 则会被拒绝并提示。
* **不支持 ICMP**：`ping b` / traceroute 到对端不通，VPN 只承载 TCP 与 UDP。
* UDP 单包上限 1232 字节，适合 DNS / QUIC 首包，不适合大包高带宽 UDP。
* 没有节点自动发现：对端地址由运维配置。
* mesh 只在服务端之间、只转发一跳、不跨 region；mesh 未配或对端不可用时，跨中继的
  数据包按 `PeerGoneReasonNotHere` 丢弃（同中继内不受影响）。
* **规模上限是同一 region 3 台中继（推荐 1-2 台）**：服务端 `mesh_peers` 最多 2 条、
  节点最多标记 3 条 `"derp": true`（规范化去重后），两侧都在配置加载阶段报错拒绝
  启动（`vpn.enabled=false` 时节点侧不校验）。
* **当前服务端必须在声明的 DERP 列表里**（见上）：否则 VPN 本会话不工作，日志给出
  一条 ERROR，代理功能不受影响。
* 客户端会按地址里节点的顺序尝试中继：不在它隧道落点上的节点会由服务端直连出去并被
  伪装页面拒绝（快速失败），随后自动落到它自己的那台上。
* 地址长度随中继节点数增长。
* **Android 客户端暂不支持 VPN**：DERP 连接走的是 tailcat 的拨号器选项（见下），
  库层面在 Android 上同样可用；缺的是移动端的 VPN 配置入口与状态目录（当前非目标）。
* `vpn.enabled=false`（默认）时对现有功能零影响。

## LICENSE

MIT License
