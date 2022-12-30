# Easyss

Easyss是一款兼容socks5的安全代理上网工具，目标是使访问国外技术网站更流畅免受干扰。

有报道表明访问国外技术网站正变得越来越困难，即使用了一些常用代理技术也面临被干扰的可能性。
为了以防万一，提前准备，重新实现了一套协议以加快访问速度和对抗嗅探。

## 特性

* 简单稳定易用, 没有复杂的配置项
* 全平台支持(Linux, MacOS, Windows, Android等)
* 支持SOCKS5(TCP/UDP)、HTTP 代理协议
* 支持浏览器级别代理(设置系统代理), 和系统全局代理(基于Tun2socks,thanks [tun2socks](https://github.com/xjasonlyu/tun2socks)); 支持可选代理规则
* 支持TCP连接池 (默认启用，大幅降低请求延迟)
* 支持系统托盘图标管理 (thanks [systray](https://github.com/getlantern/systray))
* 支持可配置多服务器切换, 支持自定义直连白名单(IP/域名)
* 基于TLS, 支持(AEAD类型)高强度加密通信, 如aes-256-gcm, chacha20-poly1305
* http2帧格式交互 (更灵活通用, 更易扩展)
* 内建DNS服务器，支持DNS Forward转发，可用于透明代理部署时使用 (默认关闭，可通过命令行启用)

## 下载安装

### 在release页面直接下载(各平台)编译好的二进制文件

[去下载](https://github.com/nange/easyss/releases)

### 或者 通过源码安装(go version 1.19+ is required)

```sh
// Ubuntu20.04 or Debian11 
apt-get install libgtk-3-dev libayatana-appindicator3-dev

// Ubuntu18.04 or Debian10
apt-get install libgtk-3-dev libappindicator3-dev -y

// build easyss client
make easyss

// build easyss server
make easyss-server

```

## 用法

### 客户端
创建配置文件：`config.json`，并把配置文件放入`easyss`二进制相同目录中。

**单服务器配置文件示例：**
```json
{
  "server": "your-domain.com",
  "server_port": 9999,
  "password": "your-pass",
  "local_port": 2080,
  "method": "aes-256-gcm",
  "timeout": 60,
  "bind_all": false
}
```

**多服务器配置文件示例：**
```json
{
  "server_list": [
    {
      "server": "your-domain.com",
      "server_port": 7878,
      "password": "your-pass"
    },
    {
      "server": "your-domain2.com",
      "server_port": 9898,
      "password": "your-pass2"
    }
  ],
  "local_port": 2080,
  "method": "aes-256-gcm",
  "timeout": 60,
  "bind_all": false
}
```

**参数说明：**
* server: 服务器域名(必填，必须是域名，不能是IP)
* server_port: 服务器对应端口(必填)
* password: 通信加密密钥(必填)
* local_port: 本地监听端口(默认2080)
* method: 通信加密方式(默认aes-256-gcm)
* timeout: 超时时间,单位秒(默认60)
* bind_all: 是否将监听端口绑定到所有本地IP上(默认false)

其他还有一些参数没有列出，如无必要，无需关心。除了3个必填的参数，其他都是可选的，甚至可以不要配置文件，全部通过命令行指定即可。

如需查看完整配置参数，可执行：`./easyss -show-config-example`

保存好配置文件后，双击`easyss`，程序会自动启动，托盘会出现Easyss的图标，如下:

![托盘图标](img/tray.png)
![托盘图标](img/tray2.png)
![托盘图标](img/tray3.png)

右键图标可选择代理规则和代理对象。**注意：代理对象，选择系统全局流量时，需要管理员权限。**

**自定义直连白名单：**

对于少部分国内的IP/域名，或者部分特殊的IP/域名，可能`Easyss`没有正确识别，造成本该直连的IP/域名走了代理，
这时可在`easyss`所在目录下， 新建`direct_ips.txt`, `direct_domains.txt`， 分别用于存储直连IP列表和直连域名列表，每行一条记录。

`direct_ips.txt`文件示例：
```text
39.156.66.10
110.242.68.66
106.11.84.3
```

`direct_domains.txt`文件示例：
```text
baidu.com
taobao.com
your-custom-domain.com
```

### 手机客户端

手机客户端apk文件可直接在release页面下载。

手机客户端是基于Matsuri扩展修改而来，源代码在[Matsuri](https://github.com/bingooo/Matsuri/tree/easyss)，感谢 [bingooo](https://github.com/bingooo)

用法：创建Easyss配置项：点击右上角+图标 -> 手动输入 -> 选择Easyss

注意: 在菜单路由项里面，把绕过：中国域名规则和中国IP规则，勾选上。这样对于绝大部分国内的APP和网站就不会走代理了。

### 服务器端
和客户端一样, 同样先创建配置文件`config.json`，并配置文件和二进制`easyss-server`放同一目录中。

**服务端配置文件示例：**
```json
{
    "server": "your-domain.com",
    "server_port": 9999,
    "password": "your-pass",
    "timeout": 60
}
```
保存config.json文件, 其中server(必须是服务器的域名)、server_port和password必填, 执行:

```sh
# 需sudo权限
./easyss-server
```

**注意：服务器的443端口必须对外可访问，用于TLS校验使用。**

#### docker部署

docker run -d --name easyss --network host nange/docker-easyss:latest -p yourport -k yourpassword -s yourdomain.com

## LICENSE

MIT License
