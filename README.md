# easyss

easyss是一款兼容socks5的安全上网工具，目标是使访问国外技术网站更流畅免受干扰。

有报道表明访问国外技术网站正变得越来越困难，即使用了一些常用代理技术也面临被干扰的可能性。
为了以防万一，提前准备，重新实现了一套协议以加快访问速度和对抗嗅探。

## 特性

* 支持SOCKS5,HTTP(S)代理协议

* 全平台支持(Linux，MacOS，Windows，Android，iOS等)

* (只)支持(AEAD类型)高强度加密通信, 如aes-256-gcm, chacha20-poly1305

* http2帧格式交互 (更灵活通用, 更易扩展)

* 支持tcp连接池 (默认启用，大幅降低请求延迟)

* 自动pac代理, (可选)支持全局模式, 支持系统托盘图标管理 (thanks [lantern](https://github.com/getlantern))

## 下载安装

### 在release页面直接下载(各平台)编译好的二进制文件

[去下载](https://github.com/nange/easyss/releases)

### 或者 通过源码安装(go version 1.17+ is required)

```sh
// Ubuntu20.04 or Debian11 
apt-get install libgtk-3-dev libayatana-appindicator3-dev

// Ubuntu18.04 or Debian10
apt-get install libgtk-3-dev libappindicator3-dev -y

// install fyne which deps by mobile client
go install fyne.io/fyne/v2/cmd/fyne

# build client server
make client-server

# build remote server
make remote-server

# build android apk
make easyss-android
```

## 用法

### 客户端

copy本项目中的config.json文件和上面下载的二进制文件放同一目录.
打开config.json文件, 修改里面对应的项:

* server: 服务器域名(必填，必须是域名，不能是IP)
* server_port: 服务器对应端口(必填)
* local_port: 本地监听端口(默认1080)
* password: 通信加密密钥(必填)
* method: 通信加密方式(默认aes-256-gcm)
* timeout: 超时时间,单位秒

修改完成后, 双击二进制文件，程序会自动启动，托盘会出现easyss的图标，如下:

![托盘图标](https://raw.githubusercontent.com/nange/easyss/master/img/tray.png)

右键图标可选择全局模式.

### 手机客户端

Easyss的手机客户端只是在本地启动一个Socks5 Server，然后再将流量加密转发到远端服务器，
因此还需要一个程序能将系统的流量转换为Socks5协议，再转发到Easyss的Socks5端口。

推荐使用[Kitsunebi](https://github.com/eycorsican/kitsunebi-android) 配合Easyss一起使用。

### 服务器端

和客户端一样, 先把二进制和config.json文件放同一目录.
修改config.json文件, 其中server(必须是服务器的域名)、server_port和password必填, 执行:

```sh
./remote-server
```

注意：服务器的443端口必须对外可访问，用于TLS校验使用。

#### docker部署

docker run -d --name easyss --network host nange/docker-easyss:latest -p yourport -k yourpassword -s yourdomain.com

## LICENSE

MIT License
