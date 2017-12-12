## easyss

easyss是一款兼容socks5的安全上网工具，目标是使访问国外技术网站更流畅免受干扰。

有报道表明访问国外技术网站正变得越来越困难，即使用了一些常用代理技术也面临被干扰的可能性。 
为了以防万一，提前准备，重新实现了一套协议以加快访问速度和对抗嗅探。

## 特性

* 兼容SOCKS5

* (只)支持(AEAD类型)高强度加密通信, 如aes-256-gcm, chacha20-poly1305

* http2帧格式交互 (更灵活通用, 更易扩展)

* 基于QUIC协议的流多路复用 (实验性支持，默认关闭，可以通过指定-quic参数开启。thanks [quic-go](https://github.com/lucas-clemente/quic-go))

* 支持tcp连接池 (默认启用，大幅降低请求延迟)

* 自动pac代理, (可选)支持全局模式, 支持系统托盘图标管理 (thanks [lantern](https://github.com/getlantern))


注: 由于QUIC基于UDP协议，由于运营商会限制出口UDP流量，稍微大一点的流量都会出现严重丢包，
所以目前QUIC协议不适合用于大流量应用，如下载大文件，在线观看高清视频等。 

## 当前版本

1.0 正式版


## 安装

#### go get 安装最新开发版(version 1.9+ is required)

```sh
go get -u -v github.com/nange/easyss
```

#### 在release页面直接下载(各平台)编译好的二进制文件

[点我去下载](https://github.com/nange/easyss/releases)


## 用法

#### 客户端

copy本项目中的config.json文件和上面下载的二进制文件放同一目录.
打开config.json文件, 修改里面对应的项:
* server: 服务器ip或者域名(必填)
* server_port: 服务器对应端口(必填)
* local_port: 本地监听端口(默认1080)
* password: 通信加密密钥(必填)
* method: 通信加密方式(默认aes-256-gcm)
* timeout: 超时时间,单位秒

修改完成后, 双击二进制文件，程序会自动启动，托盘会出现easyss的图标，如下:

![托盘图标](https://raw.githubusercontent.com/nange/easyss/master/img/tray.png)

右键图标可选择全局模式. 


#### 服务器端

和客户端一样, 先把二进制和config.json文件放同一目录. 
修改config.json文件, 其中server_port和password必填, 执行:
```sh
./easyss -server 
```

##### docker部署

docker run -d --name easyss -p yourport:yourport nange/docker-easyss:latest -p yourport -k yourpassword


### LICENSE

MIT License


