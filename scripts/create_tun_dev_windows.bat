@echo off

set tun_device=%1
set server_ip=%2
set local_gateway=%3

netsh interface ip set address %tun_device% static address=10.10.10.2 mask=255.255.255.0 gateway=10.10.10.1
netsh interface ip set dns name=%tun_device% static 8.8.8.8

route add %server_ip% %local_gateway% metric 5
route add 0.0.0.0 mask 0.0.0.0 10.10.10.1 metric 5
