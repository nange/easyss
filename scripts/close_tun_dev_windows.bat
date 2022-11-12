@echo off

set tun_gw=%1
set server_ip=%2
set local_gateway=%3

route delete %server_ip% %local_gateway%
route delete 0.0.0.0 %tun_gw%
