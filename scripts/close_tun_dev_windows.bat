@echo off

set server_ip=%1
set local_gateway=%2

route delete %server_ip% %local_gateway%
route delete 0.0.0.0 10.10.10.1
