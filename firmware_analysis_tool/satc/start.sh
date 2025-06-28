#!/bin/bash

# 更改挂载目录的权限
chown -R satc:satc /home/satc/SaTC/firmware_extracted /home/satc/SaTC/output

# 以 satc 用户的身份执行 satc.py
exec python /home/satc/SaTC/satc.py "$@"