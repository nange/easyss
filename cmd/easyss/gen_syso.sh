#!/usr/bin/env bash

# Ref: https://github.com/akavel/rsrc
rsrc -arch amd64 -manifest ./manifest.xml -ico ../../icon/icon_256_256.ico -o easyss_windows_amd64.syso
rsrc -arch arm64 -manifest ./manifest.xml -ico ../../icon/icon_256_256.ico -o easyss_windows_arm64.syso
