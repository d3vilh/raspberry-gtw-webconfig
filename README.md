# raspberry-gtw-webconfig
Web ui configuration and installation for [Raspberry-gateway](https://github.com/d3vilh/raspberry-gateway).

![Webinstall picture 1](/images/Webinstall-01.png)


To build the webinstall binary:
```shell
go build -o webinstall main.go
```

To build the webinstall binary for specified arch (arm64) with musl-gcc:
```shell
CC=musl-gcc GOARCH=arm64 GOOS=linux go build -o webinstall main.go
```

To compress new binary with upx:
```shell
sudo apt-get install upx-ucl
upx --best webinstall
upx -t webinstall
```

If UPX is not installed, you can install it with:
```shell
wget https://github.com/upx/upx/releases/download/v4.2.4/upx-4.2.4-arm64_linux.tar.xz
tar -xf upx-4.2.4-arm64_linux.tar.xz
sudo cp upx-4.2.4-arm64_linux/upx /usr/local/bin/
```
