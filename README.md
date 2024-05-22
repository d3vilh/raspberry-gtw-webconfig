# raspberry-gtw-webconfig
Web ui configuration and installation for [Raspberry-gateway](https://github.com/d3vilh/raspberry-gateway).

![Webinstall picture 1](/images/Webinstall-01.png)


To build the webinstall binary:
```shell
go build -o webinstall main.go
```

To build the webinstall binary for specified arch (arm64):
```shell
GOARCH=arm64 GOOS=linux go build -o webinstall main.go
```

To compress new binary with upx:
```shell
sudo apt-get install upx-ucl
upx --best webinstall
upx -t webinstall
```