# raspberry-gtw-webconfig
Web ui configuration and installation for [Raspberry-gateway](https://github.com/d3vilh/raspberry-gateway).

To build the webinstall binary, run the following command:
```shell
go build -o webinstall main.go
```

To compress binary with Ultimate Packer for eXecutables, run the following command:
```shell
sudo apt-get install upx-ucl
upx -9 webinstall
upx -t webinstall
```