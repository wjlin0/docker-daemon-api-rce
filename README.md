# docker未授权漏洞

> 练习 go 写 poc

## 用法
```bash
go get -u -v github.com/wjlin0/docker-daemon-api-rce
docker-daemon-api-rce -u tcp://localhost:2375
```


## 编译
```bash
git clone https://github.com/wjlin0/docker-daemon-api-rce

cd docker-daemon-api-rce && chmod +x build.sh && ./build.sh
```
