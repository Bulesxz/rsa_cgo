#关于rsa 签名 使用 cgo (openssl) 和golang 原生库 对比

#运行
go get github.com/Bulesxz/rsa_cgo

go test -bench="."

#测试环境:
```
硬件概览：
  型号名称：	MacBook Pro
  型号标识符：	MacBookPro13,2
  处理器名称：	Intel Core i5
  处理器速度：	3.1 GHz
  处理器数目：	1
  核总数：	2
  L2 缓存（每个核）：	256 KB
  L3 缓存：	4 MB
  内存：	16 GB

os: osx 10.12.3

openssl: OpenSSL 1.1.0f  25 May 2017

golang: go version go1.8.3 darwin/amd64

```
#经过测试 发现cgo openssl 的性能是 golang 的 5倍左右 ，5倍！！！！！
```
BenchmarkGoRsa-4            2000            670399 ns/op
BenchmarkCgoRsa-4          10000            122419 ns/op
```

#场景应用
使用golang rsa 签名的 高并发 程序，比如聚合支付相关（支付宝API)

# 注意
本人的openssl 安装在 /usr/local/Cellar/openssl@1.1/1.1.0f/ 不在此目录的可以视情况而改动 makefile