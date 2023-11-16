# pynflogpcap
## pynflog.py
同时 支持分析 nflog 和 ethernet 两种 格式的pcap包 分析 ipv4 和 ipv6的浓度测试

### 使用方法
```
python3 pynflog.py  -f uid-12141.pcap -ip4 172.21.164.52 -ip6 2408:8656:658:102:59fd:6697:74e8:b816

```
## pynflog2ethernet.py
把nflog pcap 文件转成 ethernet的pcap 文件

### 使用方法
```
python3 nflog2ethernet.py -i uid-12141.pcap  -o output.pcap
```

