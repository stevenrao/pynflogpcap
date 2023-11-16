from   scapy.all import *
from   scapy.layers.inet import IP
import argparse
import dpkt
import struct

class Stats:
    def __init__(self):
        self.ip4_size = 0
        self.ip6_size = 0
        self.ip4_count = 0
        self.ip6_count = 0

# 获取数据链路类型
def get_datalinktype( filename ):
    with open(filename, 'rb') as f:
        # Read global header
        global_header = f.read(24)
        magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network = struct.unpack('<IHHiIII', global_header)
        if network == 239:
            return 'nflog'
        elif network == 1:
            return 'ethernet'
        else:
            return 'unknown'

# 跳过nflog层数据
def skip_nflog( nflog_packet ):
    # NFLOG 头部长度应为 4 字节
    NFLOG_HDR_LEN = 4
    nflog_hdr = nflog_packet[:NFLOG_HDR_LEN]
    nflog_packet = nflog_packet[NFLOG_HDR_LEN:]
    
    # 解码 NFLOG 头部数据
    family, version, res_id = struct.unpack('>BBH', nflog_hdr)
    # print('Family: ', family)
    # print('Version: ', version)
    # print('Resource id: ', res_id)

    # 跳过所有tlv
    while nflog_packet:
        # 解码 tlv 头部
        tlv_len, tlv_type = struct.unpack('<HH', nflog_packet[:4])
        # print('TLV type: ', tlv_type)
        # print('TLV len: ', tlv_len)
        #TLV Type: NFULA_PAYLOAD (9)
        if tlv_type == 9: 
            nflog_packet = nflog_packet[4:]
            break
        # 跳过 tlv 数据, tlv_len 要对齐 4 字节
        tlv_len = (tlv_len + 3) & ~3
        nflog_packet = nflog_packet[tlv_len:]
        
    return nflog_packet, family

# 分析nflog的数据包
def parse_nflog_one_packet( packet, stats, ip4_addr = None, ip6_addr = None ):
    # 跳过 nflog 的头部，找到ip层
    packet_bytes = bytes(packet)
    ip_raw, family  = skip_nflog(packet_bytes)
    # 分析 ip4 层
    if family == 2:
        ip4 = IP(ip_raw)
        # 获得 源 。目的地址 和 包大小
        src = ip4.src
        dst = ip4.dst
        size = ip4.len
        if ip4_addr == None or src == ip4_addr or dst == ip4_addr:
            stats.ip4_size += size
            stats.ip4_count += 1
        # print("ip4 src: %s =======> dst: %s size: %s" % (src, dst, size))
    # 分析 ip6 层
    elif family == 10:
        ip6 = IPv6(ip_raw)
        # 获得 源 。目的地址 和 包大小
        src = ip6.src
        dst = ip6.dst
        size = ip6.plen
        if ip6_addr == None or src == ip6_addr or dst == ip6_addr:
            stats.ip6_size += size
            stats.ip6_count += 1
        # print("ip6 src: %s =======> dst: %s size: %s" % (src, dst, size))
    else:
        print('Unknown ip family: ', family)

# 分析普通以太网数据包
def parse_ethernet_one_packet( packet, stats ,ip4_addr = None, ip6_addr = None ):
    # 分析 ip4 层
    if packet.haslayer(IP):
        ip4 = packet[IP]
        # 获得 源 。目的地址 和 包大小
        src = ip4.src
        dst = ip4.dst
        size = ip4.len
        if ip4_addr == None or src == ip4_addr or dst == ip4_addr:
            stats.ip4_size += size
            stats.ip4_count += 1
        # print("ip4 src: %s =======> dst: %s size: %s" % (src, dst, size))
    # 分析 ip6 层
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        # 获得 源 。目的地址 和 包大小
        src = ip6.src
        dst = ip6.dst
        size = ip6.plen
        if ip6_addr == None or src == ip6_addr or dst == ip6_addr:
            stats.ip6_size += size
            stats.ip6_count += 1
        # print("ip6 src: %s =======> dst: %s size: %s" % (src, dst, size))
    else:
        print('Unknown  family: ', packet.payload.__class__.__name__)


def parse_pcap( filename, ip4_addr = None, ip6_addr = None  ):
    linktype = get_datalinktype(filename) 
    packets = rdpcap( filename )
    stats = Stats()
    for packet in packets:
        if linktype == 'nflog':
            parse_nflog_one_packet( packet, stats )
        elif linktype == 'ethernet':
            parse_ethernet_one_packet( packet, stats )
            
    return stats

# 打印 IPv4 和 IPv6 数据包的数量和占比
def print_stats( stats ):
    total_count = stats.ip4_count + stats.ip6_count
    total_size = stats.ip4_size + stats.ip6_size

    if total_count > 0:
        print('ip4 count: %d (%.2f%%) , ip6 count: %d (%.2f%%)' % (stats.ip4_count, stats.ip4_count / total_count * 100, stats.ip6_count, stats.ip6_count / total_count * 100))
    if total_size > 0:
        print('ip4 size: %d (%.2f%%) , ip6 size: %d (%.2f%%)' % (stats.ip4_size, stats.ip4_size / total_size * 100, stats.ip6_size, stats.ip6_size / total_size * 100))

if __name__ == '__main__':
    # python3 pynflog.py  -f uid-12141.pcap -ip4 172.21.164.52 -ip6 2408:8656:658:102:59fd:6697:74e8:b816
    # 通过参数传入 ip4 地址 和 ip6 地址, 获取ip4 地址 和 ip6 地址
    # 创建解析器
    parser = argparse.ArgumentParser(description='Process IP addresses.')
    parser.add_argument('-f', type=str, help='filename')
    parser.add_argument('-ip4', type=str, help='An IPv4 address')
    parser.add_argument('-ip6', type=str, help='An IPv6 address')

    # 解析命令行参数
    args = parser.parse_args()

    # 打印出解析得到的 IPv4 和 IPv6 地址
    print('filename: ', args.f )
    print('IPv4: ', args.ip4)
    print('IPv6: ', args.ip6)

    stats = parse_pcap( args.f, args.ip4, args.ip6)
    # 打印 ip 4 和 ip6 的比例
    print_stats( stats )
