from   scapy.all import *
from   scapy.layers.inet import IP
import argparse
import dpkt
import struct
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

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

# 将nflog数据包转换为以太网数据包
def convert( infilename, outfilename ):

    ethernet_packets = []    
    packets = rdpcap( infilename )
    # 读取nflog数据包
    for packet in packets:
        # 跳过 nflog 的头部，找到ip层
        packet_bytes = bytes(packet)
        ip_raw, family  = skip_nflog(packet_bytes)
        if family == 2:        # IPv4
            ip_packet = IP(ip_raw)
        elif family == 10:     # IPv6
            ip_packet = IPv6(ip_raw)
        else:
            print('Unknown ip family ', family)
            continue
        
        # 伪造一个以太网数据包 + 原来真实的ip数据包
        ethernet_packet = Ether() / ip_packet
        ethernet_packets.append(ethernet_packet)
    wrpcap(outfilename, ethernet_packets)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='nflog2ethernet.py')
    parser.add_argument('-i', type=str, help='input ilename')
    parser.add_argument('-o', type=str, help='out ilename')

    args = parser.parse_args()
    infilename = args.i
    outfilename = args.o
        
    # 先检查是否是nflog数据包
    datalinktype = get_datalinktype(infilename)
    if datalinktype != 'nflog':
        print('Not nflog data')
        exit(1)
    convert(infilename, outfilename)
    
