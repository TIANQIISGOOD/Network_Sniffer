# 协议解析模块
from scapy.layers.inet import IP, TCP, UDP, ICMP

class ProtocolParser:
    @staticmethod
    def parse(packet):
        """
        解析协议内容
        :param packet: 捕获到的网络数据包
        :return: 包的基本信息
        """
        summary = {"src": None, "dst": None, "protocol": None}
        if IP in packet:
            summary['src'] = packet[IP].src
            summary['dst'] = packet[IP].dst
            if TCP in packet:
                summary['protocol'] = 'TCP'
            elif UDP in packet:
                summary['protocol'] = 'UDP'
            elif ICMP in packet:
                summary['protocol'] = 'ICMP'
            else:
                summary['protocol'] = 'Unknown'  # 未识别的协议标记为 'Unknown'
        else:
            summary['protocol'] = 'Non-IP'  # 如果没有 IP 层，标记为 'Non-IP'
        return summary
