# 数据包存储模块
from scapy.utils import wrpcap
from datetime import datetime
class PacketStorage:
    def __init__(self, filename="captured_packets.pcap"):
        self.filename = filename+datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        self.packets = []

    def add_packet(self, packet):
        self.packets.append(packet)

    def save(self):
        wrpcap(self.filename, self.packets)
