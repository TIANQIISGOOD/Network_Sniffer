# 流量统计模块
import time
from collections import defaultdict

class TrafficStatistics:
    def __init__(self):
        self.start_time = None
        self.packet_counts = defaultdict(int)
        self.byte_counts = defaultdict(int)

    def start(self):
        self.start_time = time.time()

    def update(self, packet):
        protocol = packet.sprintf("%IP.proto%")  # 获取协议名称
        self.packet_counts[protocol] += 1
        self.byte_counts[protocol] += len(packet)

    def get_statistics(self):
        elapsed_time = time.time() - self.start_time
        stats = {
            "protocol_distribution": dict(self.packet_counts),
            "byte_distribution": dict(self.byte_counts),
            "elapsed_time": elapsed_time,
            "packet_rate": sum(self.packet_counts.values()) / elapsed_time if elapsed_time > 0 else 0,
        }
        return stats
