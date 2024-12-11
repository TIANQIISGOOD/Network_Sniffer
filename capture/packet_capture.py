# 数据包捕获模块
# capture/packet_capture.py
import time
from scapy.all import sniff
import threading

class PacketCapture:
    def __init__(self, interface, filters):
        self.interface = interface
        self.filters = filters

    def start_capture(self, callback, stop_event):
        # 使用 Scapy sniff 捕获数据包，并且每次捕获一个包后检查停止信号
        def packet_handler(packet):
            callback(packet)

        sniff(iface=self.interface, prn=packet_handler, filter=self.filters,
              store=0, timeout=1)  # 使用timeout避免死锁，每秒检查一次停止信号
        if stop_event.is_set():
            print("捕获已停止")