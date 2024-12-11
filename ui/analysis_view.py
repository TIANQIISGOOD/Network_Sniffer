import matplotlib.pyplot as plt
from collections import defaultdict

class DynamicAnalysis:
    def __init__(self, frame):
        self.frame = frame
        self.packet_data = []  # 用于存储捕获的数据包
        self.protocol_counts = defaultdict(int)  # 用于统计协议分布
        self.ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.packet_sizes = []
        # 绑定窗口关闭事件
        self.frame.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        """当窗口关闭时，清理图形资源"""
        self.cleanup_resources()
        self.frame.quit()  # 关闭 Tkinter 主循环

    def cleanup_resources(self):
        """确保在主线程中清理图形资源"""
        self.frame.after(0, self._cleanup)

    def _cleanup(self):
        """在主线程中执行资源清理"""
        plt.close()  # 关闭当前图形窗口
        print("Resources cleaned up.")


    def add_packet(self, packet):
        """将捕获的数据包添加到分析数据中"""
        self.packet_data.append(packet)

        # 解析协议
        protocol = self._get_protocol(packet)
        if protocol:
            self.protocol_counts[protocol] += 1
        else:
            print("No protocol found in packet!")

        # 更新IP计数
        if packet.haslayer('IP'):
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            self.ip_counts[src_ip] += 1
            self.ip_counts[dst_ip] += 1

        # 更新端口计数
        if packet.haslayer('TCP') or packet.haslayer('UDP'):
            src_port = packet['IP'].sport if packet.haslayer('IP') else None
            dst_port = packet['IP'].dport if packet.haslayer('IP') else None
            if src_port:
                self.port_counts[src_port] += 1
            if dst_port:
                self.port_counts[dst_port] += 1

        # 更新数据包大小
        self.packet_sizes.append(len(packet))

    def _get_protocol(self, packet):
        """获取数据包的协议名称"""
        if packet.haslayer("TCP"):
            return "TCP"
        elif packet.haslayer("UDP"):
            return "UDP"
        elif packet.haslayer("ICMP"):
            return "ICMP"
        elif packet.haslayer("ARP"):
            return "ARP"
        else:
            return None  # 如果没有匹配的协议，返回 None



    def _draw_protocol_distribution(self, labels, sizes):
        """在主线程中绘制图表"""
        plt.figure(figsize=(6, 4))
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
        plt.title("protocol")
        plt.show()

    def visualize_protocol_distribution(self):
        """生成流量协议分布的可视化图表"""
        labels = list(self.protocol_counts.keys())
        sizes = list(self.protocol_counts.values())
        if sizes:  # 只有在存在数据时才绘制
            # 使用 after 调度在主线程中绘制图表
            self.frame.after(0, self._draw_protocol_distribution, labels, sizes)
        else:
            print("No protocol data available.")


    def _draw_ip_distribution(self, labels, sizes):
        """绘制IP地址分布的图表"""
        plt.figure(figsize=(6, 4))
        plt.bar(labels, sizes, color='skyblue')
        plt.xlabel("IP Addresses")
        plt.ylabel("Frequency")
        plt.title("IP")
        plt.xticks(rotation=45)
        plt.show()

    def visualize_ip_distribution(self):
        """生成IP地址分布的可视化图表"""
        labels = list(self.ip_counts.keys())
        sizes = list(self.ip_counts.values())
        self.frame.after(0, self._draw_ip_distribution, labels, sizes)


    def _draw_port_distribution(self, labels, sizes):
        """绘制端口分布的图表"""
        plt.figure(figsize=(6, 4))
        plt.bar(labels, sizes, color='salmon')
        plt.xlabel("Ports")
        plt.ylabel("Frequency")
        plt.title("port")
        plt.xticks(rotation=45)
        plt.show()

    def visualize_port_distribution(self):
        """生成端口分布的可视化图表"""
        labels = list(self.port_counts.keys())
        sizes = list(self.port_counts.values())
        self.frame.after(0, self._draw_port_distribution, labels, sizes)


    def _draw_packet_size_distribution(self):
        """绘制数据包大小分布的图表"""
        plt.figure(figsize=(6, 4))
        plt.hist(self.packet_sizes, bins=20, color='green', edgecolor='black')
        plt.xlabel("Packet Size (bytes)")
        plt.ylabel("Frequency")
        plt.title("packet_size")
        plt.grid(True)
        plt.show()

    def visualize_packet_size_distribution(self):
        """生成数据包大小分布的可视化图表"""
        self.frame.after(0, self._draw_packet_size_distribution)

    def update_protocol_distribution(self, protocol_counts):
        """更新协议分布分析图"""
        self.protocol_counts = protocol_counts
        self.visualize_protocol_distribution()

    def update_ip_distribution(self, ip_counts):
        """更新IP地址分析图"""
        self.ip_counts = ip_counts
        self.visualize_ip_distribution()

    def update_port_distribution(self, port_counts):
        """更新端口分析图"""
        self.port_counts = port_counts
        self.visualize_port_distribution()

    def update_packet_size_distribution(self, packet_sizes):
        """更新数据包大小分析图"""
        self.packet_sizes = packet_sizes
        self.visualize_packet_size_distribution()
