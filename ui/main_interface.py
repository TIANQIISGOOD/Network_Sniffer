import tkinter as tk
from tkinter import ttk, messagebox
import threading
import queue
from collections import defaultdict
from scapy.interfaces import get_if_list

from analysis.protocol_parser import ProtocolParser
from analysis.traffic_statistics import TrafficStatistics

from capture.packet_capture import PacketCapture
from capture.packet_filter import PacketFilter
from capture.packet_storage import PacketStorage

from ui.packet_list_window import PacketDisplayWindow
from ui.analysis_view import DynamicAnalysis


class MainInterface:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("网络嗅探器")

        self.interface_var = tk.StringVar()
        self.protocol_var = tk.StringVar()
        self.ip_var = tk.StringVar()
        self.port_var = tk.StringVar()

        self.capture_thread = None
        self.capture_running = False  # 捕获进行中的标志
        self.stop_event = threading.Event()  # 用于控制捕获线程的停止
        self.packet_display_window = None  # 保存显示窗口对象
        self.packet_queue = queue.Queue()  # 用于捕获线程与主界面的通信
        self.packet_storage = PacketStorage()  # 用于存储数据包
        self.traffic_statistics = TrafficStatistics()  # 流量统计实例

        # 统计相关变量
        self.packet_counter = 0  # 数据包总数
        self.protocol_stats = defaultdict(int)  # 协议分布统计
        self.start_time = None  # 捕获开始时间

        self.visualization_queue = queue.Queue()  # 用于与可视化线程通信
        # 实例化 DynamicAnalysis
        self.dynamic_analysis = DynamicAnalysis(self.root)  # 将root窗口传递给DynamicAnalysis

        self.setup_ui()

    def setup_ui(self):
        # 获取可用网络接口
        interfaces = get_if_list()

        # 网络接口选择
        ttk.Label(self.root, text="网络接口:").grid(row=0, column=0, padx=10, pady=10)
        interface_menu = ttk.Combobox(self.root, textvariable=self.interface_var, values=interfaces)
        interface_menu.grid(row=0, column=1, padx=10, pady=10)
        interface_menu.set(interfaces[0] if interfaces else "")  # 默认选择第一个接口

        # 协议过滤
        ttk.Label(self.root, text="协议过滤:").grid(row=1, column=0, padx=10, pady=10)
        protocol_menu = ttk.Combobox(self.root, textvariable=self.protocol_var, values=["TCP", "UDP", "ICMP", "ANY"])
        protocol_menu.grid(row=1, column=1, padx=10, pady=10)
        protocol_menu.set("ANY")  # 默认选择 "ANY"

        # IP 地址过滤
        ttk.Label(self.root, text="IP 地址过滤:").grid(row=2, column=0, padx=10, pady=10)
        ttk.Entry(self.root, textvariable=self.ip_var).grid(row=2, column=1, padx=10, pady=10)

        # 端口过滤
        ttk.Label(self.root, text="端口号过滤:").grid(row=3, column=0, padx=10, pady=10)
        ttk.Entry(self.root, textvariable=self.port_var).grid(row=3, column=1, padx=10, pady=10)

        # 按钮
        ttk.Button(self.root, text="开始捕获", command=self.start_capture).grid(row=4, column=0, columnspan=2, pady=20)
        ttk.Button(self.root, text="停止捕获", command=self.stop_capture).grid(row=5, column=0, columnspan=2, pady=10)
        ttk.Button(self.root, text="保存数据包", command=self.save_packets).grid(row=6, column=0, columnspan=2, pady=10)

        # 统计信息区域
        self.stats_frame = ttk.LabelFrame(self.root, text="统计信息")
        self.stats_frame.grid(row=7, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        self.stats_labels = {
            "packet_count": ttk.Label(self.stats_frame, text="数据包总数: 0"),
            "protocol_distribution": ttk.Label(self.stats_frame, text="协议分布: TCP: 0, UDP: 0, ICMP: 0"),
            "capture_rate": ttk.Label(self.stats_frame, text="捕获速率: 0 包/秒"),
        }

        for i, label in enumerate(self.stats_labels.values()):
            label.grid(row=i, column=0, sticky="w", padx=10, pady=5)

    def start_capture(self):
        # 获取用户选择的设置
        interface = self.interface_var.get()
        protocol = self.protocol_var.get()
        ip = self.ip_var.get()
        port = self.port_var.get()

        if not interface:
            print("错误：请选择一个网络接口！")
            return

        # 初始化统计数据
        self.traffic_statistics.start()

        # 创建过滤规则
        filters = PacketFilter.create_filter(protocol, ip, port)
        print(f"捕获设置：接口={interface}，过滤规则={filters}")

        # 启动捕获
        self.capture_running = True
        self.stop_event.clear()  # 确保捕获线程可以继续
        self.capture_thread = threading.Thread(target=self.capture_packets, args=(interface, filters))
        self.capture_thread.daemon = True  # 设置为守护线程，确保主程序退出时，线程也会自动退出
        self.capture_thread.start()

        # 检查并创建新的 PacketDisplayWindow
        if not self.packet_display_window or self.packet_display_window.is_closed:
            self.packet_display_window = PacketDisplayWindow(self.root, self.dynamic_analysis)

        # 启动更新显示窗口的线程
        self.update_display_thread = threading.Thread(target=self.update_display)
        self.update_display_thread.daemon = True
        self.update_display_thread.start()

        # 启动统计信息更新
        self.update_statistics()

    # 流量统计更新
    def update_statistics(self):
        if not self.capture_running:
            return

        # 获取流量统计
        stats = self.traffic_statistics.get_statistics()

        # 过滤掉无效或异常的协议名称
        protocol_distribution = stats["protocol_distribution"]
        valid_protocol_distribution = {key: value for key, value in protocol_distribution.items() if
                                       key not in ["??", None]}

        byte_distribution = stats["byte_distribution"]
        valid_byte_distribution = {key: value for key, value in byte_distribution.items() if key not in ["??", None]}

        # 更新显示
        protocol_text = ", ".join([f"{key}: {value}" for key, value in valid_protocol_distribution.items()])
        byte_text = ", ".join([f"{key}: {value}" for key, value in valid_byte_distribution.items()])

        # 更新统计信息
        self.stats_labels["packet_count"].config(text=f"数据包总数: {sum(valid_protocol_distribution.values())}")
        self.stats_labels["protocol_distribution"].config(text=f"协议分布: {protocol_text}")
        self.stats_labels["capture_rate"].config(text=f"捕获速率: {stats['packet_rate']:.2f} 包/秒")

        # 每秒更新一次
        self.root.after(1000, self.update_statistics)

    # 捕获数据包
    def capture_packets(self, interface, filters):
        """
        捕获数据包的线程函数。
        """
        capture = PacketCapture(interface, filters)
        try:
            # 开始捕获数据包
            while not self.stop_event.is_set():
                capture.start_capture(self.packet_callback, self.stop_event)
        except Exception as e:
            print(f"捕获发生异常：{e}")
        finally:
            print("捕获线程已退出")

    # 回调
    def packet_callback(self, packet):
        if not self.stop_event.is_set():
            self.packet_counter += 1  # 更新总数

            # 调用协议解析类解析数据包
            parsed_info = ProtocolParser.parse(packet)
            #print(f"解析的包信息: {parsed_info}")

            # 获取协议名称，并增加对应的协议计数
            protocol = parsed_info['protocol']
            self.protocol_stats[protocol] += 1  # 更新协议统计

            # 更新流量统计
            self.traffic_statistics.update(packet)

            # 获取包摘要和详细信息
            packet_summary = packet.summary()
            packet_details = packet.show(dump=True)  # 获取完整数据包详细信息

            # 存储数据包
            self.packet_storage.add_packet(packet)

            # 调用 DynamicAnalysis 中的 add_packet 方法进行实时分析
            self.dynamic_analysis.add_packet(packet)
            # 打印协议计数，确认协议统计是否更新
            # print(f"Updated protocol counts in DynamicAnalysis: {self.dynamic_analysis.protocol_counts}")

            try:
                self.packet_queue.put((packet_summary, packet_details))
            except queue.Full:
                pass

    # 详情显示
    def update_display(self):
        while self.capture_running:
            try:
                packet_summary, packet_details = self.packet_queue.get(timeout=0.5)  # 获取包摘要和详细信息
                if self.packet_display_window and not self.packet_display_window.is_closed:
                    self.packet_display_window.update_display(packet_summary, packet_details)
                else:
                    # 如果窗口已关闭，停止更新
                    break
            except queue.Empty:
                continue

    # 停止捕获
    def stop_capture(self):
        if self.capture_running:
            print("停止捕获")
            self.stop_event.set()  # 停止捕获线程
            self.capture_running = False
            if self.capture_thread:
                self.capture_thread.join()  # 等待捕获线程结束
            print("捕获已停止")

        else:
            print("捕获未开始或已停止")

    def save_packets(self):
        """
        保存捕获的所有数据包
        """
        try:
            self.packet_storage.save()
            messagebox.showinfo("保存成功", "数据包已成功保存！")
        except Exception as e:
            messagebox.showerror("保存失败", f"数据包保存失败: {e}")

    def run(self):
        self.root.mainloop()
