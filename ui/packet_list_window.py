import tkinter as tk
from tkinter import ttk



class PacketDisplayWindow:
    def __init__(self, master,dynamic_analysis):
        self.window = tk.Toplevel(master)
        self.window.title("捕获的数据包")
        self.window.geometry("800x400")

        # 添加关闭窗口时的处理方法
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
        self.is_closed = False  # 标志窗口是否已关闭

        # 创建主框架，分为左右两部分
        self.main_frame = tk.Frame(self.window)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # 左侧：数据包列表框架
        self.left_frame = tk.Frame(self.main_frame, width=400, bg="lightgray")
        self.left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 右侧：分析视图框架
        self.right_frame = tk.Frame(self.main_frame, width=400, bg="white")
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # 数据包列表（左侧）
        self.tree = ttk.Treeview(self.left_frame, columns=("No", "Summary"), show="headings")
        self.tree.heading("No", text="编号")
        self.tree.heading("Summary", text="数据包摘要")
        self.tree.column("No", width=50, anchor="center")
        self.tree.column("Summary", width=350, anchor="w")
        self.tree.pack(fill=tk.BOTH, expand=True)

        # 绑定双击事件
        self.tree.bind("<Double-1>", self.show_packet_details)

        # 数据包编号
        self.packet_counter = 1
        # 存储详细包信息的字典
        self.packet_details = {}

        # 右侧分析视图初始化
        self.init_analysis_view()

        # 创建动态分析视图（右侧）
        self.dynamic_analysis = dynamic_analysis

    def init_analysis_view(self):
        """初始化右侧分析视图"""
        # 标签
        self.analysis_label = tk.Label(self.right_frame, text="视图分析", bg="white", font=("Arial", 14, "bold"))
        self.analysis_label.pack(pady=10)

        # 分析功能按钮
        self.protocol_analysis_btn = tk.Button(self.right_frame, text="流量协议分布分析", command=self.protocol_analysis)
        self.protocol_analysis_btn.pack(pady=5)

        self.ip_analysis_btn = tk.Button(self.right_frame, text="IP地址分析", command=self.ip_analysis)
        self.ip_analysis_btn.pack(pady=5)

        self.port_analysis_btn = tk.Button(self.right_frame, text="端口分析", command=self.port_analysis)
        self.port_analysis_btn.pack(pady=5)

        self.size_analysis_btn = tk.Button(self.right_frame, text="流量大小分析", command=self.size_analysis)
        self.size_analysis_btn.pack(pady=5)

    def protocol_analysis(self):
        """调用协议分布分析"""
        protocol_counts = self.dynamic_analysis.protocol_counts
        # 调试
        # print(f"协议数: {self.dynamic_analysis.protocol_counts}")  # 打印协议计数
        # print(f"协议数: {protocol_counts}")  # 打印协议计数
        if protocol_counts:
            self.dynamic_analysis.update_protocol_distribution(protocol_counts)
        else:
            print("No protocol data available.")

    def ip_analysis(self):
        """调用IP地址分析"""
        ip_counts = self.dynamic_analysis.ip_counts
        print(f"IP地址分析数据: {ip_counts}")  # 打印数据，检查是否正确
        if ip_counts:
            self.dynamic_analysis.update_ip_distribution(ip_counts)
        else:
            print("No ip data available.")

    def port_analysis(self):
        """调用端口分析"""
        port_counts = self.dynamic_analysis.port_counts
        print(f"端口分析数据: {port_counts}")  # 打印数据，检查是否正确
        if port_counts:
            self.dynamic_analysis.update_port_distribution(port_counts)
        else:
            print("No ip port available.")

    def size_analysis(self):
        """调用流量大小分析"""
        packet_sizes = self.dynamic_analysis.packet_sizes
        print(f"流量大小分析数据: {packet_sizes}")  # 打印数据，检查是否正确
        if packet_sizes:
            self.dynamic_analysis.update_packet_size_distribution(packet_sizes)
        else:
            print("No ip packet available.")

    def on_close(self):
        """窗口关闭时设置 is_closed 为 True"""
        self.is_closed = True
        self.window.destroy()

    def update_display(self, packet_summary, packet_details=None):
        """更新窗口中的显示内容"""
        if not self.is_closed:
            # 添加数据包摘要到表格
            self.tree.insert("", "end", values=(self.packet_counter, packet_summary))
            # 保存数据包详细信息
            if packet_details:
                self.packet_details[self.packet_counter] = packet_details
            self.packet_counter += 1

    def show_packet_details(self, event):
        """双击事件，显示数据包的详细信息"""
        selected_item = self.tree.selection()
        if selected_item:
            item = self.tree.item(selected_item)
            packet_no = item["values"][0]  # 第一个列为编号
            details = self.packet_details.get(packet_no, "无详细信息")
            self.show_details_window(packet_no, details)

    def show_details_window(self, packet_no, details):
        """显示数据包详细信息的窗口"""
        detail_window = tk.Toplevel(self.window)
        detail_window.title(f"数据包详细信息 - 编号 {packet_no}")
        detail_window.geometry("400x300")

        text = tk.Text(detail_window, wrap=tk.WORD)
        text.insert(tk.END, details)
        text.configure(state="disabled")  # 设置为只读
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
