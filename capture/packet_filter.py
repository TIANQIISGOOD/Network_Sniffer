# 数据包过滤模块
class PacketFilter:
    @staticmethod
    def create_filter(protocol, ip, port):
        # 基础过滤条件
        filter_expression = ""

        # 协议过滤
        if protocol != "ANY":  # 如果不是 "ANY"，则加入协议过滤
            filter_expression += protocol.lower() + " "

        # IP 地址过滤
        if ip:
            filter_expression += f"host {ip} "

        # 端口过滤
        if port:
            filter_expression += f"port {port}"

        # 去掉末尾的空格
        return filter_expression.strip()
