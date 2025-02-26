import socket
import struct
from time import time
import threading
import logging

# 配置日志记录
logging.basicConfig(level=logging.INFO, format="%(message)s")


def config(path):
    """根据配置文件提取"""
    name2ip = {}
    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            if line.strip():  # 判断行非空
                ip, domain = line.rstrip().split(" ", 1)
                name2ip[domain] = ip

    return name2ip


class query_part:
    """一条问题记录，解析+打包"""

    def __init__(self) -> None:
        self.name = ""
        self.idx = 0
        self.type = None
        self.classify = None

    def unpack(self, data):
        """解析二进制查询报文中的问题节，data -> name, type, class"""
        # 公共变量复位
        self.name = ""
        self.idx = 0
        while True:
            length = data[self.idx]  # 读取当前索引位置的长度字节
            if length == 0:  # 如果长度为0，说明域名解析完毕
                self.idx += 1
                break
            self.idx += 1
            self.name += data[self.idx : self.idx + length].decode() + "."
            self.idx += length
        self.name = self.name.rstrip(".")  # 去掉最后的点
        # struct.unpack()将字节数据解包为py的数据类型
        ## >HH表示两个无符号短整型数据，大端字节序（每个2字节，共4字节）
        self.type, self.classify = struct.unpack(">HH", data[self.idx : self.idx + 4])
        self.idx += 4  # 上面读取了四个字节，所以索引位置加4

    def pack(self):
        """将问题节打包回二进制查询报文，name, type, class -> data"""
        parts = self.name.split(".")
        data = b""  # 初始化为空字节串
        # 打包域名
        for part in parts:
            # 字节表示的长度 + 编码后的字节数据
            # B 为一个字节，H 为两个字节。每个标签最长63字节
            data += struct.pack("B", len(part)) + part.encode()
        data += b"\x00"  # 追加结束字节
        # 打包type和classify
        data += struct.pack(">HH", self.type, self.classify)
        return data


class message:
    """一封DNS报文，解析头部，若是查询报文则进一步解析问题节"""

    def __init__(self, data) -> None:
        self.data = data
        self.unpack(data)

    def unpack(self, data):
        # 处理报文的头部
        self.id, self.flags, self.quests, self.answers, self.author, self.addition = (
            struct.unpack(">HHHHHH", data[0:12])
        )
        self.qr = data[2] >> 7
        # 这种方式提取出来的值将是0（查询报文）或1（响应报文）
        if self.qr == 0:  # 是查询报文
            self.query = query_part()
            self.query.unpack(data[12:])  # 生成问题节
        else:
            self.query = None

    def r_pack(self, ip):
        """根据ip资源和当前查询报文内容生成回复报文，注意哪些头部字段要修改"""
        # 仿照上面的unpack方法，先生成data[0:12]，再调库生成data[12:]

        # self.id：事务 ID
        # response_flags: ban type
        #   0x8180：表示这是一个标准查询响应，无错误
        #   0x8183：表示域名不存在（一般都是手动封禁）
        #       1000 0001 1000 0011
        #       QR = 1（响应）
        #       Opcode = 0000（标准查询）
        #       AA = 0（非权威回答）
        #       TC = 0（未截断）
        #       RD = 1（期望递归）
        #       RA = 0（不支持递归）
        #       Z = 000（保留字段）
        #       RCODE = 0011（名称错误，表示域名不存在）
        # self.quests：问题数
        # response_answers：回答数
        # self.author：授权记录数
        # self.addition：附加记录数
        response_flags = 0x8183 if ip == "0.0.0.0" else 0x8180
        response_answers = 1
        response = struct.pack(
            ">HHHHHH",
            self.id,
            response_flags,
            self.quests,
            response_answers,
            self.author,
            self.addition,
        )
        response += self.query.pack()  # 将问题部分打包并追加到响应中
        # 回答部分:如题
        # 0xC00C：指针，指向问题部分的域名
        # 1：类型字段，表示 A 记录
        # 1：类字段，表示 IN 类
        # 666：生存时间（TTL）
        #     TTL 是 Time To Live 的缩写，表示资源记录在缓存中的有效时间
        #     设高点可以减少查询次数，减小网络负载
        # 4：数据长度，表示 IPv4 地址的长度
        # ip：IPv4 地址
        response += struct.pack(">HHHLH", 0xC00C, 1, 1, 666, 4)
        ip_parts = [int(part) for part in ip.split(".")]
        response += struct.pack("BBBB", *ip_parts)
        return response


class relay_server:
    """中继器，接收DNS报文并处理"""

    def __init__(self, path) -> None:
        self.config = config(path)  # 解析配置文件，存储为字典{name: ip}
        print(self.config)
        self.s = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM
        )  # AF_INET表示使用IPv4地址族 SOCK_DGRAM 表示UDP
        self.s.bind(("0.0.0.0", 53))
        # 将套接字绑定到本地地址 0.0.0.0 和端口 53
        # 0.0.0.0 表示绑定到所有可用的网络接口
        # 端口 53 是 DNS 服务的标准端口
        self.s.setblocking(False)
        # 在非阻塞模式下，套接字操作（如接收数据）不会阻塞程序的执行
        self.nameserver = (
            "114.114.114.114",
            53,
        )  # 一个公共DNS服务器，也可选择其他，注意事先测试

        self.transaction = {}
        # 空字典，用于存储事务ID和对应的查询报文，以便在收到回复报文时找到对应的查询报文

    def process(self, data, addr):
        """解析收到的报文，生成回复返回给请求方"""
        start_time = time()
        msg = message(data)
        domain_name = "unknown"
        handled_as = "unknown"
        flag = 0

        # 解析报文后，需要检查是否有匹配的配置。
        #       如果有匹配的配置，则生成相应的回复报文；
        #       否则，将查询转发到上游 DNS 服务器。
        if msg.qr == 0:  # 是查询报文
            domain_name = msg.query.name
            # 存在本地配置的就优先从本地找，否则转发到上游DNS服务器
            if domain_name in self.config:
                ip = self.config[domain_name]
                response = msg.r_pack(ip)
                self.s.sendto(response, addr)
                if ip == "0.0.0.0":
                    handled_as = "intercept"
                else:
                    handled_as = "local resolve"
            else:
                transaction_id = msg.id
                if transaction_id not in self.transaction:  # 避免重复修改任务字典
                    self.transaction[transaction_id] = (
                        msg.query.name,
                        addr,
                        start_time,
                    )
                    self.s.sendto(data, self.nameserver)
                flag = 1

        elif msg.qr == 1:  # 响应报文
            transaction_id = msg.id
            if transaction_id in self.transaction:
                domain_name, original_addr, start_time = self.transaction.pop(
                    transaction_id
                )
                self.s.sendto(data, original_addr)
                handled_as = "relay"
            else:
                handled_as = "[ERROR] unkonwn transaction id"
        else:
            return -1

        end_time = time()
        duration = end_time - start_time
        if flag == 0:  # 简化输出，第一段中继不打印日志
            logging.info(
                f"query to {domain_name:>50},    handled as {handled_as:>20},    takes {duration:.4f}s"
            )
        return 0

    def run(self):
        """循环接收DNS报文"""
        while True:
            try:
                data, addr = self.s.recvfrom(1024)
                # 接收最多1024字节数据，返回值是一个元组(接收数据, 发送数据的地址)
                threading.Thread(
                    target=self.process,
                    args=(data, addr),
                    # 为process函数创建一个线程，传入参数data和addr
                ).start()
            except Exception:
                pass


if __name__ == "__main__":
    path = r"D:\Study_Work\Electronic_data\CS\AAAUniversity\CN\Lab\1\example.txt"
    r = relay_server(path)
    r.run()


# 假设 DNS 查询报文中的域名部分如下：
# 03 77 77 77 06 65 78 61 6D 70 6C 65 03 63 6F 6D 00
# 03 表示长度为 3，标签为 www
# 06 表示长度为 6，标签为 example
# 03 表示长度为 3，标签为 com
# 00 表示域名部分结束。

# 常见的 DNS 资源记录类型对应的type值如下：
# A (Address Record)：1，用于将域名映射到 IPv4 地址。
# NS (Name Server Record)：2，用于指定域名的权威名称服务器。
# CNAME (Canonical Name Record)：5，用于将一个域名别名映射到另一个域名。
# MX (Mail Exchange Record)：15，用于指定邮件服务器。
# AAAA (IPv6 Address Record)：28，用于将域名映射到 IPv6 地址。
# TXT (Text Record)：16，用于存储任意文本数据。


# DNS 报文中的问题部分、回答部分、授权部分和附加部分都可能出现重复的域名。


# 刚开始写的时候没有往 self.transaction 存开始时间，存了(msg.query.name, addr)
#     导致测试结果出来的处理时间一大片0.0000s


# 在 DNS 中继情况的处理中：
#
# 使用 pop 方法
# pop 方法会从字典中删除指定的键，并返回该键对应的值。
#
# 优点：
# 节省内存：删除不再需要的记录可以节省内存。
# 避免重复处理：确保每个事务 ID 只处理一次，避免重复处理相同的查询。
# 缺点：
# 无法追踪历史：删除记录后，无法追踪或调试之前的查询。
# 保留中继查询记录
# 保留中继查询记录意味着不删除字典中的键值对。
#
# 优点：
# 便于调试和追踪：保留记录可以帮助调试和追踪查询历史。
# 处理重传：在某些情况下，客户端可能会重传查询，保留记录可以更好地处理这种情况。
# 缺点：
# 占用内存：保留所有记录会占用更多的内存，特别是在高并发的情况下。
# 可能导致重复处理：如果没有适当的机制，可能会导致重复处理相同的查询。
