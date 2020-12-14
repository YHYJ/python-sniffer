#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File: sniffer.py
Author: YJ
Email: yj1516268@outlook.com
Created Time: 2020-12-01 09:22:43

Description: 嗅探指定网络接口的指定类型的报文

1. 加-s/--sniffer和-f/--forwarder参数时需要以管理员权限运行
"""

import argparse
import json
import os
import socket
import struct
import time
from queue import Queue
from threading import Thread

import scapy.all as scapy
import toml

from nic import nic_info
from utils.log_wrapper import setupLogging

_version = '0.3'


class Sniffer(object):
    """嗅探网络数据包并解析"""
    def __init__(self, conf: dict):
        """初始化

        :conf: 配置信息

        """
        # [sniffer]配置项
        conf_sniffer = conf.get('sniffer', dict())
        # 尝试获取iface配置，如果获取不到或者值是是空字符串则为None
        iface = conf_sniffer.get('iface', None)
        self.sniffer_iface = iface if iface else None
        # 获取iface的IP
        ip = conf_sniffer.get('ip', None)
        if ip:
            self.sniffer_ip = ip
        else:
            nics_info = nic_info()
            self.sniffer_ip = nics_info[self.sniffer_iface]['v4'][0].get(
                'addr', None)
        self.sniffer_filte_role = conf_sniffer.get('filte_role', None)
        self.sniffer_filte_method = conf_sniffer.get('filte_method', None)
        self.sniffer_filte_port = conf_sniffer.get('filte_port', None)
        self.sniffer_count = conf_sniffer.get('count', 1)
        self.sniffer_format = conf_sniffer.get('format', str())  # STDOUT输出格式

        # [parser]配置项
        conf_parser = conf.get('parser', dict())
        self.parser_index = conf_parser.get('index', self.sniffer_count)
        self.parser_byte_order = conf_parser.get('byte_order', 4)
        self.parser_command_length = conf_parser.get('command_length', 4)

        # [sender]配置项
        conf_sender = conf.get('sender', dict())
        self.sender_protocol = conf_sender.get('protocol', 'UDP')
        self.sender_ip = conf_sender.get('ip', '127.0.0.1')
        self.sender_port = conf_sender.get('port', 8848)
        self.sender_backlog = conf_sender.get('backlog', 5)
        self.sender_coding = conf_sender.get('coding', 'UTF-8')

        # [log]配置项
        self.logger = setupLogging(conf['log'])

        # sniffer进程和forwarder进程通信队列
        self.queue = Queue()

        # 配置sniffer.filter
        self.full_filte = self._init_filte()

    def _init_filte(self):
        """配置sniffer.filter的规则
        :returns: 完整的filter规则

        """
        # 数据包嗅探规则（使用Berkeley Packet Filter (BPF) syntax）
        # Pre filte rules
        if self.sniffer_filte_method and self.sniffer_filte_port:
            pre_filte = '{method} port {port}'.format(
                method=self.sniffer_filte_method, port=self.sniffer_filte_port)
        elif self.sniffer_filte_method and not self.sniffer_filte_port:
            pre_filte = '{method}'.format(method=self.sniffer_filte_method)
        elif not self.sniffer_filte_method and self.sniffer_filte_port:
            pre_filte = 'port {port}'.format(port=self.sniffer_filte_port)
        else:
            pre_filte = ''
        # Post filte rules
        if self.sniffer_filte_role and self.sniffer_ip:
            post_filte = 'ip {role} {iface_ip}'.format(
                role=self.sniffer_filte_role, iface_ip=self.sniffer_ip)
        else:
            post_filte = ''

        # Full filte rules
        bearing = ' && ' if post_filte and pre_filte else ''
        full_filte = '{pre}{bearing}{post}'.format(pre=pre_filte,
                                                   bearing=bearing,
                                                   post=post_filte)

        return full_filte

    def _parser(self, raw_load: bytes):
        """解析原始数据

        :raw_load: 原始数据，类型为'bytes'
        :returns: 原始数据解析结果，类型为'tuple'

        """
        raw_value_length = len(raw_load) - 10
        if raw_value_length > 0:
            fmt = '{byte_order}2x{command_length}s3x{value_length}sx'.format(
                byte_order=self.parser_byte_order,
                command_length=self.parser_command_length,
                value_length=raw_value_length)
        else:
            fmt = '{byte_order}2x{command_length}s3x'.format(
                byte_order=self.parser_byte_order,
                command_length=self.parser_command_length)

        payload = struct.unpack(fmt, raw_load)

        return payload

    def _tuple2dict(self, data):
        """将tuple(bytes(), bytes())类型的数据转换为dict()类型

        :data: tuple(bytes(), bytes())类型数据
        :returns: dict()类型数据

        """
        result = dict()
        if isinstance(data, (tuple)):
            result['{key}'.format(
                key=data[0].decode(self.sender_coding))] = '{value}'.format(
                    value=data[1].decode(self.sender_coding))

        return result

    def _via_tcp(self, sock, data):
        """通过TCP发送数据

        :sock: TCP Server和TCP Client间的连接
        :data: 待发送的数据

        """
        while sock:
            try:
                sock.send(data)
            except Exception as e:
                self.logger.error(e)

    def forwarder(self):
        """通过指定方式(TCP/UDP)将数据转发到指定地址"""
        addr = (self.sender_ip, self.sender_port)

        self.logger.info('Send data to ({address}) via {proto}'.format(
            address=addr, proto=self.sender_protocol))

        if self.sender_protocol.upper() == 'TCP':
            # 创建TCP Server
            tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
            tcp_server.bind(address=addr)
            tcp_server.listen(self.sender_backlog)

            # TCP发送data
            while True:
                payloads = dict()
                # 获取数据包并解析
                packets = self.queue.get()
                indexs = self.parser_index if isinstance(
                    self.parser_index, (list)) else range(self.parser_index)
                for index in indexs:
                    try:
                        raw_load = packets[index][scapy.Raw].load
                        self.logger.info('raw load = {}'.format(raw_load))
                        payload = self._parser(raw_load)
                        result = self._tuple2dict(payload)
                        payloads.update(result)
                    except IndexError:
                        self.logger.warning('Layer [Raw] not found')

                self.logger.info('Payloads = {}\n'.format(payloads))
                data_jsonb = json.dumps(payloads).encode(self.sender_coding)

                sock, client_addr = tcp_server.accept()
                thread = Thread(target=self._via_tcp, args=(sock, data_jsonb))
                thread.start()
                thread.join()
        elif self.sender_protocol.upper() == 'UDP':
            # 创建UDP Client
            udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

            # UDP发送data
            while True:
                payloads = dict()
                # 获取数据包并解析
                packets = self.queue.get()
                indexs = self.parser_index if isinstance(
                    self.parser_index, (list)) else range(self.parser_index)
                for index in indexs:
                    try:
                        raw_load = packets[index][scapy.Raw].load
                        self.logger.info('raw load = {}'.format(raw_load))
                        payload = self._parser(raw_load)
                        result = self._tuple2dict(payload)
                        payloads.update(result)
                    except IndexError:
                        self.logger.warning('Layer [Raw] not found')

                self.logger.info('Payloads = {}\n'.format(payloads))
                data_jsonb = json.dumps(payloads).encode(self.sender_coding)

                udp_client.sendto(data_jsonb, addr)
        else:
            self.logger.error('Unsupported protocol')

    def sniffer(self):
        """嗅探数据包
        :returns: 嗅探到的数据包列表，类型为'scapy.plist.PacketList'

        """
        logger.info('Filter = {}'.format(self.full_filte))

        while True:
            packets = scapy.sniff(iface=self.sniffer_iface,
                                  filter=self.full_filte.lower(),
                                  count=self.sniffer_count,
                                  prn=lambda x: x.sprintf(self.sniffer_format))

            self.queue.put(packets)
            self.logger.info('Packets = {}\n'.format(packets))

            time.sleep(1)


if __name__ == "__main__":
    # 构建默认配置文件路径
    name = os.path.basename(__file__).split('.')[0]  # 程序名
    ext = 'toml'  # 配置文件后缀
    filename = '{name}.{ext}'.format(name=name, ext=ext)  # 完整配置文件名

    # 定义参数范围 -- parser是正常参数，group是互斥参数
    parser = argparse.ArgumentParser(
        prog=name, description='Packet sniffing and forwarding tool.')
    group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument('-c',
                        '--config',
                        help=("specify configuration file, "
                              "default is '{}'").format(filename))
    group.add_argument('-i',
                       '--info',
                       action='store_true',
                       help='display sniffer information')
    group.add_argument('-s',
                       '--sniffer',
                       action='store_true',
                       help='start the sniffer (run as root)')
    group.add_argument('-f',
                       '--forwarder',
                       action='store_true',
                       help='start the sniffer and forwarder (run as root)')
    parser.add_argument('-v',
                        '--version',
                        action='version',
                        default=None,
                        version='%(prog)s {}'.format(_version))

    # 获取参数列表
    args = parser.parse_args()

    # 尝试获取配置信息
    confile = args.config if args.config else os.path.join('.', filename)
    conf = toml.load(confile)
    logger = setupLogging(conf['log'])

    # 根据参数判断是否创建OPC2UDP对象
    if True in [args.info, args.sniffer, args.forwarder]:
        sniffer = Sniffer(conf)

    # 根据参数执行
    if args.info:  # -i/--info
        sniffer_infos = {
            'Sniffed network card name': sniffer.sniffer_iface,
            'Sniffed network card IP': sniffer.sniffer_ip,
            'Sniffer filter rules': sniffer.full_filte,
            'Number of packets sniffed each time': sniffer.sniffer_count,
        }
        print('Sniffer info:')
        for key, value in sniffer_infos.items():
            print('    - {:<36}: {value}'.format(key, value=value))

        parser_infos = {
            'Byte order': sniffer.parser_byte_order,
        }
        print('Parser info:')
        for key, value in parser_infos.items():
            print('    - {:<36}: {value}'.format(key, value=value))

        sender_infos = {
            'Sender protocol':
            sniffer.sender_protocol,
            'Sender address':
            '{ip}:{port}'.format(ip=sniffer.sender_ip,
                                 port=sniffer.sender_port),
            'Maximum number of connections':
            sniffer.sender_backlog,
            'Encoding format':
            sniffer.sender_coding,
        }
        print('Sender info:')
        for key, value in sender_infos.items():
            print('    - {:<36}: {value}'.format(key, value=value))

    elif args.sniffer:  # -s/--sniffer
        thread_sniffer = Thread(target=sniffer.sniffer, name='Sniffer')
        logger.info(
            'Starting {thread_name}\n'.format(thread_name=thread_sniffer.name))

        thread_sniffer.setDaemon(True)
        thread_sniffer.start()
        thread_sniffer.join()
    elif args.forwarder:  # -f/--forwarder
        thread_sniffer = Thread(target=sniffer.sniffer, name='Sniffer')
        logger.info(
            'Starting {thread_name}\n'.format(thread_name=thread_sniffer.name))

        thread_forwarder = Thread(target=sniffer.forwarder, name='Forwarder')
        logger.info('Starting {thread_name}\n'.format(
            thread_name=thread_forwarder.name))

        thread_sniffer.setDaemon(True)
        thread_forwarder.setDaemon(True)
        thread_sniffer.start()
        thread_forwarder.start()
        thread_sniffer.join()
        thread_forwarder.join()
