#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强网络监控模块
实现详细的网络活动检测，包括连接建立、数据传输、端口监听等
"""

import os
import sys
import time
import socket
import threading
from datetime import datetime
from typing import Dict, Set, Optional, List, Callable, Any, Tuple, NamedTuple
from collections import defaultdict, deque
import json
import struct

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("警告: psutil库未安装")

try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("警告: scapy库未安装，网络包捕获功能将受限")

try:
    import win32api
    import win32con
    import win32file
    import win32event
    import win32security
    import pywintypes
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    print("警告: pywin32库未安装，Windows网络监控功能将受限")

from procmon import BaseMonitor, MonitorEvent, EventType, Operation


class NetworkConnection(NamedTuple):
    """网络连接信息"""
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    protocol: str
    status: str
    pid: int
    process_name: str
    family: int
    type: int


class NetworkPacket:
    """网络数据包信息"""
    
    def __init__(self, packet_data: bytes, timestamp: float = None):
        self.timestamp = timestamp or time.time()
        self.raw_data = packet_data
        self.size = len(packet_data)
        
        # 解析包信息
        self.src_ip = ""
        self.dst_ip = ""
        self.src_port = 0
        self.dst_port = 0
        self.protocol = "UNKNOWN"
        self.flags = []
        self.payload_size = 0
        
        self._parse_packet()
    
    def _parse_packet(self):
        """解析网络包"""
        try:
            if SCAPY_AVAILABLE and len(self.raw_data) > 14:
                # 使用scapy解析
                packet = scapy.Ether(self.raw_data)
                
                if packet.haslayer(IP):
                    ip_layer = packet[IP]
                    self.src_ip = ip_layer.src
                    self.dst_ip = ip_layer.dst
                    
                    if packet.haslayer(TCP):
                        tcp_layer = packet[TCP]
                        self.src_port = tcp_layer.sport
                        self.dst_port = tcp_layer.dport
                        self.protocol = "TCP"
                        self.payload_size = len(tcp_layer.payload)
                        
                        # TCP标志
                        if tcp_layer.flags & 0x02:  # SYN
                            self.flags.append("SYN")
                        if tcp_layer.flags & 0x10:  # ACK
                            self.flags.append("ACK")
                        if tcp_layer.flags & 0x01:  # FIN
                            self.flags.append("FIN")
                        if tcp_layer.flags & 0x04:  # RST
                            self.flags.append("RST")
                        if tcp_layer.flags & 0x08:  # PSH
                            self.flags.append("PSH")
                    
                    elif packet.haslayer(UDP):
                        udp_layer = packet[UDP]
                        self.src_port = udp_layer.sport
                        self.dst_port = udp_layer.dport
                        self.protocol = "UDP"
                        self.payload_size = len(udp_layer.payload)
                    
                    elif packet.haslayer(ICMP):
                        self.protocol = "ICMP"
                        self.payload_size = len(packet[ICMP].payload)
                
                elif packet.haslayer(IPv6):
                    ipv6_layer = packet[IPv6]
                    self.src_ip = ipv6_layer.src
                    self.dst_ip = ipv6_layer.dst
                    self.protocol = "IPv6"
            
            else:
                # 简单的手动解析
                self._manual_parse()
                
        except Exception as e:
            print(f"解析网络包失败: {e}")
    
    def _manual_parse(self):
        """手动解析网络包（简化版）"""
        try:
            if len(self.raw_data) < 34:  # 最小以太网+IP+TCP头部
                return
            
            # 跳过以太网头部（14字节）
            ip_header = self.raw_data[14:34]
            
            # 解析IP头部
            version_ihl = ip_header[0]
            version = version_ihl >> 4
            
            if version == 4:  # IPv4
                protocol = ip_header[9]
                src_ip = socket.inet_ntoa(ip_header[12:16])
                dst_ip = socket.inet_ntoa(ip_header[16:20])
                
                self.src_ip = src_ip
                self.dst_ip = dst_ip
                
                # 解析传输层协议
                if protocol == 6:  # TCP
                    self.protocol = "TCP"
                    if len(self.raw_data) >= 38:
                        tcp_header = self.raw_data[34:38]
                        self.src_port = struct.unpack('!H', tcp_header[0:2])[0]
                        self.dst_port = struct.unpack('!H', tcp_header[2:4])[0]
                
                elif protocol == 17:  # UDP
                    self.protocol = "UDP"
                    if len(self.raw_data) >= 38:
                        udp_header = self.raw_data[34:38]
                        self.src_port = struct.unpack('!H', udp_header[0:2])[0]
                        self.dst_port = struct.unpack('!H', udp_header[2:4])[0]
                
                elif protocol == 1:  # ICMP
                    self.protocol = "ICMP"
        
        except Exception as e:
            print(f"手动解析网络包失败: {e}")
    
    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            'timestamp': self.timestamp,
            'size': self.size,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'flags': self.flags,
            'payload_size': self.payload_size
        }


class NetworkTrafficAnalyzer:
    """网络流量分析器"""
    
    def __init__(self, max_packets: int = 10000):
        self.max_packets = max_packets
        self.packets: deque = deque(maxlen=max_packets)
        self.connections: Dict[Tuple, dict] = {}
        
        # 统计信息
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
    
    def add_packet(self, packet: NetworkPacket):
        """添加网络包"""
        self.packets.append(packet)
        self.total_packets += 1
        self.total_bytes += packet.size
        
        # 更新统计信息
        self.protocol_stats[packet.protocol] += 1
        if packet.dst_port:
            self.port_stats[packet.dst_port] += 1
        if packet.src_ip:
            self.ip_stats[packet.src_ip] += 1
        if packet.dst_ip:
            self.ip_stats[packet.dst_ip] += 1
        
        # 跟踪连接
        if packet.protocol in ['TCP', 'UDP'] and packet.src_port and packet.dst_port:
            conn_key = (packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port, packet.protocol)
            if conn_key not in self.connections:
                self.connections[conn_key] = {
                    'first_seen': packet.timestamp,
                    'last_seen': packet.timestamp,
                    'packet_count': 0,
                    'byte_count': 0,
                    'flags': set()
                }
            
            conn = self.connections[conn_key]
            conn['last_seen'] = packet.timestamp
            conn['packet_count'] += 1
            conn['byte_count'] += packet.size
            conn['flags'].update(packet.flags)
    
    def get_top_protocols(self, limit: int = 10) -> List[Tuple[str, int]]:
        """获取最活跃的协议"""
        return sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def get_top_ports(self, limit: int = 10) -> List[Tuple[int, int]]:
        """获取最活跃的端口"""
        return sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def get_top_ips(self, limit: int = 10) -> List[Tuple[str, int]]:
        """获取最活跃的IP地址"""
        return sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def get_active_connections(self, timeout: float = 300.0) -> List[dict]:
        """获取活跃连接"""
        current_time = time.time()
        active_conns = []
        
        for conn_key, conn_info in self.connections.items():
            if current_time - conn_info['last_seen'] <= timeout:
                src_ip, src_port, dst_ip, dst_port, protocol = conn_key
                active_conns.append({
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'duration': conn_info['last_seen'] - conn_info['first_seen'],
                    'packet_count': conn_info['packet_count'],
                    'byte_count': conn_info['byte_count'],
                    'flags': list(conn_info['flags'])
                })
        
        return sorted(active_conns, key=lambda x: x['last_seen'], reverse=True)
    
    def get_statistics(self) -> dict:
        """获取统计信息"""
        return {
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'unique_connections': len(self.connections),
            'protocols': dict(self.protocol_stats),
            'top_ports': self.get_top_ports(5),
            'top_ips': self.get_top_ips(5)
        }


class EnhancedNetworkMonitor(BaseMonitor):
    """增强网络监控器"""
    
    def __init__(self, event_callback: Callable[[MonitorEvent], None],
                 capture_packets: bool = False,
                 monitor_connections: bool = True,
                 monitor_dns: bool = True,
                 interface: Optional[str] = None):
        super().__init__(event_callback)
        self.capture_packets = capture_packets
        self.monitor_connections = monitor_connections
        self.monitor_dns = monitor_dns
        self.interface = interface
        
        # 网络状态跟踪
        self.connections: Dict[Tuple, NetworkConnection] = {}
        self.listening_ports: Dict[Tuple[str, int], dict] = {}
        
        # 流量分析器
        self.traffic_analyzer = NetworkTrafficAnalyzer()
        
        # 包捕获
        self.packet_capture_thread = None
        self.capture_running = False
        
        # 性能统计
        self.event_count = 0
        self.last_scan_time = 0.0
        self.scan_duration = 0.0
    
    def _monitor_loop(self):
        """监控循环"""
        print("增强网络监控器启动")
        
        # 启动包捕获
        if self.capture_packets:
            self._start_packet_capture()
        
        while self.running:
            try:
                start_time = time.time()
                
                # 监控网络连接
                if self.monitor_connections:
                    self._scan_network_connections()
                
                # 监控监听端口
                self._scan_listening_ports()
                
                # 监控DNS查询
                if self.monitor_dns:
                    self._scan_dns_activity()
                
                # 更新统计信息
                self.scan_duration = time.time() - start_time
                self.last_scan_time = time.time()
                
                # 控制扫描频率
                time.sleep(max(0.5, 2.0 - self.scan_duration))
                
            except Exception as e:
                print(f"增强网络监控出错: {e}")
                time.sleep(1.0)
        
        # 停止包捕获
        if self.capture_packets:
            self._stop_packet_capture()
    
    def _start_packet_capture(self):
        """启动包捕获"""
        if not SCAPY_AVAILABLE:
            print("Scapy不可用，包捕获功能禁用")
            return
        
        self.capture_running = True
        self.packet_capture_thread = threading.Thread(
            target=self._packet_capture_loop, daemon=True
        )
        self.packet_capture_thread.start()
        print("网络包捕获已启动")
    
    def _stop_packet_capture(self):
        """停止包捕获"""
        self.capture_running = False
        if self.packet_capture_thread and self.packet_capture_thread.is_alive():
            self.packet_capture_thread.join(timeout=5.0)
    
    def _packet_capture_loop(self):
        """包捕获循环"""
        try:
            def packet_handler(packet):
                if not self.capture_running:
                    return
                
                try:
                    # 转换为NetworkPacket
                    packet_data = bytes(packet)
                    network_packet = NetworkPacket(packet_data)
                    
                    # 添加到流量分析器
                    self.traffic_analyzer.add_packet(network_packet)
                    
                    # 发送网络事件
                    self._emit_packet_event(network_packet)
                    
                except Exception as e:
                    print(f"处理网络包失败: {e}")
            
            # 开始捕获
            scapy.sniff(
                iface=self.interface,
                prn=packet_handler,
                stop_filter=lambda x: not self.capture_running,
                store=False
            )
            
        except Exception as e:
            print(f"网络包捕获出错: {e}")
    
    def _emit_packet_event(self, packet: NetworkPacket):
        """发送网络包事件"""
        try:
            # 确定操作类型
            operation = Operation.NET_RECEIVE
            if packet.flags:
                if "SYN" in packet.flags and "ACK" not in packet.flags:
                    operation = Operation.NET_CONNECT
                elif "FIN" in packet.flags or "RST" in packet.flags:
                    operation = Operation.NET_DISCONNECT
            
            # 查找相关进程
            process_info = self._find_process_for_connection(
                packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port
            )
            
            event = MonitorEvent(
                timestamp=datetime.fromtimestamp(packet.timestamp),
                event_type=EventType.NETWORK,
                operation=operation,
                process_name=process_info.get('name', 'Unknown'),
                process_id=process_info.get('pid', 0),
                path=f"{packet.src_ip}:{packet.src_port} -> {packet.dst_ip}:{packet.dst_port}",
                result="SUCCESS",
                details={
                    **packet.to_dict(),
                    'process_info': process_info
                }
            )
            
            self._emit_event(event)
            self.event_count += 1
            
        except Exception as e:
            print(f"发送网络包事件失败: {e}")
    
    def _scan_network_connections(self):
        """扫描网络连接"""
        if not PSUTIL_AVAILABLE:
            return
        
        try:
            current_connections = {}
            
            # 获取所有网络连接
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr and conn.raddr:
                    conn_key = (
                        conn.laddr.ip, conn.laddr.port,
                        conn.raddr.ip, conn.raddr.port,
                        conn.type.name
                    )
                    
                    # 获取进程信息
                    process_name = "Unknown"
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            process_name = proc.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    
                    network_conn = NetworkConnection(
                        local_addr=conn.laddr.ip,
                        local_port=conn.laddr.port,
                        remote_addr=conn.raddr.ip,
                        remote_port=conn.raddr.port,
                        protocol=conn.type.name,
                        status=conn.status,
                        pid=conn.pid or 0,
                        process_name=process_name,
                        family=conn.family.value,
                        type=conn.type.value
                    )
                    
                    current_connections[conn_key] = network_conn
            
            # 检测新连接
            for conn_key, conn in current_connections.items():
                if conn_key not in self.connections:
                    # 新连接
                    self._emit_connection_event(conn, Operation.NET_CONNECT)
            
            # 检测断开的连接
            for conn_key, conn in self.connections.items():
                if conn_key not in current_connections:
                    # 连接断开
                    self._emit_connection_event(conn, Operation.NET_DISCONNECT)
            
            # 更新连接状态
            self.connections = current_connections
            
        except Exception as e:
            print(f"扫描网络连接出错: {e}")
    
    def _scan_listening_ports(self):
        """扫描监听端口"""
        if not PSUTIL_AVAILABLE:
            return
        
        try:
            current_listening = {}
            
            # 获取所有监听端口
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_LISTEN and conn.laddr:
                    port_key = (conn.laddr.ip, conn.laddr.port)
                    
                    # 获取进程信息
                    process_name = "Unknown"
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            process_name = proc.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    
                    current_listening[port_key] = {
                        'pid': conn.pid or 0,
                        'process_name': process_name,
                        'protocol': conn.type.name,
                        'family': conn.family.value
                    }
            
            # 检测新的监听端口
            for port_key, port_info in current_listening.items():
                if port_key not in self.listening_ports:
                    # 新的监听端口
                    self._emit_listening_event(port_key, port_info, True)
            
            # 检测停止监听的端口
            for port_key, port_info in self.listening_ports.items():
                if port_key not in current_listening:
                    # 停止监听
                    self._emit_listening_event(port_key, port_info, False)
            
            # 更新监听端口状态
            self.listening_ports = current_listening
            
        except Exception as e:
            print(f"扫描监听端口出错: {e}")
    
    def _scan_dns_activity(self):
        """扫描DNS活动（简化实现）"""
        # 这是一个简化的实现，实际的DNS监控需要更复杂的技术
        # 可以通过监控53端口的流量或使用ETW来实现
        pass
    
    def _emit_connection_event(self, conn: NetworkConnection, operation: Operation):
        """发送连接事件"""
        try:
            event = MonitorEvent(
                timestamp=datetime.now(),
                event_type=EventType.NETWORK,
                operation=operation,
                process_name=conn.process_name,
                process_id=conn.pid,
                path=f"{conn.local_addr}:{conn.local_port} -> {conn.remote_addr}:{conn.remote_port}",
                result="SUCCESS",
                details={
                    'local_addr': conn.local_addr,
                    'local_port': conn.local_port,
                    'remote_addr': conn.remote_addr,
                    'remote_port': conn.remote_port,
                    'protocol': conn.protocol,
                    'status': conn.status,
                    'family': conn.family,
                    'type': conn.type
                }
            )
            
            self._emit_event(event)
            self.event_count += 1
            
        except Exception as e:
            print(f"发送连接事件失败: {e}")
    
    def _emit_listening_event(self, port_key: Tuple[str, int], port_info: dict, is_start: bool):
        """发送监听端口事件"""
        try:
            operation = Operation.NETWORK_LISTEN if is_start else Operation.NET_DISCONNECT
            
            event = MonitorEvent(
                timestamp=datetime.now(),
                event_type=EventType.NETWORK,
                operation=operation,
                process_name=port_info['process_name'],
                process_id=port_info['pid'],
                path=f"{port_key[0]}:{port_key[1]}",
                result="SUCCESS",
                details={
                    'address': port_key[0],
                    'port': port_key[1],
                    'protocol': port_info['protocol'],
                    'family': port_info['family'],
                    'action': 'start_listening' if is_start else 'stop_listening'
                }
            )
            
            self._emit_event(event)
            self.event_count += 1
            
        except Exception as e:
            print(f"发送监听端口事件失败: {e}")
    
    def _find_process_for_connection(self, src_ip: str, src_port: int, 
                                   dst_ip: str, dst_port: int) -> dict:
        """查找连接对应的进程"""
        if not PSUTIL_AVAILABLE:
            return {'pid': 0, 'name': 'Unknown'}
        
        try:
            # 查找匹配的连接
            for conn in psutil.net_connections(kind='inet'):
                if (conn.laddr and conn.raddr and
                    conn.laddr.ip == src_ip and conn.laddr.port == src_port and
                    conn.raddr.ip == dst_ip and conn.raddr.port == dst_port):
                    
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            return {'pid': conn.pid, 'name': proc.name()}
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
            
            return {'pid': 0, 'name': 'Unknown'}
            
        except Exception:
            return {'pid': 0, 'name': 'Unknown'}
    
    def get_statistics(self) -> dict:
        """获取监控统计信息"""
        stats = {
            'event_count': self.event_count,
            'last_scan_time': self.last_scan_time,
            'scan_duration': self.scan_duration,
            'active_connections': len(self.connections),
            'listening_ports': len(self.listening_ports),
            'capture_running': self.capture_running
        }
        
        # 添加流量分析统计
        if self.capture_packets:
            stats.update(self.traffic_analyzer.get_statistics())
        
        return stats
    
    def get_active_connections(self) -> List[dict]:
        """获取活跃连接"""
        connections = []
        for conn in self.connections.values():
            connections.append({
                'local_addr': conn.local_addr,
                'local_port': conn.local_port,
                'remote_addr': conn.remote_addr,
                'remote_port': conn.remote_port,
                'protocol': conn.protocol,
                'status': conn.status,
                'pid': conn.pid,
                'process_name': conn.process_name
            })
        return connections
    
    def get_listening_ports(self) -> List[dict]:
        """获取监听端口"""
        ports = []
        for (addr, port), info in self.listening_ports.items():
            ports.append({
                'address': addr,
                'port': port,
                'protocol': info['protocol'],
                'pid': info['pid'],
                'process_name': info['process_name']
            })
        return ports
    
    def get_traffic_analysis(self) -> dict:
        """获取流量分析结果"""
        if not self.capture_packets:
            return {}
        
        return {
            'statistics': self.traffic_analyzer.get_statistics(),
            'top_protocols': self.traffic_analyzer.get_top_protocols(),
            'top_ports': self.traffic_analyzer.get_top_ports(),
            'top_ips': self.traffic_analyzer.get_top_ips(),
            'active_connections': self.traffic_analyzer.get_active_connections()
        }


def test_enhanced_network_monitor():
    """测试增强网络监控器"""
    def event_handler(event):
        print(f"[{event.timestamp.strftime('%H:%M:%S.%f')[:-3]}] "
              f"{event.process_name} ({event.process_id}) - "
              f"{event.operation.value}: {event.path} - {event.result}")
        
        if event.details:
            if 'protocol' in event.details:
                print(f"  协议: {event.details['protocol']}")
            if 'status' in event.details:
                print(f"  状态: {event.details['status']}")
    
    print("启动增强网络监控器测试...")
    
    monitor = EnhancedNetworkMonitor(
        event_handler,
        capture_packets=False,  # 设为True启用包捕获（需要管理员权限）
        monitor_connections=True,
        monitor_dns=True
    )
    
    try:
        monitor.start()
        print("网络监控器已启动")
        print("按Ctrl+C停止")
        
        # 定期显示统计信息
        last_stats_time = time.time()
        while True:
            time.sleep(1)
            
            # 每30秒显示一次统计信息
            if time.time() - last_stats_time > 30:
                stats = monitor.get_statistics()
                print(f"\n统计信息: {stats}")
                
                # 显示活跃连接
                connections = monitor.get_active_connections()
                if connections:
                    print(f"活跃连接数: {len(connections)}")
                    for conn in connections[:5]:  # 显示前5个
                        print(f"  {conn['process_name']} - {conn['local_addr']}:{conn['local_port']} -> {conn['remote_addr']}:{conn['remote_port']}")
                
                # 显示监听端口
                ports = monitor.get_listening_ports()
                if ports:
                    print(f"监听端口数: {len(ports)}")
                    for port in ports[:5]:  # 显示前5个
                        print(f"  {port['process_name']} - {port['address']}:{port['port']} ({port['protocol']})")
                
                last_stats_time = time.time()
                
    except KeyboardInterrupt:
        print("\n正在停止监控器...")
        monitor.stop()
        
        # 显示最终统计信息
        stats = monitor.get_statistics()
        print(f"最终统计信息: {stats}")
        
        # 显示流量分析（如果启用了包捕获）
        if monitor.capture_packets:
            traffic_analysis = monitor.get_traffic_analysis()
            if traffic_analysis:
                print(f"流量分析: {traffic_analysis}")
        
        print("监控器已停止")


if __name__ == "__main__":
    test_enhanced_network_monitor()