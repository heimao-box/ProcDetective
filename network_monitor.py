#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络监控模块
监控网络连接的建立、断开以及数据传输活动
"""

import os
import sys
import time
import socket
import threading
from datetime import datetime
from typing import Dict, Set, List, Optional, Tuple
from dataclasses import dataclass

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("警告: psutil库未安装，网络监控功能受限")
    print("请运行: pip install psutil")

from procmon import BaseMonitor, MonitorEvent, EventType, Operation


@dataclass
class NetworkConnection:
    """网络连接信息"""
    fd: int
    family: int
    type: int
    local_addr: Tuple[str, int]
    remote_addr: Tuple[str, int]
    status: str
    pid: int
    process_name: str
    
    def __hash__(self):
        return hash((self.local_addr, self.remote_addr, self.pid))
    
    def __eq__(self, other):
        if not isinstance(other, NetworkConnection):
            return False
        return (self.local_addr, self.remote_addr, self.pid) == (other.local_addr, other.remote_addr, other.pid)
    
    def get_connection_string(self) -> str:
        """获取连接字符串表示"""
        local = f"{self.local_addr[0]}:{self.local_addr[1]}"
        remote = f"{self.remote_addr[0]}:{self.remote_addr[1]}" if self.remote_addr[0] else "*:*"
        return f"{local} -> {remote}"


@dataclass
class NetworkStats:
    """网络统计信息"""
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    timestamp: float


class NetworkMonitor(BaseMonitor):
    """网络监控器"""
    
    def __init__(self, event_callback, target_processes: Optional[Set[str]] = None):
        super().__init__(event_callback)
        self.target_processes = target_processes or set()
        self.known_connections: Set[NetworkConnection] = set()
        self.connection_stats: Dict[str, NetworkStats] = {}
        self.scan_interval = 1.0  # 扫描间隔（秒）
        self.stats_interval = 5.0  # 统计间隔（秒）
        self.last_stats_time = time.time()
        
        if not PSUTIL_AVAILABLE:
            print("网络监控器初始化失败: psutil库不可用")
        else:
            self._initialize_known_connections()
    
    def _initialize_known_connections(self):
        """初始化已知连接列表"""
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.pid:
                    try:
                        process = psutil.Process(conn.pid)
                        process_name = process.name()
                        
                        if self._should_monitor_process(process_name):
                            net_conn = NetworkConnection(
                                fd=conn.fd,
                                family=conn.family,
                                type=conn.type,
                                local_addr=conn.laddr or ('', 0),
                                remote_addr=conn.raddr or ('', 0),
                                status=conn.status,
                                pid=conn.pid,
                                process_name=process_name
                            )
                            self.known_connections.add(net_conn)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        except Exception as e:
            print(f"初始化网络连接列表时出错: {e}")
    
    def _should_monitor_process(self, process_name: str) -> bool:
        """判断是否应该监控该进程的网络活动"""
        if not self.target_processes:
            return True
        return process_name.lower() in {p.lower() for p in self.target_processes}
    
    def _monitor_loop(self):
        """监控循环"""
        if not PSUTIL_AVAILABLE:
            print("无法启动网络监控: psutil库不可用")
            return
        
        while self.running:
            try:
                self._scan_connections()
                
                # 定期收集网络统计信息
                current_time = time.time()
                if current_time - self.last_stats_time >= self.stats_interval:
                    self._collect_network_stats()
                    self.last_stats_time = current_time
                
                time.sleep(self.scan_interval)
            except Exception as e:
                print(f"网络监控出错: {e}")
                time.sleep(1.0)
    
    def _scan_connections(self):
        """扫描网络连接变化"""
        current_connections = set()
        
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.pid:
                    try:
                        process = psutil.Process(conn.pid)
                        process_name = process.name()
                        
                        if self._should_monitor_process(process_name):
                            net_conn = NetworkConnection(
                                fd=conn.fd,
                                family=conn.family,
                                type=conn.type,
                                local_addr=conn.laddr or ('', 0),
                                remote_addr=conn.raddr or ('', 0),
                                status=conn.status,
                                pid=conn.pid,
                                process_name=process_name
                            )
                            current_connections.add(net_conn)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            
            # 检测新连接
            new_connections = current_connections - self.known_connections
            for conn in new_connections:
                self._emit_connection_event(conn, Operation.NET_CONNECT)
            
            # 检测断开的连接
            closed_connections = self.known_connections - current_connections
            for conn in closed_connections:
                self._emit_connection_event(conn, Operation.NET_DISCONNECT)
            
            # 更新已知连接
            self.known_connections = current_connections
            
        except Exception as e:
            print(f"扫描网络连接时出错: {e}")
    
    def _emit_connection_event(self, conn: NetworkConnection, operation: Operation):
        """发送网络连接事件"""
        protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        connection_info = f"{protocol} {conn.get_connection_string()}"
        
        event = MonitorEvent(
            timestamp=datetime.now(),
            event_type=EventType.NETWORK,
            operation=operation,
            process_name=conn.process_name,
            process_id=conn.pid,
            path=connection_info,
            result="SUCCESS",
            details={
                "protocol": protocol,
                "local_address": f"{conn.local_addr[0]}:{conn.local_addr[1]}",
                "remote_address": f"{conn.remote_addr[0]}:{conn.remote_addr[1]}" if conn.remote_addr[0] else "*:*",
                "connection_status": conn.status,
                "socket_family": self._get_family_name(conn.family),
                "file_descriptor": str(conn.fd)
            }
        )
        self._emit_event(event)
    
    def _get_family_name(self, family: int) -> str:
        """获取地址族名称"""
        family_names = {
            socket.AF_INET: "IPv4",
            socket.AF_INET6: "IPv6",
            socket.AF_UNIX: "Unix"
        }
        return family_names.get(family, f"Unknown({family})")
    
    def _collect_network_stats(self):
        """收集网络统计信息"""
        try:
            # 获取全局网络统计
            net_io = psutil.net_io_counters()
            if net_io:
                current_stats = NetworkStats(
                    bytes_sent=net_io.bytes_sent,
                    bytes_recv=net_io.bytes_recv,
                    packets_sent=net_io.packets_sent,
                    packets_recv=net_io.packets_recv,
                    timestamp=time.time()
                )
                
                # 如果有之前的统计数据，计算差值并发送事件
                if "global" in self.connection_stats:
                    prev_stats = self.connection_stats["global"]
                    time_diff = current_stats.timestamp - prev_stats.timestamp
                    
                    if time_diff > 0:
                        bytes_sent_rate = (current_stats.bytes_sent - prev_stats.bytes_sent) / time_diff
                        bytes_recv_rate = (current_stats.bytes_recv - prev_stats.bytes_recv) / time_diff
                        
                        # 只有当有显著网络活动时才发送事件
                        if bytes_sent_rate > 1024 or bytes_recv_rate > 1024:  # 1KB/s 阈值
                            self._emit_network_stats_event(bytes_sent_rate, bytes_recv_rate)
                
                self.connection_stats["global"] = current_stats
                
        except Exception as e:
            print(f"收集网络统计信息时出错: {e}")
    
    def _emit_network_stats_event(self, send_rate: float, recv_rate: float):
        """发送网络统计事件"""
        event = MonitorEvent(
            timestamp=datetime.now(),
            event_type=EventType.NETWORK,
            operation=Operation.NET_SEND if send_rate > recv_rate else Operation.NET_RECEIVE,
            process_name="System",
            process_id=0,
            path=f"Network Activity: {self._format_bytes(send_rate)}/s sent, {self._format_bytes(recv_rate)}/s received",
            result="SUCCESS",
            details={
                "send_rate_bps": str(int(send_rate)),
                "recv_rate_bps": str(int(recv_rate)),
                "send_rate_formatted": f"{self._format_bytes(send_rate)}/s",
                "recv_rate_formatted": f"{self._format_bytes(recv_rate)}/s",
                "activity_type": "bulk_transfer" if max(send_rate, recv_rate) > 1024*1024 else "normal"
            }
        )
        self._emit_event(event)
    
    def _format_bytes(self, bytes_value: float) -> str:
        """格式化字节数"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} TB"
    
    def add_target_process(self, process_name: str):
        """添加目标进程"""
        self.target_processes.add(process_name)
    
    def remove_target_process(self, process_name: str):
        """移除目标进程"""
        self.target_processes.discard(process_name)
    
    def get_active_connections(self) -> Set[NetworkConnection]:
        """获取当前活动连接"""
        return self.known_connections.copy()


class DetailedNetworkMonitor(NetworkMonitor):
    """详细网络监控器 - 提供更多网络信息"""
    
    def __init__(self, event_callback, target_processes: Optional[Set[str]] = None):
        super().__init__(event_callback, target_processes)
        self.connection_history: Dict[str, List] = {}  # 连接历史
        self.dns_cache: Dict[str, str] = {}  # DNS缓存
    
    def _emit_connection_event(self, conn: NetworkConnection, operation: Operation):
        """发送详细的网络连接事件"""
        protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        connection_info = f"{protocol} {conn.get_connection_string()}"
        
        # 尝试解析远程地址的主机名
        remote_hostname = self._resolve_hostname(conn.remote_addr[0]) if conn.remote_addr[0] else ""
        
        # 获取进程的详细信息
        process_details = self._get_process_network_details(conn.pid)
        
        # 记录连接历史
        conn_key = f"{conn.pid}_{conn.local_addr}_{conn.remote_addr}"
        if conn_key not in self.connection_history:
            self.connection_history[conn_key] = []
        
        self.connection_history[conn_key].append({
            "timestamp": datetime.now().isoformat(),
            "operation": operation.value,
            "status": conn.status
        })
        
        # 限制历史记录数量
        if len(self.connection_history[conn_key]) > 20:
            self.connection_history[conn_key].pop(0)
        
        event = MonitorEvent(
            timestamp=datetime.now(),
            event_type=EventType.NETWORK,
            operation=operation,
            process_name=conn.process_name,
            process_id=conn.pid,
            path=connection_info,
            result="SUCCESS",
            details={
                "protocol": protocol,
                "local_address": f"{conn.local_addr[0]}:{conn.local_addr[1]}",
                "remote_address": f"{conn.remote_addr[0]}:{conn.remote_addr[1]}" if conn.remote_addr[0] else "*:*",
                "remote_hostname": remote_hostname,
                "connection_status": conn.status,
                "socket_family": self._get_family_name(conn.family),
                "file_descriptor": str(conn.fd),
                "connection_count": str(len(self.connection_history[conn_key])),
                "process_exe": process_details.get("exe", ""),
                "process_cmdline": process_details.get("cmdline", "")
            }
        )
        self._emit_event(event)
    
    def _resolve_hostname(self, ip_address: str) -> str:
        """解析IP地址的主机名"""
        if not ip_address or ip_address in ['0.0.0.0', '127.0.0.1', '::', '::1']:
            return ""
        
        # 检查缓存
        if ip_address in self.dns_cache:
            return self.dns_cache[ip_address]
        
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            self.dns_cache[ip_address] = hostname
            return hostname
        except (socket.herror, socket.gaierror):
            self.dns_cache[ip_address] = ""
            return ""
    
    def _get_process_network_details(self, pid: int) -> Dict[str, str]:
        """获取进程的网络相关详细信息"""
        try:
            process = psutil.Process(pid)
            return {
                "exe": process.exe(),
                "cmdline": " ".join(process.cmdline()),
                "username": process.username(),
                "create_time": str(datetime.fromtimestamp(process.create_time()))
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {}


def test_network_monitor():
    """测试网络监控器"""
    if not PSUTIL_AVAILABLE:
        print("无法测试网络监控器: psutil库不可用")
        return
    
    def event_handler(event):
        print(f"[{event.timestamp.strftime('%H:%M:%S.%f')[:-3]}] {event.operation.value}: {event.process_name} (PID: {event.process_id})")
        print(f"    {event.path}")
        if event.details.get("remote_hostname"):
            print(f"    远程主机: {event.details['remote_hostname']}")
    
    print("启动网络监控器测试...")
    monitor = DetailedNetworkMonitor(event_handler)
    monitor.start()
    
    try:
        print("监控中... 按 Ctrl+C 停止")
        print("提示: 可以尝试打开浏览器或其他网络应用来测试监控功能")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n停止监控...")
        monitor.stop()
        print("监控已停止")


if __name__ == "__main__":
    test_network_monitor()