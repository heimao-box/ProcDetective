#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ProcDetective - A Python implementation similar to Process Monitor
监控指定程序的运行行为，包括进程、文件系统、注册表和网络活动
"""

import os
import sys
import time
import threading
import argparse
from datetime import datetime
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass
from enum import Enum


class EventType(Enum):
    """事件类型枚举"""
    PROCESS = "Process"
    FILE_SYSTEM = "FileSystem"
    REGISTRY = "Registry"
    NETWORK = "Network"


class Operation(Enum):
    """操作类型枚举"""
    # 进程操作
    PROCESS_CREATE = "ProcessCreate"
    PROCESS_EXIT = "ProcessExit"
    THREAD_CREATE = "ThreadCreate"
    THREAD_EXIT = "ThreadExit"
    
    # 文件系统操作
    FILE_READ = "FileRead"
    FILE_WRITE = "FileWrite"
    FILE_CREATE = "FileCreate"
    FILE_DELETE = "FileDelete"
    FILE_RENAME = "FileRename"
    DIR_CREATE = "DirCreate"
    DIR_DELETE = "DirDelete"
    DIR_RENAME = "DirRename"
    
    # 注册表操作
    REG_READ = "RegRead"
    REG_WRITE = "RegWrite"
    REG_CREATE = "RegCreate"
    REG_DELETE = "RegDelete"
    REG_OPEN_KEY = "RegOpenKey"
    REG_CREATE_KEY = "RegCreateKey"
    REG_DELETE_KEY = "RegDeleteKey"
    REG_SET_VALUE = "RegSetValue"
    REG_QUERY_VALUE = "RegQueryValue"
    
    # 模块操作
    MODULE_LOAD = "ModuleLoad"
    MODULE_UNLOAD = "ModuleUnload"
    
    # 网络操作
    NET_CONNECT = "NetConnect"
    NET_DISCONNECT = "NetDisconnect"
    NET_SEND = "NetSend"
    NET_RECEIVE = "NetReceive"
    NETWORK_LISTEN = "NetworkListen"
    NETWORK_CONNECT = "NetworkConnect"
    NETWORK_DISCONNECT = "NetworkDisconnect"


@dataclass
class MonitorEvent:
    """监控事件数据结构"""
    timestamp: datetime
    event_type: EventType
    operation: Operation
    process_name: str
    process_id: int
    path: str
    result: str
    details: Dict[str, str]


class EventFilter:
    """事件过滤器"""
    
    def __init__(self):
        self.process_names: List[str] = []
        self.event_types: List[EventType] = []
        self.operations: List[Operation] = []
        self.path_patterns: List[str] = []
    
    def add_process_filter(self, process_name: str):
        """添加进程名过滤"""
        self.process_names.append(process_name.lower())
    
    def add_event_type_filter(self, event_type: EventType):
        """添加事件类型过滤"""
        self.event_types.append(event_type)
    
    def add_operation_filter(self, operation: Operation):
        """添加操作类型过滤"""
        self.operations.append(operation)
    
    def add_path_filter(self, path_pattern: str):
        """添加路径模式过滤"""
        self.path_patterns.append(path_pattern.lower())
    
    def should_include(self, event: MonitorEvent) -> bool:
        """判断事件是否应该被包含"""
        # 如果没有设置任何过滤器，包含所有事件
        if not any([self.process_names, self.event_types, self.operations, self.path_patterns]):
            return True
        
        # 进程名过滤
        if self.process_names and event.process_name.lower() not in self.process_names:
            return False
        
        # 事件类型过滤
        if self.event_types and event.event_type not in self.event_types:
            return False
        
        # 操作类型过滤
        if self.operations and event.operation not in self.operations:
            return False
        
        # 路径模式过滤
        if self.path_patterns:
            path_match = any(pattern in event.path.lower() for pattern in self.path_patterns)
            if not path_match:
                return False
        
        return True


class EventFormatter:
    """事件格式化器"""
    
    @staticmethod
    def format_event(event: MonitorEvent) -> str:
        """格式化单个事件"""
        timestamp_str = event.timestamp.strftime("%H:%M:%S.%f")[:-3]
        return f"{timestamp_str}\t{event.process_name}\t{event.process_id}\t{event.operation.value}\t{event.path}\t{event.result}"
    
    @staticmethod
    def format_header() -> str:
        """格式化表头"""
        return "Time\t\t\tProcess Name\tPID\tOperation\t\tPath\t\t\tResult"
    
    @staticmethod
    def format_separator() -> str:
        """格式化分隔符"""
        return "-" * 120


class BaseMonitor:
    """基础监控器抽象类"""
    
    def __init__(self, event_callback: Callable[[MonitorEvent], None]):
        self.event_callback = event_callback
        self.running = False
        self.thread: Optional[threading.Thread] = None
    
    def start(self):
        """启动监控"""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()
    
    def stop(self):
        """停止监控"""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)
    
    def _monitor_loop(self):
        """监控循环 - 子类需要实现"""
        raise NotImplementedError
    
    def _emit_event(self, event: MonitorEvent):
        """发送事件"""
        if self.event_callback:
            self.event_callback(event)


class ProcMon:
    """主监控类"""
    
    def __init__(self):
        self.monitors: List[BaseMonitor] = []
        self.event_filter = EventFilter()
        self.event_formatter = EventFormatter()
        self.running = False
        self.events: List[MonitorEvent] = []
        self.max_events = 10000  # 最大事件数量
    
    def add_monitor(self, monitor: BaseMonitor):
        """添加监控器"""
        self.monitors.append(monitor)
    
    def set_filter(self, event_filter: EventFilter):
        """设置事件过滤器"""
        self.event_filter = event_filter
    
    def _handle_event(self, event: MonitorEvent):
        """处理监控事件"""
        if self.event_filter.should_include(event):
            # 添加到事件列表
            self.events.append(event)
            
            # 限制事件数量，移除最旧的事件
            if len(self.events) > self.max_events:
                self.events.pop(0)
            
            # 输出事件
            print(self.event_formatter.format_event(event))
    
    def start_monitoring(self):
        """开始监控"""
        if self.running:
            return
        
        print("ProcDetective - 进程行为侦探工具启动")
        print(self.event_formatter.format_header())
        print(self.event_formatter.format_separator())
        
        self.running = True
        
        # 启动所有监控器
        for monitor in self.monitors:
            monitor.start()
        
        try:
            while self.running:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n正在停止监控...")
        finally:
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """停止监控"""
        self.running = False
        
        # 停止所有监控器
        for monitor in self.monitors:
            monitor.stop()
        
        print(f"\n监控已停止。共捕获 {len(self.events)} 个事件。")
    
    def get_events(self) -> List[MonitorEvent]:
        """获取所有事件"""
        return self.events.copy()
    
    def save_events_to_file(self, filename: str):
        """保存事件到文件"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(self.event_formatter.format_header() + "\n")
            for event in self.events:
                f.write(self.event_formatter.format_event(event) + "\n")
        print(f"事件已保存到文件: {filename}")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='ProcDetective - 进程行为侦探工具')
    parser.add_argument('-p', '--process', help='监控指定进程名')
    parser.add_argument('-t', '--type', choices=['process', 'file', 'registry', 'network'], 
                       help='监控指定类型的事件')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('--max-events', type=int, default=10000, help='最大事件数量')
    parser.add_argument('--watch-path', action='append', help='监控指定路径（文件系统监控）')
    parser.add_argument('--detailed', action='store_true', help='启用详细监控模式')
    parser.add_argument('--no-process', action='store_true', help='禁用进程侦探')
    parser.add_argument('--no-file', action='store_true', help='禁用文件系统监控')
    parser.add_argument('--no-registry', action='store_true', help='禁用注册表监控')
    parser.add_argument('--no-network', action='store_true', help='禁用网络监控')
    
    args = parser.parse_args()
    
    # 创建主监控器
    procmon = ProcMon()
    procmon.max_events = args.max_events
    
    # 设置过滤器
    event_filter = EventFilter()
    if args.process:
        event_filter.add_process_filter(args.process)
    
    if args.type:
        type_mapping = {
            'process': EventType.PROCESS,
            'file': EventType.FILE_SYSTEM,
            'registry': EventType.REGISTRY,
            'network': EventType.NETWORK
        }
        event_filter.add_event_type_filter(type_mapping[args.type])
    
    procmon.set_filter(event_filter)
    
    # 添加监控器
    target_processes = {args.process} if args.process else set()
    
    # 进程监控
    if not args.no_process and (not args.type or args.type == 'process'):
        try:
            if args.detailed:
                from process_monitor import DetailedProcessMonitor
                monitor_class = DetailedProcessMonitor
            else:
                from process_monitor import ProcessMonitor
                monitor_class = ProcessMonitor
            process_monitor = monitor_class(procmon._handle_event, target_processes)
            procmon.add_monitor(process_monitor)
            print("✓ 进程监控器已启用")
        except ImportError as e:
            print(f"✗ 无法加载进程监控器: {e}")
    
    # 文件系统监控
    if not args.no_file and (not args.type or args.type == 'file'):
        try:
            if args.detailed:
                from filesystem_monitor import DetailedFileSystemMonitor
                monitor_class = DetailedFileSystemMonitor
            else:
                from filesystem_monitor import FileSystemMonitor
                monitor_class = FileSystemMonitor
            watch_paths = args.watch_path if args.watch_path else None
            fs_monitor = monitor_class(procmon._handle_event, watch_paths)
            procmon.add_monitor(fs_monitor)
            print("✓ 文件系统监控器已启用")
        except ImportError as e:
            print(f"✗ 无法加载文件系统监控器: {e}")
    
    # 注册表监控
    if not args.no_registry and (not args.type or args.type == 'registry'):
        try:
            if args.detailed:
                from registry_monitor import DetailedRegistryMonitor
                monitor_class = DetailedRegistryMonitor
            else:
                from registry_monitor import RegistryMonitor
                monitor_class = RegistryMonitor
            reg_monitor = monitor_class(procmon._handle_event)
            procmon.add_monitor(reg_monitor)
            print("✓ 注册表监控器已启用")
        except ImportError as e:
            print(f"✗ 无法加载注册表监控器: {e}")
    
    # 网络监控
    if not args.no_network and (not args.type or args.type == 'network'):
        try:
            if args.detailed:
                from network_monitor import DetailedNetworkMonitor
                monitor_class = DetailedNetworkMonitor
            else:
                from network_monitor import NetworkMonitor
                monitor_class = NetworkMonitor
            net_monitor = monitor_class(procmon._handle_event, target_processes)
            procmon.add_monitor(net_monitor)
            print("✓ 网络监控器已启用")
        except ImportError as e:
            print(f"✗ 无法加载网络监控器: {e}")
    
    if not procmon.monitors:
        print("错误: 没有可用的监控器")
        return 1
    
    try:
        procmon.start_monitoring()
    finally:
        if args.output:
            procmon.save_events_to_file(args.output)
    
    return 0


if __name__ == "__main__":
    main()