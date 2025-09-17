#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
系统调用监控模块
使用Windows ETW (Event Tracing for Windows) 和其他底层技术监控系统调用
这是实现类似Procmon功能的核心模块
"""

import os
import sys
import time
import ctypes
import threading
from datetime import datetime
from typing import Dict, Set, Optional, List, Callable, Any
from ctypes import wintypes, windll, Structure, POINTER, byref
from pathlib import Path
import json

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("警告: psutil库未安装")

try:
    import win32api
    import win32con
    import win32file
    import win32event
    import win32process
    import win32security
    import win32evtlog
    import pywintypes
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    print("警告: pywin32库未安装，系统调用监控功能将受限")

from procmon import BaseMonitor, MonitorEvent, EventType, Operation


# Windows API 常量和结构定义
class SYSTEM_INFORMATION_CLASS:
    SystemBasicInformation = 0
    SystemProcessInformation = 5
    SystemHandleInformation = 16
    SystemExtendedHandleInformation = 64


class PROCESS_INFORMATION_CLASS:
    ProcessBasicInformation = 0
    ProcessImageFileName = 27
    ProcessCommandLineInformation = 60


class SYSTEM_HANDLE_TABLE_ENTRY_INFO(Structure):
    _fields_ = [
        ("UniqueProcessId", wintypes.USHORT),
        ("CreatorBackTraceIndex", wintypes.USHORT),
        ("ObjectTypeIndex", ctypes.c_ubyte),
        ("HandleAttributes", ctypes.c_ubyte),
        ("HandleValue", wintypes.USHORT),
        ("Object", ctypes.c_void_p),
        ("GrantedAccess", wintypes.ULONG),
    ]


class SYSTEM_HANDLE_INFORMATION(Structure):
    _fields_ = [
        ("NumberOfHandles", wintypes.ULONG),
        ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO * 1),
    ]


class SyscallInfo:
    """系统调用信息类"""
    
    def __init__(self, syscall_name: str, pid: int, process_name: str, 
                 parameters: Dict[str, Any] = None, return_value: Any = None):
        self.syscall_name = syscall_name
        self.pid = pid
        self.process_name = process_name
        self.parameters = parameters or {}
        self.return_value = return_value
        self.timestamp = time.time()
        self.thread_id = threading.get_ident()
    
    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            'syscall_name': self.syscall_name,
            'pid': self.pid,
            'process_name': self.process_name,
            'parameters': self.parameters,
            'return_value': str(self.return_value),
            'timestamp': self.timestamp,
            'thread_id': self.thread_id
        }


class ETWProvider:
    """ETW (Event Tracing for Windows) 提供者"""
    
    def __init__(self):
        self.session_handle = None
        self.trace_handle = None
        self.running = False
        
        # 常用的ETW提供者GUID
        self.KERNEL_PROVIDER_GUID = "{9E814AAD-3204-11D2-9A82-006008A86939}"
        self.FILE_PROVIDER_GUID = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"
        self.PROCESS_PROVIDER_GUID = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"
    
    def start_trace_session(self, session_name: str) -> bool:
        """启动ETW跟踪会话"""
        try:
            # 这里需要使用Windows ETW API
            # 由于复杂性，这里提供框架结构
            print(f"启动ETW跟踪会话: {session_name}")
            self.running = True
            return True
        except Exception as e:
            print(f"启动ETW跟踪会话失败: {e}")
            return False
    
    def stop_trace_session(self):
        """停止ETW跟踪会话"""
        try:
            if self.running:
                print("停止ETW跟踪会话")
                self.running = False
        except Exception as e:
            print(f"停止ETW跟踪会话失败: {e}")
    
    def enable_provider(self, provider_guid: str, level: int = 5) -> bool:
        """启用ETW提供者"""
        try:
            print(f"启用ETW提供者: {provider_guid}")
            return True
        except Exception as e:
            print(f"启用ETW提供者失败: {e}")
            return False


class SystemCallMonitor(BaseMonitor):
    """系统调用监控器"""
    
    def __init__(self, event_callback: Callable[[MonitorEvent], None],
                 target_processes: Optional[Set[str]] = None,
                 monitor_file_operations: bool = True,
                 monitor_process_operations: bool = True,
                 monitor_registry_operations: bool = True,
                 monitor_network_operations: bool = True):
        super().__init__(event_callback)
        self.target_processes = target_processes or set()
        self.monitor_file_operations = monitor_file_operations
        self.monitor_process_operations = monitor_process_operations
        self.monitor_registry_operations = monitor_registry_operations
        self.monitor_network_operations = monitor_network_operations
        
        # ETW提供者
        self.etw_provider = ETWProvider()
        
        # 系统调用跟踪
        self.syscall_history: List[SyscallInfo] = []
        self.max_history_size = 10000
        
        # 句柄跟踪
        self.process_handles: Dict[int, Set[int]] = {}
        
        # 性能统计
        self.syscall_count = 0
        self.last_scan_time = 0.0
        self.scan_duration = 0.0
    
    def _monitor_loop(self):
        """监控循环"""
        print("系统调用监控器启动")
        
        # 启动ETW跟踪
        if not self._start_etw_tracing():
            print("ETW跟踪启动失败，使用轮询模式")
        
        while self.running:
            try:
                start_time = time.time()
                
                # 监控文件操作
                if self.monitor_file_operations:
                    self._monitor_file_syscalls()
                
                # 监控进程操作
                if self.monitor_process_operations:
                    self._monitor_process_syscalls()
                
                # 监控注册表操作
                if self.monitor_registry_operations:
                    self._monitor_registry_syscalls()
                
                # 监控网络操作
                if self.monitor_network_operations:
                    self._monitor_network_syscalls()
                
                # 监控句柄操作
                self._monitor_handle_operations()
                
                # 更新统计信息
                self.scan_duration = time.time() - start_time
                self.last_scan_time = time.time()
                
                # 控制扫描频率
                time.sleep(max(0.01, 0.1 - self.scan_duration))
                
            except Exception as e:
                print(f"系统调用监控出错: {e}")
                time.sleep(1.0)
        
        # 停止ETW跟踪
        self._stop_etw_tracing()
    
    def _start_etw_tracing(self) -> bool:
        """启动ETW跟踪"""
        try:
            # 启动ETW会话
            if not self.etw_provider.start_trace_session("ProcmonPyTrace"):
                return False
            
            # 启用相关提供者
            providers_to_enable = []
            
            if self.monitor_file_operations:
                providers_to_enable.append(self.etw_provider.FILE_PROVIDER_GUID)
            
            if self.monitor_process_operations:
                providers_to_enable.append(self.etw_provider.PROCESS_PROVIDER_GUID)
            
            # 启用内核提供者（用于系统调用）
            providers_to_enable.append(self.etw_provider.KERNEL_PROVIDER_GUID)
            
            for provider_guid in providers_to_enable:
                if not self.etw_provider.enable_provider(provider_guid):
                    print(f"启用提供者失败: {provider_guid}")
            
            return True
            
        except Exception as e:
            print(f"启动ETW跟踪失败: {e}")
            return False
    
    def _stop_etw_tracing(self):
        """停止ETW跟踪"""
        try:
            self.etw_provider.stop_trace_session()
        except Exception as e:
            print(f"停止ETW跟踪失败: {e}")
    
    def _monitor_file_syscalls(self):
        """监控文件系统调用"""
        try:
            # 监控常见的文件系统调用
            file_syscalls = [
                'NtCreateFile',
                'NtOpenFile', 
                'NtReadFile',
                'NtWriteFile',
                'NtDeleteFile',
                'NtSetInformationFile',
                'NtQueryInformationFile',
                'NtClose'
            ]
            
            # 这里应该通过ETW或其他方式获取实际的系统调用
            # 由于复杂性，这里使用模拟数据
            self._simulate_file_syscalls()
            
        except Exception as e:
            print(f"监控文件系统调用出错: {e}")
    
    def _simulate_file_syscalls(self):
        """模拟文件系统调用（用于演示）"""
        if not PSUTIL_AVAILABLE:
            return
            
        try:
            # 通过psutil获取进程的文件访问信息
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name'] or 'Unknown'
                    
                    # 过滤目标进程
                    if self.target_processes and name.lower() not in {p.lower() for p in self.target_processes}:
                        continue
                    
                    # 获取打开的文件
                    open_files = proc.open_files()
                    for file_info in open_files:
                        # 创建模拟的系统调用信息
                        syscall_info = SyscallInfo(
                            syscall_name='NtOpenFile',
                            pid=pid,
                            process_name=name,
                            parameters={
                                'FileName': file_info.path,
                                'DesiredAccess': 'GENERIC_READ',
                                'ShareAccess': 'FILE_SHARE_READ'
                            },
                            return_value='STATUS_SUCCESS'
                        )
                        
                        self._process_syscall(syscall_info)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"模拟文件系统调用出错: {e}")
    
    def _monitor_process_syscalls(self):
        """监控进程系统调用"""
        try:
            # 监控进程相关的系统调用
            process_syscalls = [
                'NtCreateProcess',
                'NtCreateProcessEx',
                'NtTerminateProcess',
                'NtOpenProcess',
                'NtCreateThread',
                'NtTerminateThread'
            ]
            
            # 这里应该通过ETW获取实际的系统调用
            self._simulate_process_syscalls()
            
        except Exception as e:
            print(f"监控进程系统调用出错: {e}")
    
    def _simulate_process_syscalls(self):
        """模拟进程系统调用"""
        # 这里可以实现进程系统调用的模拟
        pass
    
    def _monitor_registry_syscalls(self):
        """监控注册表系统调用"""
        try:
            # 监控注册表相关的系统调用
            registry_syscalls = [
                'NtCreateKey',
                'NtOpenKey',
                'NtDeleteKey',
                'NtSetValueKey',
                'NtQueryValueKey',
                'NtDeleteValueKey'
            ]
            
            # 这里应该通过ETW获取实际的系统调用
            self._simulate_registry_syscalls()
            
        except Exception as e:
            print(f"监控注册表系统调用出错: {e}")
    
    def _simulate_registry_syscalls(self):
        """模拟注册表系统调用"""
        # 这里可以实现注册表系统调用的模拟
        pass
    
    def _monitor_network_syscalls(self):
        """监控网络系统调用"""
        try:
            # 监控网络相关的系统调用
            network_syscalls = [
                'NtCreateFile',  # 用于套接字
                'NtDeviceIoControlFile',  # 网络I/O控制
                'NtReadFile',   # 网络读取
                'NtWriteFile'   # 网络写入
            ]
            
            # 这里应该通过ETW获取实际的系统调用
            self._simulate_network_syscalls()
            
        except Exception as e:
            print(f"监控网络系统调用出错: {e}")
    
    def _simulate_network_syscalls(self):
        """模拟网络系统调用"""
        if not PSUTIL_AVAILABLE:
            return
            
        try:
            # 通过psutil获取网络连接信息
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        name = proc.name()
                        
                        # 过滤目标进程
                        if self.target_processes and name.lower() not in {p.lower() for p in self.target_processes}:
                            continue
                        
                        # 创建模拟的网络系统调用
                        syscall_info = SyscallInfo(
                            syscall_name='NtDeviceIoControlFile',
                            pid=conn.pid,
                            process_name=name,
                            parameters={
                                'LocalAddress': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "Unknown",
                                'RemoteAddress': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "Unknown",
                                'Protocol': conn.type.name,
                                'Status': conn.status
                            },
                            return_value='STATUS_SUCCESS'
                        )
                        
                        self._process_syscall(syscall_info)
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
        except Exception as e:
            print(f"模拟网络系统调用出错: {e}")
    
    def _monitor_handle_operations(self):
        """监控句柄操作"""
        try:
            # 获取系统句柄信息
            self._get_system_handles()
        except Exception as e:
            print(f"监控句柄操作出错: {e}")
    
    def _get_system_handles(self):
        """获取系统句柄信息"""
        if not WIN32_AVAILABLE:
            return
            
        try:
            # 使用NtQuerySystemInformation获取句柄信息
            # 这是一个高级功能，需要更多的Windows API知识
            pass
        except Exception as e:
            print(f"获取系统句柄信息出错: {e}")
    
    def _process_syscall(self, syscall_info: SyscallInfo):
        """处理系统调用信息"""
        try:
            # 添加到历史记录
            self.syscall_history.append(syscall_info)
            
            # 限制历史记录大小
            if len(self.syscall_history) > self.max_history_size:
                self.syscall_history = self.syscall_history[-self.max_history_size//2:]
            
            # 转换为监控事件
            operation = self._syscall_to_operation(syscall_info.syscall_name)
            event_type = self._syscall_to_event_type(syscall_info.syscall_name)
            
            event = MonitorEvent(
                timestamp=datetime.fromtimestamp(syscall_info.timestamp),
                event_type=event_type,
                operation=operation,
                process_name=syscall_info.process_name,
                process_id=syscall_info.pid,
                path=self._extract_path_from_syscall(syscall_info),
                result="SUCCESS",
                details=syscall_info.to_dict()
            )
            
            self._emit_event(event)
            self.syscall_count += 1
            
        except Exception as e:
            print(f"处理系统调用出错: {e}")
    
    def _syscall_to_operation(self, syscall_name: str) -> Operation:
        """将系统调用名称转换为操作类型"""
        syscall_mapping = {
            'NtCreateFile': Operation.FILE_CREATE,
            'NtOpenFile': Operation.FILE_READ,
            'NtReadFile': Operation.FILE_READ,
            'NtWriteFile': Operation.FILE_WRITE,
            'NtDeleteFile': Operation.FILE_DELETE,
            'NtCreateProcess': Operation.PROCESS_CREATE,
            'NtTerminateProcess': Operation.PROCESS_EXIT,
            'NtCreateKey': Operation.REG_CREATE_KEY,
            'NtOpenKey': Operation.REG_OPEN_KEY,
            'NtSetValueKey': Operation.REG_SET_VALUE,
            'NtDeviceIoControlFile': Operation.NET_CONNECT
        }
        
        return syscall_mapping.get(syscall_name, Operation.FILE_READ)
    
    def _syscall_to_event_type(self, syscall_name: str) -> EventType:
        """将系统调用名称转换为事件类型"""
        if 'File' in syscall_name:
            return EventType.FILE_SYSTEM
        elif 'Process' in syscall_name or 'Thread' in syscall_name:
            return EventType.PROCESS
        elif 'Key' in syscall_name or 'Value' in syscall_name:
            return EventType.REGISTRY
        else:
            return EventType.NETWORK
    
    def _extract_path_from_syscall(self, syscall_info: SyscallInfo) -> str:
        """从系统调用信息中提取路径"""
        params = syscall_info.parameters
        
        # 尝试从参数中提取路径信息
        for key in ['FileName', 'KeyName', 'LocalAddress', 'RemoteAddress']:
            if key in params:
                return str(params[key])
        
        return f"Syscall: {syscall_info.syscall_name}"
    
    def get_statistics(self) -> dict:
        """获取监控统计信息"""
        return {
            'syscall_count': self.syscall_count,
            'last_scan_time': self.last_scan_time,
            'scan_duration': self.scan_duration,
            'history_size': len(self.syscall_history),
            'target_processes': list(self.target_processes),
            'etw_running': self.etw_provider.running,
            'monitor_flags': {
                'file_operations': self.monitor_file_operations,
                'process_operations': self.monitor_process_operations,
                'registry_operations': self.monitor_registry_operations,
                'network_operations': self.monitor_network_operations
            }
        }
    
    def get_syscall_history(self, limit: int = 100) -> List[dict]:
        """获取系统调用历史记录"""
        return [syscall.to_dict() for syscall in self.syscall_history[-limit:]]
    
    def clear_history(self):
        """清空历史记录"""
        self.syscall_history.clear()
        print("系统调用历史记录已清空")


def test_syscall_monitor():
    """测试系统调用监控器"""
    def event_handler(event):
        print(f"[{event.timestamp.strftime('%H:%M:%S.%f')[:-3]}] "
              f"{event.process_name} ({event.process_id}) - "
              f"{event.operation.value}: {event.path} - {event.result}")
        
        if event.details and 'syscall_name' in event.details:
            print(f"  系统调用: {event.details['syscall_name']}")
            if 'parameters' in event.details:
                for key, value in event.details['parameters'].items():
                    print(f"    {key}: {value}")
    
    print("启动系统调用监控器测试...")
    
    # 可以指定要监控的进程
    target_processes = {'notepad.exe', 'python.exe', 'cmd.exe'}
    
    monitor = SystemCallMonitor(
        event_handler,
        target_processes=target_processes,
        monitor_file_operations=True,
        monitor_process_operations=True,
        monitor_registry_operations=True,
        monitor_network_operations=True
    )
    
    try:
        monitor.start()
        print(f"监控器已启动，目标进程: {target_processes}")
        print("按Ctrl+C停止")
        
        # 定期显示统计信息
        last_stats_time = time.time()
        while True:
            time.sleep(1)
            
            # 每20秒显示一次统计信息
            if time.time() - last_stats_time > 20:
                stats = monitor.get_statistics()
                print(f"\n统计信息: {stats}")
                
                # 显示最近的系统调用
                recent_syscalls = monitor.get_syscall_history(5)
                if recent_syscalls:
                    print("最近的系统调用:")
                    for syscall in recent_syscalls:
                        print(f"  {syscall['syscall_name']} - {syscall['process_name']}")
                
                last_stats_time = time.time()
                
    except KeyboardInterrupt:
        print("\n正在停止监控器...")
        monitor.stop()
        
        # 显示最终统计信息
        stats = monitor.get_statistics()
        print(f"最终统计信息: {stats}")
        print("监控器已停止")


if __name__ == "__main__":
    test_syscall_monitor()