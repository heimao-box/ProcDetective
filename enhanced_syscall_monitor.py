#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强系统调用监控器
实现类似Procmon的深度系统调用监控功能
包括文件系统、进程、注册表、网络等系统调用的详细跟踪
"""

import os
import sys
import time
import ctypes
import threading
import subprocess
from datetime import datetime
from typing import Dict, Set, Optional, List, Callable, Any, Tuple
from ctypes import wintypes, windll, Structure, POINTER, byref
from pathlib import Path
import json
import hashlib

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


class SyscallCategory:
    """系统调用分类"""
    FILE_SYSTEM = "FileSystem"
    PROCESS_THREAD = "ProcessThread"
    REGISTRY = "Registry"
    NETWORK = "Network"
    MEMORY = "Memory"
    SYNCHRONIZATION = "Synchronization"
    SECURITY = "Security"
    DEVICE_IO = "DeviceIO"


class SyscallDetail:
    """系统调用详细信息"""
    
    def __init__(self, name: str, category: str, pid: int, process_name: str,
                 thread_id: int = 0, parameters: Dict[str, Any] = None, 
                 return_value: Any = None, duration: float = 0.0,
                 stack_trace: List[str] = None):
        self.name = name
        self.category = category
        self.pid = pid
        self.process_name = process_name
        self.thread_id = thread_id
        self.parameters = parameters or {}
        self.return_value = return_value
        self.duration = duration
        self.timestamp = datetime.now()
        self.stack_trace = stack_trace or []
        self.sequence_number = 0
    
    def to_monitor_event(self) -> MonitorEvent:
        """转换为监控事件"""
        # 根据系统调用类型确定事件类型
        event_type = self._get_event_type()
        operation = self._get_operation()
        
        # 提取路径信息
        path = self._extract_path()
        
        # 构建详细信息
        details = {
            'syscall_name': self.name,
            'category': self.category,
            'thread_id': self.thread_id,
            'duration_ms': round(self.duration * 1000, 3),
            'return_value': str(self.return_value),
            'parameters': self.parameters,
            'sequence': self.sequence_number
        }
        
        if self.stack_trace:
            details['stack_trace'] = self.stack_trace[:10]  # 限制堆栈深度
        
        return MonitorEvent(
            timestamp=self.timestamp,
            event_type=event_type,
            operation=operation,
            process_name=self.process_name,
            process_id=self.pid,
            path=path,
            result="SUCCESS" if self._is_success() else "FAILURE",
            details=details
        )
    
    def _get_event_type(self) -> EventType:
        """根据系统调用确定事件类型"""
        if self.category == SyscallCategory.FILE_SYSTEM:
            if 'Create' in self.name or 'Open' in self.name:
                return EventType.FILE_ACCESS
            elif 'Write' in self.name:
                return EventType.FILE_MODIFY
            elif 'Delete' in self.name:
                return EventType.FILE_DELETE
            else:
                return EventType.FILE_ACCESS
        elif self.category == SyscallCategory.PROCESS_THREAD:
            if 'Create' in self.name:
                return EventType.PROCESS_CREATE
            elif 'Terminate' in self.name:
                return EventType.PROCESS_EXIT
            else:
                return EventType.PROCESS_CREATE
        elif self.category == SyscallCategory.REGISTRY:
            return EventType.REGISTRY_ACCESS
        elif self.category == SyscallCategory.NETWORK:
            return EventType.NETWORK_CONNECT
        else:
            return EventType.SYSCALL
    
    def _get_operation(self) -> Operation:
        """根据系统调用确定操作类型"""
        if 'Create' in self.name or 'Open' in self.name:
            return Operation.CREATE_OPEN
        elif 'Read' in self.name:
            return Operation.READ
        elif 'Write' in self.name:
            return Operation.WRITE
        elif 'Delete' in self.name:
            return Operation.DELETE
        elif 'Query' in self.name:
            return Operation.QUERY_INFO
        elif 'Set' in self.name:
            return Operation.SET_INFO
        else:
            return Operation.OTHER
    
    def _extract_path(self) -> Optional[str]:
        """从参数中提取路径信息"""
        path_keys = ['FileName', 'ObjectName', 'KeyName', 'ValueName', 'Path']
        for key in path_keys:
            if key in self.parameters:
                return str(self.parameters[key])
        return None
    
    def _is_success(self) -> bool:
        """判断系统调用是否成功"""
        if self.return_value is None:
            return True
        
        return_str = str(self.return_value).upper()
        return 'SUCCESS' in return_str or 'STATUS_SUCCESS' in return_str


class ProcessInfo:
    """进程信息"""
    
    def __init__(self, pid: int, name: str, exe_path: str = "", 
                 command_line: str = "", parent_pid: int = 0):
        self.pid = pid
        self.name = name
        self.exe_path = exe_path
        self.command_line = command_line
        self.parent_pid = parent_pid
        self.create_time = time.time()
        self.handles: Set[int] = set()
        self.modules: Set[str] = set()
        self.threads: Set[int] = set()
        self.syscall_count = 0
        self.last_activity = time.time()


class EnhancedSyscallMonitor(BaseMonitor):
    """增强系统调用监控器"""
    
    def __init__(self, event_callback: Callable[[MonitorEvent], None],
                 target_processes: Optional[Set[str]] = None,
                 categories: List[str] = None,
                 enable_stack_trace: bool = False,
                 enable_performance_tracking: bool = True,
                 max_events: int = 100000):
        super().__init__(event_callback)
        self.target_processes = target_processes or set()
        self.categories = categories or [SyscallCategory.FILE_SYSTEM, 
                                       SyscallCategory.PROCESS_THREAD,
                                       SyscallCategory.REGISTRY,
                                       SyscallCategory.NETWORK]
        self.enable_stack_trace = enable_stack_trace
        self.enable_performance_tracking = enable_performance_tracking
        self.max_events = max_events
        
        # 进程跟踪
        self.processes: Dict[int, ProcessInfo] = {}
        self.process_tree: Dict[int, List[int]] = {}  # parent_pid -> [child_pids]
        
        # 系统调用历史
        self.syscall_history: List[SyscallDetail] = []
        self.sequence_counter = 0
        
        # 性能统计
        self.stats = {
            'total_syscalls': 0,
            'syscalls_by_category': {},
            'syscalls_by_process': {},
            'average_duration': 0.0,
            'start_time': 0.0
        }
        
        # 监控状态
        self.last_process_scan = 0.0
        self.last_handle_scan = 0.0
        self.scan_interval = 0.1  # 100ms
    
    def _monitor_loop(self):
        """主监控循环"""
        print("增强系统调用监控器启动")
        self.stats['start_time'] = time.time()
        
        while self.running:
            try:
                current_time = time.time()
                
                # 更新进程信息
                if current_time - self.last_process_scan > 1.0:  # 每秒扫描一次
                    self._update_process_info()
                    self.last_process_scan = current_time
                
                # 监控文件系统调用
                if SyscallCategory.FILE_SYSTEM in self.categories:
                    self._monitor_file_syscalls()
                
                # 监控进程/线程调用
                if SyscallCategory.PROCESS_THREAD in self.categories:
                    self._monitor_process_syscalls()
                
                # 监控注册表调用
                if SyscallCategory.REGISTRY in self.categories:
                    self._monitor_registry_syscalls()
                
                # 监控网络调用
                if SyscallCategory.NETWORK in self.categories:
                    self._monitor_network_syscalls()
                
                # 监控内存操作
                if SyscallCategory.MEMORY in self.categories:
                    self._monitor_memory_syscalls()
                
                # 监控句柄操作
                if current_time - self.last_handle_scan > 2.0:  # 每2秒扫描一次
                    self._monitor_handle_operations()
                    self.last_handle_scan = current_time
                
                # 清理历史记录
                self._cleanup_history()
                
                # 控制扫描频率
                time.sleep(self.scan_interval)
                
            except Exception as e:
                print(f"系统调用监控出错: {e}")
                time.sleep(1.0)
    
    def _update_process_info(self):
        """更新进程信息"""
        if not PSUTIL_AVAILABLE:
            return
        
        try:
            current_pids = set()
            
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid', 'create_time']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name'] or 'Unknown'
                    exe_path = proc.info['exe'] or ''
                    cmdline = ' '.join(proc.info['cmdline'] or [])
                    ppid = proc.info['ppid'] or 0
                    
                    current_pids.add(pid)
                    
                    # 过滤目标进程
                    if self.target_processes and name.lower() not in {p.lower() for p in self.target_processes}:
                        continue
                    
                    # 新进程
                    if pid not in self.processes:
                        self.processes[pid] = ProcessInfo(pid, name, exe_path, cmdline, ppid)
                        
                        # 更新进程树
                        if ppid not in self.process_tree:
                            self.process_tree[ppid] = []
                        self.process_tree[ppid].append(pid)
                        
                        # 生成进程创建事件
                        self._generate_process_create_event(pid, name, exe_path, cmdline, ppid)
                    
                    # 更新进程信息
                    process_info = self.processes[pid]
                    process_info.last_activity = time.time()
                    
                    # 更新模块信息
                    try:
                        for dll in proc.memory_maps():
                            if dll.path and dll.path not in process_info.modules:
                                process_info.modules.add(dll.path)
                                self._generate_module_load_event(pid, name, dll.path)
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # 检测退出的进程
            exited_pids = set(self.processes.keys()) - current_pids
            for pid in exited_pids:
                process_info = self.processes[pid]
                self._generate_process_exit_event(pid, process_info.name)
                del self.processes[pid]
                
                # 清理进程树
                if pid in self.process_tree:
                    del self.process_tree[pid]
                
        except Exception as e:
            print(f"更新进程信息出错: {e}")
    
    def _monitor_file_syscalls(self):
        """监控文件系统调用"""
        if not PSUTIL_AVAILABLE:
            return
        
        try:
            for pid, process_info in self.processes.items():
                try:
                    proc = psutil.Process(pid)
                    
                    # 监控打开的文件
                    open_files = proc.open_files()
                    for file_info in open_files:
                        self._generate_file_syscall(
                            'NtOpenFile',
                            pid,
                            process_info.name,
                            {'FileName': file_info.path, 'Mode': file_info.mode}
                        )
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"监控文件系统调用出错: {e}")
    
    def _monitor_process_syscalls(self):
        """监控进程/线程系统调用"""
        # 这里可以实现更详细的进程系统调用监控
        pass
    
    def _monitor_registry_syscalls(self):
        """监控注册表系统调用"""
        # 这里可以实现注册表系统调用监控
        pass
    
    def _monitor_network_syscalls(self):
        """监控网络系统调用"""
        if not PSUTIL_AVAILABLE:
            return
        
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.pid and conn.pid in self.processes:
                    process_info = self.processes[conn.pid]
                    
                    if conn.status == psutil.CONN_ESTABLISHED:
                        self._generate_network_syscall(
                            'NtDeviceIoControlFile',
                            conn.pid,
                            process_info.name,
                            {
                                'LocalAddress': f"{conn.laddr.ip}:{conn.laddr.port}",
                                'RemoteAddress': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "Unknown",
                                'Status': conn.status
                            }
                        )
                        
        except Exception as e:
            print(f"监控网络系统调用出错: {e}")
    
    def _monitor_memory_syscalls(self):
        """监控内存系统调用"""
        if not PSUTIL_AVAILABLE:
            return
        
        try:
            for pid, process_info in self.processes.items():
                try:
                    proc = psutil.Process(pid)
                    memory_info = proc.memory_info()
                    
                    # 检测内存使用变化
                    if hasattr(process_info, 'last_memory_usage'):
                        if memory_info.rss != process_info.last_memory_usage:
                            self._generate_memory_syscall(
                                'NtAllocateVirtualMemory',
                                pid,
                                process_info.name,
                                {
                                    'Size': memory_info.rss - process_info.last_memory_usage,
                                    'TotalMemory': memory_info.rss
                                }
                            )
                    
                    process_info.last_memory_usage = memory_info.rss
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"监控内存系统调用出错: {e}")
    
    def _monitor_handle_operations(self):
        """监控句柄操作"""
        # 这里可以实现句柄操作监控
        pass
    
    def _generate_file_syscall(self, syscall_name: str, pid: int, process_name: str, parameters: Dict[str, Any]):
        """生成文件系统调用事件"""
        syscall = SyscallDetail(
            name=syscall_name,
            category=SyscallCategory.FILE_SYSTEM,
            pid=pid,
            process_name=process_name,
            parameters=parameters,
            return_value='STATUS_SUCCESS'
        )
        self._process_syscall(syscall)
    
    def _generate_network_syscall(self, syscall_name: str, pid: int, process_name: str, parameters: Dict[str, Any]):
        """生成网络系统调用事件"""
        syscall = SyscallDetail(
            name=syscall_name,
            category=SyscallCategory.NETWORK,
            pid=pid,
            process_name=process_name,
            parameters=parameters,
            return_value='STATUS_SUCCESS'
        )
        self._process_syscall(syscall)
    
    def _generate_memory_syscall(self, syscall_name: str, pid: int, process_name: str, parameters: Dict[str, Any]):
        """生成内存系统调用事件"""
        syscall = SyscallDetail(
            name=syscall_name,
            category=SyscallCategory.MEMORY,
            pid=pid,
            process_name=process_name,
            parameters=parameters,
            return_value='STATUS_SUCCESS'
        )
        self._process_syscall(syscall)
    
    def _generate_process_create_event(self, pid: int, name: str, exe_path: str, cmdline: str, ppid: int):
        """生成进程创建事件"""
        syscall = SyscallDetail(
            name='NtCreateProcess',
            category=SyscallCategory.PROCESS_THREAD,
            pid=pid,
            process_name=name,
            parameters={
                'ProcessName': name,
                'ExecutablePath': exe_path,
                'CommandLine': cmdline,
                'ParentPID': ppid
            },
            return_value='STATUS_SUCCESS'
        )
        self._process_syscall(syscall)
    
    def _generate_process_exit_event(self, pid: int, name: str):
        """生成进程退出事件"""
        syscall = SyscallDetail(
            name='NtTerminateProcess',
            category=SyscallCategory.PROCESS_THREAD,
            pid=pid,
            process_name=name,
            parameters={'ProcessName': name},
            return_value='STATUS_SUCCESS'
        )
        self._process_syscall(syscall)
    
    def _generate_module_load_event(self, pid: int, process_name: str, module_path: str):
        """生成模块加载事件"""
        syscall = SyscallDetail(
            name='LdrLoadDll',
            category=SyscallCategory.PROCESS_THREAD,
            pid=pid,
            process_name=process_name,
            parameters={
                'ModulePath': module_path,
                'ModuleName': os.path.basename(module_path)
            },
            return_value='STATUS_SUCCESS'
        )
        self._process_syscall(syscall)
    
    def _process_syscall(self, syscall: SyscallDetail):
        """处理系统调用"""
        try:
            # 设置序列号
            self.sequence_counter += 1
            syscall.sequence_number = self.sequence_counter
            
            # 添加到历史记录
            self.syscall_history.append(syscall)
            
            # 更新统计信息
            self._update_stats(syscall)
            
            # 转换为监控事件并发送
            event = syscall.to_monitor_event()
            self.event_callback(event)
            
        except Exception as e:
            print(f"处理系统调用出错: {e}")
    
    def _update_stats(self, syscall: SyscallDetail):
        """更新统计信息"""
        self.stats['total_syscalls'] += 1
        
        # 按分类统计
        category = syscall.category
        self.stats['syscalls_by_category'][category] = self.stats['syscalls_by_category'].get(category, 0) + 1
        
        # 按进程统计
        process_key = f"{syscall.process_name} ({syscall.pid})"
        self.stats['syscalls_by_process'][process_key] = self.stats['syscalls_by_process'].get(process_key, 0) + 1
        
        # 更新进程系统调用计数
        if syscall.pid in self.processes:
            self.processes[syscall.pid].syscall_count += 1
    
    def _cleanup_history(self):
        """清理历史记录"""
        if len(self.syscall_history) > self.max_events:
            # 保留最新的事件
            self.syscall_history = self.syscall_history[-self.max_events//2:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        runtime = time.time() - self.stats['start_time']
        
        return {
            'runtime_seconds': round(runtime, 2),
            'total_syscalls': self.stats['total_syscalls'],
            'syscalls_per_second': round(self.stats['total_syscalls'] / max(runtime, 1), 2),
            'syscalls_by_category': self.stats['syscalls_by_category'],
            'syscalls_by_process': dict(list(self.stats['syscalls_by_process'].items())[:10]),  # 前10个
            'active_processes': len(self.processes),
            'monitored_categories': self.categories
        }
    
    def get_process_tree(self) -> Dict[int, List[int]]:
        """获取进程树"""
        return self.process_tree.copy()
    
    def get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """获取进程信息"""
        return self.processes.get(pid)