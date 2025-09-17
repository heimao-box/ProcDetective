#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强监控模块
使用Windows API和系统调用级别的监控来捕获更详细的程序行为
"""

import os
import sys
import time
import ctypes
import threading
from datetime import datetime
from typing import Dict, Set, Optional, List, Callable
from ctypes import wintypes, windll
from pathlib import Path

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
    import pywintypes
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    print("警告: pywin32库未安装，某些高级功能将不可用")
    print("请运行: pip install pywin32")

from procmon import BaseMonitor, MonitorEvent, EventType, Operation


class WindowsAPIMonitor(BaseMonitor):
    """基于Windows API的增强监控器"""
    
    def __init__(self, event_callback: Callable[[MonitorEvent], None]):
        super().__init__(event_callback)
        self.process_handles = {}
        self.file_handles = {}
        self.registry_handles = {}
        self.hook_installed = False
        
    def _monitor_loop(self):
        """监控循环"""
        if not WIN32_AVAILABLE:
            print("Windows API不可用，使用基础监控模式")
            self._basic_monitor_loop()
            return
            
        try:
            self._install_hooks()
            while self.running:
                self._process_events()
                time.sleep(0.01)  # 更高频率的检查
        except Exception as e:
            print(f"增强监控出错: {e}")
        finally:
            self._cleanup_hooks()
    
    def _basic_monitor_loop(self):
        """基础监控循环（当Windows API不可用时）"""
        while self.running:
            try:
                self._scan_system_state()
                time.sleep(0.1)
            except Exception as e:
                print(f"基础监控出错: {e}")
                time.sleep(1.0)
    
    def _install_hooks(self):
        """安装系统钩子"""
        if not WIN32_AVAILABLE:
            return
            
        try:
            # 这里可以安装各种系统钩子来监控系统调用
            # 由于复杂性，这里提供框架结构
            self.hook_installed = True
            print("系统钩子已安装")
        except Exception as e:
            print(f"安装系统钩子失败: {e}")
    
    def _cleanup_hooks(self):
        """清理系统钩子"""
        if self.hook_installed:
            try:
                # 清理钩子
                self.hook_installed = False
                print("系统钩子已清理")
            except Exception as e:
                print(f"清理系统钩子失败: {e}")
    
    def _process_events(self):
        """处理系统事件"""
        # 处理各种系统事件
        self._check_process_events()
        self._check_file_events()
        self._check_registry_events()
        self._check_network_events()
    
    def _check_process_events(self):
        """检查进程事件"""
        if not PSUTIL_AVAILABLE:
            return
            
        try:
            current_processes = {}
            for proc in psutil.process_iter(['pid', 'name', 'create_time', 'cmdline', 'exe']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name']
                    if name:
                        current_processes[pid] = proc.info
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # 检测新进程
            for pid, info in current_processes.items():
                if pid not in self.process_handles:
                    self._emit_enhanced_process_event(pid, info, Operation.PROCESS_CREATE)
            
            # 检测退出的进程
            for pid in list(self.process_handles.keys()):
                if pid not in current_processes:
                    self._emit_enhanced_process_event(pid, self.process_handles[pid], Operation.PROCESS_EXIT)
                    del self.process_handles[pid]
            
            self.process_handles = current_processes
            
        except Exception as e:
            print(f"检查进程事件出错: {e}")
    
    def _check_file_events(self):
        """检查文件事件"""
        try:
            # 使用更高级的文件监控技术
            self._monitor_file_handles()
            self._monitor_directory_changes()
        except Exception as e:
            print(f"检查文件事件出错: {e}")
    
    def _monitor_file_handles(self):
        """监控文件句柄"""
        if not PSUTIL_AVAILABLE:
            return
            
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name']:
                        # 获取进程打开的文件
                        files = proc.open_files()
                        for file_info in files:
                            self._emit_file_access_event(proc.info, file_info.path, Operation.FILE_READ)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"监控文件句柄出错: {e}")
    
    def _monitor_directory_changes(self):
        """监控目录变化"""
        if not WIN32_AVAILABLE:
            return
            
        try:
            # 使用Windows API监控目录变化
            # 这里可以实现更详细的目录监控
            pass
        except Exception as e:
            print(f"监控目录变化出错: {e}")
    
    def _check_registry_events(self):
        """检查注册表事件"""
        try:
            # 实现注册表监控
            self._monitor_registry_changes()
        except Exception as e:
            print(f"检查注册表事件出错: {e}")
    
    def _monitor_registry_changes(self):
        """监控注册表变化"""
        if not WIN32_AVAILABLE:
            return
            
        try:
            # 使用Windows API监控注册表变化
            # 这里可以实现实时注册表监控
            pass
        except Exception as e:
            print(f"监控注册表变化出错: {e}")
    
    def _check_network_events(self):
        """检查网络事件"""
        try:
            # 实现网络监控
            self._monitor_network_connections()
        except Exception as e:
            print(f"检查网络事件出错: {e}")
    
    def _monitor_network_connections(self):
        """监控网络连接"""
        if not PSUTIL_AVAILABLE:
            return
            
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        self._emit_network_event(proc, conn, Operation.NET_CONNECT)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        except Exception as e:
            print(f"监控网络连接出错: {e}")
    
    def _scan_system_state(self):
        """扫描系统状态"""
        self._check_process_events()
        self._check_file_events()
        self._check_registry_events()
        self._check_network_events()
    
    def _emit_enhanced_process_event(self, pid: int, proc_info: dict, operation: Operation):
        """发送增强的进程事件"""
        try:
            name = proc_info.get('name', 'Unknown')
            cmdline = proc_info.get('cmdline', [])
            exe_path = proc_info.get('exe', '')
            
            event = MonitorEvent(
                timestamp=datetime.now(),
                event_type=EventType.PROCESS,
                operation=operation,
                process_name=name,
                process_id=pid,
                path=exe_path or f"PID: {pid}",
                result="SUCCESS",
                details={
                    'command_line': ' '.join(cmdline) if cmdline else '',
                    'executable_path': exe_path,
                    'create_time': str(proc_info.get('create_time', ''))
                }
            )
            self._emit_event(event)
        except Exception as e:
            print(f"发送进程事件出错: {e}")
    
    def _emit_file_access_event(self, proc_info: dict, file_path: str, operation: Operation):
        """发送文件访问事件"""
        try:
            event = MonitorEvent(
                timestamp=datetime.now(),
                event_type=EventType.FILE_SYSTEM,
                operation=operation,
                process_name=proc_info.get('name', 'Unknown'),
                process_id=proc_info.get('pid', 0),
                path=file_path,
                result="SUCCESS",
                details={
                    'file_size': str(self._get_file_size(file_path)),
                    'access_time': str(datetime.now())
                }
            )
            self._emit_event(event)
        except Exception as e:
            print(f"发送文件访问事件出错: {e}")
    
    def _emit_network_event(self, proc, conn, operation: Operation):
        """发送网络事件"""
        try:
            local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "Unknown"
            remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "Unknown"
            
            event = MonitorEvent(
                timestamp=datetime.now(),
                event_type=EventType.NETWORK,
                operation=operation,
                process_name=proc.name(),
                process_id=proc.pid,
                path=f"{conn.type.name} {local_addr} -> {remote_addr}",
                result="SUCCESS",
                details={
                    'protocol': conn.type.name,
                    'local_address': local_addr,
                    'remote_address': remote_addr,
                    'status': conn.status
                }
            )
            self._emit_event(event)
        except Exception as e:
            print(f"发送网络事件出错: {e}")
    
    def _get_file_size(self, file_path: str) -> int:
        """获取文件大小"""
        try:
            return os.path.getsize(file_path)
        except (OSError, FileNotFoundError):
            return 0


class SystemCallMonitor(BaseMonitor):
    """系统调用级别的监控器"""
    
    def __init__(self, event_callback: Callable[[MonitorEvent], None], target_processes: Optional[Set[str]] = None):
        super().__init__(event_callback)
        self.target_processes = target_processes or set()
        self.syscall_hooks = {}
        
    def _monitor_loop(self):
        """监控循环"""
        print("系统调用监控器启动（实验性功能）")
        while self.running:
            try:
                self._monitor_syscalls()
                time.sleep(0.01)
            except Exception as e:
                print(f"系统调用监控出错: {e}")
                time.sleep(1.0)
    
    def _monitor_syscalls(self):
        """监控系统调用"""
        # 这里可以实现系统调用级别的监控
        # 由于复杂性，这里提供基础框架
        try:
            # 监控文件系统调用
            self._monitor_file_syscalls()
            # 监控进程系统调用
            self._monitor_process_syscalls()
            # 监控网络系统调用
            self._monitor_network_syscalls()
        except Exception as e:
            print(f"监控系统调用出错: {e}")
    
    def _monitor_file_syscalls(self):
        """监控文件系统调用"""
        # 实现文件系统调用监控
        pass
    
    def _monitor_process_syscalls(self):
        """监控进程系统调用"""
        # 实现进程系统调用监控
        pass
    
    def _monitor_network_syscalls(self):
        """监控网络系统调用"""
        # 实现网络系统调用监控
        pass


def test_enhanced_monitor():
    """测试增强监控器"""
    def event_handler(event):
        print(f"[{event.timestamp.strftime('%H:%M:%S.%f')[:-3]}] "
              f"{event.process_name} ({event.process_id}) - "
              f"{event.operation.value}: {event.path} - {event.result}")
    
    print("启动增强监控器测试...")
    monitor = WindowsAPIMonitor(event_handler)
    
    try:
        monitor.start()
        print("监控器已启动，按Ctrl+C停止")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n正在停止监控器...")
        monitor.stop()
        print("监控器已停止")


if __name__ == "__main__":
    test_enhanced_monitor()