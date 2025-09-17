#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强进程监控模块
提供更详细的进程事件检测，包括进程创建、退出、线程操作、模块加载等
"""

import os
import sys
import time
import ctypes
import threading
from datetime import datetime
from typing import Dict, Set, Optional, List, Callable, Tuple
from ctypes import wintypes, windll
from pathlib import Path

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("警告: psutil库未安装，某些功能将不可用")

try:
    import win32api
    import win32con
    import win32file
    import win32event
    import win32process
    import win32security
    import win32job
    import pywintypes
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    print("警告: pywin32库未安装，高级进程监控功能将不可用")

from procmon import BaseMonitor, MonitorEvent, EventType, Operation


def format_error_message(operation: str, error: Exception, details: str = "") -> str:
    """格式化错误信息输出"""
    timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
    error_type = type(error).__name__
    error_msg = str(error)
    
    # 构建美化的错误信息
    formatted_msg = f"\n{'='*60}\n"
    formatted_msg += f"⚠️  监控错误报告\n"
    formatted_msg += f"{'='*60}\n"
    formatted_msg += f"时间: {timestamp}\n"
    formatted_msg += f"操作: {operation}\n"
    formatted_msg += f"错误类型: {error_type}\n"
    formatted_msg += f"错误信息: {error_msg}\n"
    if details:
        formatted_msg += f"详细信息: {details}\n"
    formatted_msg += f"{'='*60}\n"
    
    return formatted_msg


class ProcessInfo:
    """进程信息类"""
    
    def __init__(self, pid: int, name: str, exe_path: str = "", cmdline: List[str] = None, 
                 parent_pid: int = 0, create_time: float = 0.0):
        self.pid = pid
        self.name = name
        self.exe_path = exe_path
        self.cmdline = cmdline or []
        self.parent_pid = parent_pid
        self.create_time = create_time
        self.threads = set()
        self.modules = set()
        self.handles = set()
        self.memory_info = {}
        self.cpu_percent = 0.0
        self.last_update = time.time()
    
    def update_stats(self):
        """更新进程统计信息"""
        if not PSUTIL_AVAILABLE:
            return
            
        try:
            proc = psutil.Process(self.pid)
            self.memory_info = proc.memory_info()._asdict()
            self.cpu_percent = proc.cpu_percent()
            self.last_update = time.time()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            'pid': self.pid,
            'name': self.name,
            'exe_path': self.exe_path,
            'cmdline': ' '.join(self.cmdline),
            'parent_pid': self.parent_pid,
            'create_time': self.create_time,
            'thread_count': len(self.threads),
            'module_count': len(self.modules),
            'handle_count': len(self.handles),
            'memory_info': self.memory_info,
            'cpu_percent': self.cpu_percent
        }


class ThreadInfo:
    """线程信息类"""
    
    def __init__(self, tid: int, pid: int, create_time: float = 0.0, 
                 user_time: float = 0.0, system_time: float = 0.0, 
                 status: str = "unknown", priority: int = 0):
        self.tid = tid
        self.pid = pid
        self.create_time = create_time
        self.user_time = user_time  # 用户态CPU时间
        self.system_time = system_time  # 内核态CPU时间
        self.status = status  # 线程状态
        self.priority = priority  # 线程优先级
        self.last_update = time.time()
        self.start_address = None  # 线程起始地址
        self.context_switches = 0  # 上下文切换次数


class ModuleInfo:
    """模块信息类"""
    
    def __init__(self, name: str, path: str, base_address: int = 0, size: int = 0):
        self.name = name
        self.path = path
        self.base_address = base_address
        self.size = size
        self.load_time = time.time()


class EnhancedProcessMonitor(BaseMonitor):
    """增强进程监控器"""
    
    def __init__(self, event_callback: Callable[[MonitorEvent], None], 
                 target_processes: Optional[Set[str]] = None,
                 monitor_threads: bool = True,
                 monitor_modules: bool = True,
                 monitor_handles: bool = False,
                 monitor_child_processes: bool = True):
        super().__init__(event_callback)
        self.target_processes = target_processes or set()
        self.monitor_threads = monitor_threads
        self.monitor_modules = monitor_modules
        self.monitor_handles = monitor_handles
        self.monitor_child_processes = monitor_child_processes
        
        # 进程跟踪
        self.processes: Dict[int, ProcessInfo] = {}
        self.threads: Dict[int, ThreadInfo] = {}
        self.modules: Dict[Tuple[int, str], ModuleInfo] = {}  # (pid, module_name) -> ModuleInfo
        
        # 子进程跟踪
        self.process_tree: Dict[int, Set[int]] = {}  # parent_pid -> {child_pids}
        self.monitored_pids: Set[int] = set()  # 当前监控的所有PID
        self.root_processes: Set[int] = set()  # 根进程PID
        
        # 性能统计
        self.scan_count = 0
        self.last_scan_time = 0.0
        self.scan_duration = 0.0
        
    def _monitor_loop(self):
        """监控循环"""
        print("增强进程监控器启动")
        
        while self.running:
            try:
                start_time = time.time()
                
                # 扫描进程变化
                self._scan_processes()
                
                # 扫描线程变化
                if self.monitor_threads:
                    self._scan_threads()
                
                # 扫描模块变化
                if self.monitor_modules:
                    self._scan_modules()
                
                # 扫描句柄变化
                if self.monitor_handles:
                    self._scan_handles()
                
                # 更新统计信息
                self.scan_count += 1
                self.scan_duration = time.time() - start_time
                self.last_scan_time = time.time()
                
                # 控制扫描频率
                time.sleep(max(0.1, 0.5 - self.scan_duration))
                
            except Exception as e:
                print(format_error_message("增强进程监控", e, "监控循环执行异常"))
                time.sleep(1.0)
    
    def _scan_processes(self):
        """扫描进程变化"""
        if not PSUTIL_AVAILABLE:
            return
            
        try:
            current_processes = {}
            
            # 获取当前所有进程
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid', 'create_time']):
                try:
                    info = proc.info
                    pid = info['pid']
                    name = info['name'] or 'Unknown'
                    
                    # 判断是否需要监控此进程
                    should_monitor = False
                    
                    # 1. 目标进程
                    if self.target_processes and name.lower() in {p.lower() for p in self.target_processes}:
                        should_monitor = True
                        self.root_processes.add(pid)
                    
                    # 2. 子进程监控
                    elif self.monitor_child_processes:
                        parent_pid = info.get('ppid', 0)
                        if parent_pid in self.monitored_pids:
                            should_monitor = True
                            # 更新进程树
                            if parent_pid not in self.process_tree:
                                self.process_tree[parent_pid] = set()
                            self.process_tree[parent_pid].add(pid)
                    
                    if not should_monitor:
                        continue
                    
                    # 添加到监控列表
                    self.monitored_pids.add(pid)
                    
                    proc_info = ProcessInfo(
                        pid=pid,
                        name=name,
                        exe_path=info.get('exe', ''),
                        cmdline=info.get('cmdline', []),
                        parent_pid=info.get('ppid', 0),
                        create_time=info.get('create_time', 0.0)
                    )
                    
                    current_processes[pid] = proc_info
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # 检测新进程
            for pid, proc_info in current_processes.items():
                if pid not in self.processes:
                    self._emit_process_event(proc_info, Operation.PROCESS_CREATE)
                    self.processes[pid] = proc_info
                else:
                    # 更新现有进程信息
                    self.processes[pid].update_stats()
            
            # 检测退出的进程
            for pid in list(self.processes.keys()):
                if pid not in current_processes:
                    proc_info = self.processes[pid]
                    self._emit_process_event(proc_info, Operation.PROCESS_EXIT)
                    del self.processes[pid]
                    
                    # 清理进程树和监控列表
                    self._cleanup_process_tree(pid)
                    self.monitored_pids.discard(pid)
                    self.root_processes.discard(pid)
                    
                    # 清理相关的线程和模块信息
                    self._cleanup_process_data(pid)
            
        except Exception as e:
            print(format_error_message("扫描进程", e, "进程状态检查失败"))
    
    def _scan_threads(self):
        """扫描线程变化"""
        if not PSUTIL_AVAILABLE:
            return
            
        try:
            current_threads = {}
            
            for pid, proc_info in self.processes.items():
                try:
                    proc = psutil.Process(pid)
                    threads = proc.threads()
                    
                    for thread in threads:
                        tid = thread.id
                        
                        # 收集详细的线程信息
                        user_time = getattr(thread, 'user_time', 0.0)
                        system_time = getattr(thread, 'system_time', 0.0)
                        
                        # 尝试获取线程状态信息
                        try:
                            # 获取线程的详细信息
                            thread_handle = None
                            status = "running"
                            priority = 0
                            
                            # 在Windows上尝试获取更多信息
                            if hasattr(proc, 'nice'):
                                try:
                                    priority = proc.nice()
                                except:
                                    priority = 0
                                    
                        except Exception:
                            status = "unknown"
                            priority = 0
                        
                        thread_info = ThreadInfo(
                            tid=tid,
                            pid=pid,
                            create_time=user_time,
                            user_time=user_time,
                            system_time=system_time,
                            status=status,
                            priority=priority
                        )
                        current_threads[tid] = thread_info
                        
                        # 检测新线程
                        if tid not in self.threads:
                            self._emit_thread_event(proc_info, thread_info, Operation.THREAD_CREATE)
                            proc_info.threads.add(tid)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # 检测退出的线程
            for tid in list(self.threads.keys()):
                if tid not in current_threads:
                    thread_info = self.threads[tid]
                    if thread_info.pid in self.processes:
                        proc_info = self.processes[thread_info.pid]
                        self._emit_thread_event(proc_info, thread_info, Operation.THREAD_EXIT)
                        proc_info.threads.discard(tid)
                    del self.threads[tid]
            
            self.threads = current_threads
            
        except Exception as e:
            print(format_error_message("扫描线程", e, "线程状态检查失败"))
    
    def _scan_modules(self):
        """扫描模块变化"""
        if not PSUTIL_AVAILABLE:
            return
            
        try:
            current_modules = {}
            
            for pid, proc_info in self.processes.items():
                try:
                    proc = psutil.Process(pid)
                    
                    # 获取进程模块（在Windows上可能需要特殊处理）
                    try:
                        memory_maps = proc.memory_maps()
                        for mmap in memory_maps:
                            if mmap.path and os.path.exists(mmap.path):
                                module_name = os.path.basename(mmap.path)
                                module_key = (pid, module_name)
                                
                                if module_key not in current_modules:
                                    module_info = ModuleInfo(
                                        name=module_name,
                                        path=mmap.path,
                                        base_address=0,  # psutil不提供基地址
                                        size=0
                                    )
                                    current_modules[module_key] = module_info
                                    
                                    # 检测新模块
                                    if module_key not in self.modules:
                                        self._emit_module_event(proc_info, module_info, Operation.MODULE_LOAD)
                                        proc_info.modules.add(module_name)
                    except (psutil.AccessDenied, AttributeError):
                        # 某些进程可能无法访问内存映射
                        pass
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # 检测卸载的模块
            for module_key in list(self.modules.keys()):
                if module_key not in current_modules:
                    pid, module_name = module_key
                    if pid in self.processes:
                        proc_info = self.processes[pid]
                        module_info = self.modules[module_key]
                        self._emit_module_event(proc_info, module_info, Operation.MODULE_UNLOAD)
                        proc_info.modules.discard(module_name)
                    del self.modules[module_key]
            
            self.modules = current_modules
            
        except Exception as e:
            print(format_error_message("扫描模块", e, "模块加载/卸载检查失败"))
    
    def _scan_handles(self):
        """扫描句柄变化"""
        # 句柄监控比较复杂，这里提供基础框架
        try:
            for pid, proc_info in self.processes.items():
                try:
                    if PSUTIL_AVAILABLE:
                        proc = psutil.Process(pid)
                        # 获取打开的文件句柄
                        open_files = proc.open_files()
                        current_handles = {f.path for f in open_files}
                        
                        # 检测新句柄
                        new_handles = current_handles - proc_info.handles
                        for handle in new_handles:
                            self._emit_handle_event(proc_info, handle, Operation.HANDLE_CREATE)
                        
                        # 检测关闭的句柄
                        closed_handles = proc_info.handles - current_handles
                        for handle in closed_handles:
                            self._emit_handle_event(proc_info, handle, Operation.HANDLE_CLOSE)
                        
                        proc_info.handles = current_handles
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(format_error_message("扫描句柄", e, "句柄状态检查失败"))
    
    def _cleanup_process_data(self, pid: int):
        """清理进程相关数据"""
        # 清理线程
        threads_to_remove = [tid for tid, thread_info in self.threads.items() if thread_info.pid == pid]
        for tid in threads_to_remove:
            del self.threads[tid]
        
        # 清理模块
        modules_to_remove = [key for key in self.modules.keys() if key[0] == pid]
        for key in modules_to_remove:
            del self.modules[key]
    
    def _cleanup_process_tree(self, pid: int):
        """清理进程树相关数据"""
        # 移除作为父进程的记录
        if pid in self.process_tree:
            # 递归清理子进程
            child_pids = self.process_tree[pid].copy()
            for child_pid in child_pids:
                self.monitored_pids.discard(child_pid)
                self._cleanup_process_tree(child_pid)
            del self.process_tree[pid]
        
        # 从其他进程的子进程列表中移除
        for parent_pid, children in self.process_tree.items():
            children.discard(pid)
    
    def get_process_tree_info(self, pid: int) -> dict:
        """获取进程树信息"""
        info = {
            'pid': pid,
            'is_root': pid in self.root_processes,
            'children': list(self.process_tree.get(pid, set())),
            'depth': 0
        }
        
        # 计算进程深度
        current_pid = pid
        depth = 0
        visited = set()
        
        while current_pid not in self.root_processes and current_pid not in visited:
            visited.add(current_pid)
            # 查找父进程
            parent_found = False
            for parent_pid, children in self.process_tree.items():
                if current_pid in children:
                    current_pid = parent_pid
                    depth += 1
                    parent_found = True
                    break
            if not parent_found:
                break
        
        info['depth'] = depth
        return info
    
    def _emit_process_event(self, proc_info: ProcessInfo, operation: Operation):
        """发送进程事件"""
        try:
            # 获取进程树信息
            tree_info = self.get_process_tree_info(proc_info.pid)
            
            # 合并进程信息和树信息
            details = proc_info.to_dict()
            details.update({
                'process_depth': tree_info['depth'],
                'is_root_process': tree_info['is_root'],
                'child_count': len(tree_info['children']),
                'children_pids': tree_info['children']
            })
            
            event = MonitorEvent(
                timestamp=datetime.now(),
                event_type=EventType.PROCESS,
                operation=operation,
                process_name=proc_info.name,
                process_id=proc_info.pid,
                path=proc_info.exe_path or f"PID: {proc_info.pid}",
                result="SUCCESS",
                details=details
            )
            self._emit_event(event)
        except Exception as e:
            print(format_error_message("发送进程事件", e, f"进程: {proc_info.name} (PID: {proc_info.pid})"))
    
    def _emit_thread_event(self, proc_info: ProcessInfo, thread_info: ThreadInfo, operation: Operation):
        """发送线程事件"""
        try:
            # 计算总CPU时间
            total_cpu_time = thread_info.user_time + thread_info.system_time
            
            # 格式化CPU时间显示
            cpu_time_str = f"{total_cpu_time:.3f}s" if total_cpu_time > 0 else "0.000s"
            user_time_str = f"{thread_info.user_time:.3f}s" if thread_info.user_time > 0 else "0.000s"
            system_time_str = f"{thread_info.system_time:.3f}s" if thread_info.system_time > 0 else "0.000s"
            
            event = MonitorEvent(
                timestamp=datetime.now(),
                event_type=EventType.PROCESS,
                operation=operation,
                process_name=proc_info.name,
                process_id=proc_info.pid,
                path=f"Thread {thread_info.tid}",
                result="SUCCESS",
                details={
                    'thread_id': thread_info.tid,
                    'process_id': thread_info.pid,
                    'create_time': thread_info.create_time,
                    'user_time': thread_info.user_time,
                    'system_time': thread_info.system_time,
                    'total_cpu_time': total_cpu_time,
                    'status': thread_info.status,
                    'priority': thread_info.priority,
                    'context_switches': thread_info.context_switches,
                    'start_address': thread_info.start_address,
                    # 格式化的显示字符串
                    'cpu_time_display': cpu_time_str,
                    'user_time_display': user_time_str,
                    'system_time_display': system_time_str,
                    'status_display': thread_info.status.upper(),
                    'priority_display': f"Priority: {thread_info.priority}"
                }
            )
            self._emit_event(event)
        except Exception as e:
            print(format_error_message("发送线程事件", e, f"线程ID: {thread_info.tid}, 进程: {proc_info.name}"))
    
    def _emit_module_event(self, proc_info: ProcessInfo, module_info: ModuleInfo, operation: Operation):
        """发送模块事件"""
        try:
            event = MonitorEvent(
                timestamp=datetime.now(),
                event_type=EventType.PROCESS,
                operation=operation,
                process_name=proc_info.name,
                process_id=proc_info.pid,
                path=module_info.path,
                result="SUCCESS",
                details={
                    'module_name': module_info.name,
                    'module_path': module_info.path,
                    'base_address': hex(module_info.base_address) if module_info.base_address else '0x0',
                    'size': module_info.size,
                    'load_time': module_info.load_time
                }
            )
            self._emit_event(event)
        except Exception as e:
            print(format_error_message("发送模块事件", e, f"模块: {module_info.name}, 进程: {proc_info.name}"))
    
    def _emit_handle_event(self, proc_info: ProcessInfo, handle_path: str, operation: Operation):
        """发送句柄事件"""
        try:
            event = MonitorEvent(
                timestamp=datetime.now(),
                event_type=EventType.PROCESS,
                operation=operation,
                process_name=proc_info.name,
                process_id=proc_info.pid,
                path=handle_path,
                result="SUCCESS",
                details={
                    'handle_type': 'FILE',
                    'handle_path': handle_path
                }
            )
            self._emit_event(event)
        except Exception as e:
            print(format_error_message("发送句柄事件", e, f"句柄类型: {handle_type}, 进程: {proc_info.name}"))
    
    def get_statistics(self) -> dict:
        """获取监控统计信息"""
        return {
            'scan_count': self.scan_count,
            'last_scan_time': self.last_scan_time,
            'scan_duration': self.scan_duration,
            'process_count': len(self.processes),
            'thread_count': len(self.threads),
            'module_count': len(self.modules),
            'target_processes': list(self.target_processes)
        }


def test_enhanced_process_monitor():
    """测试增强进程监控器"""
    def event_handler(event):
        print(f"[{event.timestamp.strftime('%H:%M:%S.%f')[:-3]}] "
              f"{event.process_name} ({event.process_id}) - "
              f"{event.operation.value}: {event.path} - {event.result}")
        
        if event.details:
            for key, value in event.details.items():
                if key not in ['cmdline', 'memory_info'] or value:
                    print(f"  {key}: {value}")
    
    print("启动增强进程监控器测试...")
    
    # 可以指定要监控的进程
    target_processes = {'notepad.exe', 'python.exe', 'cmd.exe'}
    
    monitor = EnhancedProcessMonitor(
        event_handler, 
        target_processes=target_processes,
        monitor_threads=True,
        monitor_modules=True,
        monitor_handles=False  # 句柄监控可能产生大量事件
    )
    
    try:
        monitor.start()
        print(f"监控器已启动，目标进程: {target_processes}")
        print("按Ctrl+C停止")
        
        # 定期显示统计信息
        last_stats_time = time.time()
        while True:
            time.sleep(1)
            
            # 每10秒显示一次统计信息
            if time.time() - last_stats_time > 10:
                stats = monitor.get_statistics()
                print(f"\n统计信息: {stats}")
                last_stats_time = time.time()
                
    except KeyboardInterrupt:
        print("\n正在停止监控器...")
        monitor.stop()
        
        # 显示最终统计信息
        stats = monitor.get_statistics()
        print(f"最终统计信息: {stats}")
        print("监控器已停止")


if __name__ == "__main__":
    test_enhanced_process_monitor()