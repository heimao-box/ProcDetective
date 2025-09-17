#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
进程监控模块
监控进程的创建、退出、线程操作等活动
"""

import os
import sys
import time
import psutil
import threading
from datetime import datetime
from typing import Dict, Set, Optional
from procmon import BaseMonitor, MonitorEvent, EventType, Operation


class ProcessInfo:
    """进程信息类"""
    
    def __init__(self, pid: int, name: str, create_time: float):
        self.pid = pid
        self.name = name
        self.create_time = create_time
        self.threads: Set[int] = set()


class ProcessMonitor(BaseMonitor):
    """进程监控器"""
    
    def __init__(self, event_callback, target_processes: Optional[Set[str]] = None):
        super().__init__(event_callback)
        self.target_processes = target_processes or set()
        self.known_processes: Dict[int, ProcessInfo] = {}
        self.scan_interval = 0.5  # 扫描间隔（秒）
        self._initialize_known_processes()
    
    def _initialize_known_processes(self):
        """初始化已知进程列表"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'create_time']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name']
                    create_time = proc.info['create_time']
                    
                    if name:
                        self.known_processes[pid] = ProcessInfo(pid, name, create_time)
                        
                        # 获取线程信息
                        try:
                            process = psutil.Process(pid)
                            for thread in process.threads():
                                self.known_processes[pid].threads.add(thread.id)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            print(f"初始化进程列表时出错: {e}")
    
    def _should_monitor_process(self, process_name: str) -> bool:
        """判断是否应该监控该进程"""
        if not self.target_processes:
            return True
        return process_name.lower() in {p.lower() for p in self.target_processes}
    
    def _monitor_loop(self):
        """监控循环"""
        while self.running:
            try:
                self._scan_processes()
                time.sleep(self.scan_interval)
            except Exception as e:
                print(f"进程监控出错: {e}")
                time.sleep(1.0)
    
    def _scan_processes(self):
        """扫描进程变化"""
        current_processes = {}
        
        try:
            # 获取当前所有进程
            for proc in psutil.process_iter(['pid', 'name', 'create_time']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name']
                    create_time = proc.info['create_time']
                    
                    if name and self._should_monitor_process(name):
                        current_processes[pid] = ProcessInfo(pid, name, create_time)
                        
                        # 获取线程信息
                        try:
                            process = psutil.Process(pid)
                            for thread in process.threads():
                                current_processes[pid].threads.add(thread.id)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # 检测新进程
            for pid, proc_info in current_processes.items():
                if pid not in self.known_processes:
                    self._emit_process_create_event(proc_info)
                else:
                    # 检测新线程
                    old_threads = self.known_processes[pid].threads
                    new_threads = proc_info.threads - old_threads
                    for thread_id in new_threads:
                        self._emit_thread_create_event(proc_info, thread_id)
            
            # 检测已退出的进程
            for pid, proc_info in self.known_processes.items():
                if pid not in current_processes:
                    self._emit_process_exit_event(proc_info)
                else:
                    # 检测已退出的线程
                    old_threads = proc_info.threads
                    current_threads = current_processes[pid].threads
                    exited_threads = old_threads - current_threads
                    for thread_id in exited_threads:
                        self._emit_thread_exit_event(proc_info, thread_id)
            
            # 更新已知进程列表
            self.known_processes = current_processes
            
        except Exception as e:
            print(f"扫描进程时出错: {e}")
    
    def _emit_process_create_event(self, proc_info: ProcessInfo):
        """发送进程创建事件"""
        event = MonitorEvent(
            timestamp=datetime.now(),
            event_type=EventType.PROCESS,
            operation=Operation.PROCESS_CREATE,
            process_name=proc_info.name,
            process_id=proc_info.pid,
            path=f"PID: {proc_info.pid}",
            result="SUCCESS",
            details={
                "create_time": str(datetime.fromtimestamp(proc_info.create_time)),
                "thread_count": str(len(proc_info.threads))
            }
        )
        self._emit_event(event)
    
    def _emit_process_exit_event(self, proc_info: ProcessInfo):
        """发送进程退出事件"""
        event = MonitorEvent(
            timestamp=datetime.now(),
            event_type=EventType.PROCESS,
            operation=Operation.PROCESS_EXIT,
            process_name=proc_info.name,
            process_id=proc_info.pid,
            path=f"PID: {proc_info.pid}",
            result="SUCCESS",
            details={
                "create_time": str(datetime.fromtimestamp(proc_info.create_time)),
                "thread_count": str(len(proc_info.threads))
            }
        )
        self._emit_event(event)
    
    def _emit_thread_create_event(self, proc_info: ProcessInfo, thread_id: int):
        """发送线程创建事件"""
        event = MonitorEvent(
            timestamp=datetime.now(),
            event_type=EventType.PROCESS,
            operation=Operation.THREAD_CREATE,
            process_name=proc_info.name,
            process_id=proc_info.pid,
            path=f"TID: {thread_id}",
            result="SUCCESS",
            details={
                "thread_id": str(thread_id),
                "process_pid": str(proc_info.pid)
            }
        )
        self._emit_event(event)
    
    def _emit_thread_exit_event(self, proc_info: ProcessInfo, thread_id: int):
        """发送线程退出事件"""
        event = MonitorEvent(
            timestamp=datetime.now(),
            event_type=EventType.PROCESS,
            operation=Operation.THREAD_EXIT,
            process_name=proc_info.name,
            process_id=proc_info.pid,
            path=f"TID: {thread_id}",
            result="SUCCESS",
            details={
                "thread_id": str(thread_id),
                "process_pid": str(proc_info.pid)
            }
        )
        self._emit_event(event)
    
    def add_target_process(self, process_name: str):
        """添加目标进程"""
        self.target_processes.add(process_name)
    
    def remove_target_process(self, process_name: str):
        """移除目标进程"""
        self.target_processes.discard(process_name)
    
    def get_running_processes(self) -> Dict[int, ProcessInfo]:
        """获取当前运行的进程列表"""
        return self.known_processes.copy()


class DetailedProcessMonitor(ProcessMonitor):
    """详细进程监控器 - 提供更多进程信息"""
    
    def __init__(self, event_callback, target_processes: Optional[Set[str]] = None):
        super().__init__(event_callback, target_processes)
        self.process_details: Dict[int, Dict] = {}
    
    def _get_process_details(self, pid: int) -> Dict:
        """获取进程详细信息"""
        try:
            process = psutil.Process(pid)
            return {
                "exe": process.exe(),
                "cmdline": " ".join(process.cmdline()),
                "cwd": process.cwd(),
                "username": process.username(),
                "memory_info": process.memory_info()._asdict(),
                "cpu_percent": process.cpu_percent(),
                "status": process.status(),
                "parent_pid": process.ppid()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return {}
    
    def _emit_process_create_event(self, proc_info: ProcessInfo):
        """发送详细的进程创建事件"""
        details = self._get_process_details(proc_info.pid)
        self.process_details[proc_info.pid] = details
        
        event = MonitorEvent(
            timestamp=datetime.now(),
            event_type=EventType.PROCESS,
            operation=Operation.PROCESS_CREATE,
            process_name=proc_info.name,
            process_id=proc_info.pid,
            path=details.get("exe", f"PID: {proc_info.pid}"),
            result="SUCCESS",
            details={
                "create_time": str(datetime.fromtimestamp(proc_info.create_time)),
                "thread_count": str(len(proc_info.threads)),
                "cmdline": details.get("cmdline", ""),
                "cwd": details.get("cwd", ""),
                "username": details.get("username", ""),
                "parent_pid": str(details.get("parent_pid", 0))
            }
        )
        self._emit_event(event)
    
    def _emit_process_exit_event(self, proc_info: ProcessInfo):
        """发送详细的进程退出事件"""
        details = self.process_details.get(proc_info.pid, {})
        
        event = MonitorEvent(
            timestamp=datetime.now(),
            event_type=EventType.PROCESS,
            operation=Operation.PROCESS_EXIT,
            process_name=proc_info.name,
            process_id=proc_info.pid,
            path=details.get("exe", f"PID: {proc_info.pid}"),
            result="SUCCESS",
            details={
                "create_time": str(datetime.fromtimestamp(proc_info.create_time)),
                "thread_count": str(len(proc_info.threads)),
                "cmdline": details.get("cmdline", ""),
                "username": details.get("username", "")
            }
        )
        self._emit_event(event)
        
        # 清理已退出进程的详细信息
        self.process_details.pop(proc_info.pid, None)


def test_process_monitor():
    """测试进程监控器"""
    def event_handler(event):
        print(f"[{event.timestamp.strftime('%H:%M:%S.%f')[:-3]}] {event.operation.value}: {event.process_name} (PID: {event.process_id}) - {event.path}")
    
    print("启动进程监控器测试...")
    monitor = DetailedProcessMonitor(event_handler)
    monitor.start()
    
    try:
        print("监控中... 按 Ctrl+C 停止")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n停止监控...")
        monitor.stop()
        print("监控已停止")


if __name__ == "__main__":
    test_process_monitor()