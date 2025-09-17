#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件系统监控模块
监控文件和目录的创建、删除、修改、读写等操作
"""

import os
import sys
import time
import threading
from datetime import datetime
from typing import Set, List, Dict, Optional
from pathlib import Path

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("警告: watchdog库未安装，文件系统监控功能受限")
    print("请运行: pip install watchdog")

from procmon import BaseMonitor, MonitorEvent, EventType, Operation


class FileSystemEventHandler(FileSystemEventHandler):
    """文件系统事件处理器"""
    
    def __init__(self, monitor_callback):
        super().__init__()
        self.monitor_callback = monitor_callback
    
    def on_created(self, event):
        """文件/目录创建事件"""
        if event.is_directory:
            operation = Operation.DIR_CREATE
        else:
            operation = Operation.FILE_CREATE
        
        self.monitor_callback(event.src_path, operation, "SUCCESS")
    
    def on_deleted(self, event):
        """文件/目录删除事件"""
        if event.is_directory:
            operation = Operation.DIR_DELETE
        else:
            operation = Operation.FILE_DELETE
        
        self.monitor_callback(event.src_path, operation, "SUCCESS")
    
    def on_modified(self, event):
        """文件/目录修改事件"""
        if not event.is_directory:
            self.monitor_callback(event.src_path, Operation.FILE_WRITE, "SUCCESS")
    
    def on_moved(self, event):
        """文件/目录移动事件"""
        # 将移动操作视为删除旧文件和创建新文件
        if event.is_directory:
            self.monitor_callback(event.src_path, Operation.DIR_DELETE, "SUCCESS")
            self.monitor_callback(event.dest_path, Operation.DIR_CREATE, "SUCCESS")
        else:
            self.monitor_callback(event.src_path, Operation.FILE_DELETE, "SUCCESS")
            self.monitor_callback(event.dest_path, Operation.FILE_CREATE, "SUCCESS")


class FileSystemMonitor(BaseMonitor):
    """文件系统监控器"""
    
    def __init__(self, event_callback, watch_paths: Optional[List[str]] = None):
        super().__init__(event_callback)
        self.watch_paths = watch_paths or ["C:\\"]
        self.observers: List[Observer] = []
        self.file_access_tracker = FileAccessTracker()
        self.excluded_extensions = {'.tmp', '.log', '.swp', '.bak'}
        self.excluded_paths = {'$Recycle.Bin', 'System Volume Information', 'pagefile.sys', 'hiberfil.sys'}
        
        if not WATCHDOG_AVAILABLE:
            print("文件系统监控器初始化失败: watchdog库不可用")
    
    def add_watch_path(self, path: str):
        """添加监控路径"""
        if path not in self.watch_paths:
            self.watch_paths.append(path)
    
    def remove_watch_path(self, path: str):
        """移除监控路径"""
        if path in self.watch_paths:
            self.watch_paths.remove(path)
    
    def _should_monitor_path(self, path: str) -> bool:
        """判断是否应该监控该路径"""
        path_obj = Path(path)
        
        # 检查文件扩展名
        if path_obj.suffix.lower() in self.excluded_extensions:
            return False
        
        # 检查路径中是否包含排除的目录
        for excluded in self.excluded_paths:
            if excluded in path:
                return False
        
        return True
    
    def _handle_filesystem_event(self, path: str, operation: Operation, result: str):
        """处理文件系统事件"""
        if not self._should_monitor_path(path):
            return
        
        # 尝试获取访问该文件的进程信息
        process_name, process_id = self.file_access_tracker.get_accessing_process(path)
        
        event = MonitorEvent(
            timestamp=datetime.now(),
            event_type=EventType.FILE_SYSTEM,
            operation=operation,
            process_name=process_name,
            process_id=process_id,
            path=path,
            result=result,
            details={
                "file_size": str(self._get_file_size(path)),
                "file_type": Path(path).suffix,
                "parent_dir": str(Path(path).parent)
            }
        )
        self._emit_event(event)
    
    def _get_file_size(self, path: str) -> int:
        """获取文件大小"""
        try:
            return os.path.getsize(path)
        except (OSError, FileNotFoundError):
            return 0
    
    def start(self):
        """启动文件系统监控"""
        if not WATCHDOG_AVAILABLE:
            print("无法启动文件系统监控: watchdog库不可用")
            return
        
        super().start()
        
        for watch_path in self.watch_paths:
            if os.path.exists(watch_path):
                observer = Observer()
                event_handler = FileSystemEventHandler(self._handle_filesystem_event)
                observer.schedule(event_handler, watch_path, recursive=True)
                observer.start()
                self.observers.append(observer)
                print(f"开始监控路径: {watch_path}")
            else:
                print(f"警告: 监控路径不存在: {watch_path}")
    
    def stop(self):
        """停止文件系统监控"""
        super().stop()
        
        for observer in self.observers:
            observer.stop()
            observer.join()
        
        self.observers.clear()
    
    def _monitor_loop(self):
        """监控循环 - 对于watchdog，主要工作由Observer完成"""
        while self.running:
            time.sleep(1.0)


class FileAccessTracker:
    """文件访问跟踪器 - 尝试识别访问文件的进程"""
    
    def __init__(self):
        self.recent_processes: Dict[str, tuple] = {}  # path -> (process_name, pid, timestamp)
        self.cleanup_interval = 60  # 清理间隔（秒）
        self.last_cleanup = time.time()
    
    def get_accessing_process(self, path: str) -> tuple:
        """获取访问指定文件的进程信息"""
        # 清理过期记录
        current_time = time.time()
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_records(current_time)
            self.last_cleanup = current_time
        
        # 尝试从最近的进程记录中查找
        if path in self.recent_processes:
            process_name, pid, timestamp = self.recent_processes[path]
            if current_time - timestamp < 5.0:  # 5秒内的记录认为有效
                return process_name, pid
        
        # 尝试通过系统调用查找当前访问该文件的进程
        process_name, pid = self._find_process_using_file(path)
        
        if process_name:
            self.recent_processes[path] = (process_name, pid, current_time)
        
        return process_name, pid
    
    def _find_process_using_file(self, path: str) -> tuple:
        """查找当前使用指定文件的进程"""
        try:
            import psutil
            
            # 遍历所有进程，查找打开了指定文件的进程
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    # 获取进程打开的文件列表
                    open_files = proc.open_files()
                    for file_info in open_files:
                        if file_info.path.lower() == path.lower():
                            return proc.info['name'], proc.info['pid']
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except ImportError:
            pass
        except Exception as e:
            pass
        
        return "Unknown", 0
    
    def _cleanup_old_records(self, current_time: float):
        """清理过期的进程记录"""
        expired_paths = []
        for path, (_, _, timestamp) in self.recent_processes.items():
            if current_time - timestamp > 300:  # 5分钟过期
                expired_paths.append(path)
        
        for path in expired_paths:
            del self.recent_processes[path]


class DetailedFileSystemMonitor(FileSystemMonitor):
    """详细文件系统监控器 - 提供更多文件操作信息"""
    
    def __init__(self, event_callback, watch_paths: Optional[List[str]] = None):
        super().__init__(event_callback, watch_paths)
        self.file_stats_cache: Dict[str, Dict] = {}
    
    def _get_file_details(self, path: str) -> Dict:
        """获取文件详细信息"""
        try:
            stat_info = os.stat(path)
            return {
                "size": stat_info.st_size,
                "mtime": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                "ctime": datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                "atime": datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                "mode": oct(stat_info.st_mode),
                "uid": stat_info.st_uid,
                "gid": stat_info.st_gid
            }
        except (OSError, FileNotFoundError):
            return {}
    
    def _handle_filesystem_event(self, path: str, operation: Operation, result: str):
        """处理详细的文件系统事件"""
        if not self._should_monitor_path(path):
            return
        
        # 获取文件详细信息
        file_details = self._get_file_details(path)
        
        # 尝试获取访问该文件的进程信息
        process_name, process_id = self.file_access_tracker.get_accessing_process(path)
        
        # 检测文件内容变化
        content_changed = self._detect_content_change(path, file_details)
        
        event = MonitorEvent(
            timestamp=datetime.now(),
            event_type=EventType.FILE_SYSTEM,
            operation=operation,
            process_name=process_name,
            process_id=process_id,
            path=path,
            result=result,
            details={
                "file_size": str(file_details.get("size", 0)),
                "file_type": Path(path).suffix,
                "parent_dir": str(Path(path).parent),
                "mtime": file_details.get("mtime", ""),
                "content_changed": str(content_changed),
                "file_mode": file_details.get("mode", "")
            }
        )
        self._emit_event(event)
        
        # 更新文件统计缓存
        if file_details:
            self.file_stats_cache[path] = file_details
    
    def _detect_content_change(self, path: str, current_details: Dict) -> bool:
        """检测文件内容是否发生变化"""
        if path not in self.file_stats_cache:
            return True
        
        old_details = self.file_stats_cache[path]
        
        # 比较文件大小和修改时间
        size_changed = current_details.get("size") != old_details.get("size")
        mtime_changed = current_details.get("mtime") != old_details.get("mtime")
        
        return size_changed or mtime_changed


def test_filesystem_monitor():
    """测试文件系统监控器"""
    def event_handler(event):
        print(f"[{event.timestamp.strftime('%H:%M:%S.%f')[:-3]}] {event.operation.value}: {event.path} - {event.process_name} (PID: {event.process_id})")
    
    print("启动文件系统监控器测试...")
    
    # 监控当前目录
    current_dir = os.getcwd()
    monitor = DetailedFileSystemMonitor(event_handler, [current_dir])
    monitor.start()
    
    try:
        print(f"监控目录: {current_dir}")
        print("监控中... 按 Ctrl+C 停止")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n停止监控...")
        monitor.stop()
        print("监控已停止")


if __name__ == "__main__":
    test_filesystem_monitor()