#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强文件系统监控模块
提供更精确的文件操作检测，包括文件读写、创建、删除、重命名、属性修改等
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
import hashlib
import stat

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
    import win32security
    import pywintypes
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    print("警告: pywin32库未安装，高级文件系统监控功能将不可用")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("警告: watchdog库未安装，文件系统监控功能将受限")

from procmon import BaseMonitor, MonitorEvent, EventType, Operation


class FileInfo:
    """文件信息类"""
    
    def __init__(self, path: str):
        self.path = path
        self.name = os.path.basename(path)
        self.size = 0
        self.mtime = 0.0
        self.ctime = 0.0
        self.atime = 0.0
        self.attributes = 0
        self.hash_md5 = ""
        self.is_directory = False
        self.exists = False
        self.last_update = time.time()
        
        self._update_info()
    
    def _update_info(self):
        """更新文件信息"""
        try:
            if os.path.exists(self.path):
                self.exists = True
                stat_info = os.stat(self.path)
                self.size = stat_info.st_size
                self.mtime = stat_info.st_mtime
                self.ctime = stat_info.st_ctime
                self.atime = stat_info.st_atime
                self.is_directory = os.path.isdir(self.path)
                
                # 获取文件属性（Windows）
                if WIN32_AVAILABLE and os.name == 'nt':
                    try:
                        self.attributes = win32api.GetFileAttributes(self.path)
                    except pywintypes.error:
                        pass
                
                # 计算文件哈希（仅对小文件）
                if not self.is_directory and self.size < 1024 * 1024:  # 1MB以下
                    self._calculate_hash()
            else:
                self.exists = False
                
            self.last_update = time.time()
            
        except (OSError, IOError) as e:
            self.exists = False
    
    def _calculate_hash(self):
        """计算文件MD5哈希"""
        try:
            with open(self.path, 'rb') as f:
                hash_md5 = hashlib.md5()
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
                self.hash_md5 = hash_md5.hexdigest()
        except (OSError, IOError):
            self.hash_md5 = ""
    
    def has_changed(self, other: 'FileInfo') -> bool:
        """检查文件是否发生变化"""
        if not self.exists or not other.exists:
            return self.exists != other.exists
        
        return (self.size != other.size or 
                abs(self.mtime - other.mtime) > 0.1 or
                self.hash_md5 != other.hash_md5)
    
    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            'path': self.path,
            'name': self.name,
            'size': self.size,
            'mtime': self.mtime,
            'ctime': self.ctime,
            'atime': self.atime,
            'attributes': self.attributes,
            'hash_md5': self.hash_md5,
            'is_directory': self.is_directory,
            'exists': self.exists
        }


class ProcessFileAccess:
    """进程文件访问信息"""
    
    def __init__(self, pid: int, process_name: str, file_path: str, operation: str):
        self.pid = pid
        self.process_name = process_name
        self.file_path = file_path
        self.operation = operation
        self.timestamp = time.time()
        self.access_count = 1
    
    def update_access(self):
        """更新访问信息"""
        self.timestamp = time.time()
        self.access_count += 1


class EnhancedFileSystemEventHandler(FileSystemEventHandler):
    """增强文件系统事件处理器"""
    
    def __init__(self, monitor: 'EnhancedFileSystemMonitor'):
        super().__init__()
        self.monitor = monitor
    
    def on_created(self, event: FileSystemEvent):
        """文件创建事件"""
        if not event.is_directory:
            self.monitor._handle_file_event(event.src_path, Operation.FILE_CREATE)
        else:
            self.monitor._handle_file_event(event.src_path, Operation.DIR_CREATE)
    
    def on_deleted(self, event: FileSystemEvent):
        """文件删除事件"""
        if not event.is_directory:
            self.monitor._handle_file_event(event.src_path, Operation.FILE_DELETE)
        else:
            self.monitor._handle_file_event(event.src_path, Operation.DIR_DELETE)
    
    def on_modified(self, event: FileSystemEvent):
        """文件修改事件"""
        if not event.is_directory:
            self.monitor._handle_file_event(event.src_path, Operation.FILE_WRITE)
    
    def on_moved(self, event: FileSystemEvent):
        """文件移动/重命名事件"""
        if hasattr(event, 'dest_path'):
            if not event.is_directory:
                self.monitor._handle_file_move_event(event.src_path, event.dest_path)
            else:
                self.monitor._handle_dir_move_event(event.src_path, event.dest_path)


class EnhancedFileSystemMonitor(BaseMonitor):
    """增强文件系统监控器"""
    
    def __init__(self, event_callback: Callable[[MonitorEvent], None],
                 watch_paths: Optional[List[str]] = None,
                 monitor_process_access: bool = True,
                 track_file_changes: bool = True,
                 calculate_hashes: bool = False):
        super().__init__(event_callback)
        self.watch_paths = watch_paths or ["C:\\"]
        self.monitor_process_access = monitor_process_access
        self.track_file_changes = track_file_changes
        self.calculate_hashes = calculate_hashes
        
        # 文件跟踪
        self.files: Dict[str, FileInfo] = {}
        self.process_file_access: Dict[Tuple[int, str], ProcessFileAccess] = {}
        
        # Watchdog观察器
        self.observers = []
        self.event_handler = EnhancedFileSystemEventHandler(self)
        
        # 性能统计
        self.event_count = 0
        self.last_scan_time = 0.0
        self.scan_duration = 0.0
    
    def _monitor_loop(self):
        """监控循环"""
        print("增强文件系统监控器启动")
        
        # 启动Watchdog观察器
        self._start_watchdog_observers()
        
        while self.running:
            try:
                start_time = time.time()
                
                # 监控进程文件访问
                if self.monitor_process_access:
                    self._scan_process_file_access()
                
                # 跟踪文件变化
                if self.track_file_changes:
                    self._track_file_changes()
                
                # 更新统计信息
                self.scan_duration = time.time() - start_time
                self.last_scan_time = time.time()
                
                # 控制扫描频率
                time.sleep(max(0.5, 2.0 - self.scan_duration))
                
            except Exception as e:
                print(f"增强文件系统监控出错: {e}")
                time.sleep(1.0)
        
        # 停止观察器
        self._stop_watchdog_observers()
    
    def _start_watchdog_observers(self):
        """启动Watchdog观察器"""
        if not WATCHDOG_AVAILABLE:
            print("Watchdog不可用，使用轮询模式")
            return
        
        try:
            for watch_path in self.watch_paths:
                if os.path.exists(watch_path):
                    observer = Observer()
                    observer.schedule(self.event_handler, watch_path, recursive=True)
                    observer.start()
                    self.observers.append(observer)
                    print(f"开始监控路径: {watch_path}")
        except Exception as e:
            print(f"启动Watchdog观察器失败: {e}")
    
    def _stop_watchdog_observers(self):
        """停止Watchdog观察器"""
        for observer in self.observers:
            try:
                observer.stop()
                observer.join(timeout=5.0)
            except Exception as e:
                print(f"停止观察器失败: {e}")
        self.observers.clear()
    
    def _scan_process_file_access(self):
        """扫描进程文件访问"""
        if not PSUTIL_AVAILABLE:
            return
        
        try:
            current_access = {}
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name'] or 'Unknown'
                    
                    # 获取进程打开的文件
                    open_files = proc.open_files()
                    for file_info in open_files:
                        file_path = file_info.path
                        access_key = (pid, file_path)
                        
                        if access_key in self.process_file_access:
                            # 更新现有访问记录
                            self.process_file_access[access_key].update_access()
                        else:
                            # 新的文件访问
                            access_info = ProcessFileAccess(pid, name, file_path, "READ")
                            self.process_file_access[access_key] = access_info
                            current_access[access_key] = access_info
                            
                            # 发送文件访问事件
                            self._emit_file_access_event(access_info)
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # 清理过期的访问记录（超过60秒）
            current_time = time.time()
            expired_keys = []
            for key, access_info in self.process_file_access.items():
                if current_time - access_info.timestamp > 60:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.process_file_access[key]
                
        except Exception as e:
            print(f"扫描进程文件访问出错: {e}")
    
    def _track_file_changes(self):
        """跟踪文件变化"""
        # 这里可以实现更详细的文件变化跟踪
        # 由于性能考虑，这里只提供框架
        pass
    
    def _handle_file_event(self, file_path: str, operation: Operation):
        """处理文件事件"""
        try:
            # 获取触发事件的进程信息
            process_info = self._get_process_for_file_operation(file_path)
            
            # 创建文件信息
            file_info = FileInfo(file_path)
            
            # 发送事件
            event = MonitorEvent(
                timestamp=datetime.now(),
                event_type=EventType.FILE_SYSTEM,
                operation=operation,
                process_name=process_info.get('name', 'Unknown'),
                process_id=process_info.get('pid', 0),
                path=file_path,
                result="SUCCESS",
                details={
                    **file_info.to_dict(),
                    'process_info': process_info
                }
            )
            
            self._emit_event(event)
            self.event_count += 1
            
            # 更新文件跟踪
            if operation in [Operation.FILE_CREATE, Operation.FILE_WRITE]:
                self.files[file_path] = file_info
            elif operation == Operation.FILE_DELETE:
                self.files.pop(file_path, None)
                
        except Exception as e:
            print(f"处理文件事件出错: {e}")
    
    def _handle_file_move_event(self, src_path: str, dest_path: str):
        """处理文件移动事件"""
        try:
            process_info = self._get_process_for_file_operation(src_path)
            
            event = MonitorEvent(
                timestamp=datetime.now(),
                event_type=EventType.FILE_SYSTEM,
                operation=Operation.FILE_RENAME,
                process_name=process_info.get('name', 'Unknown'),
                process_id=process_info.get('pid', 0),
                path=f"{src_path} -> {dest_path}",
                result="SUCCESS",
                details={
                    'source_path': src_path,
                    'destination_path': dest_path,
                    'process_info': process_info
                }
            )
            
            self._emit_event(event)
            self.event_count += 1
            
            # 更新文件跟踪
            if src_path in self.files:
                file_info = self.files.pop(src_path)
                file_info.path = dest_path
                file_info.name = os.path.basename(dest_path)
                self.files[dest_path] = file_info
                
        except Exception as e:
            # 如果获取进程信息失败，使用默认信息继续处理事件
            event = MonitorEvent(
                timestamp=datetime.now(),
                event_type=EventType.FILE_SYSTEM,
                operation=Operation.FILE_RENAME,
                process_name='System',
                process_id=0,
                path=f"{src_path} -> {dest_path}",
                result="SUCCESS",
                details={
                    'source_path': src_path,
                    'destination_path': dest_path,
                    'error': str(e)
                }
            )
            
            self._emit_event(event)
            self.event_count += 1
    
    def _handle_dir_move_event(self, src_path: str, dest_path: str):
        """处理目录移动事件"""
        try:
            process_info = self._get_process_for_file_operation(src_path)
            
            event = MonitorEvent(
                timestamp=datetime.now(),
                event_type=EventType.FILE_SYSTEM,
                operation=Operation.DIR_RENAME,
                process_name=process_info.get('name', 'Unknown'),
                process_id=process_info.get('pid', 0),
                path=f"{src_path} -> {dest_path}",
                result="SUCCESS",
                details={
                    'source_path': src_path,
                    'destination_path': dest_path,
                    'process_info': process_info
                }
            )
            
            self._emit_event(event)
            self.event_count += 1
            
        except Exception as e:
            # 如果获取进程信息失败，使用默认信息继续处理事件
            event = MonitorEvent(
                timestamp=datetime.now(),
                event_type=EventType.FILE_SYSTEM,
                operation=Operation.DIR_RENAME,
                process_name='System',
                process_id=0,
                path=f"{src_path} -> {dest_path}",
                result="SUCCESS",
                details={
                    'source_path': src_path,
                    'destination_path': dest_path,
                    'error': str(e)
                }
            )
            
            self._emit_event(event)
            self.event_count += 1
    
    def _get_process_for_file_operation(self, file_path: str) -> dict:
        """获取执行文件操作的进程信息"""
        # 这是一个简化的实现，实际上很难准确确定哪个进程触发了文件事件
        # 在真实的实现中，可能需要使用更高级的技术如ETW (Event Tracing for Windows)
        
        try:
            # 查找最近访问该文件的进程
            for (pid, path), access_info in self.process_file_access.items():
                if path == file_path and time.time() - access_info.timestamp < 5.0:
                    return {
                        'pid': pid,
                        'name': access_info.process_name
                    }
            
            # 如果找不到，返回默认信息
            return {'pid': 0, 'name': 'System'}
            
        except Exception:
            return {'pid': 0, 'name': 'Unknown'}
    
    def _emit_file_access_event(self, access_info: ProcessFileAccess):
        """发送文件访问事件"""
        try:
            event = MonitorEvent(
                timestamp=datetime.now(),
                event_type=EventType.FILE_SYSTEM,
                operation=Operation.FILE_READ,
                process_name=access_info.process_name,
                process_id=access_info.pid,
                path=access_info.file_path,
                result="SUCCESS",
                details={
                    'operation': access_info.operation,
                    'access_count': access_info.access_count,
                    'first_access': access_info.timestamp
                }
            )
            
            self._emit_event(event)
            self.event_count += 1
            
        except Exception as e:
            print(f"发送文件访问事件出错: {e}")
    
    def get_statistics(self) -> dict:
        """获取监控统计信息"""
        return {
            'event_count': self.event_count,
            'last_scan_time': self.last_scan_time,
            'scan_duration': self.scan_duration,
            'tracked_files': len(self.files),
            'active_file_access': len(self.process_file_access),
            'watch_paths': self.watch_paths,
            'observers_count': len(self.observers)
        }
    
    def add_watch_path(self, path: str):
        """添加监控路径"""
        if path not in self.watch_paths and os.path.exists(path):
            self.watch_paths.append(path)
            
            # 如果监控器正在运行，立即添加观察器
            if self.running and WATCHDOG_AVAILABLE:
                try:
                    observer = Observer()
                    observer.schedule(self.event_handler, path, recursive=True)
                    observer.start()
                    self.observers.append(observer)
                    print(f"添加监控路径: {path}")
                except Exception as e:
                    print(f"添加监控路径失败: {e}")
    
    def remove_watch_path(self, path: str):
        """移除监控路径"""
        if path in self.watch_paths:
            self.watch_paths.remove(path)
            print(f"移除监控路径: {path}")


def test_enhanced_filesystem_monitor():
    """测试增强文件系统监控器"""
    def event_handler(event):
        print(f"[{event.timestamp.strftime('%H:%M:%S.%f')[:-3]}] "
              f"{event.process_name} ({event.process_id}) - "
              f"{event.operation.value}: {event.path} - {event.result}")
        
        if event.details and 'file_size' in event.details:
            print(f"  文件大小: {event.details['file_size']} bytes")
    
    print("启动增强文件系统监控器测试...")
    
    # 监控当前目录和临时目录
    watch_paths = [
        os.getcwd(),
        os.path.expanduser("~/Desktop"),
        "C:\\temp"
    ]
    
    # 过滤存在的路径
    watch_paths = [path for path in watch_paths if os.path.exists(path)]
    
    monitor = EnhancedFileSystemMonitor(
        event_handler,
        watch_paths=watch_paths,
        monitor_process_access=True,
        track_file_changes=True,
        calculate_hashes=False  # 关闭哈希计算以提高性能
    )
    
    try:
        monitor.start()
        print(f"监控器已启动，监控路径: {watch_paths}")
        print("按Ctrl+C停止")
        
        # 定期显示统计信息
        last_stats_time = time.time()
        while True:
            time.sleep(1)
            
            # 每15秒显示一次统计信息
            if time.time() - last_stats_time > 15:
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
    test_enhanced_filesystem_monitor()