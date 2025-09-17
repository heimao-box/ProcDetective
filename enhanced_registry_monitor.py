#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强注册表监控模块
实现实时注册表变化检测，包括键创建、删除、值修改等操作
"""

import os
import sys
import time
import ctypes
import threading
from datetime import datetime
from typing import Dict, Set, Optional, List, Callable, Any, Tuple
from ctypes import wintypes, windll
from pathlib import Path
import json

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("警告: psutil库未安装")

try:
    import winreg
    import win32api
    import win32con
    import win32file
    import win32event
    import win32security
    import win32evtlog
    import pywintypes
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    print("警告: pywin32库未安装，注册表监控功能将受限")

from procmon import BaseMonitor, MonitorEvent, EventType, Operation


class RegistryKeyInfo:
    """注册表键信息类"""
    
    def __init__(self, key_path: str, hive: int = winreg.HKEY_LOCAL_MACHINE):
        self.key_path = key_path
        self.hive = hive
        self.hive_name = self._get_hive_name(hive)
        self.full_path = f"{self.hive_name}\\{key_path}"
        self.exists = False
        self.subkeys = set()
        self.values = {}
        self.last_modified = 0.0
        self.last_update = time.time()
        
        self._update_info()
    
    def _get_hive_name(self, hive: int) -> str:
        """获取注册表根键名称"""
        hive_names = {
            winreg.HKEY_CLASSES_ROOT: "HKEY_CLASSES_ROOT",
            winreg.HKEY_CURRENT_USER: "HKEY_CURRENT_USER",
            winreg.HKEY_LOCAL_MACHINE: "HKEY_LOCAL_MACHINE",
            winreg.HKEY_USERS: "HKEY_USERS",
            winreg.HKEY_CURRENT_CONFIG: "HKEY_CURRENT_CONFIG"
        }
        return hive_names.get(hive, "UNKNOWN_HIVE")
    
    def _update_info(self):
        """更新注册表键信息"""
        try:
            with winreg.OpenKey(self.hive, self.key_path, 0, winreg.KEY_READ) as key:
                self.exists = True
                
                # 获取键的基本信息
                try:
                    key_info = winreg.QueryInfoKey(key)
                    if isinstance(key_info, tuple) and len(key_info) > 9:
                        self.last_modified = key_info[9]  # 最后修改时间
                except (ValueError, TypeError, IndexError):
                    self.last_modified = None
                
                # 获取子键
                self.subkeys.clear()
                try:
                    i = 0
                    while True:
                        subkey_name = winreg.EnumKey(key, i)
                        self.subkeys.add(subkey_name)
                        i += 1
                except OSError:
                    pass  # 没有更多子键
                
                # 获取值
                self.values.clear()
                try:
                    i = 0
                    while True:
                        try:
                            enum_result = winreg.EnumValue(key, i)
                            if isinstance(enum_result, tuple) and len(enum_result) == 3:
                                value_name, value_data, value_type = enum_result
                                self.values[value_name] = {
                                    'data': value_data,
                                    'type': value_type,
                                    'type_name': self._get_value_type_name(value_type)
                                }
                            i += 1
                        except (ValueError, TypeError):
                            # 跳过无效的值
                            i += 1
                            continue
                except OSError:
                    pass  # 没有更多值
                    
            self.last_update = time.time()
            
        except (OSError, PermissionError) as e:
            self.exists = False
    
    def _get_value_type_name(self, value_type: int) -> str:
        """获取注册表值类型名称"""
        type_names = {
            winreg.REG_NONE: "REG_NONE",
            winreg.REG_SZ: "REG_SZ",
            winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
            winreg.REG_BINARY: "REG_BINARY",
            winreg.REG_DWORD: "REG_DWORD",
            winreg.REG_DWORD_BIG_ENDIAN: "REG_DWORD_BIG_ENDIAN",
            winreg.REG_LINK: "REG_LINK",
            winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
            winreg.REG_RESOURCE_LIST: "REG_RESOURCE_LIST",
            winreg.REG_FULL_RESOURCE_DESCRIPTOR: "REG_FULL_RESOURCE_DESCRIPTOR",
            winreg.REG_RESOURCE_REQUIREMENTS_LIST: "REG_RESOURCE_REQUIREMENTS_LIST",
            winreg.REG_QWORD: "REG_QWORD"
        }
        return type_names.get(value_type, f"UNKNOWN_TYPE_{value_type}")
    
    def has_changed(self, other: 'RegistryKeyInfo') -> bool:
        """检查注册表键是否发生变化"""
        if not self.exists or not other.exists:
            return self.exists != other.exists
        
        return (self.subkeys != other.subkeys or
                self.values != other.values or
                abs(self.last_modified - other.last_modified) > 0.1)
    
    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            'key_path': self.key_path,
            'hive_name': self.hive_name,
            'full_path': self.full_path,
            'exists': self.exists,
            'subkey_count': len(self.subkeys),
            'value_count': len(self.values),
            'last_modified': self.last_modified,
            'subkeys': list(self.subkeys),
            'values': {k: {'data': str(v['data'])[:100], 'type': v['type_name']} 
                      for k, v in self.values.items()}
        }


class RegistryWatcher:
    """注册表监视器"""
    
    def __init__(self, key_path: str, hive: int = winreg.HKEY_LOCAL_MACHINE,
                 callback: Optional[Callable] = None):
        self.key_path = key_path
        self.hive = hive
        self.callback = callback
        self.running = False
        self.thread = None
        self.event_handle = None
        self.key_handle = None
    
    def start(self):
        """启动监视器"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._watch_loop, daemon=True)
        self.thread.start()
    
    def stop(self):
        """停止监视器"""
        self.running = False
        if self.event_handle:
            try:
                win32event.SetEvent(self.event_handle)
            except:
                pass
        
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5.0)
    
    def _watch_loop(self):
        """监视循环"""
        if not WIN32_AVAILABLE:
            return
        
        try:
            # 打开注册表键
            self.key_handle = winreg.OpenKey(self.hive, self.key_path, 0, 
                                           winreg.KEY_NOTIFY | winreg.KEY_READ)
            
            # 创建事件对象
            self.event_handle = win32event.CreateEvent(None, False, False, None)
            
            while self.running:
                try:
                    # 使用轮询方式监控注册表变化
                    time.sleep(2.0)  # 轮询间隔
                    
                    if self.running and self.callback:
                        self.callback(self.key_path, self.hive)
                    
                except Exception as e:
                    if self.running:
                        print(f"注册表监视出错: {e}")
                        time.sleep(1.0)
                    
        except Exception as e:
            print(f"启动注册表监视失败: {e}")
        finally:
            self._cleanup()
    
    def _cleanup(self):
        """清理资源"""
        try:
            if self.key_handle:
                winreg.CloseKey(self.key_handle)
                self.key_handle = None
            
            if self.event_handle:
                win32api.CloseHandle(self.event_handle)
                self.event_handle = None
        except Exception as e:
            print(f"清理注册表监视器资源失败: {e}")


class EnhancedRegistryMonitor(BaseMonitor):
    """增强注册表监控器"""
    
    def __init__(self, event_callback: Callable[[MonitorEvent], None],
                 watch_keys: Optional[List[Tuple[str, int]]] = None,
                 monitor_process_registry_access: bool = True,
                 track_value_changes: bool = True):
        super().__init__(event_callback)
        self.watch_keys = watch_keys or self._get_default_watch_keys()
        self.monitor_process_registry_access = monitor_process_registry_access
        self.track_value_changes = track_value_changes
        
        # 注册表跟踪
        self.registry_keys: Dict[str, RegistryKeyInfo] = {}
        self.watchers: List[RegistryWatcher] = []
        
        # 进程注册表访问跟踪
        self.process_registry_access: Dict[Tuple[int, str], float] = {}
        
        # 性能统计
        self.event_count = 0
        self.last_scan_time = 0.0
        self.scan_duration = 0.0
    
    def _get_default_watch_keys(self) -> List[Tuple[str, int]]:
        """获取默认监控的注册表键"""
        return [
            ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", winreg.HKEY_LOCAL_MACHINE),
            ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", winreg.HKEY_CURRENT_USER),
            ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", winreg.HKEY_LOCAL_MACHINE),
            ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", winreg.HKEY_CURRENT_USER),
            ("SYSTEM\\CurrentControlSet\\Services", winreg.HKEY_LOCAL_MACHINE),
            ("SOFTWARE\\Classes", winreg.HKEY_LOCAL_MACHINE),
            ("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", winreg.HKEY_LOCAL_MACHINE),
            ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies", winreg.HKEY_LOCAL_MACHINE),
            ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies", winreg.HKEY_CURRENT_USER)
        ]
    
    def _monitor_loop(self):
        """监控循环"""
        print("增强注册表监控器启动")
        
        # 启动注册表监视器
        self._start_registry_watchers()
        
        while self.running:
            try:
                start_time = time.time()
                
                # 监控进程注册表访问
                if self.monitor_process_registry_access:
                    self._scan_process_registry_access()
                
                # 跟踪注册表值变化
                if self.track_value_changes:
                    self._track_registry_changes()
                
                # 更新统计信息
                self.scan_duration = time.time() - start_time
                self.last_scan_time = time.time()
                
                # 控制扫描频率
                time.sleep(max(1.0, 3.0 - self.scan_duration))
                
            except Exception as e:
                print(f"增强注册表监控出错: {e}")
                time.sleep(1.0)
        
        # 停止监视器
        self._stop_registry_watchers()
    
    def _start_registry_watchers(self):
        """启动注册表监视器"""
        if not WIN32_AVAILABLE:
            print("Windows API不可用，注册表监控功能受限")
            return
        
        for key_path, hive in self.watch_keys:
            try:
                watcher = RegistryWatcher(
                    key_path, hive, 
                    callback=self._on_registry_change
                )
                watcher.start()
                self.watchers.append(watcher)
                print(f"开始监控注册表键: {self._get_hive_name(hive)}\\{key_path}")
            except Exception as e:
                print(f"启动注册表监视器失败 {key_path}: {e}")
    
    def _stop_registry_watchers(self):
        """停止注册表监视器"""
        for watcher in self.watchers:
            try:
                watcher.stop()
            except Exception as e:
                print(f"停止注册表监视器失败: {e}")
        self.watchers.clear()
    
    def _get_hive_name(self, hive: int) -> str:
        """获取注册表根键名称"""
        hive_names = {
            winreg.HKEY_CLASSES_ROOT: "HKEY_CLASSES_ROOT",
            winreg.HKEY_CURRENT_USER: "HKEY_CURRENT_USER",
            winreg.HKEY_LOCAL_MACHINE: "HKEY_LOCAL_MACHINE",
            winreg.HKEY_USERS: "HKEY_USERS",
            winreg.HKEY_CURRENT_CONFIG: "HKEY_CURRENT_CONFIG"
        }
        return hive_names.get(hive, "UNKNOWN_HIVE")
    
    def _on_registry_change(self, key_path: str, hive: int):
        """注册表变化回调"""
        try:
            # 获取触发变化的进程信息
            process_info = self._get_process_for_registry_operation(key_path)
            
            # 创建注册表键信息
            full_key = f"{self._get_hive_name(hive)}\\{key_path}"
            old_key_info = self.registry_keys.get(full_key)
            new_key_info = RegistryKeyInfo(key_path, hive)
            
            # 确定操作类型
            operation = self._determine_registry_operation(old_key_info, new_key_info)
            
            # 发送事件
            event = MonitorEvent(
                timestamp=datetime.now(),
                event_type=EventType.REGISTRY,
                operation=operation,
                process_name=process_info.get('name', 'System'),
                process_id=process_info.get('pid', 0),
                path=full_key,
                result="SUCCESS",
                details={
                    **new_key_info.to_dict(),
                    'process_info': process_info,
                    'change_type': operation.value
                }
            )
            
            self._emit_event(event)
            self.event_count += 1
            
            # 更新跟踪信息
            self.registry_keys[full_key] = new_key_info
            
        except Exception as e:
            print(f"处理注册表变化事件出错: {e}")
    
    def _determine_registry_operation(self, old_info: Optional[RegistryKeyInfo], 
                                    new_info: RegistryKeyInfo) -> Operation:
        """确定注册表操作类型"""
        if not old_info:
            return Operation.REG_CREATE_KEY if new_info.exists else Operation.REG_OPEN_KEY
        
        if not new_info.exists and old_info.exists:
            return Operation.REG_DELETE_KEY
        
        if old_info.subkeys != new_info.subkeys:
            if len(new_info.subkeys) > len(old_info.subkeys):
                return Operation.REG_CREATE_KEY
            else:
                return Operation.REG_DELETE_KEY
        
        if old_info.values != new_info.values:
            return Operation.REG_SET_VALUE
        
        return Operation.REG_QUERY_VALUE
    
    def _scan_process_registry_access(self):
        """扫描进程注册表访问"""
        # 这是一个简化的实现，实际上很难直接检测进程的注册表访问
        # 在真实的实现中，可能需要使用ETW或其他高级技术
        try:
            current_time = time.time()
            
            # 清理过期的访问记录
            expired_keys = []
            for key, timestamp in self.process_registry_access.items():
                try:
                    if current_time - timestamp > 300:  # 5分钟过期
                        expired_keys.append(key)
                except (TypeError, ValueError):
                    # 如果timestamp不是数字，也标记为过期
                    expired_keys.append(key)
            
            for key in expired_keys:
                try:
                    del self.process_registry_access[key]
                except KeyError:
                    pass  # 键可能已被其他线程删除
                
        except Exception as e:
            print(f"扫描进程注册表访问出错: {e}")
    
    def _track_registry_changes(self):
        """跟踪注册表变化"""
        try:
            # 定期检查监控的注册表键是否发生变化
            for key_path, hive in self.watch_keys:
                try:
                    full_key = f"{self._get_hive_name(hive)}\\{key_path}"
                    old_info = self.registry_keys.get(full_key)
                    new_info = RegistryKeyInfo(key_path, hive)
                    
                    if not old_info or new_info.has_changed(old_info):
                        # 检测到变化，但不重复发送事件（由监视器处理）
                        self.registry_keys[full_key] = new_info
                        
                except Exception as e:
                    print(f"跟踪注册表键变化出错 {key_path}: {e}")
                    
        except Exception as e:
            print(f"跟踪注册表变化出错: {e}")
    
    def _get_process_for_registry_operation(self, key_path: str) -> dict:
        """获取执行注册表操作的进程信息"""
        # 这是一个简化的实现，实际上很难准确确定哪个进程触发了注册表变化
        # 在真实的实现中，需要使用更高级的技术如ETW
        
        try:
            # 查找最近访问注册表的进程
            current_time = time.time()
            for key, timestamp in self.process_registry_access.items():
                try:
                    # 安全地解包tuple键
                    if isinstance(key, tuple) and len(key) == 2:
                        pid, reg_path = key
                        if reg_path in key_path and current_time - timestamp < 10.0:
                            if PSUTIL_AVAILABLE:
                                proc = psutil.Process(pid)
                                return {'pid': pid, 'name': proc.name()}
                except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, TypeError):
                    continue
            
            # 如果找不到，返回系统进程
            return {'pid': 0, 'name': 'System'}
            
        except Exception:
            return {'pid': 0, 'name': 'Unknown'}
    
    def get_statistics(self) -> dict:
        """获取监控统计信息"""
        return {
            'event_count': self.event_count,
            'last_scan_time': self.last_scan_time,
            'scan_duration': self.scan_duration,
            'tracked_keys': len(self.registry_keys),
            'active_watchers': len(self.watchers),
            'watch_keys_count': len(self.watch_keys),
            'process_registry_access_count': len(self.process_registry_access)
        }
    
    def add_watch_key(self, key_path: str, hive: int = winreg.HKEY_LOCAL_MACHINE):
        """添加监控的注册表键"""
        watch_key = (key_path, hive)
        if watch_key not in self.watch_keys:
            self.watch_keys.append(watch_key)
            
            # 如果监控器正在运行，立即添加监视器
            if self.running and WIN32_AVAILABLE:
                try:
                    watcher = RegistryWatcher(
                        key_path, hive,
                        callback=self._on_registry_change
                    )
                    watcher.start()
                    self.watchers.append(watcher)
                    print(f"添加注册表监控: {self._get_hive_name(hive)}\\{key_path}")
                except Exception as e:
                    print(f"添加注册表监控失败: {e}")
    
    def remove_watch_key(self, key_path: str, hive: int = winreg.HKEY_LOCAL_MACHINE):
        """移除监控的注册表键"""
        watch_key = (key_path, hive)
        if watch_key in self.watch_keys:
            self.watch_keys.remove(watch_key)
            print(f"移除注册表监控: {self._get_hive_name(hive)}\\{key_path}")
    
    def get_registry_snapshot(self) -> dict:
        """获取当前注册表快照"""
        snapshot = {}
        for full_key, key_info in self.registry_keys.items():
            snapshot[full_key] = key_info.to_dict()
        return snapshot


def test_enhanced_registry_monitor():
    """测试增强注册表监控器"""
    def event_handler(event):
        print(f"[{event.timestamp.strftime('%H:%M:%S.%f')[:-3]}] "
              f"{event.process_name} ({event.process_id}) - "
              f"{event.operation.value}: {event.path} - {event.result}")
        
        if event.details:
            if 'subkey_count' in event.details:
                print(f"  子键数量: {event.details['subkey_count']}")
            if 'value_count' in event.details:
                print(f"  值数量: {event.details['value_count']}")
    
    print("启动增强注册表监控器测试...")
    
    # 自定义监控的注册表键
    watch_keys = [
        ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", winreg.HKEY_LOCAL_MACHINE),
        ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", winreg.HKEY_CURRENT_USER),
        ("SOFTWARE\\Classes", winreg.HKEY_LOCAL_MACHINE)
    ]
    
    monitor = EnhancedRegistryMonitor(
        event_handler,
        watch_keys=watch_keys,
        monitor_process_registry_access=True,
        track_value_changes=True
    )
    
    try:
        monitor.start()
        print(f"监控器已启动，监控 {len(watch_keys)} 个注册表键")
        print("按Ctrl+C停止")
        
        # 定期显示统计信息
        last_stats_time = time.time()
        while True:
            time.sleep(1)
            
            # 每30秒显示一次统计信息
            if time.time() - last_stats_time > 30:
                stats = monitor.get_statistics()
                print(f"\n统计信息: {stats}")
                
                # 显示注册表快照
                snapshot = monitor.get_registry_snapshot()
                if snapshot:
                    print(f"当前跟踪的注册表键: {len(snapshot)}")
                
                last_stats_time = time.time()
                
    except KeyboardInterrupt:
        print("\n正在停止监控器...")
        monitor.stop()
        
        # 显示最终统计信息
        stats = monitor.get_statistics()
        print(f"最终统计信息: {stats}")
        print("监控器已停止")


if __name__ == "__main__":
    test_enhanced_registry_monitor()