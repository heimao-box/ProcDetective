#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
注册表监控模块
监控Windows注册表的读写、创建、删除等操作
"""

import os
import sys
import time
import threading
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple

try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False
    print("警告: winreg库不可用，注册表监控功能仅在Windows系统上可用")

from procmon import BaseMonitor, MonitorEvent, EventType, Operation


class RegistryKey:
    """注册表键信息"""
    
    def __init__(self, hkey, subkey: str, name: str = ""):
        self.hkey = hkey
        self.subkey = subkey
        self.name = name
        self.full_path = self._get_full_path()
    
    def _get_full_path(self) -> str:
        """获取完整的注册表路径"""
        hkey_names = {
            winreg.HKEY_CLASSES_ROOT: "HKEY_CLASSES_ROOT",
            winreg.HKEY_CURRENT_USER: "HKEY_CURRENT_USER",
            winreg.HKEY_LOCAL_MACHINE: "HKEY_LOCAL_MACHINE",
            winreg.HKEY_USERS: "HKEY_USERS",
            winreg.HKEY_CURRENT_CONFIG: "HKEY_CURRENT_CONFIG"
        }
        
        hkey_name = hkey_names.get(self.hkey, "UNKNOWN_HKEY")
        if self.name:
            return f"{hkey_name}\\{self.subkey}\\{self.name}"
        else:
            return f"{hkey_name}\\{self.subkey}"


class RegistrySnapshot:
    """注册表快照"""
    
    def __init__(self):
        self.keys: Dict[str, Dict] = {}  # path -> {values, subkeys, timestamp}
    
    def add_key(self, key_path: str, values: Dict, subkeys: List[str]):
        """添加键信息到快照"""
        self.keys[key_path] = {
            "values": values.copy(),
            "subkeys": subkeys.copy(),
            "timestamp": time.time()
        }
    
    def get_key_info(self, key_path: str) -> Optional[Dict]:
        """获取键信息"""
        return self.keys.get(key_path)
    
    def has_key(self, key_path: str) -> bool:
        """检查是否包含指定键"""
        return key_path in self.keys


class RegistryMonitor(BaseMonitor):
    """注册表监控器"""
    
    def __init__(self, event_callback, monitor_keys: Optional[List[Tuple]] = None):
        super().__init__(event_callback)
        self.monitor_keys = monitor_keys or self._get_default_monitor_keys()
        self.scan_interval = 2.0  # 扫描间隔（秒）
        self.previous_snapshot = RegistrySnapshot()
        self.current_snapshot = RegistrySnapshot()
        
        if not WINREG_AVAILABLE:
            print("注册表监控器初始化失败: winreg库不可用")
    
    def _get_default_monitor_keys(self) -> List[Tuple]:
        """获取默认监控的注册表键"""
        if not WINREG_AVAILABLE:
            return []
        
        return [
            (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
            (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services"),
            (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"),
            (winreg.HKEY_CURRENT_USER, "Software\\Classes"),
        ]
    
    def add_monitor_key(self, hkey, subkey: str):
        """添加监控键"""
        self.monitor_keys.append((hkey, subkey))
    
    def _monitor_loop(self):
        """监控循环"""
        if not WINREG_AVAILABLE:
            print("无法启动注册表监控: winreg库不可用")
            return
        
        # 初始快照
        self._take_snapshot(self.previous_snapshot)
        
        while self.running:
            try:
                # 创建新快照
                self.current_snapshot = RegistrySnapshot()
                self._take_snapshot(self.current_snapshot)
                
                # 比较快照并生成事件
                self._compare_snapshots()
                
                # 更新前一个快照
                self.previous_snapshot = self.current_snapshot
                
                time.sleep(self.scan_interval)
            except Exception as e:
                print(f"注册表监控出错: {e}")
                time.sleep(1.0)
    
    def _take_snapshot(self, snapshot: RegistrySnapshot):
        """创建注册表快照"""
        for hkey, subkey in self.monitor_keys:
            try:
                self._scan_registry_key(snapshot, hkey, subkey)
            except Exception as e:
                # 忽略无法访问的键
                pass
    
    def _scan_registry_key(self, snapshot: RegistrySnapshot, hkey, subkey: str, max_depth: int = 2, current_depth: int = 0):
        """扫描注册表键"""
        if current_depth > max_depth:
            return
        
        try:
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                # 获取值
                values = {}
                try:
                    i = 0
                    while True:
                        try:
                            name, value, reg_type = winreg.EnumValue(key, i)
                            values[name] = (value, reg_type)
                            i += 1
                        except WindowsError:
                            break
                except Exception:
                    pass
                
                # 获取子键
                subkeys = []
                try:
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkeys.append(subkey_name)
                            i += 1
                        except WindowsError:
                            break
                except Exception:
                    pass
                
                # 添加到快照
                reg_key = RegistryKey(hkey, subkey)
                snapshot.add_key(reg_key.full_path, values, subkeys)
                
                # 递归扫描子键（限制深度）
                if current_depth < max_depth:
                    for subkey_name in subkeys[:10]:  # 限制子键数量
                        try:
                            full_subkey = f"{subkey}\\{subkey_name}"
                            self._scan_registry_key(snapshot, hkey, full_subkey, max_depth, current_depth + 1)
                        except Exception:
                            continue
                            
        except Exception as e:
            # 无法访问的键，跳过
            pass
    
    def _compare_snapshots(self):
        """比较快照并生成事件"""
        # 检查新增的键
        for key_path in self.current_snapshot.keys:
            if not self.previous_snapshot.has_key(key_path):
                self._emit_registry_event(key_path, Operation.REG_CREATE, "SUCCESS", "新键创建")
        
        # 检查删除的键
        for key_path in self.previous_snapshot.keys:
            if not self.current_snapshot.has_key(key_path):
                self._emit_registry_event(key_path, Operation.REG_DELETE, "SUCCESS", "键已删除")
        
        # 检查修改的键
        for key_path in self.current_snapshot.keys:
            if self.previous_snapshot.has_key(key_path):
                current_info = self.current_snapshot.get_key_info(key_path)
                previous_info = self.previous_snapshot.get_key_info(key_path)
                
                if current_info and previous_info:
                    # 比较值
                    current_values = current_info["values"]
                    previous_values = previous_info["values"]
                    
                    # 检查新增或修改的值
                    for value_name, (value_data, reg_type) in current_values.items():
                        if value_name not in previous_values:
                            self._emit_registry_event(
                                f"{key_path}\\{value_name}", 
                                Operation.REG_CREATE, 
                                "SUCCESS", 
                                f"新值: {value_data}"
                            )
                        elif previous_values[value_name] != (value_data, reg_type):
                            old_value = previous_values[value_name][0]
                            self._emit_registry_event(
                                f"{key_path}\\{value_name}", 
                                Operation.REG_WRITE, 
                                "SUCCESS", 
                                f"值变更: {old_value} -> {value_data}"
                            )
                    
                    # 检查删除的值
                    for value_name in previous_values:
                        if value_name not in current_values:
                            self._emit_registry_event(
                                f"{key_path}\\{value_name}", 
                                Operation.REG_DELETE, 
                                "SUCCESS", 
                                "值已删除"
                            )
    
    def _emit_registry_event(self, path: str, operation: Operation, result: str, details: str):
        """发送注册表事件"""
        # 尝试获取访问注册表的进程信息
        process_name, process_id = self._get_accessing_process()
        
        event = MonitorEvent(
            timestamp=datetime.now(),
            event_type=EventType.REGISTRY,
            operation=operation,
            process_name=process_name,
            process_id=process_id,
            path=path,
            result=result,
            details={
                "change_details": details,
                "registry_type": "REG_KEY" if "\\\\" not in path.split("\\")[-1] else "REG_VALUE"
            }
        )
        self._emit_event(event)
    
    def _get_accessing_process(self) -> Tuple[str, int]:
        """获取访问注册表的进程信息（简化实现）"""
        # 注册表访问很难直接追踪到具体进程，这里返回通用信息
        return "System", 0


class DetailedRegistryMonitor(RegistryMonitor):
    """详细注册表监控器"""
    
    def __init__(self, event_callback, monitor_keys: Optional[List[Tuple]] = None):
        super().__init__(event_callback, monitor_keys)
        self.value_history: Dict[str, List] = {}  # 值变更历史
    
    def _emit_registry_event(self, path: str, operation: Operation, result: str, details: str):
        """发送详细的注册表事件"""
        # 记录值变更历史
        if operation == Operation.REG_WRITE:
            if path not in self.value_history:
                self.value_history[path] = []
            self.value_history[path].append({
                "timestamp": datetime.now().isoformat(),
                "details": details
            })
            # 限制历史记录数量
            if len(self.value_history[path]) > 10:
                self.value_history[path].pop(0)
        
        # 获取更多详细信息
        additional_details = self._get_registry_details(path)
        
        process_name, process_id = self._get_accessing_process()
        
        event = MonitorEvent(
            timestamp=datetime.now(),
            event_type=EventType.REGISTRY,
            operation=operation,
            process_name=process_name,
            process_id=process_id,
            path=path,
            result=result,
            details={
                "change_details": details,
                "registry_type": "REG_KEY" if "\\\\" not in path.split("\\")[-1] else "REG_VALUE",
                "change_count": str(len(self.value_history.get(path, []))),
                **additional_details
            }
        )
        self._emit_event(event)
    
    def _get_registry_details(self, path: str) -> Dict[str, str]:
        """获取注册表详细信息"""
        details = {}
        
        try:
            # 解析路径
            parts = path.split("\\")
            if len(parts) >= 2:
                hkey_name = parts[0]
                subkey_path = "\\".join(parts[1:-1]) if len(parts) > 2 else parts[1]
                
                # 获取键的权限信息等
                details["hkey"] = hkey_name
                details["subkey"] = subkey_path
                
                if len(parts) > 2:
                    details["value_name"] = parts[-1]
        except Exception:
            pass
        
        return details


def test_registry_monitor():
    """测试注册表监控器"""
    if not WINREG_AVAILABLE:
        print("无法测试注册表监控器: winreg库不可用")
        return
    
    def event_handler(event):
        print(f"[{event.timestamp.strftime('%H:%M:%S.%f')[:-3]}] {event.operation.value}: {event.path}")
        if event.details.get("change_details"):
            print(f"    详情: {event.details['change_details']}")
    
    print("启动注册表监控器测试...")
    monitor = DetailedRegistryMonitor(event_handler)
    monitor.start()
    
    try:
        print("监控中... 按 Ctrl+C 停止")
        print("提示: 可以尝试修改注册表中的启动项来测试监控功能")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n停止监控...")
        monitor.stop()
        print("监控已停止")


if __name__ == "__main__":
    test_registry_monitor()