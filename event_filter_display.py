#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
事件过滤和显示优化模块
提供高级事件过滤、格式化显示和性能优化功能
"""

import os
import sys
import time
import re
import threading
from datetime import datetime, timedelta
from typing import Dict, Set, Optional, List, Callable, Any, Tuple, Union
from collections import deque, defaultdict
from dataclasses import dataclass, field
from enum import Enum
import json

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from procmon import MonitorEvent, EventType, Operation
from enhanced_process_monitor import format_error_message


class FilterType(Enum):
    """过滤器类型"""
    INCLUDE = "include"
    EXCLUDE = "exclude"


class FilterOperator(Enum):
    """过滤器操作符"""
    EQUALS = "equals"
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    REGEX = "regex"
    GREATER_THAN = "gt"
    LESS_THAN = "lt"
    IN_LIST = "in"
    NOT_IN_LIST = "not_in"


@dataclass
class EventFilter:
    """事件过滤器"""
    name: str
    field: str  # 要过滤的字段名
    operator: FilterOperator
    value: Any
    filter_type: FilterType = FilterType.INCLUDE
    enabled: bool = True
    case_sensitive: bool = False
    
    def __post_init__(self):
        if self.operator == FilterOperator.REGEX:
            try:
                flags = 0 if self.case_sensitive else re.IGNORECASE
                self.compiled_regex = re.compile(str(self.value), flags)
            except re.error as e:
                raise ValueError(f"无效的正则表达式 '{self.value}': {e}")
    
    def matches(self, event: MonitorEvent) -> bool:
        """检查事件是否匹配过滤器"""
        if not self.enabled:
            return True
        
        # 获取字段值
        field_value = self._get_field_value(event, self.field)
        if field_value is None:
            return False
        
        # 执行匹配
        match_result = self._execute_match(field_value)
        
        # 根据过滤器类型返回结果
        if self.filter_type == FilterType.INCLUDE:
            return match_result
        else:  # EXCLUDE
            return not match_result
    
    def _get_field_value(self, event: MonitorEvent, field_path: str) -> Any:
        """获取事件字段值（支持嵌套字段）"""
        try:
            value = event
            for field_name in field_path.split('.'):
                if hasattr(value, field_name):
                    value = getattr(value, field_name)
                elif isinstance(value, dict) and field_name in value:
                    value = value[field_name]
                else:
                    return None
            return value
        except Exception:
            return None
    
    def _execute_match(self, field_value: Any) -> bool:
        """执行匹配操作"""
        try:
            if self.operator == FilterOperator.EQUALS:
                return self._compare_values(field_value, self.value, exact=True)
            
            elif self.operator == FilterOperator.CONTAINS:
                return self._string_contains(field_value, self.value)
            
            elif self.operator == FilterOperator.STARTS_WITH:
                return self._string_starts_with(field_value, self.value)
            
            elif self.operator == FilterOperator.ENDS_WITH:
                return self._string_ends_with(field_value, self.value)
            
            elif self.operator == FilterOperator.REGEX:
                return bool(self.compiled_regex.search(str(field_value)))
            
            elif self.operator == FilterOperator.GREATER_THAN:
                return self._numeric_compare(field_value, self.value, '>')
            
            elif self.operator == FilterOperator.LESS_THAN:
                return self._numeric_compare(field_value, self.value, '<')
            
            elif self.operator == FilterOperator.IN_LIST:
                return field_value in self.value
            
            elif self.operator == FilterOperator.NOT_IN_LIST:
                return field_value not in self.value
            
            return False
            
        except Exception:
            return False
    
    def _compare_values(self, value1: Any, value2: Any, exact: bool = True) -> bool:
        """比较两个值"""
        if exact:
            return value1 == value2
        else:
            str1 = str(value1)
            str2 = str(value2)
            if not self.case_sensitive:
                str1 = str1.lower()
                str2 = str2.lower()
            return str1 == str2
    
    def _string_contains(self, text: Any, substring: str) -> bool:
        """字符串包含检查"""
        text_str = str(text)
        if not self.case_sensitive:
            text_str = text_str.lower()
            substring = substring.lower()
        return substring in text_str
    
    def _string_starts_with(self, text: Any, prefix: str) -> bool:
        """字符串开头检查"""
        text_str = str(text)
        if not self.case_sensitive:
            text_str = text_str.lower()
            prefix = prefix.lower()
        return text_str.startswith(prefix)
    
    def _string_ends_with(self, text: Any, suffix: str) -> bool:
        """字符串结尾检查"""
        text_str = str(text)
        if not self.case_sensitive:
            text_str = text_str.lower()
            suffix = suffix.lower()
        return text_str.endswith(suffix)
    
    def _numeric_compare(self, value1: Any, value2: Any, operator: str) -> bool:
        """数值比较"""
        try:
            num1 = float(value1)
            num2 = float(value2)
            if operator == '>':
                return num1 > num2
            elif operator == '<':
                return num1 < num2
            return False
        except (ValueError, TypeError):
            return False
    
    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            'name': self.name,
            'field': self.field,
            'operator': self.operator.value,
            'value': self.value,
            'filter_type': self.filter_type.value,
            'enabled': self.enabled,
            'case_sensitive': self.case_sensitive
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'EventFilter':
        """从字典创建过滤器"""
        return cls(
            name=data['name'],
            field=data['field'],
            operator=FilterOperator(data['operator']),
            value=data['value'],
            filter_type=FilterType(data.get('filter_type', 'include')),
            enabled=data.get('enabled', True),
            case_sensitive=data.get('case_sensitive', False)
        )


class EventAggregator:
    """事件聚合器"""
    
    def __init__(self, max_events: int = 50000):
        self.max_events = max_events
        self.events: deque = deque(maxlen=max_events)
        self.event_counts = defaultdict(int)
        self.process_stats = defaultdict(lambda: {'count': 0, 'operations': defaultdict(int)})
        self.operation_stats = defaultdict(int)
        self.hourly_stats = defaultdict(int)
        
        # 性能统计
        self.total_events = 0
        self.filtered_events = 0
        self.last_cleanup_time = time.time()
    
    def add_event(self, event: MonitorEvent):
        """添加事件"""
        self.events.append(event)
        self.total_events += 1
        
        # 更新统计信息
        self._update_statistics(event)
        
        # 定期清理过期统计
        current_time = time.time()
        if current_time - self.last_cleanup_time > 300:  # 5分钟清理一次
            self._cleanup_statistics()
            self.last_cleanup_time = current_time
    
    def _update_statistics(self, event: MonitorEvent):
        """更新统计信息"""
        # 事件类型统计
        self.event_counts[event.event_type.value] += 1
        
        # 进程统计
        process_key = f"{event.process_name} ({event.process_id})"
        self.process_stats[process_key]['count'] += 1
        self.process_stats[process_key]['operations'][event.operation.value] += 1
        
        # 操作统计
        self.operation_stats[event.operation.value] += 1
        
        # 小时统计
        hour_key = event.timestamp.strftime('%Y-%m-%d %H:00')
        self.hourly_stats[hour_key] += 1
    
    def _cleanup_statistics(self):
        """清理过期统计信息"""
        try:
            # 清理超过24小时的小时统计
            cutoff_time = datetime.now() - timedelta(hours=24)
            expired_hours = []
            
            for hour_key in self.hourly_stats:
                try:
                    hour_time = datetime.strptime(hour_key, '%Y-%m-%d %H:00')
                    if hour_time < cutoff_time:
                        expired_hours.append(hour_key)
                except ValueError:
                    expired_hours.append(hour_key)
            
            for hour_key in expired_hours:
                del self.hourly_stats[hour_key]
                
        except Exception as e:
            print(f"清理统计信息失败: {e}")
    
    def get_events(self, limit: Optional[int] = None, 
                  start_time: Optional[datetime] = None,
                  end_time: Optional[datetime] = None) -> List[MonitorEvent]:
        """获取事件列表"""
        events = list(self.events)
        
        # 时间过滤
        if start_time or end_time:
            filtered_events = []
            for event in events:
                if start_time and event.timestamp < start_time:
                    continue
                if end_time and event.timestamp > end_time:
                    continue
                filtered_events.append(event)
            events = filtered_events
        
        # 限制数量
        if limit:
            events = events[-limit:]
        
        return events
    
    def get_statistics(self) -> dict:
        """获取统计信息"""
        return {
            'total_events': self.total_events,
            'filtered_events': self.filtered_events,
            'stored_events': len(self.events),
            'event_types': dict(self.event_counts),
            'top_processes': self._get_top_processes(10),
            'top_operations': self._get_top_operations(10),
            'hourly_distribution': dict(self.hourly_stats)
        }
    
    def _get_top_processes(self, limit: int) -> List[Tuple[str, int]]:
        """获取最活跃的进程"""
        return sorted(
            [(proc, stats['count']) for proc, stats in self.process_stats.items()],
            key=lambda x: x[1], reverse=True
        )[:limit]
    
    def _get_top_operations(self, limit: int) -> List[Tuple[str, int]]:
        """获取最频繁的操作"""
        return sorted(
            self.operation_stats.items(),
            key=lambda x: x[1], reverse=True
        )[:limit]


class EventFormatter:
    """事件格式化器"""
    
    def __init__(self, show_details: bool = True, 
                 max_path_length: int = 80,
                 time_format: str = '%H:%M:%S.%f',
                 enable_colors: bool = True,
                 show_process_tree: bool = True):
        self.show_details = show_details
        self.max_path_length = max_path_length
        self.time_format = time_format
        self.enable_colors = enable_colors
        self.show_process_tree = show_process_tree
        
        # 颜色定义 (ANSI颜色码) - 适合白色背景的深色字体
        self.colors = {
            'reset': '\033[0m',
            'bold': '\033[1m',
            'dim': '\033[2m',
            'red': '\033[38;5;124m',        # 深红色
            'green': '\033[38;5;28m',       # 深绿色
            'yellow': '\033[38;5;136m',     # 深黄色/橙色
            'blue': '\033[38;5;21m',        # 深蓝色
            'magenta': '\033[38;5;90m',     # 深紫色
            'cyan': '\033[38;5;30m',        # 深青色
            'white': '\033[38;5;15m',       # 纯白色
            'gray': '\033[38;5;240m',       # 深灰色
            'black': '\033[38;5;16m',       # 黑色
            'dark_blue': '\033[38;5;18m',   # 深蓝色
            'dark_green': '\033[38;5;22m',  # 深绿色
            'brown': '\033[38;5;94m'        # 棕色
        } if enable_colors else {key: '' for key in ['reset', 'bold', 'dim', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white', 'gray', 'black', 'dark_blue', 'dark_green', 'brown']}
        
        # 操作类型颜色映射 - 适合白色背景的深色配色
        self.operation_colors = {
            'PROCESS_CREATE': 'dark_green',
            'PROCESS_EXIT': 'red',
            'THREAD_CREATE': 'dark_blue',
            'THREAD_EXIT': 'magenta',
            'MODULE_LOAD': 'blue',
            'MODULE_UNLOAD': 'brown',
            'FILE_CREATE': 'green',
            'FILE_DELETE': 'red',
            'FILE_READ': 'blue',
            'FILE_WRITE': 'cyan',
            'FILE_RENAME': 'yellow',
            'DIR_CREATE': 'green',
            'DIR_DELETE': 'red',
            'DIR_RENAME': 'yellow',
            'REG_CREATE': 'dark_green',
            'REG_DELETE': 'red',
            'REG_READ': 'blue',
            'REG_WRITE': 'magenta',
            'NET_CONNECT': 'cyan',
            'NET_DISCONNECT': 'magenta',
            'NET_SEND': 'blue',
            'NET_RECEIVE': 'green'
        }
    
    def format_event(self, event: MonitorEvent) -> str:
        """格式化单个事件 - 增强版procmon风格"""
        # 时间戳 (HH:MM:SS.mmm)
        timestamp = event.timestamp.strftime('%H:%M:%S.%f')[:-3]
        timestamp_colored = f"{self.colors['black']}{timestamp}{self.colors['reset']}"
        
        # 进程名和PID
        process_name = event.process_name or "Unknown"
        process_id = event.process_id or 0
        
        # 进程层级显示
        process_prefix = ""
        if self.show_process_tree and event.details:
            depth = event.details.get('process_depth', 0)
            is_root = event.details.get('is_root_process', False)
            child_count = event.details.get('child_count', 0)
            
            # 创建层级缩进
            if depth > 0:
                process_prefix = "  " * depth + "└─ "
            elif is_root:
                process_prefix = "🌳 "  # 根进程标识
            
            # 添加子进程数量提示
            if child_count > 0:
                process_prefix += f"({child_count}) "
        
        # 操作类型着色
        operation = event.operation.value if event.operation else "Unknown"
        operation_color = self.operation_colors.get(operation, 'white')
        operation_colored = f"{self.colors[operation_color]}{operation}{self.colors['reset']}"
        
        # 进程名着色
        process_colored = f"{self.colors['bold']}{process_prefix}{process_name}{self.colors['reset']}"
        
        # 路径处理和着色
        path = event.path or ""
        if len(path) > self.max_path_length:
            path = "..." + path[-(self.max_path_length-3):]
        
        # 根据操作类型给路径着色 - 使用深色字体
        if 'CREATE' in operation:
            path_colored = f"{self.colors['dark_green']}{path}{self.colors['reset']}"
        elif 'DELETE' in operation:
            path_colored = f"{self.colors['red']}{path}{self.colors['reset']}"
        elif 'RENAME' in operation or 'MOVE' in operation:
            path_colored = f"{self.colors['brown']}{path}{self.colors['reset']}"
        else:
            path_colored = f"{self.colors['dark_blue']}{path}{self.colors['reset']}"
        
        # 结果状态着色 - 使用深色字体
        result = event.result or "UNKNOWN"
        if result == "SUCCESS":
            result_colored = f"{self.colors['dark_green']}{result}{self.colors['reset']}"
        elif result in ["FAILED", "ERROR", "ACCESS_DENIED"]:
            result_colored = f"{self.colors['red']}{result}{self.colors['reset']}"
        else:
            result_colored = f"{self.colors['brown']}{result}{self.colors['reset']}"
        
        # 构建单行格式 - 彩色输出
        timestamp_colored = f"\033[36m{timestamp}\033[0m"  # 青色时间戳
        process_colored = f"\033[32m{process_name}\033[0m"    # 绿色进程名
        pid_colored = f"\033[33m{process_id}\033[0m"         # 黄色PID
        operation_colored = f"\033[35m{operation}\033[0m"     # 紫色操作
        path_colored = f"\033[34m{path}\033[0m"              # 蓝色路径
        
        if result.upper() == 'SUCCESS':
            result_colored = f"\033[92m{result}\033[0m"       # 亮绿色成功
        else:
            result_colored = f"\033[91m{result}\033[0m"       # 亮红色失败
        
        base_format = f"[{timestamp_colored}] {process_colored} (PID:{pid_colored}) {operation_colored} -> {path_colored} [{result_colored}]"
        
        # 添加详细信息
        if self.show_details and event.details:
            detail_parts = []
            
            # 添加特定操作的详细信息 - 使用深色字体
            if 'thread_id' in event.details:
                # 线程基本信息
                detail_parts.append(f"{self.colors['dark_blue']}TID: {event.details['thread_id']}{self.colors['reset']}")
                
                # 线程状态信息
                if 'status_display' in event.details:
                    status_color = 'dark_green' if event.details.get('status') == 'running' else 'brown'
                    detail_parts.append(f"{self.colors[status_color]}{event.details['status_display']}{self.colors['reset']}")
                
                # CPU时间信息
                if 'cpu_time_display' in event.details:
                    detail_parts.append(f"{self.colors['blue']}CPU: {event.details['cpu_time_display']}{self.colors['reset']}")
                
                # 用户态和内核态时间
                if 'user_time_display' in event.details and 'system_time_display' in event.details:
                    detail_parts.append(f"{self.colors['dark_green']}User: {event.details['user_time_display']}{self.colors['reset']}")
                    detail_parts.append(f"{self.colors['red']}Sys: {event.details['system_time_display']}{self.colors['reset']}")
                
                # 优先级信息
                if 'priority_display' in event.details:
                    priority_color = 'magenta' if event.details.get('priority', 0) != 0 else 'gray'
                    detail_parts.append(f"{self.colors[priority_color]}{event.details['priority_display']}{self.colors['reset']}")
                
                # 上下文切换次数
                if 'context_switches' in event.details and event.details['context_switches'] > 0:
                    detail_parts.append(f"{self.colors['brown']}Switches: {event.details['context_switches']}{self.colors['reset']}")
                
                # 起始地址
                if 'start_address' in event.details and event.details['start_address']:
                    detail_parts.append(f"{self.colors['gray']}Start: {event.details['start_address']}{self.colors['reset']}")
                    
            if 'module_name' in event.details:
                detail_parts.append(f"{self.colors['magenta']}Module: {event.details['module_name']}{self.colors['reset']}")
            if 'size' in event.details:
                detail_parts.append(f"{self.colors['blue']}Size: {event.details['size']}{self.colors['reset']}")
            if 'source_path' in event.details and 'destination_path' in event.details:
                src = event.details['source_path']
                dst = event.details['destination_path']
                src_colored = f"\033[34m{src}\033[0m"    # 蓝色源路径
                dst_colored = f"\033[94m{dst}\033[0m"    # 亮蓝色目标路径
                base_format = f"[{timestamp_colored}] {process_colored} (PID:{pid_colored}) {operation_colored} {src_colored} -> {dst_colored} [{result_colored}]"
            
            if detail_parts:
                # 清理ANSI颜色码
                clean_parts = []
                for part in detail_parts:
                    clean_part = part.replace('\033[0m', '')
                    if '\033[' in clean_part:
                        clean_part = clean_part.split('m')[-1]
                    clean_parts.append(clean_part)
                detail_str = f" \033[90m({', '.join(clean_parts)})\033[0m"  # 灰色详细信息
                return base_format + detail_str
        
        return base_format
    
    def get_process_tree_visual(self, event: MonitorEvent) -> str:
        """获取进程树可视化字符串"""
        if not event.details:
            return ""
        
        depth = event.details.get('process_depth', 0)
        is_root = event.details.get('is_root_process', False)
        child_count = event.details.get('child_count', 0)
        
        if is_root:
            return f"{self.colors['bold']}🌳{self.colors['reset']} "
        elif depth > 0:
            indent = "  " * (depth - 1)
            return f"{indent}{self.colors['dim']}├─{self.colors['reset']} "
        
        return base_format
    
    def format_event_plain_text(self, event: MonitorEvent) -> str:
        """格式化事件 - 纯文本输出，无颜色编码"""
        timestamp = event.timestamp.strftime('%H:%M:%S.%f')[:-3] if event.timestamp else "00:00:00.000"
        process_name = event.process_name or "Unknown"
        process_id = event.process_id or 0
        operation = event.operation.value if event.operation else "Unknown"
        path = event.path or "Unknown"
        result = event.result or "Unknown"
        
        # 构建纯文本格式
        base_format = f"[{timestamp}] {process_name} (PID:{process_id}) {operation} -> {path} [{result}]"
        
        # 添加详细信息
        detail_parts = []
        
        if event.details:
            # 线程详细信息
            if 'thread_id' in event.details and event.details['thread_id'] is not None:
                tid = event.details['thread_id']
                detail_parts.append(f"TID:{tid}")
                
                if 'status' in event.details and event.details['status'] is not None:
                    status = event.details['status']
                    detail_parts.append(f"状态:{status}")
                
                if 'user_time' in event.details and event.details['user_time'] is not None:
                    user_time = event.details['user_time']
                    detail_parts.append(f"用户时间:{user_time:.3f}s")
                
                if 'context_switches' in event.details and event.details['context_switches'] is not None:
                    switches = event.details['context_switches']
                    detail_parts.append(f"上下文切换:{switches}")
                
                if 'start_address' in event.details and event.details['start_address'] is not None:
                    start_addr = event.details['start_address']
                    detail_parts.append(f"起始地址:0x{start_addr:x}")
            
            # 模块详细信息
            if 'module_name' in event.details and event.details['module_name'] is not None:
                module_name = event.details['module_name']
                detail_parts.append(f"模块:{module_name}")
                
                if 'module_size' in event.details and event.details['module_size'] is not None:
                    size = event.details['module_size']
                    detail_parts.append(f"大小:{size}")
            
            # 处理源路径和目标路径
            if ('source_path' in event.details and event.details['source_path'] is not None and
                'destination_path' in event.details and event.details['destination_path'] is not None):
                src = event.details['source_path']
                dst = event.details['destination_path']
                base_format = f"[{timestamp}] {process_name} (PID:{process_id}) {operation} {src} -> {dst} [{result}]"
        
        if detail_parts:
            detail_str = f" ({', '.join(detail_parts)})"
            return base_format + detail_str
        
        return base_format
    
    def format_events(self, events: List[MonitorEvent]) -> str:
        """格式化事件列表 - 逐条输出，彩色显示"""
        if not events:
            return f"{self.colors['gray']}═══ 暂无监控事件 ═══{self.colors['reset']}"
        
        # 逐条输出，每个事件单独显示
        formatted_events = []
        for i, event in enumerate(events, 1):
            # 彩色事件编号
            event_header = f"{self.colors['cyan']}[事件 {i:03d}]{self.colors['reset']}"
            formatted_events.append(event_header)
            formatted_events.append(self.format_event(event))
            formatted_events.append("")  # 空行分隔
        
        return '\n'.join(formatted_events)
    
    def format_single_event(self, event: MonitorEvent, event_number: int = 1) -> str:
        """格式化单个事件 - 彩色单行输出"""
        formatted_event = self.format_event(event)
        event_header = f"\033[96m[事件 {event_number:03d}]\033[0m"  # 亮青色事件编号
        return f"{event_header} {formatted_event}"
    
    def format_process_tree(self, process_monitor) -> str:
        """格式化进程树可视化显示"""
        if not hasattr(process_monitor, 'process_tree') or not process_monitor.process_tree:
            return f"{self.colors['dim']}暂无进程树信息{self.colors['reset']}"
        
        lines = []
        lines.append(f"{self.colors['bold']}=== 进程树可视化 ==={self.colors['reset']}")
        
        # 显示根进程
        for root_pid in process_monitor.root_processes:
            if root_pid in process_monitor.processes:
                proc_info = process_monitor.processes[root_pid]
                lines.append(f"{self.colors['bold']}🌳 {proc_info.name} (PID: {root_pid}){self.colors['reset']}")
                self._format_process_children(process_monitor, root_pid, lines, depth=1)
        
        return '\n'.join(lines)
    
    def _format_process_children(self, process_monitor, parent_pid: int, lines: List[str], depth: int = 0):
        """递归格式化子进程"""
        if parent_pid not in process_monitor.process_tree:
            return
        
        children = process_monitor.process_tree[parent_pid]
        for i, child_pid in enumerate(sorted(children)):
            if child_pid in process_monitor.processes:
                proc_info = process_monitor.processes[child_pid]
                
                # 确定连接符
                is_last = (i == len(children) - 1)
                prefix = "  " * (depth - 1) + ("└─ " if is_last else "├─ ")
                
                # 子进程数量
                child_count = len(process_monitor.process_tree.get(child_pid, set()))
                child_info = f" ({child_count} 子进程)" if child_count > 0 else ""
                
                # 进程状态颜色
                status_color = self.colors['green'] if proc_info.pid in process_monitor.monitored_pids else self.colors['gray']
                
                lines.append(f"{self.colors['dim']}{prefix}{self.colors['reset']}{status_color}{proc_info.name} (PID: {child_pid}){child_info}{self.colors['reset']}")
                
                # 递归显示子进程
                if child_count > 0:
                    self._format_process_children(process_monitor, child_pid, lines, depth + 1)
    
    def format_statistics(self, stats: dict) -> str:
        """格式化统计信息"""
        lines = []
        lines.append("=== 事件统计信息 ===")
        lines.append(f"总事件数: {stats.get('total_events', 0)}")
        lines.append(f"已过滤事件数: {stats.get('filtered_events', 0)}")
        lines.append(f"存储事件数: {stats.get('stored_events', 0)}")
        
        # 事件类型分布
        if 'event_types' in stats:
            lines.append("\n事件类型分布:")
            for event_type, count in stats['event_types'].items():
                lines.append(f"  {event_type}: {count}")
        
        # 最活跃进程
        if 'top_processes' in stats:
            lines.append("\n最活跃进程:")
            for process, count in stats['top_processes'][:5]:
                lines.append(f"  {process}: {count}")
        
        # 最频繁操作
        if 'top_operations' in stats:
            lines.append("\n最频繁操作:")
            for operation, count in stats['top_operations'][:5]:
                lines.append(f"  {operation}: {count}")
        
        return '\n'.join(lines)


class EnhancedEventProcessor:
    """增强事件处理器"""
    
    def __init__(self, max_events: int = 50000):
        self.filters: List[EventFilter] = []
        self.aggregator = EventAggregator(max_events)
        self.formatter = EventFormatter(
            show_details=True,
            enable_colors=True,
            show_process_tree=True
        )
        
        # 事件回调
        self.event_callbacks: List[Callable[[MonitorEvent], None]] = []
        self.filtered_callbacks: List[Callable[[MonitorEvent], None]] = []
        
        # 性能优化
        self.batch_size = 100
        self.batch_events: List[MonitorEvent] = []
        self.batch_lock = threading.Lock()
        self.batch_thread = None
        self.batch_running = False
        
        # 统计信息
        self.processing_stats = {
            'events_processed': 0,
            'events_filtered': 0,
            'processing_time': 0.0,
            'last_process_time': 0.0
        }
    
    def add_filter(self, event_filter: EventFilter):
        """添加过滤器"""
        self.filters.append(event_filter)
    
    def remove_filter(self, filter_name: str) -> bool:
        """移除过滤器"""
        for i, f in enumerate(self.filters):
            if f.name == filter_name:
                del self.filters[i]
                return True
        return False
    
    def get_filter(self, filter_name: str) -> Optional[EventFilter]:
        """获取过滤器"""
        for f in self.filters:
            if f.name == filter_name:
                return f
        return None
    
    def enable_filter(self, filter_name: str, enabled: bool = True):
        """启用/禁用过滤器"""
        f = self.get_filter(filter_name)
        if f:
            f.enabled = enabled
    
    def process_event(self, event: MonitorEvent):
        """处理单个事件"""
        start_time = time.time()
        
        try:
            self.processing_stats['events_processed'] += 1
            
            # 应用过滤器
            if self._should_include_event(event):
                # 添加到聚合器
                self.aggregator.add_event(event)
                
                # 调用回调
                for callback in self.event_callbacks:
                    try:
                        callback(event)
                    except Exception as e:
                         print(format_error_message("事件回调", e, f"处理事件失败: {event.process_name if hasattr(event, 'process_name') else '未知进程'}"))
            else:
                self.processing_stats['events_filtered'] += 1
                self.aggregator.filtered_events += 1
                
                # 调用过滤事件回调
                for callback in self.filtered_callbacks:
                    try:
                        callback(event)
                    except Exception as e:
                         print(format_error_message("过滤事件回调", e, f"事件过滤处理失败: {event.process_name if hasattr(event, 'process_name') else '未知进程'}"))
            
            # 更新处理时间统计
            processing_time = time.time() - start_time
            self.processing_stats['processing_time'] += processing_time
            self.processing_stats['last_process_time'] = processing_time
            
        except Exception as e:
            print(f"处理事件失败: {e}")
    
    def process_events_batch(self, events: List[MonitorEvent]):
        """批量处理事件"""
        with self.batch_lock:
            self.batch_events.extend(events)
            
            if len(self.batch_events) >= self.batch_size:
                self._process_batch()
    
    def _process_batch(self):
        """处理批量事件"""
        if not self.batch_events:
            return
        
        events_to_process = self.batch_events[:]
        self.batch_events.clear()
        
        for event in events_to_process:
            self.process_event(event)
    
    def _should_include_event(self, event: MonitorEvent) -> bool:
        """检查事件是否应该被包含"""
        if not self.filters:
            return True
        
        # 分离INCLUDE和EXCLUDE过滤器
        include_filters = [f for f in self.filters if f.enabled and f.filter_type == FilterType.INCLUDE]
        exclude_filters = [f for f in self.filters if f.enabled and f.filter_type == FilterType.EXCLUDE]
        
        # 如果有EXCLUDE过滤器匹配，则排除事件
        for f in exclude_filters:
            if f.matches(event):
                return False
        
        # 如果有INCLUDE过滤器，至少要有一个匹配
        if include_filters:
            for f in include_filters:
                if f.matches(event):
                    return True
            return False  # 没有INCLUDE过滤器匹配
        
        # 没有INCLUDE过滤器时，只要没被EXCLUDE就包含
        return True
    
    def add_event_callback(self, callback: Callable[[MonitorEvent], None]):
        """添加事件回调"""
        self.event_callbacks.append(callback)
    
    def add_filtered_callback(self, callback: Callable[[MonitorEvent], None]):
        """添加过滤事件回调"""
        self.filtered_callbacks.append(callback)
    
    def get_events(self, limit: Optional[int] = None,
                  start_time: Optional[datetime] = None,
                  end_time: Optional[datetime] = None) -> List[MonitorEvent]:
        """获取事件"""
        return self.aggregator.get_events(limit, start_time, end_time)
    
    def get_formatted_events(self, limit: Optional[int] = None) -> str:
        """获取格式化的事件"""
        events = self.get_events(limit)
        return self.formatter.format_events(events)
    
    def get_statistics(self) -> dict:
        """获取统计信息"""
        stats = self.aggregator.get_statistics()
        stats.update(self.processing_stats)
        return stats
    
    def get_formatted_statistics(self) -> str:
        """获取格式化的统计信息"""
        stats = self.get_statistics()
        return self.formatter.format_statistics(stats)
    
    def save_filters(self, filename: str):
        """保存过滤器到文件"""
        try:
            filter_data = [f.to_dict() for f in self.filters]
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(filter_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"保存过滤器失败: {e}")
    
    def load_filters(self, filename: str):
        """从文件加载过滤器"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                filter_data = json.load(f)
            
            self.filters.clear()
            for data in filter_data:
                try:
                    f = EventFilter.from_dict(data)
                    self.filters.append(f)
                except Exception as e:
                    print(f"加载过滤器失败 {data.get('name', 'unknown')}: {e}")
                    
        except Exception as e:
            print(f"加载过滤器文件失败: {e}")
    
    def create_common_filters(self):
        """创建常用过滤器"""
        common_filters = [
            # 排除系统进程
            EventFilter(
                name="排除系统进程",
                field="process_name",
                operator=FilterOperator.NOT_IN_LIST,
                value=["System", "Registry", "Idle", "csrss.exe", "winlogon.exe"],
                filter_type=FilterType.EXCLUDE
            ),
            
            # 只显示文件操作
            EventFilter(
                name="只显示文件操作",
                field="event_type",
                operator=FilterOperator.EQUALS,
                value=EventType.FILE_SYSTEM,
                enabled=False
            ),
            
            # 排除成功的操作
            EventFilter(
                name="只显示失败操作",
                field="result",
                operator=FilterOperator.NOT_IN_LIST,
                value=["SUCCESS", "BUFFER_OVERFLOW"],
                enabled=False
            ),
            
            # 排除临时文件
            EventFilter(
                name="排除临时文件",
                field="path",
                operator=FilterOperator.REGEX,
                value=r"\\(Temp|tmp|cache)\\|\.(tmp|temp|cache)$",
                filter_type=FilterType.EXCLUDE,
                enabled=False
            ),
            
            # 只显示特定进程
            EventFilter(
                name="只显示特定进程",
                field="process_name",
                operator=FilterOperator.CONTAINS,
                value="notepad",
                enabled=False
            )
        ]
        
        for f in common_filters:
            self.add_filter(f)


def test_event_filter_display():
    """测试事件过滤和显示功能"""
    from procmon import MonitorEvent, EventType, Operation
    
    # 创建事件处理器
    processor = EnhancedEventProcessor()
    
    # 创建常用过滤器
    processor.create_common_filters()
    
    # 添加事件回调
    def event_callback(event):
        print(f"处理事件: {event.process_name} - {event.operation.value}")
    
    processor.add_event_callback(event_callback)
    
    # 创建测试事件
    test_events = [
        MonitorEvent(
            timestamp=datetime.now(),
            event_type=EventType.FILESYSTEM,
            operation=Operation.CREATE_FILE,
            process_name="notepad.exe",
            process_id=1234,
            path="C:\\Users\\test\\document.txt",
            result="SUCCESS",
            details={'file_size': 1024, 'attributes': 'NORMAL'}
        ),
        MonitorEvent(
            timestamp=datetime.now(),
            event_type=EventType.PROCESS,
            operation=Operation.PROCESS_START,
            process_name="System",
            process_id=4,
            path="System",
            result="SUCCESS",
            details={'parent_pid': 0}
        ),
        MonitorEvent(
            timestamp=datetime.now(),
            event_type=EventType.REGISTRY,
            operation=Operation.REG_QUERY_VALUE,
            process_name="explorer.exe",
            process_id=2345,
            path="HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows",
            result="ACCESS_DENIED",
            details={'value_name': 'Version'}
        )
    ]
    
    print("处理测试事件...")
    for event in test_events:
        processor.process_event(event)
    
    print("\n=== 所有事件 ===")
    print(processor.get_formatted_events())
    
    print("\n=== 统计信息 ===")
    print(processor.get_formatted_statistics())
    
    # 测试过滤器
    print("\n启用'只显示文件操作'过滤器...")
    processor.enable_filter("只显示文件操作", True)
    
    print("\n=== 过滤后的事件 ===")
    print(processor.get_formatted_events())
    
    # 保存和加载过滤器
    filter_file = "test_filters.json"
    processor.save_filters(filter_file)
    print(f"\n过滤器已保存到 {filter_file}")
    
    # 清空过滤器并重新加载
    processor.filters.clear()
    processor.load_filters(filter_file)
    print(f"过滤器已从 {filter_file} 加载")
    
    # 清理测试文件
    try:
        os.remove(filter_file)
    except:
        pass


if __name__ == "__main__":
    test_event_filter_display()