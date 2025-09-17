#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
综合侦探器
整合所有功能模块，提供统一的进程行为侦探解决方案
"""

import os
import sys
import time
import threading
import signal
from datetime import datetime, timedelta
from typing import Dict, Set, Optional, List, Callable, Any, Tuple
from pathlib import Path
import json
import argparse

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("警告: psutil库未安装，某些功能将受限")

# 导入所有监控模块
from procmon import BaseMonitor, MonitorEvent, EventType, Operation
from enhanced_process_monitor import EnhancedProcessMonitor, format_error_message
from enhanced_filesystem_monitor import EnhancedFileSystemMonitor
from enhanced_registry_monitor import EnhancedRegistryMonitor
from enhanced_network_monitor import EnhancedNetworkMonitor
from syscall_monitor import SystemCallMonitor
from event_filter_display import EnhancedEventProcessor, EventFilter, FilterOperator, FilterType


class MonitorConfig:
    """侦探器配置"""
    
    def __init__(self):
        # 基本配置
        self.target_process: Optional[str] = None
        self.target_pid: Optional[int] = None
        self.output_file: Optional[str] = None
        self.log_level: str = "INFO"
        self.max_events: int = 100000
        
        # 侦探模块启用状态
        self.enable_process_monitor = True
        self.enable_filesystem_monitor = True
        self.enable_registry_monitor = True
        self.enable_network_monitor = True
        self.enable_syscall_monitor = False  # 需要管理员权限
        
        # 进程侦探配置
        self.monitor_child_processes = True
        self.track_process_tree = True
        self.monitor_threads = True
        self.monitor_modules = True
        self.monitor_handles = False
        
        # 文件系统侦探配置
        self.watch_directories: List[str] = []
        self.monitor_file_content = False
        self.track_file_access = True
        self.exclude_system_files = True
        
        # 注册表侦探配置
        self.watch_registry_keys: List[Tuple[str, int]] = []
        self.monitor_process_registry_access = True
        self.track_value_changes = True
        
        # 网络侦探配置
        self.capture_packets = False  # 需要管理员权限
        self.monitor_connections = True
        self.monitor_dns = True
        self.network_interface: Optional[str] = None
        
        # 系统调用侦探配置
        self.syscall_categories: List[str] = ["process", "file", "registry", "network"]
        
        # 过滤器配置
        self.filter_config_file: Optional[str] = None
        self.auto_create_filters = True
        
        # 输出配置
        self.output_format = "text"  # text, json, csv
        self.show_details = True
        self.real_time_display = True
        self.save_to_file = False
    
    def load_from_file(self, config_file: str):
        """从文件加载配置"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            for key, value in config_data.items():
                if hasattr(self, key):
                    setattr(self, key, value)
                    
        except Exception as e:
            print(f"加载配置文件失败: {e}")
    
    def save_to_file(self, config_file: str):
        """保存配置到文件"""
        try:
            config_data = {}
            for key, value in self.__dict__.items():
                if not key.startswith('_'):
                    config_data[key] = value
            
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, ensure_ascii=False, indent=2)
                
        except Exception as e:
            print(f"保存配置文件失败: {e}")


class ComprehensiveMonitor:
    """综合监控器"""
    
    def __init__(self, config: MonitorConfig):
        self.config = config
        self.running = False
        self.start_time = None
        
        # 事件处理器
        self.event_processor = EnhancedEventProcessor(config.max_events)
        
        # 监控器实例
        self.monitors: Dict[str, BaseMonitor] = {}
        
        # 统计信息
        self.total_events = 0
        self.events_by_type = {}
        self.events_by_process = {}
        
        # 输出文件
        self.output_file_handle = None
        
        # 初始化
        self._initialize_event_processor()
        self._initialize_monitors()
    
    def _initialize_event_processor(self):
        """初始化事件处理器"""
        # 添加事件回调
        self.event_processor.add_event_callback(self._on_event_received)
        
        # 创建常用过滤器
        if self.config.auto_create_filters:
            self.event_processor.create_common_filters()
        
        # 加载过滤器配置
        if self.config.filter_config_file and os.path.exists(self.config.filter_config_file):
            self.event_processor.load_filters(self.config.filter_config_file)
        
        # 根据目标进程创建过滤器
        if self.config.target_process:
            target_filter = EventFilter(
                name="目标进程过滤器",
                field="process_name",
                operator=FilterOperator.CONTAINS,
                value=self.config.target_process,
                filter_type=FilterType.INCLUDE
            )
            self.event_processor.add_filter(target_filter)
        
        if self.config.target_pid:
            pid_filter = EventFilter(
                name="目标PID过滤器",
                field="process_id",
                operator=FilterOperator.EQUALS,
                value=self.config.target_pid,
                filter_type=FilterType.INCLUDE
            )
            self.event_processor.add_filter(pid_filter)
    
    def _initialize_monitors(self):
        """初始化监控器"""
        # 进程监控器
        if self.config.enable_process_monitor:
            try:
                target_processes = None
                if self.config.target_process:
                    target_processes = {self.config.target_process}
                process_monitor = EnhancedProcessMonitor(
                    self.event_processor.process_event,
                    target_processes=target_processes,
                    monitor_threads=self.config.monitor_threads,
                    monitor_modules=self.config.monitor_modules,
                    monitor_handles=self.config.monitor_handles,
                    monitor_child_processes=self.config.monitor_child_processes
                )
                self.monitors['process'] = process_monitor
                print("进程监控器已初始化")
            except Exception as e:
                print(f"初始化进程监控器失败: {e}")
        
        # 文件系统监控器
        if self.config.enable_filesystem_monitor:
            try:
                watch_dirs = self.config.watch_directories or ["C:\\"]
                filesystem_monitor = EnhancedFileSystemMonitor(
                    self.event_processor.process_event,
                    watch_paths=watch_dirs,
                    monitor_process_access=True,
                    track_file_changes=True,
                    calculate_hashes=False
                )
                self.monitors['filesystem'] = filesystem_monitor
                print(f"文件系统监控器已初始化，监控目录: {watch_dirs}")
            except Exception as e:
                print(f"初始化文件系统监控器失败: {e}")
        
        # 注册表监控器
        if self.config.enable_registry_monitor:
            try:
                registry_monitor = EnhancedRegistryMonitor(
                    self.event_processor.process_event,
                    watch_keys=self.config.watch_registry_keys,
                    monitor_process_registry_access=self.config.monitor_process_registry_access,
                    track_value_changes=self.config.track_value_changes
                )
                self.monitors['registry'] = registry_monitor
                print("注册表监控器已初始化")
            except Exception as e:
                print(f"初始化注册表监控器失败: {e}")
        
        # 网络监控器
        if self.config.enable_network_monitor:
            try:
                network_monitor = EnhancedNetworkMonitor(
                    self.event_processor.process_event,
                    capture_packets=self.config.capture_packets,
                    monitor_connections=self.config.monitor_connections,
                    monitor_dns=self.config.monitor_dns,
                    interface=self.config.network_interface
                )
                self.monitors['network'] = network_monitor
                print("网络监控器已初始化")
            except Exception as e:
                print(f"初始化网络监控器失败: {e}")
        
        # 系统调用监控器
        if self.config.enable_syscall_monitor:
            try:
                syscall_monitor = SystemCallMonitor(
                    self.event_processor.process_event,
                    categories=self.config.syscall_categories
                )
                self.monitors['syscall'] = syscall_monitor
                print("系统调用监控器已初始化")
            except Exception as e:
                print(f"初始化系统调用监控器失败: {e}")
    
    def _on_event_received(self, event: MonitorEvent):
        """事件接收回调"""
        self.total_events += 1
        
        # 更新统计信息
        event_type = event.event_type.value
        self.events_by_type[event_type] = self.events_by_type.get(event_type, 0) + 1
        
        process_key = f"{event.process_name} ({event.process_id})"
        self.events_by_process[process_key] = self.events_by_process.get(process_key, 0) + 1
        
        # 实时显示
        if self.config.real_time_display:
            self._display_event(event)
        
        # 保存到文件
        if self.config.save_to_file and self.output_file_handle:
            self._write_event_to_file(event)
    
    def _display_event(self, event: MonitorEvent):
        """显示事件 - 逐条输出，彩色显示"""
        if self.config.output_format == "json":
            event_data = {
                'timestamp': event.timestamp.isoformat(),
                'event_type': event.event_type.value,
                'operation': event.operation.value,
                'process_name': event.process_name,
                'process_id': event.process_id,
                'path': event.path,
                'result': event.result,
                'details': event.details
            }
            print(json.dumps(event_data, ensure_ascii=False))
        
        elif self.config.output_format == "csv":
            # CSV格式输出
            csv_line = f"{event.timestamp.isoformat()},{event.event_type.value},{event.operation.value},{event.process_name},{event.process_id},{event.path},{event.result}"
            print(csv_line)
        
        else:
            # 文本格式输出 - 逐条显示，彩色显示，一行完成
            formatted_event = self.event_processor.formatter.format_single_event(event, self.total_events)
            print(formatted_event)
    
    def _write_event_to_file(self, event: MonitorEvent):
        """写入事件到文件"""
        try:
            if self.config.output_format == "json":
                event_data = {
                    'timestamp': event.timestamp.isoformat(),
                    'event_type': event.event_type.value,
                    'operation': event.operation.value,
                    'process_name': event.process_name,
                    'process_id': event.process_id,
                    'path': event.path,
                    'result': event.result,
                    'details': event.details
                }
                self.output_file_handle.write(json.dumps(event_data, ensure_ascii=False) + '\n')
            
            elif self.config.output_format == "csv":
                csv_line = f"{event.timestamp.isoformat()},{event.event_type.value},{event.operation.value},{event.process_name},{event.process_id},{event.path},{event.result}\n"
                self.output_file_handle.write(csv_line)
            
            else:
                # 文本格式输出到文件 - 纯文本，无颜色编码
                formatted_event = self.event_processor.formatter.format_event_plain_text(event)
                self.output_file_handle.write(formatted_event + '\n')
            
            self.output_file_handle.flush()
            
        except Exception as e:
            print(f"写入文件失败: {e}")
    
    def start(self):
        """启动监控"""
        if self.running:
            print("监控器已在运行")
            return
        
        print("启动综合监控器...")
        self.running = True
        self.start_time = datetime.now()
        
        # 打开输出文件
        if self.config.save_to_file and self.config.output_file:
            try:
                self.output_file_handle = open(self.config.output_file, 'w', encoding='utf-8')
                print(f"输出将保存到: {self.config.output_file}")
            except Exception as e:
                print(f"打开输出文件失败: {e}")
        
        # 启动所有监控器
        for name, monitor in self.monitors.items():
            try:
                monitor.start()
                print(f"{name}监控器已启动")
            except Exception as e:
                print(f"启动{name}监控器失败: {e}")
        
        print(f"监控器启动完成，共启用 {len(self.monitors)} 个监控模块")
        
        # 显示配置信息
        self._display_config_info()
    
    def stop(self):
        """停止监控"""
        if not self.running:
            return
        
        print("\n正在停止监控器...")
        self.running = False
        
        # 停止所有监控器
        for name, monitor in self.monitors.items():
            try:
                monitor.stop()
                print(f"{name}监控器已停止")
            except Exception as e:
                print(f"停止{name}监控器失败: {e}")
        
        # 关闭输出文件
        if self.output_file_handle:
            try:
                self.output_file_handle.close()
                print(f"输出文件已关闭")
            except Exception as e:
                print(f"关闭输出文件失败: {e}")
        
        # 显示最终统计信息
        self._display_final_statistics()
        
        print("监控器已停止")
    
    def _display_config_info(self):
        """显示配置信息"""
        print("\n=== 监控配置 ===")
        if self.config.target_process:
            print(f"目标进程: {self.config.target_process}")
        if self.config.target_pid:
            print(f"目标PID: {self.config.target_pid}")
        
        enabled_monitors = [name for name in self.monitors.keys()]
        print(f"启用的监控器: {', '.join(enabled_monitors)}")
        
        if self.config.watch_directories:
            print(f"监控目录: {', '.join(self.config.watch_directories)}")
        
        if self.config.watch_registry_keys:
            keys = [f"{key[0]}" for key in self.config.watch_registry_keys]
            print(f"监控注册表键: {', '.join(keys)}")
        
        print(f"输出格式: {self.config.output_format}")
        print(f"最大事件数: {self.config.max_events}")
        print(f"实时显示: {'是' if self.config.real_time_display else '否'}")
        print(f"保存到文件: {'是' if self.config.save_to_file else '否'}")
        print(f"子进程监控: {'是' if self.config.monitor_child_processes else '否'}")
        print("="*50)
    
    def show_process_tree(self):
        """显示进程树"""
        if 'process' in self.monitors:
            process_monitor = self.monitors['process']
            tree_display = self.event_processor.formatter.format_process_tree(process_monitor)
            print(tree_display)
        else:
            print("进程监控器未启用，无法显示进程树")
    
    def get_process_tree_info(self) -> dict:
        """获取进程树信息"""
        if 'process' not in self.monitors:
            return {}
        
        process_monitor = self.monitors['process']
        return {
            'root_processes': list(process_monitor.root_processes),
            'process_tree': {str(k): list(v) for k, v in process_monitor.process_tree.items()},
            'monitored_pids': list(process_monitor.monitored_pids),
            'total_processes': len(process_monitor.processes)
        }
    
    def _display_final_statistics(self):
        """显示最终统计信息"""
        if not self.start_time:
            return
        
        duration = datetime.now() - self.start_time
        
        print("\n=== 监控统计信息 ===")
        print(f"监控时长: {duration}")
        print(f"总事件数: {self.total_events}")
        
        if self.events_by_type:
            print("\n事件类型分布:")
            for event_type, count in sorted(self.events_by_type.items(), key=lambda x: x[1], reverse=True):
                print(f"  {event_type}: {count}")
        
        if self.events_by_process:
            print("\n最活跃进程 (前10):")
            top_processes = sorted(self.events_by_process.items(), key=lambda x: x[1], reverse=True)[:10]
            for process, count in top_processes:
                print(f"  {process}: {count}")
        
        # 显示各监控器统计信息
        for name, monitor in self.monitors.items():
            try:
                if hasattr(monitor, 'get_statistics'):
                    stats = monitor.get_statistics()
                    print(f"\n{name}监控器统计:")
                    for key, value in stats.items():
                        print(f"  {key}: {value}")
            except Exception as e:
                print(f"获取{name}监控器统计失败: {e}")
        
        print("="*50)
    
    def get_events(self, limit: Optional[int] = None) -> List[MonitorEvent]:
        """获取事件列表"""
        return self.event_processor.get_events(limit)
    
    def get_statistics(self) -> dict:
        """获取统计信息"""
        stats = {
            'total_events': self.total_events,
            'events_by_type': self.events_by_type,
            'events_by_process': self.events_by_process,
            'running': self.running,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'enabled_monitors': list(self.monitors.keys())
        }
        
        # 添加事件处理器统计
        processor_stats = self.event_processor.get_statistics()
        stats['processor'] = processor_stats
        
        # 添加各监控器统计
        stats['monitors'] = {}
        for name, monitor in self.monitors.items():
            try:
                if hasattr(monitor, 'get_statistics'):
                    stats['monitors'][name] = monitor.get_statistics()
            except Exception as e:
                stats['monitors'][name] = {'error': str(e)}
        
        return stats
    
    def add_filter(self, event_filter: EventFilter):
        """添加过滤器"""
        self.event_processor.add_filter(event_filter)
    
    def enable_filter(self, filter_name: str, enabled: bool = True):
        """启用/禁用过滤器"""
        self.event_processor.enable_filter(filter_name, enabled)
    
    def save_filters(self, filename: str):
        """保存过滤器"""
        self.event_processor.save_filters(filename)
    
    def load_filters(self, filename: str):
        """加载过滤器"""
        self.event_processor.load_filters(filename)


def create_default_config() -> MonitorConfig:
    """创建默认配置"""
    config = MonitorConfig()
    
    # 设置常用的监控目录
    config.watch_directories = [
        "C:\\",  # C盘根目录
        "C:\\Users\\Administrator\\Desktop",  # 桌面目录
        "C:\\Users",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "C:\\Windows\\System32"
    ]
    
    # 设置常用的注册表键
    import winreg
    config.watch_registry_keys = [
        ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", winreg.HKEY_LOCAL_MACHINE),
        ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", winreg.HKEY_CURRENT_USER),
        ("SYSTEM\\CurrentControlSet\\Services", winreg.HKEY_LOCAL_MACHINE)
    ]
    
    return config


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="综合进程行为监控器")
    parser.add_argument("-p", "--process", help="目标进程名称")
    parser.add_argument("--pid", type=int, help="目标进程PID")
    parser.add_argument("-o", "--output", help="输出文件路径")
    parser.add_argument("-f", "--format", choices=["text", "json", "csv"], default="text", help="输出格式")
    parser.add_argument("-c", "--config", help="配置文件路径")
    parser.add_argument("--no-process", action="store_true", help="禁用进程监控")
    parser.add_argument("--no-filesystem", action="store_true", help="禁用文件系统监控")
    parser.add_argument("--no-registry", action="store_true", help="禁用注册表监控")
    parser.add_argument("--no-network", action="store_true", help="禁用网络监控")
    parser.add_argument("--enable-syscall", action="store_true", help="启用系统调用监控（需要管理员权限）")
    parser.add_argument("--capture-packets", action="store_true", help="启用网络包捕获（需要管理员权限）")
    parser.add_argument("--max-events", type=int, default=100000, help="最大事件数")
    parser.add_argument("--watch-dir", action="append", help="监控目录（可多次指定）")
    parser.add_argument("--quiet", action="store_true", help="静默模式，不显示实时事件")
    
    args = parser.parse_args()
    
    # 创建配置
    if args.config and os.path.exists(args.config):
        config = MonitorConfig()
        config.load_from_file(args.config)
    else:
        config = create_default_config()
    
    # 应用命令行参数
    if args.process:
        config.target_process = args.process
    if args.pid:
        config.target_pid = args.pid
    if args.output:
        config.output_file = args.output
        config.save_to_file = True
    if args.format:
        config.output_format = args.format
    if args.max_events:
        config.max_events = args.max_events
    if args.watch_dir:
        config.watch_directories = args.watch_dir
    if args.quiet:
        config.real_time_display = False
    
    # 禁用选项
    if args.no_process:
        config.enable_process_monitor = False
    if args.no_filesystem:
        config.enable_filesystem_monitor = False
    if args.no_registry:
        config.enable_registry_monitor = False
    if args.no_network:
        config.enable_network_monitor = False
    
    # 启用选项
    if args.enable_syscall:
        config.enable_syscall_monitor = True
    if args.capture_packets:
        config.capture_packets = True
    
    # 创建监控器
    monitor = ComprehensiveMonitor(config)
    
    # 信号处理
    def signal_handler(signum, frame):
        print(f"\n接收到信号 {signum}，正在停止监控器...")
        monitor.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # 启动监控
        monitor.start()
        
        if config.target_process:
            print(f"\n正在监控进程: {config.target_process}")
        elif config.target_pid:
            print(f"\n正在监控PID: {config.target_pid}")
        else:
            print("\n正在监控所有进程活动")
        
        print("按 Ctrl+C 停止监控\n")
        
        # 主循环
        while monitor.running:
            time.sleep(1)
            
            # 定期显示统计信息（可选）
            # stats = monitor.get_statistics()
            # print(f"\r事件总数: {stats['total_events']}", end="", flush=True)
    
    except KeyboardInterrupt:
        print("\n用户中断")
    except Exception as e:
         print(format_error_message("综合监控器运行", e, "监控循环执行异常"))
    finally:
        monitor.stop()


if __name__ == "__main__":
    main()