#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ProcDetective - 进程行为侦探工具
主入口脚本
"""

import os
import sys
import time
import argparse
from pathlib import Path

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from comprehensive_monitor import ComprehensiveMonitor, MonitorConfig, create_default_config
    from enhanced_process_monitor import format_error_message
except ImportError as e:
    print(f"导入监控模块失败: {e}")
    print("请确保所有依赖模块都在同一目录下")
    sys.exit(1)


def print_banner():
    """打印程序横幅"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                      ProcDetective                           ║
║                   进程行为侦探工具                             ║
║                                                              ║
║  功能特性:                                                    ║
║  • 进程侦探 - 进程创建/退出、线程、模块加载                      ║
║  • 文件系统侦探 - 文件读写、创建删除、权限变更                   ║
║  • 注册表侦探 - 注册表键值变化、进程注册表访问                   ║
║  • 网络侦探 - 网络连接、DNS查询、数据包捕获                      ║
║  • 系统调用侦探 - 底层系统调用跟踪                              ║
║  • 智能分析 - 多种过滤器、事件聚合、格式化输出                   ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_usage_examples():
    """打印使用示例"""
    examples = """
使用示例:

1. 监控特定进程:
   python ProcDetective.py -p notepad.exe
   python ProcDetective.py --pid 1234

2. 监控并保存到文件:
   python ProcDetective.py -p chrome.exe -o chrome_activity.log
   python ProcDetective.py -p firefox.exe -o firefox.json -f json

3. 监控特定目录:
   python ProcDetective.py --watch-dir "C:\\Users\\Administrator\\Documents"
   python ProcDetective.py --watch-dir "C:\\Program Files" --watch-dir "C:\\Windows"

4. 启用高级功能（需要管理员权限）:
   python ProcDetective.py -p malware.exe --enable-syscall --capture-packets

5. 自定义监控模块:
   python ProcDetective.py --no-network --no-registry -p target.exe

6. 使用配置文件:
   python ProcDetective.py -c config.json

7. 静默模式监控:
   python ProcDetective.py -p service.exe --quiet -o service_log.txt
"""
    print(examples)


def check_admin_privileges():
    """检查管理员权限"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def create_sample_config():
    """创建示例配置文件"""
    config = create_default_config()
    
    # 自定义一些设置
    config.target_process = "notepad.exe"
    config.output_file = "monitor_output.log"
    config.output_format = "text"
    config.real_time_display = True
    config.save_to_file = True
    config.max_events = 50000
    
    # 保存示例配置
    config_file = "sample_config.json"
    config.save_to_file(config_file)
    print(f"示例配置文件已创建: {config_file}")
    return config_file


def interactive_setup():
    """交互式设置"""
    print("\n=== 交互式侦探设置 ===")
    
    config = create_default_config()
    
    # 目标进程
    target = input("请输入目标进程名称（留空侦探所有进程）: ").strip()
    if target:
        if target.isdigit():
            config.target_pid = int(target)
        else:
            config.target_process = target
    
    # 输出文件
    output_file = input("请输入输出文件路径（留空不保存到文件）: ").strip()
    if output_file:
        config.output_file = output_file
        config.save_to_file = True
    
    # 输出格式
    format_choice = input("选择输出格式 (1=text, 2=json, 3=csv) [1]: ").strip()
    if format_choice == "2":
        config.output_format = "json"
    elif format_choice == "3":
        config.output_format = "csv"
    else:
        config.output_format = "text"
    
    # 监控模块选择
    print("\n选择要启用的侦探模块:")
    
    modules = [
        ("进程侦探", "enable_process_monitor"),
        ("文件系统侦探", "enable_filesystem_monitor"),
        ("注册表侦探", "enable_registry_monitor"),
        ("网络侦探", "enable_network_monitor")
    ]
    
    for i, (name, attr) in enumerate(modules, 1):
        choice = input(f"{i}. 启用{name}? (Y/n) [Y]: ").strip().lower()
        if choice in ['n', 'no']:
            setattr(config, attr, False)
    
    # 高级功能
    if check_admin_privileges():
        syscall_choice = input("启用系统调用监控? (需要管理员权限) (y/N) [N]: ").strip().lower()
        if syscall_choice in ['y', 'yes']:
            config.enable_syscall_monitor = True
        
        packet_choice = input("启用网络包捕获? (需要管理员权限) (y/N) [N]: ").strip().lower()
        if packet_choice in ['y', 'yes']:
            config.capture_packets = True
    else:
        print("注意: 当前没有管理员权限，无法启用系统调用监控和网络包捕获")
    
    # 监控目录
    watch_dirs = input("请输入要监控的目录（多个目录用分号分隔，留空使用默认）: ").strip()
    if watch_dirs:
        config.watch_directories = [d.strip() for d in watch_dirs.split(';') if d.strip()]
    
    return config


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="ProcDetective - 进程行为侦探工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="更多信息请访问: https://github.com/heimao-box/ProcDetective"
    )
    
    # 基本选项
    parser.add_argument("-p", "--process", help="目标进程名称")
    parser.add_argument("--pid", type=int, help="目标进程PID")
    parser.add_argument("-o", "--output", help="输出文件路径")
    parser.add_argument("-f", "--format", choices=["text", "json", "csv"], 
                       default="text", help="输出格式 (默认: text)")
    parser.add_argument("-c", "--config", help="配置文件路径")
    
    # 侦探模块控制
    parser.add_argument("--no-process", action="store_true", help="禁用进程侦探")
    parser.add_argument("--no-filesystem", action="store_true", help="禁用文件系统侦探")
    parser.add_argument("--no-registry", action="store_true", help="禁用注册表侦探")
    parser.add_argument("--no-network", action="store_true", help="禁用网络侦探")
    
    # 高级功能
    parser.add_argument("--enable-syscall", action="store_true", 
                       help="启用系统调用侦探（需要管理员权限）")
    parser.add_argument("--capture-packets", action="store_true", 
                       help="启用网络包捕获（需要管理员权限）")
    
    # 其他选项
    parser.add_argument("--max-events", type=int, default=100000, help="最大事件数 (默认: 100000)")
    parser.add_argument("--watch-dir", action="append", help="侦探目录（可多次指定）")
    parser.add_argument("--quiet", action="store_true", help="静默模式，不显示实时事件")
    parser.add_argument("--interactive", action="store_true", help="交互式设置")
    parser.add_argument("--create-config", action="store_true", help="创建示例配置文件")
    parser.add_argument("--examples", action="store_true", help="显示使用示例")
    parser.add_argument("--version", action="version", version="ProcDetective 1.0.0")
    
    args = parser.parse_args()
    
    # 显示横幅
    if not args.quiet:
        print_banner()
    
    # 处理特殊选项
    if args.examples:
        print_usage_examples()
        return
    
    if args.create_config:
        create_sample_config()
        return
    
    # 交互式设置
    if args.interactive:
        config = interactive_setup()
    else:
        # 从配置文件加载或创建默认配置
        if args.config and os.path.exists(args.config):
            config = MonitorConfig()
            config.load_from_file(args.config)
            print(f"已加载配置文件: {args.config}")
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
        if check_admin_privileges():
            config.enable_syscall_monitor = True
        else:
            print("警告: 系统调用监控需要管理员权限，已忽略该选项")
    
    if args.capture_packets:
        if check_admin_privileges():
            config.capture_packets = True
        else:
            print("警告: 网络包捕获需要管理员权限，已忽略该选项")
    
    # 权限检查提示
    if not check_admin_privileges() and not args.quiet:
        print("提示: 当前以普通用户权限运行，某些高级功能可能受限")
        print("      以管理员身份运行可获得完整功能")
    
    try:
        # 创建并启动监控器
        monitor = ComprehensiveMonitor(config)
        
        # 信号处理
        import signal
        def signal_handler(signum, frame):
            print(f"\n接收到信号 {signum}，正在停止监控器...")
            monitor.stop()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # 启动监控
        monitor.start()
        
        # 显示监控信息
        if not args.quiet:
            if config.target_process:
                print(f"\n正在监控进程: {config.target_process}")
            elif config.target_pid:
                print(f"\n正在监控PID: {config.target_pid}")
            else:
                print("\n正在监控所有进程活动")
            
            print("按 Ctrl+C 停止监控\n")
        
        # 主循环
        try:
            while monitor.running:
                time.sleep(1)
        except KeyboardInterrupt:
            if not args.quiet:
                print("\n用户中断")
        
    except Exception as e:
        print(format_error_message("监控器运行", e, "主程序执行异常"))
        import traceback
        traceback.print_exc()
    
    finally:
        try:
            monitor.stop()
        except:
            pass


if __name__ == "__main__":
    main()
