# ProcDetective

一个功能强大的Python进程行为监控工具，类似于微软的Process Monitor，但提供了更多的自定义功能和编程接口。

## 功能特性

### 🔍 多维度监控
- **进程监控**: 监控进程创建、退出、线程操作
- **文件系统监控**: 监控文件和目录的创建、删除、修改、访问
- **注册表监控**: 监控Windows注册表的读写操作
- **网络监控**: 监控网络连接的建立、断开和数据传输

### 🎯 灵活过滤
- 按进程名过滤
- 按事件类型过滤
- 按操作类型过滤
- 按路径模式过滤

### 📊 详细信息
- 实时事件显示
- 详细的事件信息记录
- 支持事件导出到文件
- 可配置的事件数量限制

## 系统要求

- Python 3.7+
- Windows 操作系统（注册表监控功能）
- 管理员权限（推荐，用于完整的系统监控）

## 安装

1. 克隆或下载项目文件
2. 安装依赖包：
```bash
pip install -r requirements.txt
```

## 使用方法

### 基本用法

```bash
# 启动完整监控（所有类型）
python procmon.py

# 监控指定进程
python procmon.py -p notepad.exe

# 只监控文件系统活动
python procmon.py -t file

# 启用详细监控模式
python procmon.py --detailed
```

### 命令行参数

| 参数 | 说明 |
|------|------|
| `-p, --process` | 监控指定进程名 |
| `-t, --type` | 监控指定类型的事件 (process/file/registry/network) |
| `-o, --output` | 输出文件路径 |
| `--max-events` | 最大事件数量 (默认: 10000) |
| `--watch-path` | 监控指定路径（文件系统监控） |
| `--detailed` | 启用详细监控模式 |
| `--no-process` | 禁用进程监控 |
| `--no-file` | 禁用文件系统监控 |
| `--no-registry` | 禁用注册表监控 |
| `--no-network` | 禁用网络监控 |

### 使用示例

#### 1. 监控特定进程的所有活动
```bash
python procmon.py -p chrome.exe --detailed
```

#### 2. 只监控文件系统活动并保存到文件
```bash
python procmon.py -t file -o filesystem_log.txt
```

#### 3. 监控特定目录的文件变化
```bash
python procmon.py -t file --watch-path "C:\Users\YourName\Documents"
```

#### 4. 监控网络活动（排除其他类型）
```bash
python procmon.py --no-process --no-file --no-registry
```

#### 5. 监控注册表变化
```bash
python procmon.py -t registry --detailed
```

## 输出格式

监控输出包含以下信息：
- **时间戳**: 事件发生的精确时间
- **进程名**: 执行操作的进程名称
- **进程ID**: 进程的PID
- **操作类型**: 具体的操作类型（如FileRead、ProcessCreate等）
- **路径**: 相关的文件路径、注册表键或网络地址
- **结果**: 操作结果（SUCCESS/FAILED等）

示例输出：
```
Time            Process Name    PID     Operation       Path                    Result
--------------------------------------------------------------------------------------------------------
14:30:25.123    notepad.exe     1234    FileRead        C:\temp\test.txt        SUCCESS
14:30:25.456    chrome.exe      5678    NetConnect      TCP 192.168.1.100:443  SUCCESS
14:30:25.789    explorer.exe    9012    RegRead         HKEY_CURRENT_USER\...   SUCCESS
```

## 模块说明

### 核心模块
- `procmon.py`: 主程序和核心框架
- `process_monitor.py`: 进程监控实现
- `filesystem_monitor.py`: 文件系统监控实现
- `registry_monitor.py`: 注册表监控实现
- `network_monitor.py`: 网络监控实现

### 架构设计
- **BaseMonitor**: 监控器基类，定义统一接口
- **EventFilter**: 事件过滤器，支持多种过滤条件
- **EventFormatter**: 事件格式化器，统一输出格式
- **MonitorEvent**: 事件数据结构，包含完整的事件信息

## 性能考虑

- 默认限制最大事件数量为10,000个，避免内存溢出
- 文件系统监控排除临时文件和系统文件
- 网络监控设置流量阈值，避免过多的低级别事件
- 注册表监控限制扫描深度，提高性能

## 限制和注意事项

1. **权限要求**: 某些系统级监控需要管理员权限
2. **平台限制**: 注册表监控仅在Windows系统上可用
3. **性能影响**: 大量的文件系统活动可能影响系统性能
4. **依赖库**: 需要安装psutil和watchdog库

## 故障排除

### 常见问题

**Q: 提示"psutil库不可用"**
A: 运行 `pip install psutil` 安装依赖

**Q: 文件系统监控不工作**
A: 确保安装了watchdog库：`pip install watchdog`

**Q: 注册表监控在非Windows系统上报错**
A: 注册表监控仅支持Windows系统，在其他系统上会自动禁用

**Q: 监控输出过多**
A: 使用过滤参数限制监控范围，如 `-p 进程名` 或 `-t 类型`

## 开发和扩展

### 添加新的监控器
1. 继承 `BaseMonitor` 类
2. 实现 `_monitor_loop` 方法
3. 使用 `_emit_event` 发送事件
4. 在主程序中注册监控器

### 自定义事件过滤
```python
from procmon import EventFilter, EventType

# 创建自定义过滤器
event_filter = EventFilter()
event_filter.add_process_filter("myapp.exe")
event_filter.add_event_type_filter(EventType.FILE_SYSTEM)
```

## 许可证

本项目采用MIT许可证，详见LICENSE文件。

## 贡献

欢迎提交Issue和Pull Request来改进这个项目。

## 更新日志

### v1.0.0
- 初始版本发布
- 支持进程、文件系统、注册表、网络监控
- 实现事件过滤和格式化
- 提供命令行界面
