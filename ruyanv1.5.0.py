import sys
import os
import subprocess
import winreg
import socket
import psutil
import yara
import json
import datetime
import logging
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QCheckBox, QGroupBox, QLabel, QLineEdit, QTextEdit, QFileDialog, QDateEdit,
    QProgressBar, QTabWidget, QMessageBox
)
from PyQt5.QtCore import QDate, Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont

# 配置日志
logging.basicConfig(
    filename='security_scanner.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 导入Windows API相关模块
try:
    import win32api
    import win32con
    import win32evtlog
    import win32security
    win32_available = True
except ImportError:
    win32_available = False
    logging.warning("pywin32模块未安装，部分功能可能受限")

class ScannerThread(QThread):
    update_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    result_signal = pyqtSignal(dict)

    def __init__(self, functions, everything_path="", start_date=None, end_date=None):
        super().__init__()
        self.functions = functions
        self.everything_path = everything_path
        self.start_date = start_date
        self.end_date = end_date
        self.results = {}
        self.admin_required = False

    def run(self):
        try:
            total_steps = len(self.functions)
            current_step = 0
            
            if "network" in self.functions:
                self.update_signal.emit("正在分析网络连接...")
                self.results['network'] = self.analyze_network()
                current_step += 1
                self.progress_signal.emit(int(current_step / total_steps * 100))
                
            if "startup" in self.functions:
                self.update_signal.emit("正在检查启动项...")
                self.results['startup'] = self.check_startup_items()
                current_step += 1
                self.progress_signal.emit(int(current_step / total_steps * 100))
                
            if "registry" in self.functions:
                self.update_signal.emit("正在扫描注册表隐藏账户...")
                self.results['registry'] = self.scan_hidden_accounts()
                current_step += 1
                self.progress_signal.emit(int(current_step / total_steps * 100))
                
            if "files" in self.functions:
                self.update_signal.emit("正在检查可疑文件...")
                self.results['files'] = self.find_suspicious_files()
                current_step += 1
                self.progress_signal.emit(int(current_step / total_steps * 100))
                
            if "services" in self.functions:
                self.update_signal.emit("正在审查系统服务...")
                self.results['services'] = self.check_services()
                current_step += 1
                self.progress_signal.emit(int(current_step / total_steps * 100))
                
            if "logs" in self.functions:
                self.update_signal.emit("正在分析安全日志...")
                self.results['logs'] = self.analyze_security_logs()
                current_step += 1
                self.progress_signal.emit(int(current_step / total_steps * 100))
                
            if "memory" in self.functions:
                self.update_signal.emit("正在分析内存进程...")
                self.results['memory'] = self.analyze_memory()
                current_step += 1
                self.progress_signal.emit(int(current_step / total_steps * 100))
                
            self.update_signal.emit("扫描完成！")
            self.result_signal.emit(self.results)
            
        except Exception as e:
            self.update_signal.emit(f"错误: {str(e)}")
            logging.error(f"扫描错误: {str(e)}")

    def analyze_network(self):
        """分析网络连接并显示所有远程连接详情"""
        results = {
            "all_connections": [],  # 所有远程连接
            "suspicious": []        # 可疑连接
        }
        
        for conn in psutil.net_connections(kind='inet'):
            # 只处理有远程地址的连接
            if conn.raddr:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                
                # 获取进程信息
                process_name = "未知进程"
                try:
                    if conn.pid:
                        proc = psutil.Process(conn.pid)
                        process_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                
                # 创建连接信息字典
                conn_info = {
                    "pid": conn.pid,
                    "process": process_name,
                    "laddr": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "raddr": f"{remote_ip}:{remote_port}",
                    "status": conn.status,
                    "is_suspicious": False
                }
                
                # 添加到所有连接列表
                results["all_connections"].append(conn_info)
                
                # 检测可疑连接
                is_suspicious = False
                
                # 1. 检测外部IP
                if not remote_ip.startswith(('192.168.', '10.', '127.', '172.16.')):
                    is_suspicious = True
                
                # 2. 检测非常规端口
                if remote_port > 1024 and conn.laddr.port < 1024:
                    is_suspicious = True
                    
                # 3. 检测知名恶意IP范围（示例）
                if remote_ip.startswith(('5.188.', '45.9.', '185.191.')):
                    is_suspicious = True
                    
                if is_suspicious:
                    conn_info["is_suspicious"] = True
                    results["suspicious"].append(conn_info)
        
        # 按目标IP排序
        results["all_connections"].sort(key=lambda x: x["raddr"])
        
        return results

    def check_startup_items(self):
        """检查启动项"""
        startup_items = []
        locations = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
        ]
        
        for hive, subkey in locations:
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            startup_items.append({"name": name, "path": value})
                            i += 1
                        except OSError:
                            break
            except FileNotFoundError:
                continue
                
        return startup_items

    def scan_hidden_accounts(self):
        """扫描注册表隐藏账户"""
        hidden_accounts = []
        try:
            # 尝试打开SAM注册表项（需要管理员权限）
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SAM\SAM\Domains\Account\Users", 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    # 隐藏账户通常以特殊前缀命名（SAM数据库中用户ID前缀）
                    if subkey_name.startswith('00000'):
                        with winreg.OpenKey(key, f"{subkey_name}\\Names") as names_key:
                            j = 0
                            while True:
                                try:
                                    account_name = winreg.EnumKey(names_key, j)
                                    hidden_accounts.append(account_name)
                                    j += 1
                                except OSError:
                                    break
                    i += 1
                except OSError:
                    break
        except PermissionError:
            # 没有管理员权限
            self.admin_required = True
            logging.warning("注册表扫描需要管理员权限")
            return {
                "status": "admin_required",
                "message": "扫描注册表隐藏账户需要管理员权限",
                "manual_steps": self._get_manual_check_steps()
            }
        except Exception as e:
            logging.error(f"注册表扫描错误: {str(e)}")
            # 扫描出错时也提示手动检查
            return {
                "status": "error",
                "message": f"自动扫描失败: {str(e)}，建议手动检查",
                "manual_steps": self._get_manual_check_steps()
            }
    
        if not hidden_accounts:
            # 未发现隐藏账户时返回手动检查步骤
            return {
                "status": "no_hidden",
                "message": "未自动检测到隐藏账户，建议手动检查确认",
                "manual_steps": self._get_manual_check_steps()
            }
        else:
            # 发现隐藏账户时返回结果
            return {
                "status": "found",
                "message": f"检测到 {len(hidden_accounts)} 个可疑隐藏账户",
                "accounts": hidden_accounts
            }

    def _get_manual_check_steps(self):
        """返回手动检查隐藏账户的步骤"""
        return [
            "1. 打开命令提示符（管理员模式）：",
            "   - 按下 Win + R，输入 'cmd'，按住 Ctrl + Shift + Enter 运行",
            "2. 查看所有用户列表（包括隐藏账户）：",
            "   - 输入命令：wmic useraccount get name,status",
            "   - 注意名称异常或不熟悉的账户",
            "3. 通过注册表编辑器检查：",
            "   - 按下 Win + R，输入 'regedit' 打开注册表",
            "   - 导航到路径：HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users",
            "   - 展开左侧节点，查看 'Names' 子项中的账户名称",
            "   - 注意以特殊数字前缀（如 00000xxx）开头的子项",
            "4. 检查本地用户和组：",
            "   - 按下 Win + R，输入 'lusrmgr.msc' 打开用户管理",
            "   - 在 '用户' 列表中查看是否有未识别的账户，右键选择 '属性' 检查详细信息",
            "5. 高级检查命令：",
            "   - 输入命令：net user（查看常规用户）",
            "   - 输入命令：reg query HKLM\\SAM\\SAM /s | findstr /i \"username\"（注册表深度搜索）"
        ]

    def find_suspicious_files(self):
        """使用Everything查找可疑文件"""
        if not self.everything_path or not os.path.exists(self.everything_path):
            return {"error": "Everything路径未配置或无效"}
        
        # 默认搜索最近一个月
        if not self.start_date:
            start_date = QDate.currentDate().addMonths(-1).toString("yyyy/MM/dd")
        else:
            start_date = self.start_date.toString("yyyy/MM/dd")
            
        if not self.end_date:
            end_date = QDate.currentDate().toString("yyyy/MM/dd")
        else:
            end_date = self.end_date.toString("yyyy/MM/dd")
        
        # 构建搜索命令
        search_cmd = f'"{self.everything_path}" -s "c:\\users\\* datemodified:{start_date}-{end_date} ext:exe;dll;bat;ps1;vbs"'
        
        try:
            result = subprocess.run(
                search_cmd,
                capture_output=True,
                text=True,
                shell=True,
                timeout=120
            )
            return {"files": result.stdout.splitlines()}
        except Exception as e:
            return {"error": str(e)}

    def check_services(self):
        """检查可疑服务，增强错误处理"""
        results = {
            "suspicious": [],
            "skipped": []
        }
    
        for service in psutil.win_service_iter():
            service_name = ""
            try:
                service_name = service.name()
                info = service.as_dict()
                binpath = info.get('binpath', '')
            
                # 跳过没有路径的服务
                if not binpath:
                    results["skipped"].append(f"{service_name} (无路径信息)")
                    continue
                
                # 检测非微软服务
                if "microsoft" not in binpath.lower() and \
                "windows" not in binpath.lower() and \
                not binpath.lower().startswith(('c:\\windows\\', 'c:\\program files\\')):
                    results["suspicious"].append({
                        "name": info['name'],
                        "display_name": info['display_name'],
                        "status": info['status'],
                        "binpath": binpath
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                results["skipped"].append(f"{service_name} (权限不足)")
            except Exception as e:
                results["skipped"].append(f"{service_name} (错误: {str(e)}")
    
        # 记录跳过的服务
        if results["skipped"]:
            logging.warning(f"服务扫描跳过 {len(results['skipped'])} 项")
    
        return results

    def analyze_security_logs(self):
        """分析安全日志 - 增强版"""
        # 检查pywin32模块是否可用
        if not win32_available:
            return {
                "error": "安全日志分析需要pywin32模块",
                "manual_steps": [
                    "1. 安装pywin32模块:",
                    "   - 打开命令提示符(管理员)",
                    "   - 输入: pip install pywin32",
                    "2. 重新运行扫描工具"
                ]
            }
            
        # 检查管理员权限
        try:
            # 尝试获取管理员权限信息
            if not win32api.GetUserNameEx(win32con.NameSamCompatible).endswith('-admin'):
                self.admin_required = True
                return {
                    "error": "需要管理员权限",
                    "manual_steps": [
                        "1. 以管理员身份运行此工具",
                        "2. 右键点击程序图标，选择'以管理员身份运行'",
                        "3. 如果使用命令行，请使用管理员权限的命令提示符运行"
                    ]
                }
        except:
            return {"error": "无法验证管理员权限"}
    
        try:
            # 连接到安全事件日志
            hand = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            # 设置时间范围（默认为最近7天）
            start_time = self.start_date.toPyDate() if self.start_date else datetime.datetime.now() - datetime.timedelta(days=7)
            end_time = self.end_date.toPyDate() if self.end_date else datetime.datetime.now()
            
            # 定义关键事件ID
            critical_events = {
                4624: "登录成功",
                4625: "登录失败",
                4648: "使用显式凭证登录",
                4672: "分配了特殊权限",
                4720: "创建用户账户",
                4726: "删除用户账户",
                4738: "用户账户变更",
                4740: "锁定用户账户",
                4768: "Kerberos身份验证票证请求(TGT)",
                4769: "Kerberos服务票证请求(ST)",
                4776: "域控制器尝试验证账户凭据",
                1102: "安全日志已清除"
            }
            
            events_found = []
            total_events = 0
            critical_count = 0
            
            # 读取事件日志
            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                    
                for event in events:
                    total_events += 1
                    event_time = event.TimeGenerated.Format()
                    
                    # 检查事件时间是否在范围内
                    try:
                        event_dt = datetime.datetime.strptime(event_time.split('.')[0], '%Y-%m-%d %H:%M:%S')
                        if event_dt < start_time or event_dt > end_time:
                            continue
                    except:
                        # 如果解析时间失败，仍然处理事件
                        pass
                    
                    event_id = event.EventID & 0xFFFF  # 获取低16位的事件ID
                    
                    # 只记录关键事件
                    if event_id in critical_events:
                        critical_count += 1
                        
                        # 获取事件描述
                        event_desc = ""
                        try:
                            if event.StringInserts:
                                event_desc = " | ".join(str(insert) for insert in event.StringInserts)
                        except:
                            pass
                        
                        # 添加事件信息
                        events_found.append({
                            "time": event_time,
                            "id": event_id,
                            "type": critical_events[event_id],
                            "computer": event.ComputerName,
                            "user": event.Sid,
                            "description": event_desc[:200]  # 截断长描述
                        })
            
            win32evtlog.CloseEventLog(hand)
            
            return {
                "total_events": total_events,
                "critical_events": critical_count,
                "events": events_found
            }
            
        except Exception as e:
            return {"error": f"日志分析失败: {str(e)}"}

    def analyze_memory(self):
        """分析内存进程"""
        suspicious_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'memory_info']):
            try:
                # 获取进程信息字典
                info = proc.info
                # 检测可疑进程 - 隐藏进程或路径可疑的进程
                is_suspicious = False
                reason = ""
                
                # 1. 检测隐藏进程（没有可执行路径）
                if not info['exe']:
                    is_suspicious = True
                    reason = "隐藏进程"
                
                # 2. 检测临时目录中的进程
                elif info['exe'].lower().startswith(('c:\\windows\\temp\\', 
                                                 'c:\\users\\', 
                                                 'c:\\programdata\\', 
                                                 'c:\\windows\\tasks\\')):
                    is_suspicious = True
                    reason = "位于可疑路径"
                
                # 3. 检测非常规位置的系统进程
                elif info['name'] in ('svchost.exe', 'explorer.exe', 'winlogon.exe') and \
                     not info['exe'].lower().startswith('c:\\windows\\system32\\'):
                    is_suspicious = True
                    reason = "系统进程位置异常"
                
                if is_suspicious:
                    suspicious_processes.append({
                        "pid": info['pid'],
                        "name": info['name'],
                        "path": info['exe'],  # 添加进程路径
                        "reason": reason,      # 添加可疑原因
                        "memory": f"{info['memory_info'].rss / (1024 * 1024):.2f} MB"  # 添加内存使用
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
                continue
        return suspicious_processes


class SecurityScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("如烟应急响应安全扫描工具")
        self.setGeometry(100, 100, 900, 700)
        self.init_ui()
        self.everything_path = ""
        self.start_date = None
        self.end_date = None
        self.admin_warning_shown = False

    def init_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        
        # 创建选项卡
        tabs = QTabWidget()
        scan_tab = QWidget()
        config_tab = QWidget()
        
        # 扫描选项卡
        scan_layout = QVBoxLayout()
        
        # 功能选择区域
        group_func = QGroupBox("扫描功能选择")
        func_layout = QVBoxLayout()
        
        self.cb_network = QCheckBox("网络连接分析")
        self.cb_startup = QCheckBox("启动项审查")
        self.cb_registry = QCheckBox("注册表扫描（隐藏账户）*需要管理员")
        self.cb_files = QCheckBox("文件系统检查")
        self.cb_services = QCheckBox("系统服务审查")
        self.cb_logs = QCheckBox("安全日志分析*需要管理员")
        self.cb_memory = QCheckBox("内存分析")
        self.cb_all = QCheckBox("全选")
        self.cb_all.setChecked(True)
        self.cb_all.stateChanged.connect(self.toggle_all)
        
        func_layout.addWidget(self.cb_all)
        func_layout.addWidget(self.cb_network)
        func_layout.addWidget(self.cb_startup)
        func_layout.addWidget(self.cb_registry)
        func_layout.addWidget(self.cb_files)
        func_layout.addWidget(self.cb_services)
        func_layout.addWidget(self.cb_logs)
        func_layout.addWidget(self.cb_memory)
        group_func.setLayout(func_layout)
        
        # 文件搜索配置
        group_file_search = QGroupBox("文件搜索配置")
        file_layout = QVBoxLayout()
        
        # Everything路径配置
        path_layout = QHBoxLayout()
        lbl_path = QLabel("Everything路径:")
        self.entry_path = QLineEdit()
        self.entry_path.setPlaceholderText("C:\\Program Files\\Everything\\Everything.exe")
        btn_browse = QPushButton("浏览...")
        btn_browse.clicked.connect(self.browse_everything)
        path_layout.addWidget(lbl_path)
        path_layout.addWidget(self.entry_path)
        path_layout.addWidget(btn_browse)
        
        # 日期范围
        date_layout = QHBoxLayout()
        lbl_date = QLabel("文件修改时间范围:")
        self.date_start = QDateEdit()
        self.date_start.setCalendarPopup(True)
        self.date_start.setDate(QDate.currentDate().addMonths(-1))
        self.date_end = QDateEdit()
        self.date_end.setCalendarPopup(True)
        self.date_end.setDate(QDate.currentDate())
        date_layout.addWidget(lbl_date)
        date_layout.addWidget(self.date_start)
        date_layout.addWidget(QLabel("到"))
        date_layout.addWidget(self.date_end)
        
        file_layout.addLayout(path_layout)
        file_layout.addLayout(date_layout)
        group_file_search.setLayout(file_layout)
        
        # 控制按钮
        btn_layout = QHBoxLayout()
        self.btn_scan = QPushButton("开始扫描")
        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_report = QPushButton("生成报告")
        self.btn_report.clicked.connect(self.generate_report)
        self.btn_report.setEnabled(False)
        btn_layout.addWidget(self.btn_scan)
        btn_layout.addWidget(self.btn_report)
        
        # 进度条
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        
        # 日志输出
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setFont(QFont("Courier New", 10))
        
        scan_layout.addWidget(group_func)
        scan_layout.addWidget(group_file_search)
        scan_layout.addLayout(btn_layout)
        scan_layout.addWidget(self.progress)
        scan_layout.addWidget(QLabel("扫描日志:"))
        scan_layout.addWidget(self.log_output)
        scan_tab.setLayout(scan_layout)
        
        # 配置选项卡
        config_layout = QVBoxLayout()
        config_layout.addWidget(QLabel("高级配置选项"))
        config_layout.addStretch()
        config_tab.setLayout(config_layout)
        
        # 添加选项卡
        tabs.addTab(scan_tab, "安全扫描")
        tabs.addTab(config_tab, "高级配置")
        
        main_layout.addWidget(tabs)
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # 扫描线程
        self.scanner_thread = None
        self.results = {}

    def toggle_all(self, state):
        check = state == Qt.Checked
        self.cb_network.setChecked(check)
        self.cb_startup.setChecked(check)
        self.cb_registry.setChecked(check)
        self.cb_files.setChecked(check)
        self.cb_services.setChecked(check)
        self.cb_logs.setChecked(check)
        self.cb_memory.setChecked(check)

    def browse_everything(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "选择Everything.exe",
            "C:\\Program Files\\Everything",
            "Executable Files (*.exe)"
        )
        if path:
            self.entry_path.setText(path)

    def start_scan(self):
        """开始扫描"""
        # 获取选中的功能
        functions = []
        if self.cb_network.isChecked(): functions.append("network")
        if self.cb_startup.isChecked(): functions.append("startup")
        if self.cb_registry.isChecked(): functions.append("registry")
        if self.cb_files.isChecked(): functions.append("files")
        if self.cb_services.isChecked(): functions.append("services")
        if self.cb_logs.isChecked(): functions.append("logs")
        if self.cb_memory.isChecked(): functions.append("memory")
        
        if not functions:
            QMessageBox.warning(self, "警告", "请至少选择一个扫描功能！")
            return
        
        # 获取Everything路径和日期
        self.everything_path = self.entry_path.text().strip()
        self.start_date = self.date_start.date()
        self.end_date = self.date_end.date()
        
        # 禁用按钮
        self.btn_scan.setEnabled(False)
        self.log_output.clear()
        self.progress.setValue(0)
        
        # 启动扫描线程
        self.scanner_thread = ScannerThread(
            functions,
            self.everything_path,
            self.start_date,
            self.end_date
        )
        self.scanner_thread.update_signal.connect(self.update_log)
        self.scanner_thread.progress_signal.connect(self.update_progress)
        self.scanner_thread.result_signal.connect(self.scan_completed)
        self.scanner_thread.start()

    def update_log(self, message):
        self.log_output.append(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {message}")

    def update_progress(self, value):
        self.progress.setValue(value)

    def scan_completed(self, results):
        self.results = results
        self.btn_scan.setEnabled(True)
        self.btn_report.setEnabled(True)
        self.log_output.append("\n扫描完成！点击\"生成报告\"按钮查看结果")
        self.progress.setValue(100)
        
        # 显示管理员权限警告
        if not self.admin_warning_shown:
            self.log_output.append("\n注意: 某些功能需要管理员权限才能完全运行")
            self.log_output.append("如果扫描结果不完整，请尝试以管理员身份运行此工具")
            self.admin_warning_shown = True

    def generate_report(self):
        """生成安全报告"""
        if not self.results:
            QMessageBox.warning(self, "警告", "没有可用的扫描结果！")
            return
        
        report = "===== 安全扫描报告 =====\n"
        report += f"生成时间: {datetime.datetime.now()}\n\n"
        
        if 'network' in self.results:
            report += "=== 网络连接分析 ===\n"
            
            # 显示所有远程连接
            report += f"所有远程连接 ({len(self.results['network']['all_connections'])}):\n"
            for i, conn in enumerate(self.results['network']['all_connections'], 1):
                suspicious_marker = " [可疑]" if conn["is_suspicious"] else ""
                report += f"{i}. PID: {conn['pid']} ({conn['process']}), "
                report += f"本地: {conn['laddr']}, 远程: {conn['raddr']}{suspicious_marker}\n"
            
            # 单独显示可疑连接
            if self.results['network']['suspicious']:
                report += f"\n可疑远程连接 ({len(self.results['network']['suspicious'])}):\n"
                for i, conn in enumerate(self.results['network']['suspicious'], 1):
                    report += f"{i}. PID: {conn['pid']} ({conn['process']}), "
                    report += f"本地: {conn['laddr']}, 远程: {conn['raddr']}\n"
            else:
                report += "\n未检测到可疑远程连接\n"
            
            report += "\n"
        
        if 'startup' in self.results:
            report += "=== 启动项审查 ===\n"
            report += f"发现启动项: {len(self.results['startup'])}\n"
            for item in self.results['startup']:
                report += f"{item['name']}: {item['path']}\n"
            report += "\n"
        
        if 'registry' in self.results:
            reg_result = self.results['registry']
            report += "=== 注册表扫描 (隐藏账户) ===\n"
            report += f"结果: {reg_result['message']}\n"
            
            if reg_result['status'] == 'found':
                report += f"发现隐藏账户: {len(reg_result['accounts'])}\n"
                for account in reg_result['accounts']:
                    report += f"- {account}\n"
            elif reg_result['status'] == 'admin_required' or reg_result['status'] == 'error' or reg_result['status'] == 'no_hidden':
                # 显示手动检查步骤
                report += "\n手动检查步骤:\n"
                for step in reg_result['manual_steps']:
                    report += f"{step}\n"
            
            report += "\n"
        
        if 'files' in self.results:
            report += "=== 文件系统检查 ===\n"
            if 'error' in self.results['files']:
                report += f"错误: {self.results['files']['error']}\n"
            else:
                files = self.results['files'].get('files', [])
                report += f"发现可疑文件: {len(files)}\n"
                for file in files[:50]:  # 最多显示50个
                    report += f"- {file}\n"
            report += "\n"
        
        if 'services' in self.results:
            report += "=== 系统服务审查 ===\n"
            report += f"发现可疑服务: {len(self.results['services']['suspicious'])}\n"
            for service in self.results['services']['suspicious']:
                report += f"{service['name']} ({service['display_name']}): {service['binpath']}\n"
            
            if self.results['services']['skipped']:
                report += f"\n跳过 {len(self.results['services']['skipped'])} 个服务 (权限不足或无法访问)\n"
            
            report += "\n"
        
        if 'memory' in self.results:
            report += "=== 内存分析 ===\n"
            report += f"发现可疑进程: {len(self.results['memory'])}\n"
            for proc in self.results['memory']:
                # 显示PID、进程名、路径、内存使用和可疑原因
                report += (f"PID: {proc['pid']}, "
                          f"进程名: {proc['name']}, "
                          f"路径: {proc['path']}, "
                          f"内存: {proc['memory']}, "
                          f"原因: {proc['reason']}\n")
            report += "\n"
        
        if 'logs' in self.results:
            report += "=== 安全日志分析 ===\n"
            
            if 'error' in self.results['logs']:
                report += f"错误: {self.results['logs']['error']}\n"
                
                # 显示手动步骤（如果有）
                if 'manual_steps' in self.results['logs']:
                    report += "\n解决方案:\n"
                    for step in self.results['logs']['manual_steps']:
                        report += f"{step}\n"
            else:
                report += f"扫描日志总数: {self.results['logs']['total_events']}\n"
                report += f"发现关键安全事件: {self.results['logs']['critical_events']}\n\n"
                
                if self.results['logs']['events']:
                    report += "关键事件详情:\n"
                    for event in self.results['logs']['events']:
                        report += (f"[{event['time']}] 事件ID: {event['id']} ({event['type']})\n"
                                  f"计算机: {event['computer']} | 用户: {event['user']}\n"
                                  f"描述: {event['description']}\n\n")
                else:
                    report += "未发现关键安全事件\n"
            
            report += "\n"
        
        # 添加管理员权限提示
        report += "=== 重要提示 ===\n"
        report += "1. 注册表扫描和安全日志分析需要管理员权限\n"
        report += "2. 如果扫描结果不完整，请尝试以管理员身份重新运行此工具\n"
        report += "3. 某些安全设置可能阻止了部分扫描功能\n"
        
        # 显示报告
        self.log_output.clear()
        self.log_output.append(report)
        
        # 保存报告到文件
        try:
            with open("security_report.txt", "w", encoding="utf-8") as f:
                f.write(report)
            self.log_output.append("\n报告已保存到 security_report.txt")
        except Exception as e:
            self.log_output.append(f"\n保存报告失败: {str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecurityScannerGUI()
    window.show()
    sys.exit(app.exec_())