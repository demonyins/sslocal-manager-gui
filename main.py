import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import json
import subprocess
import threading
import sys
import os
import time
import datetime  # For scheduled tasks and logging
import requests  # For downloading Geo files
import socket  # For server connectivity test
import re  # For parsing plugin_opts
import zipfile  # For unzipping downloaded files
import tarfile  # For .tar.gz files
import io  # For handling download streams
import shutil  # For moving files

# 仅在 Windows 系统上导入 winreg 模块，用于修改系统代理和开机启动项
if sys.platform == "win32":
    import winreg
    import ctypes  # For SendMessageTimeoutW


class ToolTip:
    """
    创建TTK控件的工具提示。
    """

    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event=None):
        x = self.widget.winfo_rootx() + self.widget.winfo_width() // 2
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5

        self.tooltip_window = tk.Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")

        label = ttk.Label(self.tooltip_window, text=self.text, background="#FFFFE0", relief="solid", borderwidth=1,
                          padding=3)
        label.pack()

    def hide_tooltip(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
        self.tooltip_window = None


class SettingsWindow(tk.Toplevel):
    """
    选项设置窗口
    """
    REG_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
    APP_NAME_FOR_REGISTRY = "SSLocalConfiguratorGUI"

    def __init__(self, parent):
        super().__init__(parent)
        self.transient(parent)
        self.grab_set()
        self.parent = parent
        self.title("选项设置")
        self.geometry("750x650")

        self.config_vars = {}

        self._create_settings_widgets()
        self._load_settings_from_parent()

        self.protocol("WM_DELETE_WINDOW", self._cancel_settings)

    def _create_settings_widgets(self):
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill="both", expand=True)

        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill="both", expand=True, pady=5)

        tab_paths = ttk.Frame(notebook, padding=10)
        notebook.add(tab_paths, text="程序与路径")

        entry_width = 50
        button_width = 10

        sslocal_path_group = ttk.Frame(tab_paths, padding=(0, 0, 0, 5))
        sslocal_path_group.pack(fill="x", pady=5)
        ttk.Label(sslocal_path_group, text="sslocal.exe 路径:").pack(side="top", anchor="w")
        self.config_vars["sslocal_executable_path_gui"] = tk.StringVar()
        sslocal_entry_frame = ttk.Frame(sslocal_path_group)
        sslocal_entry_frame.pack(fill="x", expand=True)
        sslocal_entry = ttk.Entry(sslocal_entry_frame, textvariable=self.config_vars["sslocal_executable_path_gui"],
                                  width=entry_width)
        sslocal_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        ToolTip(sslocal_entry, "指定 sslocal.exe 文件的完整路径。")
        ttk.Button(sslocal_entry_frame, text="浏览...", width=button_width + 2,
                   command=lambda: self._browse_file("sslocal_executable_path_gui", "选择 sslocal.exe",
                                                     (("可执行文件", "*.exe"), ("所有文件", "*.*")))).pack(side="left")
        ttk.Button(sslocal_entry_frame, text="下载", width=button_width,
                   command=lambda: self.parent._download_executable_interactive("sslocal")).pack(side="left",
                                                                                                 padx=(2, 0))

        v2ray_plugin_path_group = ttk.Frame(tab_paths, padding=(0, 5, 0, 5))
        v2ray_plugin_path_group.pack(fill="x", pady=5)
        ttk.Label(v2ray_plugin_path_group, text="v2ray-plugin 路径:").pack(side="top", anchor="w")
        self.config_vars["v2ray_plugin_path_gui"] = tk.StringVar()
        v2ray_plugin_entry_frame = ttk.Frame(v2ray_plugin_path_group)
        v2ray_plugin_entry_frame.pack(fill="x", expand=True)
        v2ray_plugin_entry = ttk.Entry(v2ray_plugin_entry_frame, textvariable=self.config_vars["v2ray_plugin_path_gui"],
                                       width=entry_width)
        v2ray_plugin_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        ToolTip(v2ray_plugin_entry, "指定 v2ray-plugin 可执行文件的完整路径。")
        ttk.Button(v2ray_plugin_entry_frame, text="浏览...", width=button_width + 2,
                   command=lambda: self._browse_file("v2ray_plugin_path_gui", "选择 v2ray-plugin",
                                                     (("可执行文件", "*.exe;v2ray-plugin*"),
                                                      ("所有文件", "*.*")))).pack(side="left")
        ttk.Button(v2ray_plugin_entry_frame, text="下载", width=button_width,
                   command=lambda: self.parent._download_executable_interactive("v2ray-plugin")).pack(side="left",
                                                                                                      padx=(2, 0))

        xray_plugin_path_group = ttk.Frame(tab_paths, padding=(0, 5, 0, 5))
        xray_plugin_path_group.pack(fill="x", pady=5)
        ttk.Label(xray_plugin_path_group, text="xray-plugin 路径:").pack(side="top", anchor="w")
        self.config_vars["xray_plugin_path_gui"] = tk.StringVar()
        xray_plugin_entry_frame = ttk.Frame(xray_plugin_path_group)
        xray_plugin_entry_frame.pack(fill="x", expand=True)
        xray_plugin_entry = ttk.Entry(xray_plugin_entry_frame, textvariable=self.config_vars["xray_plugin_path_gui"],
                                      width=entry_width)
        xray_plugin_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        ToolTip(xray_plugin_entry, "指定 xray-plugin 可执行文件的完整路径。")
        ttk.Button(xray_plugin_entry_frame, text="浏览...", width=button_width + 2,
                   command=lambda: self._browse_file("xray_plugin_path_gui", "选择 xray-plugin",
                                                     (("可执行文件", "*.exe;xray-plugin*"), ("所有文件", "*.*")))).pack(
            side="left")
        ttk.Button(xray_plugin_entry_frame, text="下载", width=button_width,
                   command=lambda: self.parent._download_executable_interactive("xray-plugin")).pack(side="left",
                                                                                                     padx=(2, 0))

        acl_path_group = ttk.Frame(tab_paths, padding=(0, 5, 0, 5))
        acl_path_group.pack(fill="x", pady=5)
        ttk.Label(acl_path_group, text="ACL 文件路径 (当前使用):").pack(side="top", anchor="w")
        acl_entry_frame = ttk.Frame(acl_path_group)
        acl_entry_frame.pack(fill="x", expand=True)
        self.config_vars["acl_file_path_gui"] = tk.StringVar()
        acl_entry = ttk.Entry(acl_entry_frame, textvariable=self.config_vars["acl_file_path_gui"], width=entry_width)
        acl_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        ToolTip(acl_entry, "指定用于 shadowsocks-rust 的 ACL 规则文件路径。\n智能分流模式需要此文件。")
        ttk.Button(acl_entry_frame, text="浏览...", width=button_width + 2,
                   command=lambda: self._browse_file("acl_file_path_gui", "选择 ACL 文件",
                                                     (("ACL 文件", "*.acl;*.txt;*.json"), ("所有文件", "*.*")))).pack(
            side="left")

        acl_url_group = ttk.Frame(tab_paths, padding=(0, 5, 0, 5))
        acl_url_group.pack(fill="x", pady=5)
        ttk.Label(acl_url_group, text="ACL 下载 URL (可选):").pack(side="top", anchor="w")
        acl_url_entry_frame = ttk.Frame(acl_url_group)
        acl_url_entry_frame.pack(fill="x", expand=True)
        self.config_vars["acl_download_url_gui"] = tk.StringVar()
        acl_url_entry = ttk.Entry(acl_url_entry_frame, textvariable=self.config_vars["acl_download_url_gui"],
                                  width=entry_width)
        acl_url_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        ToolTip(acl_url_entry, "输入 ACL 规则文件的下载链接。")
        ttk.Button(acl_url_entry_frame, text="📥 下载 ACL", width=button_width + 2,
                   command=self.parent._download_acl_file_from_gui_url).pack(side="left")

        acl_geo_actions_frame = ttk.Frame(tab_paths, padding=(0, 10, 0, 5))
        acl_geo_actions_frame.pack(fill="x", pady=5, anchor="w")
        ttk.Button(acl_geo_actions_frame, text="⚙️ 生成示例 ACL 文件", width=button_width + 8,
                   command=self.parent._generate_example_acl_file).pack(side="left", padx=5)
        ttk.Button(acl_geo_actions_frame, text="🔄 更新 Geo 数据", width=button_width + 8,
                   command=lambda: threading.Thread(target=self.parent._update_geo_data, args=(True, False),
                                                    daemon=True).start()).pack(side="left", padx=5)

        tab_startup = ttk.Frame(notebook, padding=10)
        notebook.add(tab_startup, text="启动选项")
        self.config_vars["autostart_program_on_boot_gui"] = tk.BooleanVar()
        cb_autostart_program = ttk.Checkbutton(tab_startup, text="开机时自动启动本程序 (可能需要管理员权限)",
                                               variable=self.config_vars["autostart_program_on_boot_gui"])
        cb_autostart_program.pack(anchor="w", pady=5)
        ToolTip(cb_autostart_program, "勾选后，程序将尝试设置开机自启。\n此操作会修改注册表，可能需要管理员权限。")
        self.config_vars["autostart_proxy_on_program_launch_gui"] = tk.BooleanVar()
        cb_autostart_proxy = ttk.Checkbutton(tab_startup, text="程序启动时自动启动代理服务",
                                             variable=self.config_vars["autostart_proxy_on_program_launch_gui"])
        cb_autostart_proxy.pack(anchor="w", pady=5)
        ToolTip(cb_autostart_proxy, "勾选后，每次启动本配置器时，会自动尝试启动 SSLocal 代理服务。")

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x", pady=(10, 0))
        ttk.Button(button_frame, text="保存设置", command=self._save_and_close, width=15).pack(side="right", padx=5)
        ttk.Button(button_frame, text="取消", command=self._cancel_settings, width=15).pack(side="right", padx=5)

    def _browse_file(self, config_var_key, title, filetypes):
        current_path = self.config_vars[config_var_key].get()
        initial_dir = os.path.dirname(current_path) if current_path and os.path.isdir(
            os.path.dirname(current_path)) else self.parent.script_dir
        filepath = filedialog.askopenfilename(parent=self, title=title, initialdir=initial_dir, filetypes=filetypes)
        if filepath: 
            self.config_vars[config_var_key].set(filepath)

    def _load_settings_from_parent(self):
        for key, parent_var in self.parent.config_vars.items():
            if key in self.config_vars:
                if isinstance(self.config_vars[key], tk.BooleanVar):
                    self.config_vars[key].set(parent_var.get())
                else:
                    self.config_vars[key].set(str(parent_var.get()))
        for key, default_val in self.parent.default_config.items():
            if key in self.config_vars and not self.parent.config_vars[key].get():
                if isinstance(self.config_vars[key], tk.BooleanVar):
                    self.config_vars[key].set(bool(default_val))
                else:
                    self.config_vars[key].set(str(default_val))

    def _set_startup_registry(self, enable):
        if sys.platform != "win32": return True
        if getattr(sys, 'frozen', False):
            app_path = sys.executable
        else:
            python_exe = sys.executable
            script_path = os.path.abspath(sys.argv[0]) 
            app_path = f'"{python_exe}" "{script_path}"'
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.REG_RUN_KEY, 0, winreg.KEY_WRITE)
            if enable:
                winreg.SetValueEx(key, self.APP_NAME_FOR_REGISTRY, 0, winreg.REG_SZ, app_path)
                self.parent._log_gui_thread(f"已尝试添加 '{self.APP_NAME_FOR_REGISTRY}' 到开机启动项。")
            else:
                try:
                    winreg.DeleteValue(key, self.APP_NAME_FOR_REGISTRY)
                    self.parent._log_gui_thread(
                        f"已尝试从开机启动项中移除 '{self.APP_NAME_FOR_REGISTRY}'。")
                except FileNotFoundError:
                    self.parent._log_gui_thread(f"开机启动项 '{self.APP_NAME_FOR_REGISTRY}' 未找到，无需移除。")
            winreg.CloseKey(key)
            return True
        except PermissionError:
            self.parent._log_gui_thread("设置开机启动失败: 权限不足。", is_error=True)
            messagebox.showerror("权限错误", "设置开机启动失败: 权限不足。", parent=self)
            return False
        except Exception as e:
            self.parent._log_gui_thread(f"设置开机启动时发生错误: {e}", is_error=True)
            messagebox.showerror("注册表错误", f"设置开机启动时发生错误:\n{e}", parent=self)
            return False

    def _save_and_close(self):
        autostart_program_enabled = self.config_vars["autostart_program_on_boot_gui"].get()
        current_autostart_state = False
        if sys.platform == "win32":
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.REG_RUN_KEY, 0, winreg.KEY_READ)
                winreg.QueryValueEx(key, self.APP_NAME_FOR_REGISTRY)
                current_autostart_state = True
                winreg.CloseKey(key)
            except FileNotFoundError:
                current_autostart_state = False
            except Exception:
                pass
        registry_changed_successfully = True
        if autostart_program_enabled != current_autostart_state:
            registry_changed_successfully = self._set_startup_registry(autostart_program_enabled)
            if not registry_changed_successfully: self.config_vars["autostart_program_on_boot_gui"].set(
                current_autostart_state)
        for key, settings_var in self.config_vars.items():
            if key in self.parent.config_vars:
                if isinstance(self.parent.config_vars[key], tk.BooleanVar):
                    self.parent.config_vars[key].set(settings_var.get())
                else:
                    self.parent.config_vars[key].set(str(settings_var.get()))
        self.parent._save_config()
        if registry_changed_successfully or autostart_program_enabled == current_autostart_state:
            self.parent._log_gui_thread("选项设置已保存。")
        else:
            self.parent._log_gui_thread("选项设置部分已保存，但开机启动项设置失败。", is_error=True)
        self.destroy()

    def _cancel_settings(self):
        self.parent._log_gui_thread("选项设置更改已取消.")
        self.destroy()


class SSLConfigurator(tk.Tk):
    GEOIP_URLS = ["https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
                  "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"]
    GEOSITE_URLS = ["https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
                    "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"]

    EXECUTABLES_CONFIG = {
        "sslocal": {
            "repo": "shadowsocks/shadowsocks-rust",
            "api_url_template": "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest",
            "platform_filename_pattern": r"shadowsocks-v\d+\.\d+\.\d+(\.\d+)?\.x86_64-pc-windows-msvc\.zip",
            # Updated pattern for versions like v1.2.3.4
            "exe_name_in_archive": "sslocal.exe",
            "target_exe_filename": "sslocal.exe",
            "gui_var_key": "sslocal_executable_path_gui"
        },
        "v2ray-plugin": {
            "repo": "shadowsocks/v2ray-plugin",
            "api_url_template": "https://api.github.com/repos/teddysun/v2ray-plugin/releases/latest",
            "platform_filename_pattern": r"v2ray-plugin-windows-amd64-v\d+\.\d+\.\d+\.(zip|tar\.gz)$",
            "exe_name_in_archive": "v2ray-plugin_windows_amd64.exe",
            "target_exe_filename": "v2ray-plugin.exe",
            "gui_var_key": "v2ray_plugin_path_gui"
        },
        "xray-plugin": {
            "repo": "teddysun/xray-plugin",
            "api_url_template": "https://api.github.com/repos/teddysun/xray-plugin/releases/latest",
            "platform_filename_pattern": r"xray-plugin-windows-amd64-v\d+\.\d+\.\d+\.(zip|tar\.gz)$",
            "exe_name_in_archive": "xray-plugin_windows_amd64.exe",
            "target_exe_filename": "xray-plugin.exe",
            "gui_var_key": "xray_plugin_path_gui"
        }
    }
    EXAMPLE_ACL_CONTENT = """\
# shadowsocks-rust ACL 规则文件示例
ip_cidr:127.0.0.0/8 direct
ip_cidr:10.0.0.0/8 direct
ip_cidr:172.16.0.0/12 direct
ip_cidr:192.168.0.0/16 direct
ip_cidr:::1/128 direct
geoip:cn direct
geosite:cn direct
geosite:apple-cn direct
geosite:microsoft-cn direct
geosite:google proxy
geosite:youtube proxy
geosite:facebook proxy
geosite:twitter proxy
"""

    def __init__(self):
        super().__init__()
        self.title("SSLocal 配置器 - 专业版 v3.3 (下载修复)")
        self.geometry("850x650")

        style = ttk.Style(self)
        available_themes = style.theme_names()
        if "vista" in available_themes:
            style.theme_use("vista")
        elif "clam" in available_themes:
            style.theme_use("clam")
        elif "xpnative" in available_themes:
            style.theme_use("xpnative")
        elif "alt" in available_themes:
            style.theme_use("alt")

        self.sslocal_process = None
        self.log_thread = None
        self.proxy_enabled_by_app = False
        self.config_file = "config.json"
        self.config_vars = {}
        self.script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        self.geoip_file_name = "geoip.dat"
        self.geosite_file_name = "geosite.dat"
        self._last_scheduled_geo_update = None
        self.default_config = {
            "sslocal_executable_path_gui": os.path.join(self.script_dir, "sslocal.exe"),
            "v2ray_plugin_path_gui": os.path.join(self.script_dir, "v2ray-plugin.exe"),
            "xray_plugin_path_gui": os.path.join(self.script_dir, "xray-plugin.exe"),
            "local_address": "127.0.0.1", "local_port": 1080, "server": "your.server.domain", "server_port": 443,
            "method": "2022-blake3-aes-128-gcm", "password": "zKP3uN0DwI91Ae6KZ6q0wg==", "plugin": "xray-plugin",
            "plugin_opts": "tls;mode=grpc;host=your.server.domain;path=/0748cfcc-3556-11f0-8703-57aef3718350",
            "mode": "tcp_and_udp", "fast_open": True, "timeout": 300, "nameserver": "8.8.8.8",
            "acl_file_path_gui": "", "acl_download_url_gui": "",
            "proxy_mode_selection_gui": "全局代理 (Global Proxy)",
            "autostart_program_on_boot_gui": False, "autostart_proxy_on_program_launch_gui": False,
        }
        for key, value in self.default_config.items():
            if isinstance(value, bool):
                self.config_vars[key] = tk.BooleanVar(value=value)
            else:
                self.config_vars[key] = tk.StringVar(value=str(value))
        self.current_config = {}
        self.status_bar_text = tk.StringVar()
        self.status_bar_text.set("状态: 未启动")
        self._create_main_widgets()
        self._load_config()
        self.protocol("WM_DELETE_WINDOW", self._on_closing)
        self.after(100, self._auto_start_if_needed)
        self.after(1000, self._check_scheduled_tasks)

    def _open_settings_window(self):
        if hasattr(self, 'settings_win') and self.settings_win and self.settings_win.winfo_exists():
            self.settings_win.lift()
            self.settings_win.focus_set()
        else:
            self.settings_win = SettingsWindow(self)
            self.settings_win.focus_set()

    def _auto_start_if_needed(self):
        if self.config_vars["autostart_proxy_on_program_launch_gui"].get():
            self._log_gui_thread("检测到“程序启动时自动启动代理”已启用，尝试启动 SSLocal...")
            self._start_sslocal()
        else:
            self._log_gui_thread("自动启动代理已禁用。请手动点击“启动 SSLocal”。")
        if self.config_vars["autostart_program_on_boot_gui"].get() and sys.platform == "win32":
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, SettingsWindow.REG_RUN_KEY, 0, winreg.KEY_READ)
                winreg.QueryValueEx(key, SettingsWindow.APP_NAME_FOR_REGISTRY)
                winreg.CloseKey(key)
                self._log_gui_thread("提示: '开机启动程序' 已在设置中启用并已配置到注册表。")
            except FileNotFoundError:
                self._log_gui_thread("提示: '开机启动程序' 已在设置中启用，但未在注册表中找到。")
            except Exception as e:
                self._log_gui_thread(f"检查开机启动项时出错: {e}", is_error=True)

    def _check_scheduled_tasks(self):
        now = datetime.datetime.now()
        if (now.hour == 9 and now.minute == 0) or (now.hour == 11 and now.minute == 0):
            if self._last_scheduled_geo_update is None or (now - self._last_scheduled_geo_update).total_seconds() > 120:
                self._log_gui_thread(f"计划任务: 更新 Geo 数据 ({now.hour}:{now.minute:02d})")
                threading.Thread(target=self._update_geo_data, args=(False, True), daemon=True).start()
                self._last_scheduled_geo_update = now
        self.after(60000, self._check_scheduled_tasks)

    def _create_widget_in_cell(self, parent, row, col, label_text, config_key, widget_type,
                               widget_options=None, entry_width=None, combo_width=None,
                               tooltip_text=None, is_password=False, trace_callback=None,
                               colspan=1, rowspan=1, sticky="nsew", label_width=None):
        cell_frame = ttk.Frame(parent)
        cell_frame.grid(row=row, column=col, rowspan=rowspan, columnspan=colspan, sticky=sticky, padx=3, pady=2)
        lbl_options = {"anchor": "w", "padx": 2, "pady": (2, 0)}
        if label_width:
            lbl = ttk.Label(cell_frame, text=label_text, width=label_width, anchor="w")
        else:
            lbl = ttk.Label(cell_frame, text=label_text)
        lbl.pack(**lbl_options)
        widget = None
        var = self.config_vars[config_key]
        if widget_type == "entry":
            widget = ttk.Entry(cell_frame, textvariable=var, width=entry_width or 20, show="*" if is_password else None)
        elif widget_type == "combo":
            widget = ttk.Combobox(cell_frame, textvariable=var, values=widget_options, width=combo_width or 18,
                                  state="readonly")
        elif widget_type == "checkbutton":
            widget = ttk.Checkbutton(cell_frame, variable=var, text=label_text)
            lbl.pack_forget()
            widget.pack(anchor="w", padx=2, pady=(2, 2))
            if tooltip_text: ToolTip(widget, tooltip_text); return cell_frame, widget
        if widget:
            widget.pack(fill="x", expand=True, padx=2, pady=(0, 2))
            if tooltip_text: ToolTip(widget, tooltip_text)
            if trace_callback and widget_type == "entry": var.trace_add("write", trace_callback)
        return cell_frame, widget

    def _on_server_address_changed(self, *args):
        new_server_address = self.config_vars["server"].get()
        current_plugin_opts = self.config_vars["plugin_opts"].get()
        if not new_server_address: return
        new_plugin_opts, n = re.subn(r'(host=)[^;]+(;?)', rf'\g<1>{new_server_address}\g<2>', current_plugin_opts)
        if n == 0:
            if 'tls;' in current_plugin_opts and 'host=' not in current_plugin_opts:
                parts = current_plugin_opts.split('tls;', 1)
                new_plugin_opts = f"{parts[0]}tls;host={new_server_address};{parts[1] if len(parts) > 1 else ''}".rstrip(
                    ';')
            elif not current_plugin_opts and self.config_vars["plugin"].get():
                new_plugin_opts = f"tls;host={new_server_address};"
        if new_plugin_opts != current_plugin_opts:
            self.config_vars["plugin_opts"].set(new_plugin_opts)
            self._log_gui_thread(f"插件选项 host 已更新: {new_server_address}")

    def _create_main_widgets(self):
        main_container = ttk.Frame(self, padding=(10, 10, 10, 5))
        main_container.pack(fill="both", expand=True)
        server_conn_lf = ttk.LabelFrame(main_container, text=" 服务器与连接参数 ", padding=(10, 5))
        server_conn_lf.pack(padx=5, pady=(5, 0), fill="x")
        server_conn_grid = ttk.Frame(server_conn_lf)
        server_conn_grid.pack(fill="x", expand=True)
        server_conn_grid.grid_columnconfigure(0, weight=1, uniform="server_col")
        server_conn_grid.grid_columnconfigure(1, weight=1, uniform="server_col")
        self._create_widget_in_cell(server_conn_grid, 0, 0, "服务器地址:", "server", "entry", entry_width=30,
                                    tooltip_text="您的 Shadowsocks 服务器的域名或 IP 地址。",
                                    trace_callback=self._on_server_address_changed)
        self._create_widget_in_cell(server_conn_grid, 0, 1, "服务器端口:", "server_port", "entry", entry_width=10,
                                    tooltip_text="您的 Shadowsocks 服务器的端口号。")
        self._create_widget_in_cell(server_conn_grid, 1, 0, "加密方法:", "method", "combo",
                                    widget_options=["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"],
                                    combo_width=28, tooltip_text="选择 Shadowsocks 加密方法。")
        self._create_widget_in_cell(server_conn_grid, 1, 1, "密码:", "password", "entry", entry_width=25,
                                    tooltip_text="您的 Shadowsocks 服务器密码。", is_password=True)
        self._create_widget_in_cell(server_conn_grid, 2, 0, "插件:", "plugin", "combo",
                                    widget_options=["xray-plugin", "v2ray-plugin", ""], combo_width=28,
                                    tooltip_text="如果您使用插件（如 xray-plugin），请在此选择。")
        self._create_widget_in_cell(server_conn_grid, 2, 1, "插件选项:", "plugin_opts", "entry", entry_width=40,
                                    tooltip_text="插件的特定配置选项，例如：\ntls;mode=grpc;host=your.domain;path=/yourpath")
        mode_listener_lf = ttk.LabelFrame(main_container, text=" 代理模式与本地监听 ", padding=(10, 5))
        mode_listener_lf.pack(padx=5, pady=(5, 0), fill="x")
        mode_listener_grid = ttk.Frame(mode_listener_lf)
        mode_listener_grid.pack(fill="x", expand=True)
        mode_listener_grid.grid_columnconfigure(0, weight=1, uniform="listener_col")
        mode_listener_grid.grid_columnconfigure(1, weight=1, uniform="listener_col")
        self._create_widget_in_cell(mode_listener_grid, 0, 0, "SOCKS5 代理端口:", "local_port", "entry", entry_width=15,
                                    tooltip_text="本地 SOCKS5 代理监听的端口号。")
        proxy_modes = ["全局代理 (Global Proxy)", "智能分流 (ACL 模式)", "全部直连 (Direct Connection)"]
        self._create_widget_in_cell(mode_listener_grid, 0, 1, "系统代理模式:", "proxy_mode_selection_gui", "combo",
                                    widget_options=proxy_modes, combo_width=30,
                                    tooltip_text="选择系统代理的工作模式：\n- 全局代理: 所有流量通过SSLocal。\n- 智能分流: 根据ACL规则分流 (需配置ACL文件)。\n- 全部直连: 系统不使用SSLocal代理。")
        common_lf = ttk.LabelFrame(main_container, text=" 通用配置 (General SSLocal Options) ", padding=(10, 5))
        common_lf.pack(padx=5, pady=(5, 0), fill="x")
        common_grid = ttk.Frame(common_lf)
        common_grid.pack(fill="x", expand=True)
        for i in range(4): common_grid.grid_columnconfigure(i, weight=1, uniform="common_col")
        self._create_widget_in_cell(common_grid, 0, 0, "SSLocal 模式:", "mode", "combo",
                                    widget_options=["tcp_and_udp", "tcp_only", "udp_only"], combo_width=15,
                                    tooltip_text="SSLocal 的流量转发模式 (TCP 和/或 UDP)。")
        self._create_widget_in_cell(common_grid, 0, 1, "超时 (秒):", "timeout", "entry", entry_width=10,
                                    tooltip_text="连接超时时间（秒）。")
        self._create_widget_in_cell(common_grid, 0, 2, "DNS 服务器:", "nameserver", "entry", entry_width=20,
                                    tooltip_text="SSLocal 用于解析远程服务器地址的 DNS，\n或在 UDP 转发开启时用于客户端 DNS 请求的 DNS。")
        self._create_widget_in_cell(common_grid, 0, 3, "启用 Fast Open:", "fast_open", "checkbutton",
                                    tooltip_text="启用 TCP Fast Open (需要操作系统和服务器支持)。")
        action_buttons_frame = ttk.Frame(main_container, padding=(0, 10, 0, 5))
        action_buttons_frame.pack(fill="x", padx=5, pady=5)
        self.start_button = ttk.Button(action_buttons_frame, text="▶ 启动", command=self._start_sslocal, width=10)
        self.start_button.pack(side="left", padx=5, pady=5)
        self.stop_button = ttk.Button(action_buttons_frame, text="■ 停止", command=self._stop_sslocal, state="disabled",
                                      width=10)
        self.stop_button.pack(side="left", padx=5, pady=5)
        ttk.Button(action_buttons_frame, text="💾 保存配置", command=self._save_config, width=12).pack(side="left",
                                                                                                      padx=5, pady=5)
        ttk.Button(action_buttons_frame, text="🧪 测试服务器", command=self._test_server_connection, width=12).pack(
            side="left", padx=5, pady=5)
        ttk.Button(action_buttons_frame, text="⚙️ 选项设置", command=self._open_settings_window, width=12).pack(
            side="right", padx=5, pady=5)
        ttk.Button(action_buttons_frame, text="🗑️ 清除日志", command=self._clear_log, width=12).pack(side="right",
                                                                                                     padx=5, pady=5)
        log_frame = ttk.LabelFrame(main_container, text=" 日志 (Log) ", padding=(10, 5))
        log_frame.pack(padx=5, pady=5, fill="both", expand=True)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state="disabled", height=10,
                                                  font=("Consolas", 9) if sys.platform == "win32" else ("Monospace",
                                                                                                        10))
        self.log_text.pack(fill="both", expand=True, padx=2, pady=2)
        status_bar = ttk.Frame(self, relief="sunken", padding=(2, 2))
        status_bar.pack(side="bottom", fill="x")
        ttk.Label(status_bar, textvariable=self.status_bar_text, anchor="w").pack(fill="x", padx=5)

    def _clear_log(self):
        if hasattr(self, 'log_text') and self.log_text:
            self.log_text.config(state="normal")
            self.log_text.delete(1.0, tk.END)
            self.log_text.config(state="disabled")
            self._log_gui_thread("日志已清除。")

    def _test_server_connection(self):
        server = self.config_vars["server"].get()
        port_str = self.config_vars["server_port"].get()
        if not server or not port_str: self._log_gui_thread("测试连接失败: 服务器地址或端口未配置。",
                                                            is_error=True); return
        try:
            port = int(port_str)
        except ValueError:
            self._log_gui_thread(f"测试连接失败: 服务器端口 '{port_str}' 无效。", is_error=True)
            return
        self._log_gui_thread(f"正在测试到 {server}:{port} 的连接...")
        threading.Thread(target=self._perform_server_test, args=(server, port), daemon=True).start()

    def _perform_server_test(self, server, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((server, port))
            s.close()
            self._log_gui_thread(f"成功连接到服务器 {server}:{port}。")
            self.after(0, lambda: messagebox.showinfo("连接测试成功", f"成功连接到服务器:\n{server}:{port}"))
        except socket.timeout:
            self._log_gui_thread(f"连接服务器 {server}:{port} 超时。", is_error=True)
            self.after(0, lambda: messagebox.showerror("连接测试失败", f"连接服务器超时:\n{server}:{port}"))
        except socket.error as e:
            self._log_gui_thread(f"连接服务器 {server}:{port} 失败: {e}", is_error=True)
            self.after(0, lambda: messagebox.showerror("连接测试失败", f"连接服务器失败:\n{server}:{port}\n错误: {e}"))
        except Exception as e:
            self._log_gui_thread(f"测试连接时发生未知错误: {e}", is_error=True)
            self.after(0, lambda: messagebox.showerror("连接测试错误", f"测试连接时发生未知错误: {e}"))

    def _generate_example_acl_file(self):  # Called by SettingsWindow
        save_path = filedialog.asksaveasfilename(parent=self, initialdir=self.script_dir,
                                                 title="保存示例 ACL 文件为...", initialfile="example_acl.rules",
                                                 defaultextension=".rules",
                                                 filetypes=(("ACL 规则文件", "*.rules;*.acl;*.txt"),
                                                            ("所有文件", "*.*")))
        if not save_path:
            self._log_gui_thread("示例 ACL 文件保存已取消。")
            return
        try:
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(self.EXAMPLE_ACL_CONTENT)
            self._log_gui_thread(f"示例 ACL 文件已成功保存到: {save_path}")
        except IOError as e:
            self._log_gui_thread(f"保存示例 ACL 文件失败: {e}", is_error=True)
            messagebox.showerror("保存失败", f"保存示例 ACL 文件失败: {e}")
        except Exception as e:
            self._log_gui_thread(f"保存示例 ACL 文件时发生未知错误: {e}", is_error=True)
            messagebox.showerror("操作失败", f"保存示例 ACL 文件时发生未知错误: {e}")

    def _download_acl_file_from_gui_url(self):  # Called by SettingsWindow
        acl_url = self.config_vars.get("acl_download_url_gui", tk.StringVar()).get()
        if not acl_url:
            self._log_gui_thread("ACL 下载 URL 为空。", is_error=True)
            return
        default_filename = "downloaded_acl.rules"
        try:
            parsed_url_path = requests.utils.urlparse(acl_url).path
            if parsed_url_path and os.path.basename(parsed_url_path): default_filename = os.path.basename(
                parsed_url_path)
        except Exception:
            pass
        save_path = filedialog.asksaveasfilename(parent=self, initialdir=self.script_dir, title="保存 ACL 文件为...",
                                                 initialfile=default_filename, defaultextension=".rules",
                                                 filetypes=(("ACL 规则文件", "*.rules;*.acl;*.txt"),
                                                            ("所有文件", "*.*")))
        if not save_path:
            self._log_gui_thread("ACL 文件下载已取消 (未选择保存路径)。")
            return
        threading.Thread(target=self._perform_acl_download, args=(acl_url, save_path), daemon=True).start()

    def _perform_acl_download(self, acl_url, save_path):  # Called by thread
        self._log_gui_thread(f"开始从 {acl_url} 下载 ACL 文件...")
        try:
            response = requests.get(acl_url, timeout=30, stream=True)
            response.raise_for_status()
            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192): f.write(chunk)
            self._log_gui_thread(
                f"ACL 文件已成功下载并保存到: {save_path}\n如需使用，请通过“浏览”按钮或手动将其路径填入“ACL 文件路径”。")
        except requests.exceptions.RequestException as e:
            self._log_gui_thread(f"从 {acl_url} 下载 ACL 文件失败: {e}", is_error=True)
        except IOError as e:
            self._log_gui_thread(f"保存 ACL 文件到 {save_path} 失败: {e}", is_error=True)
        except Exception as e:
            self._log_gui_thread(f"下载或保存 ACL 文件时发生未知错误: {e}", is_error=True)

    def _load_config(self):
        try:
            with open(self.config_file, "r", encoding="utf-8") as f:
                self.current_config = json.load(f)
            self._log_gui_thread("从 config.json 加载配置成功。")
        except FileNotFoundError:
            self._log_gui_thread("config.json 未找到，使用默认配置。")
            self.current_config = self.default_config.copy()
        except json.JSONDecodeError:
            self._log_gui_thread("config.json 格式错误，使用默认配置。")
            self.current_config = self.default_config.copy()
        except Exception as e:
            self._log_gui_thread(f"加载配置时发生错误: {e}")
            self.current_config = self.default_config.copy()
        for key, default_value in self.default_config.items():
            loaded_value = self.current_config.get(key, default_value)
            if isinstance(self.config_vars[key], tk.BooleanVar):
                self.config_vars[key].set(bool(loaded_value))
            else:
                self.config_vars[key].set(str(loaded_value))

    def _save_config(self):
        new_config = {}
        for key, var_instance in self.config_vars.items():
            if isinstance(var_instance, tk.BooleanVar):
                new_config[key] = var_instance.get()
            elif key in ["local_port", "server_port", "timeout"]:
                try:
                    new_config[key] = int(var_instance.get())
                except ValueError:
                    self._log_gui_thread(
                        f"保存错误: '{key}' 值 '{var_instance.get()}' 无效。使用默认值 {self.default_config[key]}。",
                        is_error=True)
                    new_config[key] = self.default_config[key]
                    var_instance.set(str(self.default_config[key]))
            else:
                new_config[key] = var_instance.get()
        new_config_for_sslocal = new_config.copy()
        new_config_for_sslocal["local_address"] = "127.0.0.1"
        try:
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(new_config, f, indent=4, ensure_ascii=False)
            self.current_config = new_config
            self._log_gui_thread("配置已成功保存到 config.json。")
        except Exception as e:
            self._log_gui_thread(f"保存配置到 config.json 时发生错误: {e}", is_error=True)
            messagebox.showerror("保存错误", f"保存配置时发生严重错误，无法写入 config.json:\n{e}")

    def _log_gui_thread(self, message, is_error=False):
        def _log_action():
            if hasattr(self, 'log_text') and self.log_text:
                self.log_text.config(state="normal")
                tag = "error_log" if is_error else "normal_log"
                if is_error and "error_log" not in self.log_text.tag_names():
                    self.log_text.tag_configure("error_log", foreground="red")
                elif not is_error and "normal_log" not in self.log_text.tag_names():
                    self.log_text.tag_configure("normal_log", foreground="black")
                self.log_text.insert(tk.END, f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n", tag)
                self.log_text.see(tk.END)
                self.log_text.config(state="disabled")
            if not is_error or "已停止" in message or "运行中" in message:
                self.status_bar_text.set(f"状态: {message[:100]}")

        if hasattr(self, 'log_text'):
            self.after(0, _log_action)
        else:
            print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}")

    def _update_button_states(self, is_running):
        state_if_running, state_if_stopped = ("disabled", "normal") if is_running else ("normal", "disabled")
        self.start_button.config(state=state_if_running)
        self.stop_button.config(state=state_if_stopped)
        status_msg = f"运行中 - 127.0.0.1:{self.config_vars.get('local_port', tk.StringVar(value='N/A')).get()}" if is_running else "已停止"
        self._log_gui_thread(status_msg)

    def _download_file(self, urls, target_path, file_description, is_archive=True, target_exe_name=None):
        last_error = None
        for url in urls:
            try:
                self._log_gui_thread(f"尝试从 {url} 下载 {file_description}...")
                response = requests.get(url, timeout=60, stream=True)
                response.raise_for_status()

                buffer = io.BytesIO()
                total_size = int(response.headers.get('content-length', 0))
                downloaded_size = 0

                parent_for_progress = self.settings_win if hasattr(self,
                                                                   'settings_win') and self.settings_win.winfo_exists() else self
                dl_progress_win = tk.Toplevel(parent_for_progress)
                dl_progress_win.title(f"下载 {file_description}")
                dl_progress_win.geometry("350x100")
                dl_progress_win.transient(parent_for_progress)
                dl_progress_win.grab_set()
                ttk.Label(dl_progress_win, text=f"下载 {file_description}...\n{os.path.basename(url)}").pack(pady=5)
                dl_bar = ttk.Progressbar(dl_progress_win, length=300, mode="determinate")
                dl_bar.pack(pady=5)
                dl_progress_win.update()

                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        buffer.write(chunk)
                        downloaded_size += len(chunk)
                        if total_size > 0: dl_bar['value'] = (downloaded_size / total_size) * 100
                        dl_progress_win.update_idletasks()

                buffer.seek(0)
                self._log_gui_thread(f"{file_description} 下载完成，正在处理...")

                if is_archive:
                    extracted = False
                    archive_filename = os.path.basename(url)
                    if archive_filename.endswith(".zip"):
                        with zipfile.ZipFile(buffer) as z:
                            for member_info in z.infolist():
                                member_name = member_info.filename
                                if target_exe_name and os.path.basename(member_name).lower() == target_exe_name.lower():
                                    final_exe_path = os.path.join(self.script_dir, target_exe_name)
                                    if os.path.dirname(member_name):
                                        source = z.open(member_info)
                                        target = open(final_exe_path, "wb")
                                        with source, target:
                                            shutil.copyfileobj(source, target)
                                    else:
                                        z.extract(member_name, self.script_dir)
                                        if os.path.join(self.script_dir, member_name) != final_exe_path:
                                            if os.path.exists(final_exe_path): os.remove(final_exe_path)
                                            os.rename(os.path.join(self.script_dir, member_name), final_exe_path)
                                    self._log_gui_thread(f"已解压 {target_exe_name} 到 {self.script_dir}")
                                    extracted = True
                                    break
                            if not extracted:
                                z.extractall(self.script_dir)
                                self._log_gui_thread(
                                    f"已解压所有文件从 {archive_filename} 到 {self.script_dir} (未直接找到 {target_exe_name or ''})")
                    elif archive_filename.endswith((".tar.gz", ".tgz")):
                        with tarfile.open(fileobj=buffer, mode="r:gz") as t:
                            for member in t.getmembers():
                                if member.isfile() and target_exe_name and os.path.basename(
                                        member.name).lower() == target_exe_name.lower():
                                    member.name = os.path.basename(member.name)
                                    t.extract(member, self.script_dir)
                                    self._log_gui_thread(f"已解压 {target_exe_name} 到 {self.script_dir}")
                                    extracted = True
                                    break
                            if not extracted:
                                t.extractall(self.script_dir)
                                self._log_gui_thread(
                                    f"已解压所有文件从 {archive_filename} 到 {self.script_dir} (未直接找到 {target_exe_name or ''})")
                    else:
                        with open(target_path, 'wb') as f:
                            f.write(buffer.read())
                else:
                    with open(target_path, 'wb') as f:
                        f.write(buffer.read())

                dl_progress_win.destroy()
                self._log_gui_thread(
                    f"{file_description} 已成功处理并保存到 {target_path if not is_archive else self.script_dir}")
                return True

            except requests.exceptions.RequestException as e:
                last_error = e; self._log_gui_thread(f"从 {url} 下载 {file_description} 失败: {e}", is_error=True)
            except (zipfile.BadZipFile, tarfile.TarError) as e:
                last_error = e; self._log_gui_thread(f"解压 {file_description} 失败: {e}", is_error=True)
            except IOError as e:
                last_error = e
                self._log_gui_thread(f"保存 {file_description} 到 {target_path} 失败: {e}",
                                     is_error=True); break
            finally:
                if 'dl_progress_win' in locals() and dl_progress_win.winfo_exists(): dl_progress_win.destroy()

        self._log_gui_thread(f"所有源尝试后，下载 {file_description} 失败。最后错误: {last_error}", is_error=True)
        return False

    def _update_geo_data(self, manual_trigger=False, scheduled=False):
        if manual_trigger:
            self._log_gui_thread("手动触发 Geo 数据更新...")
        elif scheduled:
            self._log_gui_thread("计划任务触发 Geo 数据更新...")

        if manual_trigger and hasattr(self.settings_win,
                                      'update_geo_button') and self.settings_win.update_geo_button.winfo_exists():
            self.settings_win.update_geo_button.config(state="disabled")

        geoip_path = os.path.join(self.script_dir, self.geoip_file_name)
        geosite_path = os.path.join(self.script_dir, self.geosite_file_name)

        results = {}

        def download_wrapper(urls, path, desc, key):
            results[key] = self._download_file(urls, path, desc, is_archive=False)

        thread_geoip = threading.Thread(target=download_wrapper,
                                        args=(self.GEOIP_URLS, geoip_path, "GeoIP 数据", "geoip"))
        thread_geosite = threading.Thread(target=download_wrapper,
                                          args=(self.GEOSITE_URLS, geosite_path, "Geosite 数据", "geosite"))

        dl_threads = [thread_geoip, thread_geosite]
        [t.start() for t in dl_threads]
        [t.join() for t in dl_threads]
        success_geoip = results.get("geoip", False)
        success_geosite = results.get("geosite", False)

        if success_geoip and success_geosite:
            self._log_gui_thread("GeoIP 和 Geosite 数据均已更新。")
        else:
            self._log_gui_thread("Geo 数据更新未完全成功。请查看日志获取详细信息。", is_error=True)

        if manual_trigger and hasattr(self.settings_win,
                                      'update_geo_button') and self.settings_win.update_geo_button.winfo_exists():
            self.settings_win.update_geo_button.config(state="normal")

    def _get_executable_path(self, exe_type_key):
        config_var_name = self.EXECUTABLES_CONFIG[exe_type_key]["gui_var_key"]
        user_path = self.config_vars.get(config_var_name, tk.StringVar()).get()
        if user_path and os.path.isfile(user_path): return user_path

        target_exe_filename = self.EXECUTABLES_CONFIG[exe_type_key]["target_exe_filename"]
        default_path = os.path.join(self.script_dir, target_exe_filename)
        if os.path.isfile(default_path): return default_path

        return target_exe_filename

    def _download_executable_interactive(self, exe_type):
        exe_config = self.EXECUTABLES_CONFIG.get(exe_type)
        if not exe_config:
            self._log_gui_thread(f"错误: 未知的可执行文件类型 '{exe_type}' 供下载。", is_error=True)
            return

        if sys.platform != "win32" and exe_type in ["sslocal", "v2ray-plugin", "xray-plugin"]:
            messagebox.showinfo("平台不支持", f"自动下载 {exe_type} 功能目前主要为 Windows 优化。",
                                parent=self.settings_win if hasattr(self,
                                                                    'settings_win') and self.settings_win.winfo_exists() else self)
            return

        if messagebox.askyesno("确认下载",
                               f"此操作将从 GitHub 下载最新版本的 {exe_config['repo']} "
                               f"({exe_type}, Windows x86_64 build),\n"
                               "并解压到当前程序目录。\n\n继续吗？",
                               parent=self.settings_win if hasattr(self,
                                                                   'settings_win') and self.settings_win.winfo_exists() else self):
            self._log_gui_thread(f"开始下载最新版本的 {exe_type}...")
            threading.Thread(target=self._perform_executable_download, args=(exe_type,), daemon=True).start()

    def _perform_executable_download(self, exe_type):
        config = self.EXECUTABLES_CONFIG[exe_type]
        api_url = config["api_url_template"]
        platform_pattern_zip = config.get("platform_filename_pattern")
        platform_pattern_tar = config.get("platform_filename_pattern_tar")
        exe_name_in_archive = config["exe_name_in_archive"]
        target_exe_filename = config["target_exe_filename"]
        gui_var_key = config["gui_var_key"]

        try:
            self._log_gui_thread(f"正在获取 {exe_type} 最新版本信息...")
            resp = requests.get(api_url, headers={"Accept": "application/vnd.github.v3+json"}, timeout=30)
            resp.raise_for_status()
            release = resp.json()
            version_tag = release["tag_name"]
            self._log_gui_thread(f"找到 {exe_type} 最新版本: {version_tag}")

            asset_to_download = None
            download_url = None

            for asset in release["assets"]:
                asset_name = asset["name"]
                # Try ZIP pattern first
                if platform_pattern_zip and re.search(platform_pattern_zip, asset_name, re.IGNORECASE):
                    asset_to_download = asset
                    break
                # Then try TAR.GZ pattern
                elif platform_pattern_tar and re.search(platform_pattern_tar, asset_name, re.IGNORECASE):
                    asset_to_download = asset
                    break

            if not asset_to_download:
                self._log_gui_thread(f"错误: 未找到 {exe_type} 匹配的下载资源 (版本: {version_tag})。", is_error=True)
                self.after(0, lambda: messagebox.showerror("下载失败",
                                                           f"未找到 {exe_type} (版本: {version_tag}) 匹配的下载资源。"))
                return

            download_url = asset_to_download["browser_download_url"]
            self._log_gui_thread(f"准备下载 {exe_type} 从: {download_url}")

            success = self._download_file([download_url], self.script_dir, f"{exe_type} ({version_tag})",
                                          is_archive=True, target_exe_name=exe_name_in_archive)

            if success:
                final_exe_path = os.path.join(self.script_dir, target_exe_filename)
                path_after_extraction = os.path.join(self.script_dir, exe_name_in_archive)

                if os.path.isfile(path_after_extraction):  # If the named file in archive was extracted
                    if path_after_extraction != final_exe_path:
                        try:
                            if os.path.exists(final_exe_path): os.remove(final_exe_path)
                            shutil.move(path_after_extraction, final_exe_path)  # Use shutil.move for robustness
                            self._log_gui_thread(f"已移动并重命名 {exe_name_in_archive} 为 {target_exe_filename}")
                        except Exception as e_rename:
                            self._log_gui_thread(
                                f"移动/重命名 {exe_name_in_archive} 为 {target_exe_filename} 失败: {e_rename}",
                                is_error=True)

                if os.path.isfile(final_exe_path):
                    self.config_vars[gui_var_key].set(final_exe_path)
                    self._save_config()
                    self._log_gui_thread(f"✅ {exe_type} {version_tag} 更新完成！已保存到: {final_exe_path}")
                    self.after(0,
                               lambda: messagebox.showinfo("下载成功", f"{exe_type} {version_tag} 已成功下载并解压。"))
                else:
                    self._log_gui_thread(
                        f"警告: {exe_type} 文件已解压，但未在预期位置找到 '{target_exe_filename}'。请在设置中手动指定路径。",
                        is_error=True)
                    self.after(0, lambda: messagebox.showwarning("安装可能不完整",
                                                                 f"{exe_type} 文件已解压，但未找到预期的可执行文件。\n请检查程序目录并在设置中手动指定路径。"))
            else:
                self._log_gui_thread(f"{exe_type} 下载或处理失败。", is_error=True)

        except requests.exceptions.RequestException as e:
            self._log_gui_thread(f"下载 {exe_type} 时发生网络错误: {e}", is_error=True)
            self.after(0,
                       lambda: messagebox.showerror(
                                                                                                        "下载失败",
                                                                                                        f"网络错误: {e}"))
        except json.JSONDecodeError:
            self._log_gui_thread(f"解析 {exe_type} GitHub API 响应失败", is_error=True)
            self.after(0,
                       lambda: messagebox.showerror(
                                                                                                        "下载失败",
                                                                                                        "解析 GitHub API 响应失败"))
        except Exception as e:
            self._log_gui_thread(f"下载 {exe_type} 时发生未知错误: {e}", is_error=True)
            self.after(0,
                       lambda: messagebox.showerror(
                                                                                                        "下载失败",
                                                                                                        f"发生未知错误: {e}"))

    def _start_sslocal(self):
        if self.sslocal_process and self.sslocal_process.poll() is None:
            self._log_gui_thread("SSLocal 已经在运行中。")
            return
        self._save_config()
        socks_proxy_port = 1080
        try:
            socks_proxy_port = int(self.config_vars["local_port"].get())
        except ValueError:
            self._log_gui_thread(f"SOCKS5 端口值无效，使用默认值 {socks_proxy_port}。", is_error=True)
            if self.current_config and "local_port" in self.current_config:
                try:
                    socks_proxy_port = int(self.current_config["local_port"])
                except ValueError:
                    pass

        sslocal_exe = self._get_executable_path("sslocal")
        # Command should only be sslocal -v -c config.json
        # Plugin and plugin_opts are now part of config.json for sslocal-rust
        command = [sslocal_exe, "-v", "-c", self.config_file]

        selected_proxy_mode = self.config_vars["proxy_mode_selection_gui"].get()
        acl_file_path = self.config_vars.get("acl_file_path_gui", tk.StringVar()).get()

        if selected_proxy_mode == "智能分流 (ACL 模式)":
            if acl_file_path and os.path.isfile(acl_file_path):
                command.extend(["--acl", acl_file_path])
                self._log_gui_thread(f"智能分流模式: 使用 ACL 文件: {acl_file_path}")
            else:
                self._log_gui_thread(f"警告: 选择智能分流模式，但 ACL 文件路径为空或无效 ('{acl_file_path}')。",
                                     is_error=True)
        elif selected_proxy_mode == "全局代理 (Global Proxy)":
            self._log_gui_thread("全局代理模式: 所有流量将通过 SSLocal。")
            # If an ACL is specified in global mode, it will still be passed.
            # The user must ensure the ACL doesn't conflict with global intent (e.g., its default is proxy).
            if acl_file_path and os.path.isfile(acl_file_path):
                command.extend(["--acl", acl_file_path])
                self._log_gui_thread(f"全局模式下仍传递 ACL 文件: {acl_file_path}")
            elif acl_file_path:  # Specified but not found
                self._log_gui_thread(f"警告: ACL 文件路径 '{acl_file_path}' 已指定但文件未找到。", is_error=True)

        self._log_gui_thread(f"正在启动 SSLocal: {' '.join(command)}")
        try:
            self.sslocal_process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
                cwd=self.script_dir, creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
            self.log_thread = threading.Thread(target=self._read_sslocal_output, daemon=True)
            self.log_thread.start()
            if selected_proxy_mode == "全部直连 (Direct Connection)":
                self._set_system_proxy(enable=False)
                self._log_gui_thread("全部直连模式: 系统代理已禁用。")
            else:
                self._set_system_proxy(enable=True, socks_port=socks_proxy_port)
            self._update_button_states(True)
        except FileNotFoundError:
            self._log_gui_thread(f"错误: 执行文件 '{sslocal_exe}' 未找到。", is_error=True)
            self._update_button_states(False)
            if sys.platform == "win32":
                if messagebox.askyesno("文件未找到",
                                       f"未找到 {os.path.basename(sslocal_exe)}。\n\n是否要尝试从 GitHub 下载最新版本?"):
                    self._download_executable_interactive("sslocal")
        except Exception as e:
            self._log_gui_thread(f"启动 SSLocal 时发生严重错误: {e}", is_error=True)
            messagebox.showerror("启动错误", f"启动 SSLocal 时发生严重错误: {e}")
            self._update_button_states(False)

    def _read_sslocal_output(self):
        if not self.sslocal_process: return

        def stream_reader(pipe, prefix, is_stderr=False):
            try:
                for line in iter(pipe.readline, ''):
                    if line: self._log_gui_thread(f"{prefix} {line.strip()}", is_error=is_stderr)
            except Exception as e:
                self._log_gui_thread(f"读取 {prefix} 流时出错: {e}", is_error=True)
            finally:
                if pipe:
                    try:
                        pipe.close()
                    except Exception:
                        pass

        stdout_thread = threading.Thread(target=stream_reader, args=(self.sslocal_process.stdout, "[SSLocal OUT]"))
        stderr_thread = threading.Thread(target=stream_reader,
                                         args=(self.sslocal_process.stderr, "[SSLocal ERR]", True))
        stdout_thread.daemon = True
        stderr_thread.daemon = True
        stdout_thread.start()
        stderr_thread.start()
        if stdout_thread.is_alive(): stdout_thread.join()
        if stderr_thread.is_alive(): stderr_thread.join()
        if self.sslocal_process: self.sslocal_process.wait()
        self.after(0, self._handle_sslocal_termination)

    def _handle_sslocal_termination(self):
        exit_code = "N/A"
        if self.sslocal_process:
            if self.sslocal_process.poll() is None: self.sslocal_process.wait(timeout=0.1)
            exit_code = self.sslocal_process.returncode
        self._log_gui_thread(f"SSLocal 进程退出代码: {exit_code}")
        self.sslocal_process = None
        self._set_system_proxy(enable=False)
        self._update_button_states(False)

    def _stop_sslocal(self):
        if self.sslocal_process and self.sslocal_process.poll() is None:
            self._log_gui_thread("正在停止 SSLocal 进程...")
            self.sslocal_process.terminate()
            try:
                self.sslocal_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._log_gui_thread("SSLocal 进程未能正常终止 (terminate)，尝试强制杀死 (kill)。")
                self.sslocal_process.kill()
                self.sslocal_process.wait(timeout=2)
                self._log_gui_thread("SSLocal 进程已被强制杀死 (kill)。")
        else:
            self._log_gui_thread("SSLocal 未在运行或已被终止。")
        self._set_system_proxy(enable=False)
        self._update_button_states(False)

    def _set_system_proxy(self, enable, socks_port=None):
        if sys.platform != "win32":
            self._log_gui_thread("非 Windows 系统，跳过系统代理设置。")
            return
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        settings_changed = False
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE) as key:
                if enable and socks_port:
                    proxy_server = f"127.0.0.1:{socks_port}"
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_server)
                    winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, "")
                    self._log_gui_thread(f"系统代理已启用 (全局/ACL 模式): {proxy_server}")
                    self.proxy_enabled_by_app = True
                    settings_changed = True
                else:
                    if self.proxy_enabled_by_app or not enable:
                        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                        winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, "")
                        self._log_gui_thread("系统代理已禁用 (直连模式或停止)。")
                        self.proxy_enabled_by_app = False
                        settings_changed = True
            if settings_changed: ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, "Internet Settings", 2,
                                                                          1000, None)
        except PermissionError:
            self._log_gui_thread("权限错误: 没有权限修改系统代理设置。", is_error=True)
        except FileNotFoundError:
            self._log_gui_thread("注册表或 ctypes 模块未找到。", is_error=True)
        except Exception as e:
            self._log_gui_thread(f"设置系统代理时发生错误: {e}", is_error=True)

    def _on_closing(self):
        self._log_gui_thread("正在退出程序...")
        if self.sslocal_process and self.sslocal_process.poll() is None:
            self._stop_sslocal()
        else:
            if self.proxy_enabled_by_app: self._set_system_proxy(enable=False)
        if self.log_thread and self.log_thread.is_alive():
            self._log_gui_thread("等待日志线程结束...")
            self.log_thread.join(timeout=2.0)
        self.destroy()


if __name__ == "__main__":
    app = SSLConfigurator()
    app.mainloop()
