好的，这是根据您的要求和之前提供的信息整合的完整 README 文件：

# SSLocal Configurator - 专业版 v3.4 (修复)

## 📝 简介 (Introduction)

**SSLocal Configurator - 专业版** 是一个为 `shadowsocks-rust` 的 `sslocal` 客户端量身打造的图形用户界面（GUI）配置工具。它旨在简化 `sslocal` 的配置和管理过程，尤其适合那些不熟悉命令行的用户。通过本工具，您可以轻松设置服务器参数、管理插件、配置代理模式，并监控 `sslocal` 的运行状态。

This application helps you configure and run the `sslocal` client from the `shadowsocks-rust` project by providing a user-friendly graphical interface. It manages settings, executable paths, and the `sslocal` process itself.

## ✨ 功能特性 (Features)

* **全面的参数配置**: 支持 `sslocal` 的所有核心参数，包括服务器地址、端口、加密方法、密码、插件 (xray-plugin, v2ray-plugin)、插件选项、本地监听地址和端口、运行模式 (TCP/UDP)、超时时间、DNS 服务器以及 Fast Open。
* **可执行文件管理**:
    * 自动检测或手动指定 `sslocal.exe`, `v2ray-plugin.exe`, `xray-plugin.exe` 的路径。
    * 支持从 GitHub 下载最新版本的上述可执行文件 (主要针对 Windows x86\_64)。
* **ACL 与 Geo 数据支持**:
    * 配置 ACL (访问控制列表) 文件路径以实现智能分流。
    * 从指定 URL 下载 ACL 文件。
    * 生成示例 ACL 文件。
    * 自动或手动更新 GeoIP 和 Geosite 数据文件 (`geoip.dat`, `geosite.dat`)。
    * 支持定时自动更新 Geo 数据。
* **系统代理管理 (Windows)**:
    * 一键切换系统代理模式：全局代理、智能分流 (基于ACL)、全部直连。
    * 程序启动/停止时自动配置/取消系统代理。
* **便捷操作**:
    * 保存和加载配置到 `config.json` 文件。
    * 测试与 Shadowsocks 服务器的 TCP 连接。
    * 实时显示 `sslocal` 的日志输出和程序操作日志。
    * 清除日志显示区域。
* **启动选项**:
    * 设置程序开机自启 (Windows, 可能需要管理员权限)。
    * 设置程序启动时自动开启代理服务。
* **用户友好的界面**:
    * 直观的选项卡和输入字段，多数配有工具提示。
    * 状态栏显示当前运行状态。
    * 独立的“选项设置”窗口，用于配置程序路径和启动行为。

---
## ⚙️ 服务器条件 (Server Requirements)

要使用此客户端工具，您需要一个已正确配置并运行的 `shadowsocks-rust` 服务器。

### Docker 部署示例 (Docker Deployment Example)
如果您使用 Docker，可以通过以下命令快速部署 `shadowsocks-rust` 服务器 (由 `teddysun` 提供):

```bash
docker run -d \
--name shadowsocks-rust-server \
-p 2053:2053/tcp \
-p 2053:2053/udp \
-v /path/to/your/ss-server-config/config.json:/etc/shadowsocks-rust/config.json \
-v /path/to/your/tls/your.domain.key:/etc/shadowsocks-rust/tls/your.domain.key \
-v /path/to/your/tls/your.domain.crt:/etc/shadowsocks-rust/tls/your.domain.crt \
--restart=always \
teddysun/shadowsocks-rust
```
**说明**:
* `-p 2053:2053/tcp -p 2053:2053/udp`: 将服务器的 2053 端口映射到主机的 2053 端口 (TCP 和 UDP)。这应与您服务器 `config.json` 文件中的 `server_port` (`2053`) 保持一致。
* `-v /path/to/your/ss-server-config/config.json:/etc/shadowsocks-rust/config.json`: 挂载服务器的配置文件。您需要在主机上创建 `config.json` 文件 (例如，在 `/path/to/your/ss-server-config/config.json`)，其内容应如下所示，以匹配您提供的服务端配置：
    ```json
    {
        "server": "0.0.0.0",
        "server_port": 2053,
        "password": "zKP3uN0DwI91Ae6KZ6q0wg==",
        "method": "2022-blake3-aes-128-gcm",
        "mode": "tcp_and_udp",
        "plugin": "xray-plugin",
        "plugin_opts": "server;tls;mode=grpc;host=your.server.domain;path=/your-grpc-path;cert=/etc/shadowsocks-rust/tls/your.domain.crt;key=/etc/shadowsocks-rust/tls/your.domain.key",
        "fast_open": true,
        "timeout": 300,
        "nameserver": "8.8.8.8"
    }
    ```
* `-v /path/to/your/tls/...`: 如果您的插件选项 (如 `xray-plugin` 的 `tls` 模式) 需要 TLS 证书和私钥，请将它们从主机路径 (例如 `/path/to/your/tls/`) 挂载到容器中对应的路径。确保 `plugin_opts` 中的 `cert` 和 `key`路径 (`/etc/shadowsocks-rust/tls/your.domain.crt` 和 `/etc/shadowsocks-rust/tls/your.domain.key`) 指向容器内正确的文件位置。`your.domain.key` 是您的私钥文件，`your.domain.crt` 是您的证书文件。 **请将 `your.server.domain` 替换为您的实际域名，并将 `/your-grpc-path` 替换为您选择的 gRPC 路径。**

### 手动部署 (Manual Deployment)
您也可以直接在服务器上编译和运行 `shadowsocks-rust`。请参考 `shadowsocks-rust` 官方文档 获取详细的安装和配置指南。确保服务器端配置（如上述 `config.json` 所示）与您在本 GUI 工具中设置的客户端参数（密码、加密方法、端口、插件选项等）一致。

---
## 🚀 使用方法 (Usage Instructions)

### 首次运行 (First Run)
1.  **准备可执行文件**:
    * **sslocal.exe**: 核心的 Shadowsocks 客户端程序。
    * **xray-plugin.exe / v2ray-plugin.exe** (可选): 如果您的服务器配置使用了这些插件，则需要对应的插件程序。
    * 程序会尝试在启动时检测这些文件。 如果未找到，您可以在 “选项设置” 中手动指定路径，或使用内置的下载功能从 GitHub 获取 (主要支持 Windows x86\_64 版本)。
2.  **启动程序**: 直接运行 `main.py` (如果从源码运行) 或编译后的可执行文件。

### 主界面 (Main Interface)

#### 服务器与连接参数 (Server & Connection Parameters)
* **服务器地址**: 您的 Shadowsocks 服务器域名或 IP 地址。
* **服务器端口**: 服务器监听的端口号。
* **加密方法**: 选择与服务器匹配的加密算法 (例如 `2022-blake3-aes-256-gcm`)。
* **密码**: 连接服务器所需的密码。
* **插件**: 如果使用插件，选择 `xray-plugin` 或 `v2ray-plugin`。 留空则不使用插件。
* **插件选项**: 插件的特定配置字符串，例如 `tls;mode=grpc;host=your.server.domain;path=/your-grpc-path`。 当“服务器地址”更改时，插件选项中的 `host=` 会尝试自动更新。

#### 代理模式与本地监听 (Proxy Mode & Local Listener)
* **SOCKS5 代理端口**: 本地 SOCKS5 代理监听的端口 (默认为 `1080`)。
* **系统代理模式**:
    * **全局代理 (Global Proxy)**: 所有系统流量都尝试通过 SSLocal。
    * **智能分流 (ACL 模式)**: 根据 ACL 文件规则决定流量走向（直连或代理）。 需要正确配置 "ACL 文件路径"。
    * **全部直连 (Direct Connection)**: 系统不使用 SSLocal 作为代理，但 SSLocal 进程可能仍在运行。

#### 通用配置 (General SSLocal Options)
* **SSLocal 模式**: 选择 `tcp_and_udp`, `tcp_only`, 或 `udp_only`。
* **超时 (秒)**: 连接超时时间。
* **DNS 服务器**: SSLocal 用于解析远程服务器地址或客户端 DNS 请求的 DNS 服务器。
* **启用 Fast Open**: 勾选以启用 TCP Fast Open (需要操作系统和服务器支持)。

#### 操作按钮 (Action Buttons)
* **▶ 启动**: 根据当前配置启动 `sslocal` 进程，并根据所选模式设置系统代理。
* **■ 停止**: 停止 `sslocal` 进程，并取消系统代理。
* **💾 保存配置**: 将当前界面上的所有设置保存到 `config.json` 文件中。
* **🧪 测试服务器**: 测试与配置的 Shadowsocks 服务器的 TCP 连通性。
* **🗑️ 清除日志**: 清空下方的日志显示区域。
* **⚙️ 选项设置**: 打开“选项设置”窗口。

#### 日志区域 (Log Area)
显示 `sslocal` 进程的实时输出、程序自身的操作日志以及错误信息。

#### 状态栏 (Status Bar)
显示当前 `sslocal` 的运行状态 (例如：未启动、运行中、已停止) 和简要信息。

### 选项设置 (Settings Window)

通过主界面的 “⚙️ 选项设置” 按钮打开。

#### 程序与路径 (Program & Paths)
* **sslocal.exe 路径**: 指定 `sslocal.exe` 文件的完整路径。 可“浏览”选择或“下载”最新版。
* **v2ray-plugin 路径**: 指定 `v2ray-plugin` 可执行文件的路径。 可“浏览”选择或“下载”最新版。
* **xray-plugin 路径**: 指定 `xray-plugin` 可执行文件的路径。 可“浏览”选择或“下载”最新版。
* **ACL 文件路径 (当前使用)**: 指定 `sslocal` 使用的 ACL 规则文件路径。 智能分流模式需要此文件。
* **ACL 下载 URL (可选)**: 输入 ACL 规则文件的下载链接，可通过 “📥 下载 ACL” 按钮下载并保存。
* **⚙️ 生成示例 ACL 文件**: 在指定位置生成一个包含常用规则的示例 ACL 文件。
* **🔄 更新 Geo 数据**: 从 Loyalsoldier/v2ray-rules-dat 仓库下载或更新 `geoip.dat` 和 `geosite.dat` 文件到程序目录。

#### 启动选项 (Startup Options)
* **开机时自动启动本程序**: 勾选后，程序将尝试设置开机自启 (Windows 系统，此操作会修改注册表，可能需要管理员权限)。
* **程序启动时自动启动代理服务**: 勾选后，每次启动本配置器时，会自动尝试根据当前保存的配置启动 `sslocal` 代理服务。

点击“保存设置”会应用所有更改并关闭选项窗口；“取消”则放弃更改。

### 注意事项
* 在 Windows 系统上修改系统代理或设置开机启动可能需要管理员权限运行本程序。
* 下载功能依赖于稳定的网络连接和 GitHub 的可访问性。
* 确保客户端配置 (加密方法、密码、插件等) 与您的 Shadowsocks 服务器端配置完全一致。
* 如果选择“智能分流 (ACL 模式)”，请确保提供了有效的 ACL 文件，并且 GeoIP/Geosite 数据文件存在于程序目录或 `sslocal` 可访问的路径。 ACL 文件中的规则决定哪些流量走代理，哪些直连。

---
## 🛠️ 程序解析 (Program Analysis)

### 核心组件
* **`SSLConfigurator` 类**: 主应用程序类，负责构建和管理图形用户界面 (GUI)，处理用户输入，调用 `sslocal` 进程，并与系统设置交互。
* **`SettingsWindow` 类**: 一个独立的顶层窗口，用于配置程序级设置，如可执行文件路径、ACL 文件管理和启动选项。
* **`sslocal` 进程管理**: 程序会启动和停止 `shadowsocks-rust` 的 `sslocal` 子进程，并捕获其标准输出和错误流显示在日志区域。
* **配置文件 (`config.json`)**:
    * **GUI 配置**: `config.json` 保存了界面上所有输入字段的值，包括服务器设置、插件信息、本地端口、代理模式选择以及“选项设置”中的路径和布尔选项。
    * **`sslocal` 配置**: 当启动 `sslocal` 时，程序会确保 `config.json` 中包含 `sslocal` 运行所需的核心参数 (如 `server`, `server_port`, `password`, `method`, `local_address`, `local_port`, 以及可选的 `plugin`, `plugin_opts`, `mode`, `fast_open`, `timeout`, `nameserver`)。 `sslocal` 进程会通过 `-c config.json` 参数加载这些设置。
* **系统代理设置 (Windows)**: 使用 `winreg` 模块直接修改 Windows 注册表中的 Internet 设置来启用或禁用系统代理，并将 SOCKS5 代理指向 `127.0.0.1` 和配置的本地端口。
* **可执行文件和 Geo 数据下载**: 使用 `requests` 库从 GitHub API 获取最新版本信息，下载可执行文件的压缩包 (zip/tar.gz) 或 Geo 数据文件，并进行解压或保存。
* **日志记录**: 通过 `_log_gui_thread` 方法将程序活动和 `sslocal` 输出安全地记录到 GUI 的文本区域。

### 配置文件
程序使用 `config.json` 文件（位于程序同目录下）来持久化所有设置。 这包括：
* 服务器连接详情 (地址, 端口, 方法, 密码)
* 插件选择和插件选项
* 本地监听端口和模式
* 超时和 DNS 设置
* Fast Open 启用状态
* ACL 文件路径和下载 URL
* 选择的系统代理模式
* 可执行文件 (`sslocal`, `v2ray-plugin`, `xray-plugin`) 的路径
* 开机启动和自动启动代理的布尔选项

当您点击“保存配置”或“启动 SSLocal”时，当前界面的设置会写入此文件。 程序启动时也会从此文件加载配置。

### 依赖
程序主要依赖以下 Python 模块 (大部分为标准库):
* `tkinter` (及其 `ttk`, `scrolledtext`, `messagebox`, `filedialog` 子模块): 用于构建图形用户界面。
* `json`: 用于读写 `config.json` 配置文件。
* `subprocess`: 用于启动和管理 `sslocal` 子进程。
* `threading`: 用于执行耗时操作 (如 `sslocal` 日志读取、下载、服务器测试) 以避免阻塞 GUI。
* `sys`, `os`: 用于系统和文件路径操作。
* `time`, `datetime`: 用于日志时间戳和计划任务。
* `requests`: 用于从网络下载文件 (如可执行文件、ACL、Geo 数据) 和调用 GitHub API。
* `socket`: 用于测试服务器连接。
* `re`: 用于解析插件选项等字符串。
* `zipfile`, `tarfile`: 用于解压下载的存档文件。
* `io`: 用于处理下载流。
* `shutil`: 用于移动文件。
* `winreg` (仅 Windows): 用于读写注册表以配置系统代理和开机启动。
* `ctypes` (仅 Windows): 用于通知系统代理设置已更改。

---
## ⚠️ 免责声明 (Disclaimer)

* **软件用途**: 本软件 (SSLocal Configurator - 专业版) 旨在为 `shadowsocks-rust` (`sslocal`) 提供一个图形化配置界面，以方便用户进行合法的网络配置和调试。
* **用户责任**: 用户应自行承担使用本软件及 `shadowsocks-rust` 服务的所有风险和责任。开发者不对任何因使用或无法使用本软件所导致的直接或间接损失负责。
* **法律合规**: 用户必须严格遵守所在国家/地区的法律法规。严禁使用本软件从事任何违反当地法律法规的活动。开发者对此类行为不承担任何责任。
* **安全性**: 虽然 `shadowsocks-rust` 本身是一个注重安全性的项目，但用户仍需对自己的服务器安全、密码强度以及客户端运行环境的安全负责。请确保从官方或可信赖的来源获取 `shadowsocks-rust` 及其插件。
* **无担保**: 本软件按“原样”提供，不附带任何明示或暗示的担保，包括但不限于适销性、特定用途适用性和非侵权性的担保。
* **第三方服务**: 本软件可能依赖第三方服务（如 GitHub）进行更新和下载。这些服务的可用性和策略可能会发生变化，开发者无法对此提供保证。

**使用本软件即表示您已阅读、理解并同意上述所有条款。**