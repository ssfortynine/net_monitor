# 📡 Net Monitor (Rust)

![alt text](https://img.shields.io/badge/Built_with-Nix-blue.svg)
![alt text](https://img.shields.io/badge/Language-Rust-orange.svg)
![alt text](https://img.shields.io/badge/License-MIT-green.svg)

一个基于 Rust 编写的轻量级终端网络流量监控工具。受到 iftop 的启发，利用 TUI (Terminal UI) 实时展示局域网内的网络流量、带宽占用峰值以及实时速率图表。

支持通过 Nix Flakes 进行构建和开发环境配置。

## 🛠️ 构建与安装 (Build & Install)

本项目优先推荐使用 Nix 进行管理，但也支持标准的 Cargo 流程。

### 方式一：使用 Nix (推荐)

如果您安装了 Nix package manager 并启用了 Flakes：

1. 编译构建
```Bash
nix build
# 构建完成后，可执行文件位于 ./result/bin/
```
2. 进入开发环境

环境会自动配置 rustc, cargo, libpcap, pkg-config 以及必要的 LD_LIBRARY_PATH。
```Bash
nix develop
# 进入 Shell 后即可直接运行 cargo 命令
cargo run
```
### 方式二：标准 Cargo 构建

**前置依赖:**
请确保系统已安装 `libpcap` 开发库。

+ Debian/Ubuntu: `sudo apt install libpcap-dev`
+ Arch Linux: `sudo pacman -S libpcap`
+ Fedora: `sudo dnf install libpcap-devel`

**构建:**
```Bash
cargo build --release
```
## 📖 使用指南 (Usage)
由于工具需要通过 libpcap 捕获数据包，通常需要 root 权限。

### 基本用法
默认情况下，程序会自动查找默认网卡，并统计标准的私有地址段 (192.168.x.x, 10.x.x.x, 等)。
```Bash
# 使用 Nix 构建的产物
sudo ./result/bin/net_monitor

# 或者在开发环境中
sudo -E cargo run
```
### 指定监控网段 (CIDR 过滤)
如果你只想监控特定的子网（例如只关心家庭局域网流量，忽略 Docker 或其他虚拟网卡流量），可以在命令后追加 CIDR 地址：
```Bash
# 只监控 192.168.50.0/24 网段的流量
sudo ./result/bin/net_monitor 192.168.50.0/24

# 只监控特定 IP
sudo ./result/bin/net_monitor 192.168.1.100/32
```

### 键盘操作
+ `q` 或 `Ctrl+C`: 退出程序。

## ⚡ 故障排查 (Troubleshooting)

报错: `error while loading shared libraries: libpcap.so`

如果在非 Nix 环境下运行 Nix 构建的二进制文件，或者环境变量未生效：
确保 `LD_LIBRARY_PATH` 包含 `libpcap` 的路径。在 Nix `devShell` 中这已经自动配置好了。

报错: `Permission denied` / `You don't have permission to capture on that device`

抓包需要特权。请使用 `sudo` 运行，或者给二进制文件授予 `cap_net_raw` 权限：
```Bash
sudo setcap cap_net_raw,cap_net_admin=eip target/release/net_monitor
```
## 📜 License
MIT License
