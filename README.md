# ss-2022

一个基于 [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) 的 Shadowsocks 2022 一键安装与管理脚本。

## 功能特点

- 自动获取并安装 shadowsocks-rust 最新稳定版
- 支持交互式安装和带参数的无交互安装
- 使用 `2022-blake3-aes-128-gcm` 加密方式
- 自动生成或校验 16 字节 Base64 密钥
- 支持端口冲突检查
- 自动创建 systemd 服务并设置开机启动
- 支持安装、更新、卸载、配置修改和服务管理
- 下载二进制后自动进行 SHA-256 完整性校验

## 支持环境

- Debian
- Ubuntu
- CentOS（使用 yum）
- systemd
- CPU 架构：`x86_64`、`aarch64`、`armv7l`

脚本会根据系统自动安装以下依赖：`curl`、`jq`、`wget`、`tar`、`xz` 和 `openssl`。

> 不支持 Alpine、Windows、macOS，以及不使用 systemd 的精简系统。

## 安装

### 推荐：先下载、检查，再执行

不要直接执行未经检查的远程脚本。可以先下载到本地查看：

```bash
curl -fL --proto '=https' --tlsv1.2 \
  https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh \
  -o install.sh

less install.sh
chmod 700 install.sh
sudo bash install.sh
```

脚本需要 root 权限运行。首次进入交互菜单后，选择 `1` 开始安装。

### 直接交互式安装

确认信任当前仓库内容后，也可以直接执行：

```bash
sudo bash <(curl -fL --proto '=https' --tlsv1.2 \
  https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh)
```

## 无交互安装

`2022-blake3-aes-128-gcm` 要求密码是**恰好 16 字节密钥的 Base64 编码**。推荐使用 OpenSSL 生成：

```bash
PASSWORD="$(openssl rand -base64 16)"
sudo bash install.sh --port 8388 --password "$PASSWORD"
```

如果使用远程脚本：

```bash
PASSWORD="$(openssl rand -base64 16)"
sudo bash <(curl -fL --proto '=https' --tlsv1.2 \
  https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh) \
  --port 8388 --password "$PASSWORD"
```

> 注意：通过 `--password` 传参时，密码可能短暂出现在进程参数中。对密码暴露敏感的环境建议使用交互式安装，并在安装后妥善保存配置。

## 参数

```text
-p, --port <端口>       指定端口，范围 1-65535
-w, --password <密码>   指定 Base64 编码的 16 字节密钥
-f, --force             强制重新安装，覆盖现有安装
-h, --help              显示帮助信息
```

查看完整帮助：

```bash
bash install.sh --help
```

## 服务管理

安装完成后，脚本会创建 `ss-rust.service` 并设置开机启动。也可以直接使用 systemd 管理：

```bash
sudo systemctl status ss-rust
sudo systemctl restart ss-rust
sudo systemctl stop ss-rust
sudo systemctl start ss-rust
sudo journalctl -u ss-rust -n 50 --no-pager
```

配置文件位置：

```text
/etc/ss-rust/config.json
```

配置文件权限为 `600`，仅 root 可读写。二进制文件位置：

```text
/usr/local/bin/ss-rust
```

## 管理菜单

不带参数运行脚本即可进入交互式管理菜单：

```bash
sudo bash install.sh
```

菜单支持：

1. 安装 Shadowsocks-rust
2. 更新 Shadowsocks-rust
3. 卸载 Shadowsocks-rust
4. 修改端口或密码
5. 查看配置信息
6. 启动服务
7. 停止服务
8. 重启服务
9. 查看服务状态

## 更新与卸载

进入菜单后选择对应功能即可，也可以先下载最新脚本再执行：

```bash
sudo bash install.sh
```

卸载会停止并禁用服务，同时删除：

- `/usr/local/bin/ss-rust`
- `/etc/ss-rust/`
- `/etc/systemd/system/ss-rust.service`

卸载前请确认已备份需要保留的配置和密钥。

## 安全说明

- 脚本以 root 权限运行，请先审阅脚本内容。
- 脚本从 shadowsocks-rust GitHub Release 获取最新稳定版，不固定版本号。
- 下载的二进制会使用上游提供的 `.sha256` 文件进行校验，校验失败时不会继续安装。
- 请在服务器防火墙和云平台安全组中放行实际使用的 TCP/UDP 端口。
- Shadowsocks 只负责代理服务本身，服务器系统更新、防火墙和 SSH 安全仍需自行维护。

## 许可证

本项目暂未单独声明许可证。使用、修改或分发前，请遵守本项目作者及上游 shadowsocks-rust 的相关许可和使用条款。
