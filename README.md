# ss-2022

基于 [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) 的 Shadowsocks 2022 安装管理脚本。

## 特点

- 支持 Debian、Ubuntu、CentOS
- 支持 `x86_64`、`aarch64`、`armv7l`
- 支持 `2022-blake3-aes-128-gcm` 和 `2022-blake3-chacha20-poly1305`
- 支持交互式和无交互安装
- 自动创建 systemd 服务
- 自动校验下载文件的 SHA-256
- 支持安装、更新、卸载、配置和服务管理
- 支持自动检测或手动指定服务器地址并生成 SS 链接

## 安装

直接运行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh)
```

脚本需要 root 权限，首次运行后选择菜单中的 `1` 安装。运行前需要系统已安装 `curl`。

脚本适用于使用 `systemd` 的 Debian、Ubuntu 和 CentOS，并支持 `x86_64`、`aarch64`、`armv7l`。不适用于 Alpine、OpenWrt 或不带 systemd 的容器环境。缺少 `jq`、`tar`、`xz` 或 `openssl` 时，脚本会在安装/更新过程中提示并尝试通过系统包管理器安装。

如果当前终端已经是 root（提示符通常以 `root@` 开头），直接使用上面的 `bash <(curl ...)` 命令即可。如果当前用户不是 root，请先执行 `sudo -i` 切换到 root shell，再运行该命令。不要写成 `sudo bash <(curl ...)`：进程替换生成的 `/dev/fd/*` 由当前 Shell 创建，`sudo` 可能无法访问，导致 `/dev/fd/*: No such file or directory`。

## 无交互安装

使用 `2022-blake3-aes-128-gcm`，密钥 Base64 编码 16 字节。

```bash
PASSWORD="$(openssl rand -base64 16)" && bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh) --port 8388 --password "$PASSWORD" --method 2022-blake3-aes-128-gcm
```

使用 `2022-blake3-chacha20-poly1305`，密钥 Base64 编码 32 字节。

```bash
PASSWORD="$(openssl rand -base64 32)" && bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh) --port 8388 --password "$PASSWORD" --method 2022-blake3-chacha20-poly1305
```

参数：

```text
-p, --port <端口>       端口，范围 1-65535
-w, --password <密码>   指定 Base64 编码的密钥
-m, --method <方式>     2022-blake3-aes-128-gcm 或 2022-blake3-chacha20-poly1305
-f, --force             强制重新安装
-h, --help              显示帮助
```

## 管理

不带参数重新运行上面的一键命令即可进入管理菜单：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh)
```

服务管理：

```bash
sudo systemctl status ss-rust
sudo systemctl restart ss-rust
sudo journalctl -u ss-rust -n 50 --no-pager
```

配置文件：`/etc/ss-rust/config.json`
二进制文件：`/usr/local/bin/ss-rust`

## 注意事项

- 脚本从 shadowsocks-rust GitHub Release 获取最新稳定版。
- 下载文件会进行 SHA-256 校验，校验失败不会继续安装。
- 请在防火墙和云平台安全组中放行实际使用的 TCP/UDP 端口。
- 生成的 `ss://` 链接使用 Shadowsocks 2022 的标准 SIP002 格式，`method:password` 整体进行 Base64URL 编码。
- 使用 `--password` 传参时，密码可能短暂出现在进程参数中；固定密钥的无交互安装方式仍然可用。
- Shadowsocks 2022 密钥是随机原始密钥的 Base64 表示：AES-128-GCM 为 16 字节，ChaCha20-Poly1305 为 32 字节。
- `--force` 重新安装时会在写入新配置前暂时停止旧服务，以避免旧服务占用原端口；失败会尝试恢复原安装。
- 更新或强制重新安装失败时，会尝试恢复原二进制、配置、服务文件及服务运行状态。
- `--port` 和 `--password` 必须同时提供；`--force` 仅允许覆盖已有安装，不会自动修改现有配置。
- 卸载会删除服务、二进制文件和 `/etc/ss-rust/` 配置目录。

本项目暂未单独声明许可证。使用和分发前请遵守作者及上游项目的相关许可条款。
