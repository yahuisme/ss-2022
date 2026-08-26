# ss-2022

基于 [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) 的 Shadowsocks 2022 安装管理脚本。

## 支持

- Debian、Ubuntu、CentOS（需要 systemd）
- x86_64、aarch64、armv7l
- AES-128-GCM、ChaCha20-Poly1305

## 安装

需要 root 权限，并确保系统已安装 `curl`：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh)
```

首次运行选择菜单 `1` 安装。

## 无交互安装

```bash
PASSWORD="$(openssl rand -base64 16)" && bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh) --port 8388 --password "$PASSWORD"
```

使用 ChaCha20：

```bash
PASSWORD="$(openssl rand -base64 32)" && bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh) --port 8388 --password "$PASSWORD" --method 2022-blake3-chacha20-poly1305
```

## 管理

不带参数运行脚本进入菜单，可进行更新、卸载、修改配置和服务管理。

```bash
systemctl status ss-rust
systemctl restart ss-rust
journalctl -u ss-rust -n 50 --no-pager
```

## 文件

```text
配置：/etc/ss-rust/config.json
程序：/usr/local/bin/ss-rust
服务：ss-rust.service
```

## 注意

- 请在防火墙和云安全组放行实际使用的 TCP/UDP 端口。
- `--password` 为 Base64 密钥：AES-128-GCM 使用 16 字节，ChaCha20 使用 32 字节。
- `--password` 传参可能出现在进程信息中。
- 下载文件会进行 SHA-256 校验。
- 已安装时不能重复安装，如需重装请先卸载。
