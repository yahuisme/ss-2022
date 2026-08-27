# ss-2022

基于 [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) 的 Shadowsocks 2022 安装管理脚本。

## 支持

- Debian、Ubuntu、CentOS
- x86_64、aarch64、armv7l
- `2022-blake3-aes-128-gcm`
- `2022-blake3-chacha20-poly1305`

## 安装

需要 root 权限和 systemd。脚本会自动安装缺少的 `curl`、`jq`、`tar`、`xz`、`openssl`。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh)
```

首次运行选择 `1` 安装。

## 无交互安装

先生成对应长度的 Base64 密钥，再作为 `--password` 传入。

AES-128-GCM（16 字节）：

```bash
PASSWORD="$(openssl rand -base64 16)" && bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh) --port 8388 --password "$PASSWORD" --method 2022-blake3-aes-128-gcm
```

ChaCha20-Poly1305（32 字节）：

```bash
PASSWORD="$(openssl rand -base64 32)" && bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh) --port 8388 --password "$PASSWORD" --method 2022-blake3-chacha20-poly1305
```

## 管理

不带参数运行脚本进入管理菜单，可更新、修改配置、管理服务或卸载。

```bash
systemctl status ss-rust
journalctl -u ss-rust -n 50 --no-pager
```

卸载会删除程序、配置、systemd 服务及相关临时文件，不保留安装备份。

## 文件

```text
配置：/etc/ss-rust/config.json
程序：/usr/local/bin/ss-rust
服务：/etc/systemd/system/ss-rust.service
```

请在防火墙和云安全组放行实际使用的 TCP/UDP 端口。
