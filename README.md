# ss-2022

Shadowsocks 2022 一键安装与管理脚本，基于
[shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)。

当前版本：`v26.09.04`

支持 Debian、Ubuntu、CentOS，以及 x86_64、aarch64、armv7l：

- `2022-blake3-aes-128-gcm`
- `2022-blake3-chacha20-poly1305`

## 安装

需要 root 权限和 systemd。脚本会自动安装缺少的 `curl`、`jq`、`tar`、`xz`、`openssl`。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh)
```

选择 `1` 开始安装。不带参数运行脚本可进入管理菜单。

## 无交互安装

`--port` 与 `--password` 必须同时提供。密码必须是对应长度的 Base64 密钥：

```bash
PASSWORD="$(openssl rand -base64 16)" && bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh) --port 8388 --password "$PASSWORD" --method 2022-blake3-aes-128-gcm
```

```bash
PASSWORD="$(openssl rand -base64 32)" && bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh) --port 8388 --password "$PASSWORD" --method 2022-blake3-chacha20-poly1305
```

查看帮助：

```bash
bash install.sh --help
```

## 卸载

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh) --uninstall
```

`--uninstall` 无需交互确认。若检测到已安装（或存在残留文件），一键安装会被拒绝，请先执行上述卸载命令。

## 管理命令

```bash
systemctl status ss-rust
journalctl -u ss-rust -n 50 --no-pager
```

请放行实际使用的 TCP/UDP 端口。

脚本的配置信息（含 SS 链接）输出到标准错误（stderr），重定向 stdout 不会影响显示。

服务以系统 `nobody` 用户运行（systemd `User=nobody`），因此可监听普通端口；
若需绑定 1024 以下端口，脚本已授予 `CAP_NET_BIND_SERVICE` 能力。

配置文件：`/etc/ss-rust/config.json`（root 所有，644，含密码明文）

程序文件：`/usr/local/bin/ss-rust`

服务文件：`/etc/systemd/system/ss-rust.service`
