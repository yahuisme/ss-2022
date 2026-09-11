# ss-2022

Shadowsocks 2022 一键安装与管理脚本，基于
[shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)。

当前版本：`v26.09.11`

支持 Debian、Ubuntu、CentOS，以及 x86_64、aarch64、armv7l：

- `2022-blake3-aes-128-gcm`：默认，16 字节密钥，适合有 AES 硬件加速的设备。
- `2022-blake3-chacha20-poly1305`：32 字节密钥，适合无 AES 硬件加速的设备。

## 安装

需要 root 权限和 systemd。脚本会自动安装缺少的 `curl`、`jq`、`tar`、`xz`、`openssl`。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh)
```

选择 `1` 开始安装。不带参数进入 36 列管理菜单；交互输入从 `/dev/tty` 读取，需要控制终端。无 TTY 请提供完整安装参数；输入结束会中止当前操作。

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

`--uninstall` 无需交互确认，必须单独使用；`--help` 同样不得混用其他参数，且无需 root。参数组合错误返回 2。卸载后可返回菜单继续安装；不会批量删除其他会话或失败回滚的临时恢复目录。若检测到已安装（或存在残留文件），一键安装会被拒绝，请先执行上述卸载命令。

## 管理命令

```bash
systemctl status ss-rust
journalctl -u ss-rust -n 50 --no-pager
```

请放行实际使用的 TCP/UDP 端口。

菜单输出到 stdout，日志和配置信息（含密钥及 SS 链接）输出到 stderr；重定向 stdout 不会隐藏密钥。颜色按实际输出目标判断：非 TTY、设置 `NO_COLOR`（含空值）或 `TERM=dumb` 时不输出 ANSI 颜色。密钥输入不回显，但修改前会展示当前密钥。安装时密钥留空随机生成；修改时留空保留，切换加密方式后留空则重新随机生成；修改时输入 `random` 始终随机生成。

更新、重装和修改配置保留已有服务的启停及自启状态；原来停止的服务不会自动启动。修改配置仅替换 `server_port`、`password`、`method`，保留 `server`、`mode`、`nameserver`、`acl` 等自定义字段；非法 JSON 会被拒绝。

关键步骤失败会中止当前操作并尝试回滚，菜单仍可继续使用。回滚不完整时会明确报告恢复目录（`/tmp/ss-rust.*`，可能含密钥），保留材料并阻止同一会话覆盖备份；请先按其中的 `old-*` 文件和 `was-*` 状态手动恢复，再删除该目录。脚本不会自动清理这类材料。

服务以系统 `nobody` 用户运行（systemd `User=nobody`），因此可监听普通端口；
若需绑定 1024 以下端口，脚本已授予 `CAP_NET_BIND_SERVICE` 能力。

配置文件：`/etc/ss-rust/config.json`（root 所有，644，含密码明文）

程序文件：`/usr/local/bin/ss-rust`

服务文件：`/etc/systemd/system/ss-rust.service`
