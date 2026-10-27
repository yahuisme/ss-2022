# ss-2022

基于 [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) 的 Shadowsocks 2022 一键安装与管理脚本。

## 使用

支持 Debian、Ubuntu、CentOS，架构为 x86_64、aarch64、armv7l。需要 **root、Bash、curl、systemd**；在交互终端运行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh)
```

选择 `1` 安装，按提示设置端口和密钥，完成后将 `ss://` 链接导入支持所选算法的客户端。

- 默认端口 `8388`，密钥留空随机生成。
- `2022-blake3-aes-128-gcm`：默认，16 字节密钥，有 AES 硬件加速时优先。
- `2022-blake3-chacha20-poly1305`：32 字节密钥，适合无 AES 硬件加速的设备。

请在服务器防火墙和云安全组放行所选 **TCP/UDP 端口**。

## 管理

再次运行上方命令，按菜单更新、卸载、修改配置或查看链接，也可管理服务启停。

- 配置：`/etc/ss-rust/config.json`；状态：`systemctl status ss-rust`。
- 日志：`journalctl -u ss-rust -n 50 --no-pager`。
- 修改时留空保留当前值；切换算法后密钥留空重新生成，输入 `random` 也会生成新密钥。更改后重新导入客户端。
- 更新、重装和修改保留原服务启停及自启状态；菜单重装可选择保留配置，修改仅替换端口、密钥和算法。
- **卸载删除程序、服务及 `/etc/ss-rust` 全部内容；菜单确认回车即同意。**
- 配置含明文密钥，权限为 `644`；配置信息和链接输出到 stderr，重定向 stdout 不会隐藏密钥，请勿公开。

<details>
<summary>无交互安装与帮助</summary>

须同时提供端口和密钥，且无已有安装或残留。以下为默认 AES 算法，需先安装 OpenSSL：

```bash
PASSWORD="$(openssl rand -base64 16)" && bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh) --port 8388 --password "$PASSWORD" --method 2022-blake3-aes-128-gcm
```

使用 ChaCha 时，将 `16` 改为 `32`，算法改为 `2022-blake3-chacha20-poly1305`。

在首次命令末尾加 `--help` 查看参数，或加 `--uninstall` 直接卸载，后者无需确认。

</details>

失败时脚本尝试回滚；未完成时保留报出的 `${TMPDIR:-/tmp}/ss-rust.*` 恢复目录，按其中的 `old-*` 文件和 `was-*` 状态人工恢复后再重试。重新运行不会自动接续恢复，勿删除备份绕过错误。
