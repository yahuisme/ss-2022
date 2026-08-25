# ss-2022

基于 [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) 的 Shadowsocks 2022 安装管理脚本。

## 特点

- 支持 Debian、Ubuntu、CentOS
- 支持 `x86_64`、`aarch64`、`armv7l`
- 支持交互式和无交互安装
- 自动创建 systemd 服务
- 自动校验下载文件的 SHA-256
- 支持安装、更新、卸载、配置和服务管理

## 安装

推荐先下载并检查脚本：

```bash
curl -fL --proto '=https' --tlsv1.2 \
  https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh \
  -o install.sh

less install.sh
sudo bash install.sh
```

也可以直接运行：

```bash
sudo bash <(curl -fL --proto '=https' --tlsv1.2 \
  https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh)
```

脚本需要 root 权限，首次运行后选择菜单中的 `1` 安装。

## 无交互安装

默认使用 `2022-blake3-aes-128-gcm`，密码必须是 **16 字节密钥的 Base64 编码**：

```bash
PASSWORD="$(openssl rand -base64 16)"
sudo bash install.sh --port 8388 --password "$PASSWORD"
```

参数：

```text
-p, --port <端口>       端口，范围 1-65535
-w, --password <密码>   16 字节密钥的 Base64 编码
-f, --force             强制重新安装
-h, --help              显示帮助
```

## 管理

不带参数运行脚本即可进入菜单：

```bash
sudo bash install.sh
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
- 使用 `--password` 传参时，密码可能短暂出现在进程参数中。
- 卸载会删除服务、二进制文件和 `/etc/ss-rust/` 配置目录。

本项目暂未单独声明许可证。使用和分发前请遵守作者及上游项目的相关许可条款。
