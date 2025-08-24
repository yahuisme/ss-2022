# ss-2022
一个 shadowsocks-rust 2022 一键安装脚本

## 脚本特点
1. 交互管理菜单
2. 交互安装可自定义端口和密码
3. 支持带参数一键无交互安装
4. 支持交互菜单更新和卸载
5. 极简纯净高效

## 默认安装
```
bash <(curl -sL https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh)
```

## 无交互一键安装
```
bash <(curl -sL https://raw.githubusercontent.com/yahuisme/ss-2022/main/install.sh) -p 12345 -w 'X3Z7Cp6YoxFvjD1dS+Gy4w=='
```
使用无交互安装请自行修改端口和密码，密码需要符合 shadowsocks 2022-blake3-aes-128-gcm 加密规范。
