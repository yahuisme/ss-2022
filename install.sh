#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155

# ===================================================================================
# Shadowsocks Rust 管理脚本
#
# 作者：yahuisme
# 版本：4.0
# 描述：一个安全、健壮的 shadowsocks-rust 管理脚本。
# ===================================================================================
set -euo pipefail

# --- 脚本配置与变量 ---
readonly SCRIPT_VERSION="4.0"
readonly INSTALL_DIR="/etc/ss-rust"
readonly BINARY_PATH="/usr/local/bin/ss-rust"
readonly CONFIG_PATH="${INSTALL_DIR}/config.json"
readonly VERSION_FILE="${INSTALL_DIR}/ver.txt"
readonly SYSTEMD_SERVICE_FILE="/etc/systemd/system/ss-rust.service"
readonly ENCRYPTION_METHOD="2022-blake3-aes-128-gcm"
readonly KEY_BYTES=16

# --- 颜色定义 ---
readonly C_RESET='\033[0m'
readonly C_RED='\033[0;31m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_BLUE='\033[0;34m'

# --- 创建并注册临时目录清理函数 ---
readonly TMP_DIR=$(mktemp -d)
trap 'cleanup' EXIT

# 在脚本退出时清理临时文件
cleanup() {
    rm -rf "$TMP_DIR"
}

# ===================================================================================
# --- 日志与辅助函数 ---
# ===================================================================================

# 打印信息
info() { echo -e "${C_BLUE}[信息]${C_RESET} $1" >&2; }
# 打印成功信息
success() { echo -e "${C_GREEN}[成功]${C_RESET} $1" >&2; }
# 打印警告信息
warn() { echo -e "${C_YELLOW}[警告]${C_RESET} $1" >&2; }
# 打印错误信息并退出
error() { echo -e "${C_RED}[错误]${C_RESET} $1" >&2; exit 1; }

# 检查是否以 root 权限运行
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        error "此脚本必须以 root 权限运行，请使用 sudo。"
    fi
}

# 获取公共 IP 地址 (支持 IPv4 和 IPv6)
get_public_ip() {
    info "正在查询公网IP地址..."
    local ip
    ip=$(curl -s -4 --max-time 5 https://api.ipify.org) || \
    ip=$(curl -s -4 --max-time 5 https://ip.sb)

    if [[ -n "$ip" ]]; then
        echo "$ip"
        success "成功获取公网 IPv4 地址。"
        return
    fi
    
    warn "未能获取公网 IPv4 地址，正在尝试获取 IPv6..."
    ip=$(curl -s -6 --max-time 5 https://api64.ipify.org) || \
    ip=$(curl -s -6 --max-time 5 https://ip.sb)

    if [[ -n "$ip" ]]; then
        echo "[$ip]"
        success "成功获取公网 IPv6 地址。"
    else
        error "无法获取公网IP地址，请检查网络连接。"
    fi
}

# 检测操作系统类型
detect_os() {
    if grep -qs "ubuntu" /etc/os-release; then
        echo "ubuntu"
    elif [[ -e /etc/debian_version ]]; then
        echo "debian"
    elif [[ -e /etc/redhat-release ]]; then
        echo "centos"
    else
        error "不支持的操作系统。"
    fi
}

# 检测 CPU 架构
detect_arch() {
    case "$(uname -m)" in
        x86_64) echo "x86_64-unknown-linux-gnu" ;;
        aarch64) echo "aarch64-unknown-linux-gnu" ;;
        armv7l) echo "armv7-unknown-linux-gnueabihf" ;;
        *) error "不支持的CPU架构: $(uname -m)" ;;
    esac
}

# 检查并安装脚本所需的依赖工具
check_dependencies() {
    info "正在检查必要的依赖工具..."
    local dependencies=("curl" "jq" "wget" "tar" "xz" "openssl")
    local os_type="$1"
    local missing_deps=()

    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing_deps+=("$dep")
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        warn "检测到以下依赖缺失: ${missing_deps[*]}"
        if [[ "${non_interactive:-false}" == "true" ]]; then
            info "将在非交互模式下自动安装..."
        else
            read -p "是否需要现在自动安装它们? (Y/n): " choice
            if [[ "$choice" =~ ^[Nn]$ ]]; then
                error "缺少必要的依赖，脚本无法继续运行。"
            fi
        fi
        install_dependencies "$os_type" "${missing_deps[@]}"
    fi
    success "所有依赖均已满足。"
}

# 安装依赖工具
install_dependencies() {
    local os_type="$1"
    shift
    local deps_to_install=("$@")
    info "正在安装依赖: ${deps_to_install[*]}"

    local packages=()
    for dep in "${deps_to_install[@]}"; do
        case "$dep" in
            xz) [[ "$os_type" == "ubuntu" || "$os_type" == "debian" ]] && packages+=("xz-utils") || packages+=("xz") ;;
            *) packages+=("$dep") ;;
        esac
    done

    if [[ "$os_type" == "ubuntu" || "$os_type" == "debian" ]]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y
        apt-get install -y "${packages[@]}"
    elif [[ "$os_type" == "centos" ]]; then
        yum install -y epel-release &>/dev/null || true
        yum install -y "${packages[@]}"
    fi
}

# ===================================================================================
# --- 安装与配置核心函数 ---
# ===================================================================================

# 获取 shadowsocks-rust 的最新版本号
get_latest_version() {
    info "正在获取 shadowsocks-rust 的最新版本号..."
    local latest_version
    latest_version=$(curl -s "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" | jq -r '.tag_name // empty')
    if [[ -z "$latest_version" ]]; then
        error "获取最新版本失败，请检查网络或GitHub API访问。"
    fi
    echo "${latest_version#v}"
}

# 下载并安装二进制文件
download_and_install() {
    local version="$1"
    local arch="$2"
    local download_url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${version}/shadowsocks-v${version}.${arch}.tar.xz"
    local download_path="${TMP_DIR}/ss-rust.tar.xz"

    info "从以下地址下载: $download_url"
    wget -qO "$download_path" "$download_url" || error "下载失败。"

    info "正在解压并安装..."
    tar -xf "$download_path" -C "$TMP_DIR"
    install -m 755 "${TMP_DIR}/ssserver" "$BINARY_PATH"

    mkdir -p "$INSTALL_DIR"
    echo "$version" > "$VERSION_FILE"

    success "shadowsocks-rust v${version} 安装成功。"
}

# 生成配置文件
generate_config() {
    local port=${1:-}
    local password=${2:-}

    info "正在生成配置文件..."
    info "将使用固定的加密方式: ${ENCRYPTION_METHOD}"

    if [[ -z "$port" ]]; then
        while true; do
            read -p "请输入 Shadowsocks 端口 [1-65535] (默认: 8388): " port
            port=${port:-8388}
            if [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]]; then
                break
            else
                warn "输入无效，请输入一个 1 到 65535 之间的数字。"
            fi
        done
    else
        info "使用指定的端口: $port"
    fi

    if [[ -z "$password" ]]; then
        read -p "请输入 Shadowsocks 密码 (留空则随机生成): " password_input
        if [[ -z "$password_input" ]]; then
            info "为 ${ENCRYPTION_METHOD} 生成 ${KEY_BYTES} 字节随机密码..."
            password=$(openssl rand -base64 ${KEY_BYTES})
        else
            password=$password_input
        fi
    else
        info "使用指定的密码。"
        if [[ "${non_interactive:-false}" == "true" ]]; then
            info "正在验证密码格式..."
            local decoded_len
            decoded_len=$(echo "$password" | openssl base64 -d -A 2>/dev/null | wc -c)
            if [[ "$decoded_len" -ne "$KEY_BYTES" ]]; then
                error "密码验证失败！提供的密码不是一个有效的 Base64 字符串，或者解码后的密钥长度不是 ${KEY_BYTES} 字节。"
            fi
            success "密码格式正确。"
        fi
    fi

    # 使用多行排版，让 JSON 结构更清晰
    jq -n \
        --argjson server_port "$port" \
        --arg password "$password" \
        --arg method "$ENCRYPTION_METHOD" \
        '{
            "server": "::",
            "server_port": $server_port,
            "password": $password,
            "method": $method,
            "fast_open": true,
            "mode": "tcp_and_udp"
        }' > "$CONFIG_PATH"

    success "配置文件已创建于 $CONFIG_PATH"
}

# 创建 systemd 服务文件
create_systemd_service() {
    info "正在创建 systemd 服务..."
    cat > "$SYSTEMD_SERVICE_FILE" << EOF
[Unit]
Description=Shadowsocks-rust Server Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=$BINARY_PATH -c $CONFIG_PATH
Restart=on-failure
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ss-rust
    success "Systemd 服务已创建并设为开机自启。"
}

# ===================================================================================
# --- 服务管理与操作函数 ---
# ===================================================================================

# 启动、停止、重启或查看服务状态
manage_service() {
    if ! command -v systemctl &> /dev/null; then
        error "未找到 systemd，无法管理服务。"
    fi
    if [[ ! -f "$SYSTEMD_SERVICE_FILE" ]]; then
        error "shadowsocks-rust 未安装，无法执行操作。"
    fi

    case "$1" in
        start|stop|restart|status)
            if [[ "$1" == "status" ]]; then
                systemctl status --full --no-pager ss-rust
            else
                info "正在执行: systemctl $1 ss-rust"
                systemctl "$1" ss-rust
            fi
            ;;
        *)
            error "无效的操作: $1"
            ;;
    esac
}

# 执行卸载逻辑
run_uninstall_logic() {
    if [[ -f "$SYSTEMD_SERVICE_FILE" ]]; then
        info "正在停止并禁用服务..."
        systemctl stop ss-rust &>/dev/null || true
        systemctl disable ss-rust &>/dev/null || true
    fi
    info "正在删除相关文件..."
    rm -f "$BINARY_PATH"
    rm -f "$SYSTEMD_SERVICE_FILE"
    rm -rf "$INSTALL_DIR"
    if command -v systemctl &> /dev/null; then
        info "正在重载 systemd..."
        systemctl daemon-reload
    fi
    success "清理完成。"
}

# 执行安装流程
do_install() {
    if [[ -f "$BINARY_PATH" ]]; then
        warn "检测到 shadowsocks-rust 已安装。如果需要重装，请先运行卸载功能。"
        return
    fi
    local os_type arch latest_version
    os_type=$(detect_os)
    check_dependencies "$os_type"
    arch=$(detect_arch)
    latest_version=$(get_latest_version)
    download_and_install "$latest_version" "$arch"
    generate_config
    create_systemd_service
    manage_service "start"
    success "安装完成，shadowsocks-rust 已成功启动！"
    view_config
}

# 执行更新流程
do_update() {
    if [[ ! -f "$BINARY_PATH" ]]; then
        error "shadowsocks-rust 未安装。"
    fi
    local current_version latest_version arch
    current_version=$(cat "$VERSION_FILE")
    latest_version=$(get_latest_version)
    if [[ "$current_version" == "$latest_version" ]]; then
        info "您当前已是最新版本: v$current_version"
        return
    fi
    info "发现新版本，准备从 v$current_version 更新到 v$latest_version..."
    arch=$(detect_arch)
    download_and_install "$latest_version" "$arch"
    manage_service "restart"
    success "更新完成。"
}

# 执行卸载流程
do_uninstall() {
    info "准备卸载 shadowsocks-rust..."
    if [[ ! -f "$BINARY_PATH" && ! -d "$INSTALL_DIR" ]]; then
        warn "未发现任何 shadowsocks-rust 相关文件，无需卸载。"
        return
    fi
    read -p "您确定要彻底清理 shadowsocks-rust 吗? (Y/n): " choice
    if [[ "$choice" =~ ^[Nn]$ ]]; then
        info "已取消卸载操作。"
        return
    fi
    run_uninstall_logic
}

# 查看当前配置信息并生成 SS 链接
view_config() {
    if [[ ! -f "$CONFIG_PATH" ]]; then
        error "找不到配置文件，请先执行安装。"
    fi
    local ip_address
    ip_address=$(get_public_ip)
    
    local port password method node_name
    port=$(jq -r '.server_port' "$CONFIG_PATH")
    password=$(jq -r '.password' "$CONFIG_PATH")
    method=$(jq -r '.method' "$CONFIG_PATH")
    node_name="$(hostname) ss2022"

    local encoded_credentials
    encoded_credentials=$(echo -n "${method}:${password}" | base64 | tr -d '\n')
    local ss_link="ss://${encoded_credentials}@${ip_address}:${port}#${node_name}"

    {
        echo -e "\n--- Shadowsocks-2022 订阅信息 ---"
        printf "  %-15s%s\n" "${C_YELLOW}名称:${C_RESET}" "${node_name}"
        printf "  %-15s%s\n" "${C_YELLOW}服务器地址:${C_RESET}" "${ip_address}"
        printf "  %-15s%s\n" "${C_YELLOW}端口:${C_RESET}" "${port}"
        printf "  %-15s%s\n" "${C_YELLOW}密码:${C_RESET}" "${password}"
        printf "  %-15s%s\n" "${C_YELLOW}加密方式:${C_RESET}" "${method}"
        echo "-----------------------------------"
        echo -e "  ${C_GREEN}SS 链接:${C_RESET} ${ss_link}"
        echo -e "(您可以复制上面的 SS 链接直接导入到客户端)"
    } >&2
}

# ===================================================================================
# --- 主菜单与脚本入口 ---
# ===================================================================================

# 交互式主菜单
main_menu() {
    while true; do
        clear
        echo -e "${C_GREEN}======================================================${C_RESET}"
        echo -e "              ${C_BLUE}Shadowsocks-rust 管理脚本${C_RESET}"
        
        # --- 状态显示逻辑 ---
        local status_info
        if [[ -f "$VERSION_FILE" ]]; then
            local version="v$(cat "$VERSION_FILE")"
            if systemctl is-active --quiet ss-rust; then
                status_info="${C_GREEN}${version} (运行中)${C_RESET}"
            else
                status_info="${C_YELLOW}${version} (已停止)${C_RESET}"
            fi
        else
            status_info="${C_RED}未安装${C_RESET}"
        fi
        echo -e "  当前状态: ${status_info}"
        
        echo -e "${C_GREEN}======================================================${C_RESET}"
        echo ""
        echo -e "  ${C_YELLOW}1.${C_RESET} 安装 Shadowsocks-rust"
        echo -e "  ${C_YELLOW}2.${C_RESET} 更新 Shadowsocks-rust"
        echo -e "  ${C_YELLOW}3.${C_RESET} 卸载 Shadowsocks-rust"
        echo "  ------------------------------------"
        echo -e "  ${C_YELLOW}4.${C_RESET} 启动服务"
        echo -e "  ${C_YELLOW}5.${C_RESET} 停止服务"
        echo -e "  ${C_YELLOW}6.${C_RESET} 重启服务"
        echo -e "  ${C_YELLOW}7.${C_RESET} 查看服务状态"
        echo "  ------------------------------------"
        echo -e "  ${C_YELLOW}8.${C_RESET} 查看配置信息"
        echo -e "  ${C_YELLOW}0.${C_RESET} 退出脚本"
        echo ""

        read -p "请输入您的选项 [0-8]: " choice

        case "$choice" in
            1) do_install ;;
            2) do_update ;;
            3) do_uninstall ;;
            4) manage_service "start"; success "启动命令已发送" ;;
            5) manage_service "stop"; success "停止命令已发送" ;;
            6) manage_service "restart"; success "重启命令已发送" ;;
            7) manage_service "status" ;;
            8) view_config ;;
            0) exit 0 ;;
            *) error "无效的选项，请输入正确的数字。" ;;
        esac

        echo ""
        read -p "按回车键返回主菜单..."
    done
}

# 脚本主入口点，处理参数或进入菜单
main() {
    check_root

    local ss_port=""
    local ss_password=""

    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p|--port)
                ss_port="$2"
                shift 2
                ;;
            -w|--password)
                ss_password="$2"
                shift 2
                ;;
            *)
                error "未知参数: $1"
                ;;
        esac
    done

    # 非交互式安装模式
    if [[ -n "$ss_port" && -n "$ss_password" ]]; then
        non_interactive=true
        info "--- 进入一键安装模式 ---"
        info "步骤 1/6: 清理旧版本..."
        run_uninstall_logic
        info "步骤 2/6: 环境检测与依赖安装..."
        local os_type arch latest_version
        os_type=$(detect_os)
        check_dependencies "$os_type"
        arch=$(detect_arch)
        info "步骤 3/6: 下载并安装最新版本..."
        latest_version=$(get_latest_version)
        download_and_install "$latest_version" "$arch"
        info "步骤 4/6: 生成配置文件..."
        generate_config "$ss_port" "$ss_password"
        info "步骤 5/6: 创建并启动服务..."
        create_systemd_service
        manage_service "start"
        info "步骤 6/6: 显示最终配置..."
        view_config
        success "--- 一键安装完成 ---"
        exit 0
    # 参数不完整则报错
    elif [[ -n "$ss_port" || -n "$ss_password" ]]; then
        error "一键安装模式需要同时提供 --port <端口> 和 --password <密码> 参数。"
    # 无参数则进入交互式菜单
    else
        main_menu
    fi
}

# 执行主函数
main "$@"
