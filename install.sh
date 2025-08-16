#!/usr/bin/env bash
set -euo pipefail

# ===================================================================================
# 优化的 Shadowsocks Rust 管理脚本
#
# 作者：Gemini
# 版本：2.7
# 描述：一个简化且健壮的，用于安装和管理 shadowsocks-rust 的脚本。
# ===================================================================================

# --- 脚本配置与变量 ---
readonly SCRIPT_VERSION="2.7"
readonly INSTALL_DIR="/etc/ss-rust"
readonly BINARY_PATH="/usr/local/bin/ssserver" # 使用官方名称
readonly OLD_BINARY_PATH="/usr/local/bin/ss-rust" # 兼容旧脚本的路径，用于清理
readonly CONFIG_PATH="${INSTALL_DIR}/config.json"
readonly VERSION_FILE="${INSTALL_DIR}/ver.txt"
readonly SYSTEMD_SERVICE_FILE="/etc/systemd/system/ss-rust.service"

# --- 颜色定义 ---
readonly C_RESET='\033[0m'
readonly C_RED='\033[0;31m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_BLUE='\033[0;34m'

# --- 日志函数 ---
info() { echo -e "${C_BLUE}[信息]${C_RESET} $1" >&2; }
success() { echo -e "${C_GREEN}[成功]${C_RESET} $1" >&2; }
warn() { echo -e "${C_YELLOW}[警告]${C_RESET} $1" >&2; }
error() { echo -e "${C_RED}[错误]${C_RESET} $1" >&2; exit 1; }

# --- 辅助函数 ---
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        error "此脚本必须以 root 权限运行，请使用 sudo。"
    fi
}

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

detect_arch() {
    case "$(uname -m)" in
        x86_64) echo "x86_64-unknown-linux-gnu" ;;
        aarch64) echo "aarch64-unknown-linux-gnu" ;;
        armv7l) echo "armv7-unknown-linux-gnueabihf" ;;
        *) error "不支持的CPU架构: $(uname -m)" ;;
    esac
}

check_dependencies() {
    info "正在检查必要的依赖工具..."
    local dependencies=("curl" "jq" "wget" "tar" "xz" "hostname")
    local os_type="$1"
    local missing_deps=()

    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing_deps+=("$dep")
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        warn "检测到以下依赖缺失: ${missing_deps[*]}"
        read -p "是否需要现在自动安装它们? (y/N): " choice
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            install_dependencies "$os_type" "${missing_deps[@]}"
        else
            error "缺少必要的依赖，脚本无法继续运行。"
        fi
    fi
    success "所有依赖均已满足。"
}

install_dependencies() {
    local os_type="$1"
    shift
    local deps_to_install=("$@")
    info "正在安装依赖: ${deps_to_install[*]}"

    if [[ "$os_type" == "ubuntu" || "$os_type" == "debian" ]]; then
        local apt_packages=()
        for dep in "${deps_to_install[@]}"; do
            case "$dep" in
                xz) apt_packages+=("xz-utils") ;;
                hostname) apt_packages+=("hostname") ;;
                *) apt_packages+=("$dep") ;;
            esac
        done
        apt-get update
        apt-get install -y "${apt_packages[@]}"
    elif [[ "$os_type" == "centos" ]]; then
        yum install -y epel-release &>/dev/null || true
        yum install -y "${deps_to_install[@]}"
    fi
}


# --- Shadowsocks 核心功能函数 ---
get_latest_version() {
    info "正在获取 shadowsocks-rust 的最新版本号..."
    local latest_version
    latest_version=$(curl -s "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" | jq -r '.tag_name')
    if [[ -z "$latest_version" ]]; then
        error "获取最新版本失败，请检查网络或稍后再试。"
    fi
    echo "${latest_version#v}"
}

download_and_install() {
    local version="$1"
    local arch="$2"
    local download_url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${version}/shadowsocks-v${version}.${arch}.tar.xz"

    info "从以下地址下载: $download_url"
    wget -qO "/tmp/ss-rust.tar.xz" "$download_url" || error "下载失败。"

    info "正在解压并安装..."
    tar -xf "/tmp/ss-rust.tar.xz" -C /tmp
    install -m 755 /tmp/ssserver "$BINARY_PATH"
    
    mkdir -p "$INSTALL_DIR"
    echo "$version" > "$VERSION_FILE"
    
    rm -f /tmp/ss-rust.tar.xz /tmp/ssserver /tmp/sslocal /tmp/ssurl /tmp/ssmanager
    success "shadowsocks-rust v${version} 安装成功。"
}

generate_config() {
    info "正在生成配置文件..."
    local port
    read -p "请输入 Shadowsocks 端口 (默认: 8388): " port
    port=${port:-8388}

    local password
    read -p "请输入 Shadowsocks 密码 (留空则随机生成): " password
    if [[ -z "$password" ]]; then
        password=$(head -c 16 /dev/urandom | base64)
        info "已为您生成随机密码。"
    fi
    
    local method="2022-blake3-aes-256-gcm"
    info "将使用推荐的加密方式: $method"

    # 修正：默认禁用 fast_open 以提高兼容性
    jq -n \
        --arg server_port "$port" \
        --arg password "$password" \
        --arg method "$method" \
        '{
            "server": "::",
            "server_port": ($server_port | tonumber),
            "password": $password,
            "method": $method,
            "fast_open": false,
            "mode": "tcp_and_udp"
        }' > "$CONFIG_PATH"
    
    success "配置文件已创建于 $CONFIG_PATH"
}

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

# --- 服务管理 ---
manage_service() {
    if [[ ! -f "$SYSTEMD_SERVICE_FILE" ]]; then
        error "shadowsocks-rust 未安装，无法执行操作。"
    fi
    
    case "$1" in
        start|stop|restart|status)
            info "正在执行: systemctl $1 ss-rust"
            if [[ "$1" == "status" ]]; then
                systemctl status ss-rust
            else
                systemctl "$1" ss-rust
            fi
            ;;
        *)
            error "无效的操作: $1"
            ;;
    esac
}

# --- 面向用户的菜单功能 ---
do_install() {
    if [[ -f "$BINARY_PATH" || -f "$OLD_BINARY_PATH" ]]; then
        warn "检测到 shadowsocks-rust 已安装。如果需要重装，请先运行卸载功能。"
        return
    fi
    
    local os_type
    os_type=$(detect_os)
    check_dependencies "$os_type"
    
    local arch
    arch=$(detect_arch)
    
    local latest_version
    latest_version=$(get_latest_version)
    
    download_and_install "$latest_version" "$arch"
    generate_config
    create_systemd_service
    manage_service "start"
    
    success "安装完成，shadowsocks-rust 已成功启动！"
    view_config
}

do_update() {
    if [[ ! -f "$BINARY_PATH" ]]; then
        error "shadowsocks-rust 未安装。"
    fi
    
    local current_version
    current_version=$(cat "$VERSION_FILE")
    local latest_version
    latest_version=$(get_latest_version)

    if [[ "$current_version" == "$latest_version" ]]; then
        info "您当前已是最新版本: v$current_version"
        return
    fi
    
    info "发现新版本，准备从 v$current_version 更新到 v$latest_version..."
    local arch
    arch=$(detect_arch)
    download_and_install "$latest_version" "$arch"
    manage_service "restart"
    
    success "更新完成。"
}

do_uninstall() {
    # 修正：强化卸载功能，清理所有已知路径和文件
    info "准备卸载 shadowsocks-rust..."
    read -p "您确定要彻底清理 shadowsocks-rust 吗? (y/N): " choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        info "正在停止并禁用服务..."
        systemctl stop ss-rust &>/dev/null || true
        systemctl disable ss-rust &>/dev/null || true
        info "正在删除相关文件..."
        rm -f "$BINARY_PATH"
        rm -f "$OLD_BINARY_PATH"
        rm -f "$SYSTEMD_SERVICE_FILE"
        rm -rf "$INSTALL_DIR"
        info "正在重载 systemd..."
        systemctl daemon-reload
        success "shadowsocks-rust 已被彻底卸载。"
    else
        info "已取消卸载操作。"
    fi
}

view_config() {
    if [[ ! -f "$CONFIG_PATH" ]]; then
        error "找不到配置文件，请先执行安装。"
    fi

    local ip
    ip=$(curl -s --max-time 5 https://api.ipify.org) || ip="<获取IP失败,请手动查询>"
    
    local port
    port=$(jq -r '.server_port' "$CONFIG_PATH")
    local password
    password=$(jq -r '.password' "$CONFIG_PATH")
    local method
    method=$(jq -r '.method' "$CONFIG_PATH")
    
    local hostname
    hostname=$(hostname)
    local node_name="${hostname}-ss2022"
    
    local encoded_credentials
    encoded_credentials=$(echo -n "${method}:${password}" | base64 | tr -d '\n')
    local ss_link="ss://${encoded_credentials}@${ip}:${port}#${node_name}"
    
    echo -e "\n--- Shadowsocks 配置信息 ---"
    echo -e "  ${C_YELLOW}服务器地址:${C_RESET}  $ip"
    echo -e "  ${C_YELLOW}端口:${C_RESET}        $port"
    echo -e "  ${C_YELLOW}密码:${C_RESET}        $password"
    echo -e "  ${C_YELLOW}加密方式:${C_RESET}    $method"
    echo -e "  ${C_YELLOW}节点名称:${C_RESET}    $node_name"
    echo "-----------------------------------"
    echo -e "  ${C_GREEN}SS 链接:${C_RESET} $ss_link"
    echo -e "(您可以复制上面的 SS 链接直接导入到客户端)"
}

# --- 主菜单 ---
main_menu() {
    clear
    echo -e "${C_GREEN}============================================${C_RESET}"
    echo -e "  ${C_BLUE}优化的 Shadowsocks-rust 管理脚本${C_RESET}"
    echo -e "  版本: ${C_YELLOW}${SCRIPT_VERSION}${C_RESET}"
    echo -e "${C_GREEN}============================================${C_RESET}"
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
    main_menu
}

# --- 脚本入口 ---
check_root
main_menu
