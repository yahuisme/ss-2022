#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155

# Shadowsocks Rust 2022 安装管理脚本
# 安装、更新、卸载、配置和 systemd 服务管理。

set -euo pipefail

# --- 脚本配置与变量 ---
readonly SCRIPT_VERSION="4.5"
readonly INSTALL_DIR="/etc/ss-rust"
readonly BINARY_PATH="/usr/local/bin/ss-rust"
readonly CONFIG_PATH="${INSTALL_DIR}/config.json"
readonly VERSION_FILE="${INSTALL_DIR}/ver.txt"
readonly SYSTEMD_SERVICE_FILE="/etc/systemd/system/ss-rust.service"

# --- 加密配置常量 ---
readonly DEFAULT_ENCRYPTION_METHOD="2022-blake3-aes-128-gcm"
readonly AES_KEY_BYTES=16
readonly CHACHA_KEY_BYTES=32
readonly DEFAULT_PORT=8388
readonly MIN_PORT=1
readonly MAX_PORT=65535

# --- 网络配置常量 ---
readonly NETWORK_TIMEOUT=10
readonly MAX_RETRIES=3
readonly SERVICE_START_WAIT=1
readonly SERVICE_START_ATTEMPTS=5

# --- 颜色定义 ---
readonly C_RESET='\033[0m'
readonly C_RED='\033[0;31m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_BLUE='\033[0;34m'

# --- 临时目录和失败恢复 ---
readonly TMP_DIR=$(mktemp -d -t ss-rust.XXXXXX)

cleanup() {
    if [[ -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}

BACKUP_ACTIVE=false
INSTALL_COMMITTED=false

restore_install_state() {
    [[ "$BACKUP_ACTIVE" == true ]] || return 0

    if [[ -f "${TMP_DIR}/old-binary" ]]; then
        install -m 755 "${TMP_DIR}/old-binary" "$BINARY_PATH" 2>/dev/null || true
    else
        rm -f "$BINARY_PATH" 2>/dev/null || true
    fi
    if [[ -f "${TMP_DIR}/old-version" ]]; then
        install -m 644 "${TMP_DIR}/old-version" "$VERSION_FILE" 2>/dev/null || true
    else
        rm -f "$VERSION_FILE" 2>/dev/null || true
    fi
    if [[ -f "${TMP_DIR}/old-config" ]]; then
        install -m 600 "${TMP_DIR}/old-config" "$CONFIG_PATH" 2>/dev/null || true
    else
        rm -f "$CONFIG_PATH" 2>/dev/null || true
    fi
    if [[ -f "${TMP_DIR}/old-service" ]]; then
        install -m 644 "${TMP_DIR}/old-service" "$SYSTEMD_SERVICE_FILE" 2>/dev/null || true
    else
        rm -f "$SYSTEMD_SERVICE_FILE" 2>/dev/null || true
    fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        if [[ -f "${TMP_DIR}/old-service" && -f "${TMP_DIR}/was-active" ]]; then
            systemctl restart ss-rust >/dev/null 2>&1 || true
        elif [[ -f "${TMP_DIR}/old-service" ]]; then
            systemctl stop ss-rust >/dev/null 2>&1 || true
        fi
    fi
}

on_exit() {
    local status=$?
    if [[ $status -ne 0 && "$BACKUP_ACTIVE" == true && "$INSTALL_COMMITTED" != true ]]; then
        warn "操作失败，正在恢复原有安装..."
        restore_install_state
    fi
    cleanup
    return "$status"
}

trap 'on_exit' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

backup_install_state() {
    BACKUP_ACTIVE=true
    if [[ -f "$BINARY_PATH" ]]; then cp -p "$BINARY_PATH" "${TMP_DIR}/old-binary"; fi
    if [[ -f "$VERSION_FILE" ]]; then cp -p "$VERSION_FILE" "${TMP_DIR}/old-version"; fi
    if [[ -f "$CONFIG_PATH" ]]; then cp -p "$CONFIG_PATH" "${TMP_DIR}/old-config"; fi
    if [[ -f "$SYSTEMD_SERVICE_FILE" ]]; then cp -p "$SYSTEMD_SERVICE_FILE" "${TMP_DIR}/old-service"; fi
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ss-rust 2>/dev/null; then
        : > "${TMP_DIR}/was-active"
    fi
}

# --- 日志函数 ---
info() { echo -e "${C_BLUE}[信息]${C_RESET} $1" >&2; }
success() { echo -e "${C_GREEN}[成功]${C_RESET} $1" >&2; }
warn() { echo -e "${C_YELLOW}[警告]${C_RESET} $1" >&2; }
error() { echo -e "${C_RED}[错误]${C_RESET} $1" >&2; exit 1; }

# --- 安全网络请求函数 ---
safe_curl() {
    local url="$1"
    local retry=0
    
    while [[ $retry -lt $MAX_RETRIES ]]; do
        if curl -s --fail --max-time "$NETWORK_TIMEOUT" \
                --user-agent "ss-rust-manager/$SCRIPT_VERSION" \
                --tlsv1.2 "$url" 2>/dev/null; then
            return 0
        fi
        retry=$((retry + 1))
        if [[ $retry -lt $MAX_RETRIES ]]; then
            sleep $retry
        fi
    done
    return 1
}

# --- 基础检查函数 ---
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        error "此脚本必须以 root 权限运行，请使用 sudo。"
    fi
}

# --- 端口可用性检查 ---
check_port_available() {
    local port="$1"
    
    if command -v ss >/dev/null 2>&1; then
        if ss -H -ltn "sport = :$port" 2>/dev/null | grep -q . || \
           ss -H -lun "sport = :$port" 2>/dev/null | grep -q .; then
            error "端口 ${port} 已被占用，请选择其他端口。"
        fi
    elif command -v netstat >/dev/null 2>&1; then
        if netstat -tuln 2>/dev/null | awk -v p=":$port" '$4 ~ p"$" || $4 ~ p" " {found=1} END {exit !found}'; then
            error "端口 ${port} 已被占用，请选择其他端口。"
        fi
    fi
}

# --- 密码验证函数 ---
validate_password() {
    local password="$1"
    local key_bytes="$2"
    
    # 检查是否为有效的 Base64
    if ! echo "$password" | base64 -d >/dev/null 2>&1; then
        error "密码必须是有效的 Base64 编码字符串。"
    fi
    
    # 检查解码后的长度
    local decoded_len
    decoded_len=$(echo "$password" | base64 -d 2>/dev/null | wc -c)
    if [[ "$decoded_len" -ne "$key_bytes" ]]; then
        error "密码解码后的长度必须为 ${key_bytes} 字节，当前为 ${decoded_len} 字节。"
    fi
}

get_key_bytes() {
    case "$1" in
        2022-blake3-aes-128-gcm) echo "$AES_KEY_BYTES" ;;
        2022-blake3-chacha20-poly1305) echo "$CHACHA_KEY_BYTES" ;;
        *) error "不支持的加密方式: $1" ;;
    esac
}

get_public_ip() {
    info "正在查询公网IP地址..."
    local ip=""
    local ipv4_services=("https://api.ipify.org" "https://ip.sb")
    local ipv6_services=("https://api64.ipify.org" "https://ipv6.ip.sb")
    
    # 优先尝试获取 IPv4
    for service in "${ipv4_services[@]}"; do
        if ip=$(safe_curl "$service" | tr -d '[:space:]'); then
            if [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
                local valid=true octet
                IFS=. read -ra octets <<< "$ip"
                for octet in "${octets[@]}"; do
                    [[ "$octet" -le 255 ]] || valid=false
                done
                if [[ "$valid" == true ]]; then
                    echo "$ip"
                    success "成功获取公网 IPv4 地址。"
                    return 0
                fi
            fi
        fi
    done
    
    warn "未能获取公网 IPv4 地址，正在尝试获取 IPv6..."
    
    # 尝试获取 IPv6
    for service in "${ipv6_services[@]}"; do
        if ip=$(safe_curl "$service" | tr -d '[:space:]'); then
            if [[ "$ip" =~ ^[0-9a-fA-F:]+$ && "$ip" == *:* ]]; then
                echo "[$ip]"
                success "成功获取公网 IPv6 地址。"
                return 0
            fi
        fi
    done
    
    warn "无法获取公网IP地址，请检查网络连接。"
    return 1
}

detect_os() {
    if grep -qs "ubuntu" /etc/os-release; then
        echo "ubuntu"
    elif [[ -e /etc/debian_version ]]; then
        echo "debian"
    elif [[ -e /etc/redhat-release ]]; then
        echo "centos"
    else
        error "不支持的操作系统。支持的系统: Ubuntu, Debian, CentOS"
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64) echo "x86_64-unknown-linux-gnu" ;;
        aarch64) echo "aarch64-unknown-linux-gnu" ;;
        armv7l) echo "armv7-unknown-linux-gnueabihf" ;;
        *) error "不支持的CPU架构: $(uname -m). 支持的架构: x86_64, aarch64, armv7l" ;;
    esac
}

check_dependencies() {
    info "正在检查必要的依赖工具..."
    local os_type="$1"
    local dependencies=("curl" "jq" "wget" "tar" "xz" "openssl")
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

install_dependencies() {
    local os_type="$1"
    shift
    local deps_to_install=("$@")
    info "正在安装依赖: ${deps_to_install[*]}"

    local packages=()
    for dep in "${deps_to_install[@]}"; do
        case "$dep" in
            xz) 
                if [[ "$os_type" == "ubuntu" || "$os_type" == "debian" ]]; then
                    packages+=("xz-utils")
                else
                    packages+=("xz")
                fi
                ;;
            *) packages+=("$dep") ;;
        esac
    done

    case "$os_type" in
        ubuntu|debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y
            apt-get install -y "${packages[@]}"
            ;;
        centos)
            yum install -y epel-release &>/dev/null || true
            yum install -y "${packages[@]}"
            ;;
    esac
    
    success "依赖安装完成。"
}

get_latest_version() {
    info "正在获取 shadowsocks-rust 的最新版本号..."
    local latest_version
    
    latest_version=$(safe_curl "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" | jq -r '.tag_name // empty')
    
    if [[ -z "$latest_version" ]]; then
        error "获取最新版本失败，请检查网络连接或稍后重试。"
    fi
    
    latest_version="${latest_version#v}"
    echo "$latest_version"
}

download_and_install() {
    local version="$1"
    local arch="$2"
    local download_url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${version}/shadowsocks-v${version}.${arch}.tar.xz"
    local download_path="${TMP_DIR}/ss-rust.tar.xz"
    local checksum_path="${TMP_DIR}/ss-rust.tar.xz.sha256"

    info "正在下载 shadowsocks-rust v${version}..."
    
    if ! wget --timeout="$NETWORK_TIMEOUT" --tries="$MAX_RETRIES" \
             --user-agent="ss-rust-manager/$SCRIPT_VERSION" \
             -qO "$download_path" "$download_url"; then
        error "下载失败，请检查网络连接或稍后重试。"
    fi

    info "正在下载校验文件..."
    if ! wget --timeout="$NETWORK_TIMEOUT" --tries="$MAX_RETRIES" \
             --user-agent="ss-rust-manager/$SCRIPT_VERSION" \
             -qO "$checksum_path" "${download_url}.sha256"; then
        error "下载校验文件失败，已停止安装。"
    fi

    info "正在验证下载文件..."
    if [[ ! -f "$download_path" || ! -s "$download_path" ]]; then
        error "下载的文件无效或为空。"
    fi
    local checksum
    checksum=$(awk 'match($0,/^[[:xdigit:]]{64}/){print substr($0,RSTART,RLENGTH); exit}' "$checksum_path")
    if [[ ! -f "$checksum_path" || ! -s "$checksum_path" || -z "$checksum" ]]; then
        error "下载的校验文件无效或为空。"
    fi
    if ! printf '%s  %s\n' "$checksum" "$download_path" | sha256sum -c - >/dev/null; then
        error "下载文件 SHA-256 校验失败。"
    fi

    info "正在解压并安装..."
    if ! tar -xf "$download_path" -C "$TMP_DIR"; then
        error "文件解压失败，可能下载文件已损坏。"
    fi

    if [[ ! -f "${TMP_DIR}/ssserver" ]]; then
        error "解压后未找到 ssserver 可执行文件。"
    fi

    # 先准备临时文件，再原子替换，避免写入中断留下损坏二进制。
    local new_binary="${BINARY_PATH}.new.$$"
    install -m 755 "${TMP_DIR}/ssserver" "$new_binary"
    mv -f "$new_binary" "$BINARY_PATH"

    # 创建安装目录和版本文件
    mkdir -p "$INSTALL_DIR"
    local new_version="${VERSION_FILE}.new.$$"
    printf '%s\n' "$version" > "$new_version"
    chmod 644 "$new_version"
    chown root:root "$new_version"
    mv -f "$new_version" "$VERSION_FILE"

    success "shadowsocks-rust v${version} 安装成功。"
}

# --- 配置写入函数 ---
write_config() {
    local port="$1"
    local password="$2"
    local method="$3"
    
    # 确保安装目录存在
    mkdir -p "$INSTALL_DIR"
    
    # 生成配置文件
    local tmp_config="${CONFIG_PATH}.tmp.$$"

    jq -n \
        --argjson server_port "$port" \
        --arg password "$password" \
        --arg method "$method" \
        '{
            "server": "::",
            "server_port": $server_port,
            "password": $password,
            "method": $method,
            "fast_open": true,
            "mode": "tcp_and_udp",
            "timeout": 300,
            "no_delay": true
        }' > "$tmp_config"
    
    # 设置严格的文件权限
    chmod 600 "$tmp_config"
    chown root:root "$tmp_config"
    mv -f "$tmp_config" "$CONFIG_PATH"
}

generate_config() {
    local port=${1:-}
    local password=${2:-}
    local method=${3:-$DEFAULT_ENCRYPTION_METHOD}
    local key_bytes

    if [[ -z "${3:-}" && -z "$port" ]]; then
        read -p "加密方式 [1: AES-128-GCM, 2: ChaCha20-Poly1305] (默认: 1): " method_choice
        [[ "$method_choice" == "2" ]] && method="2022-blake3-chacha20-poly1305"
        [[ -z "$method_choice" || "$method_choice" == "1" ]] || error "无效的加密方式选项"
    fi
    key_bytes=$(get_key_bytes "$method")

    info "正在生成配置文件..."
    info "使用加密方式: ${method}"

    # 端口验证和输入
    if [[ -z "$port" ]]; then
        while true; do
            read -p "请输入 Shadowsocks 端口 [${MIN_PORT}-${MAX_PORT}] (默认: ${DEFAULT_PORT}): " port
            port=${port:-$DEFAULT_PORT}
            if [[ "$port" =~ ^[0-9]+$ && "$port" -ge $MIN_PORT && "$port" -le $MAX_PORT ]]; then
                check_port_available "$port"
                break
            else
                warn "输入无效，请输入一个 ${MIN_PORT} 到 ${MAX_PORT} 之间的数字。"
            fi
        done
    else
        info "使用指定的端口: $port"
        if [[ ! "$port" =~ ^[0-9]+$ || "$port" -lt $MIN_PORT || "$port" -gt $MAX_PORT ]]; then
            error "端口 $port 无效，必须在 ${MIN_PORT}-${MAX_PORT} 范围内。"
        fi
        check_port_available "$port"
    fi

    # 密码验证和输入
    if [[ -z "$password" ]]; then
        read -p "请输入 Shadowsocks 密码 (留空则随机生成): " password_input
        if [[ -z "$password_input" ]]; then
            info "为 ${method} 生成 ${key_bytes} 字节随机密码..."
            password=$(openssl rand -base64 "$key_bytes")
            success "已生成随机密码。"
        else
            password=$password_input
            validate_password "$password" "$key_bytes"
        fi
    else
        info "使用指定的密码。"
        validate_password "$password" "$key_bytes"
    fi
    
    # 写入新配置
    write_config "$port" "$password" "$method"
    success "配置文件已创建于 $CONFIG_PATH"
}

create_systemd_service() {
    info "正在创建 systemd 服务..."
    cat > "$SYSTEMD_SERVICE_FILE" << EOF
[Unit]
Description=Shadowsocks-rust Server Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$BINARY_PATH -c $CONFIG_PATH
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "$SYSTEMD_SERVICE_FILE"
    systemctl daemon-reload
    systemctl enable ss-rust
    success "Systemd 服务已创建并设为开机自启。"
}

manage_service() {
    if ! command -v systemctl &> /dev/null; then
        error "未找到 systemd，无法管理服务。"
    fi
    if [[ ! -f "$SYSTEMD_SERVICE_FILE" ]]; then
        error "shadowsocks-rust 未安装，无法执行操作。"
    fi

    case "$1" in
        start|stop|restart)
            info "正在执行: systemctl $1 ss-rust"
            if systemctl "$1" ss-rust; then
                success "$1 命令执行成功"
                if [[ "$1" == "start" || "$1" == "restart" ]]; then
                    local attempt
                    for ((attempt=1; attempt<=SERVICE_START_ATTEMPTS; attempt++)); do
                        systemctl is-active --quiet ss-rust && break
                        sleep "$SERVICE_START_WAIT"
                    done
                    if systemctl is-active --quiet ss-rust; then
                        success "服务运行正常"
                    else
                        warn "服务启动失败，请检查配置或查看日志"
                        journalctl -u ss-rust --no-pager -n 20 >&2 || true
                        return 1
                    fi
                fi
            else
                error "$1 命令执行失败"
            fi
            ;;
        status)
            echo -e "\n${C_YELLOW}=== 服务状态 ===${C_RESET}"
            systemctl status --full --no-pager ss-rust || true
            echo -e "\n${C_YELLOW}=== 最新日志 ===${C_RESET}"
            journalctl -u ss-rust --no-pager -n 10 || true
            ;;
        *)
            error "无效的操作: $1"
            ;;
    esac
}

run_uninstall_logic() {
    info "正在卸载 shadowsocks-rust..."
    
    # 停止并禁用服务
    if [[ -f "$SYSTEMD_SERVICE_FILE" ]]; then
        info "正在停止并禁用服务..."
        systemctl stop ss-rust &>/dev/null || true
        systemctl disable ss-rust &>/dev/null || true
    fi
    
    # 删除所有相关文件和目录
    info "正在删除所有相关文件和配置文件..."
    rm -f "$BINARY_PATH"
    rm -f "$SYSTEMD_SERVICE_FILE"
    rm -rf "$INSTALL_DIR"
    
    # 重载 systemd
    if command -v systemctl &> /dev/null; then
        systemctl daemon-reload
    fi
    
    success "卸载完成。"
}

install_flow() {
    local configure="$1" port="${2:-}" password="${3:-}" method="${4:-$DEFAULT_ENCRYPTION_METHOD}" version="${5:-}"
    local os_type arch

    os_type=$(detect_os)
    check_dependencies "$os_type"
    arch=$(detect_arch)
    backup_install_state
    version=${version:-$(get_latest_version)}
    download_and_install "$version" "$arch"

    if [[ "$configure" == true ]]; then
        generate_config "$port" "$password" "$method"
    fi
    create_systemd_service
    manage_service "restart"
    INSTALL_COMMITTED=true
}

do_install() {
    if [[ -f "$BINARY_PATH" ]]; then
        warn "检测到 shadowsocks-rust 已安装。"
        read -p "是否要重新安装? (y/N): " choice
        if [[ ! "$choice" =~ ^[Yy]$ ]]; then
            info "安装已取消。"
            return
        fi
        info "将覆盖现有安装..."
    fi

    install_flow true

    success "安装完成，shadowsocks-rust 已成功启动！"
    view_config
}

do_update() {
    if [[ ! -f "$BINARY_PATH" ]]; then
        error "shadowsocks-rust 未安装。请先执行安装。"
    fi

    local current_version latest_version os_type
    current_version=$(cat "$VERSION_FILE" 2>/dev/null || echo "unknown")
    os_type=$(detect_os)
    check_dependencies "$os_type"
    latest_version=$(get_latest_version)

    if [[ "$current_version" == "$latest_version" ]]; then
        info "您当前已是最新版本: v$current_version"
        return
    fi

    info "发现新版本，准备从 v$current_version 更新到 v$latest_version..."
    
    install_flow false "" "" "$DEFAULT_ENCRYPTION_METHOD" "$latest_version"
    success "更新完成！"
}

do_uninstall() {
    if [[ ! -f "$BINARY_PATH" && ! -d "$INSTALL_DIR" ]]; then
        warn "未发现任何 shadowsocks-rust 相关文件，无需卸载。"
        return
    fi

    read -p "您确定要完全卸载 shadowsocks-rust 吗? (Y/n): " choice
    if [[ "$choice" =~ ^[Nn]$ ]]; then
        info "已取消卸载操作。"
        return
    fi

    run_uninstall_logic
}

load_config() {
    [[ -f "$CONFIG_PATH" ]] || error "找不到配置文件，请先执行安装。"
    if ! config_values=$(jq -er '[.server_port, .password, .method] | @tsv' "$CONFIG_PATH" 2>/dev/null); then
        error "配置文件格式错误，无法读取必要信息。"
    fi
    IFS=$'\t' read -r current_port current_password current_method <<< "$config_values"
    [[ -n "$current_port" && -n "$current_password" && -n "$current_method" ]] || \
        error "配置文件格式错误，无法读取必要信息。"
}

do_modify_config() {
    info "加载当前配置..."
    local current_port current_password current_method key_bytes new_port new_password
    load_config
    key_bytes=$(get_key_bytes "$current_method")

    info "当前配置："
    info "  端口: $current_port"
    info "  密码: $current_password"
    echo ""
    info "请输入新配置 (直接回车则保留当前值)"
    
    # 端口输入和验证
    while true; do
        read -p "新端口 [${MIN_PORT}-${MAX_PORT}] (当前: ${current_port}): " new_port
        new_port=${new_port:-$current_port}
        if [[ "$new_port" =~ ^[0-9]+$ && "$new_port" -ge $MIN_PORT && "$new_port" -le $MAX_PORT ]]; then
            if [[ "$new_port" != "$current_port" ]]; then
                check_port_available "$new_port"
            fi
            break
        else
            warn "输入无效，请输入一个 ${MIN_PORT} 到 ${MAX_PORT} 之间的数字。"
        fi
    done

    # 密码输入和验证
    read -p "新密码 (当前: ${current_password}, 留空保留, 输入 'random' 生成新的): " new_password_input
    if [[ -z "$new_password_input" ]]; then
        new_password=$current_password
    elif [[ "$new_password_input" == "random" ]]; then
        info "正在生成新的随机密码..."
        new_password=$(openssl rand -base64 "$key_bytes")
        success "新密码: ${new_password}"
    else
        new_password=$new_password_input
        validate_password "$new_password" "$key_bytes"
    fi

    # 检查是否有变化
    if [[ "$new_port" == "$current_port" && "$new_password" == "$current_password" ]]; then
        info "配置无变化，操作已取消。"
        return
    fi

    # 写入新配置
    backup_install_state
    info "正在写入新配置..."
    write_config "$new_port" "$new_password" "$current_method"

    info "正在重启服务以应用新配置..."
    manage_service "restart"
    INSTALL_COMMITTED=true
    
    success "配置修改成功！"
    view_config
}

generate_ss_url() {
    local ip_address="$1"
    local port="$2"
    local password="$3"
    local method="$4"
    local node_name="$5"
    local encoded_password encoded_name

    encoded_password=$(printf '%s' "$password" | jq -sRr @uri)
    encoded_name=$(printf '%s' "$node_name" | jq -sRr @uri)
    printf 'ss://%s:%s@%s:%s#%s\n' \
        "$method" "$encoded_password" "$ip_address" "$port" "$encoded_name"
}

view_config() {
    local ip_address=""
    local port password method node_name ss_link
    load_config
    port="$current_port"
    password="$current_password"
    method="$current_method"
    node_name="$(hostname)-ss2022"

    if ! ip_address=$(get_public_ip); then
        warn "无法获取公网 IP，将只显示本地配置。"
    fi

    {
        echo ""
        echo -e "${C_GREEN}======================================${C_RESET}"
        echo -e "  ${C_BLUE}Shadowsocks-2022 配置信息${C_RESET}"
        echo -e "${C_GREEN}======================================${C_RESET}"
        echo -e "  ${C_YELLOW}节点名称:${C_RESET}       ${node_name}"
        if [[ -n "$ip_address" ]]; then
            echo -e "  ${C_YELLOW}服务器地址:${C_RESET}     ${ip_address}"
        else
            echo -e "  ${C_YELLOW}服务器地址:${C_RESET}     请手动填写服务器地址"
        fi
        echo -e "  ${C_YELLOW}端口:${C_RESET}           ${port}"
        echo -e "  ${C_YELLOW}密码:${C_RESET}           ${password}"
        echo -e "  ${C_YELLOW}加密方式:${C_RESET}       ${method}"
        echo -e "${C_GREEN}======================================${C_RESET}"
        echo ""
        if [[ -n "$ip_address" ]]; then
            ss_link=$(generate_ss_url "$ip_address" "$port" "$password" "$method" "$node_name")
            echo -e "  ${C_GREEN}SS链接:${C_RESET}"
            echo -e "  ${ss_link}"
        else
            echo -e "  ${C_YELLOW}SS链接:${C_RESET} 无法生成，请手动填写服务器地址"
        fi
        echo ""
        echo -e "  ${C_BLUE}提示:${C_RESET} 复制上面的SS链接导入到客户端即可使用"
        echo -e "${C_GREEN}======================================${C_RESET}"
    } >&2
}

main_menu() {
    while true; do
        clear
        echo -e "${C_GREEN}============================================================${C_RESET}"
        echo -e "  ${C_BLUE}Shadowsocks-rust 管理脚本 (v${SCRIPT_VERSION})${C_RESET}"
        
        local status_info
        if [[ -f "$VERSION_FILE" ]]; then
            local version="v$(cat "$VERSION_FILE")"
            if systemctl is-active --quiet ss-rust 2>/dev/null; then
                status_info="${C_GREEN}${version} (运行中)${C_RESET}"
            else
                status_info="${C_YELLOW}${version} (已停止)${C_RESET}"
            fi
        else
            status_info="${C_RED}未安装${C_RESET}"
        fi
        echo -e "  当前状态: ${status_info}"
        
        echo -e "${C_GREEN}============================================================${C_RESET}"
        echo ""
        echo -e "  ${C_YELLOW}1.${C_RESET} 安装 Shadowsocks-rust"
        echo -e "  ${C_YELLOW}2.${C_RESET} 更新 Shadowsocks-rust"
        echo -e "  ${C_YELLOW}3.${C_RESET} 卸载 Shadowsocks-rust"
        echo "  ------------------------------------"
        echo -e "  ${C_YELLOW}4.${C_RESET} 修改配置 (端口/密码)"
        echo -e "  ${C_YELLOW}5.${C_RESET} 查看配置信息"
        echo "  ------------------------------------"
        echo -e "  ${C_YELLOW}6.${C_RESET} 启动服务"
        echo -e "  ${C_YELLOW}7.${C_RESET} 停止服务"
        echo -e "  ${C_YELLOW}8.${C_RESET} 重启服务"
        echo -e "  ${C_YELLOW}9.${C_RESET} 查看服务状态"
        echo "  ------------------------------------"
        echo -e "  ${C_YELLOW}0.${C_RESET} 退出脚本"
        echo ""

        read -p "请输入您的选项 [0-9]: " choice

        case "$choice" in
            1) do_install ;;
            2) do_update ;;
            3) do_uninstall ;;
            4) do_modify_config ;;
            5) view_config ;;
            6) manage_service "start" ;;
            7) manage_service "stop" ;;
            8) manage_service "restart" ;;
            9) manage_service "status" ;;
            0) 
                info "感谢使用！"
                exit 0 
                ;;
            *) 
                warn "无效的选项，请输入正确的数字 (0-9)。" 
                ;;
        esac

        echo ""
        read -p "按回车键返回主菜单..."
    done
}

# --- 脚本入口 ---
main() {
    check_root

    local ss_port=""
    local ss_password=""
    local ss_method="$DEFAULT_ENCRYPTION_METHOD"
    local force_install=false

    # 参数解析
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p|--port)
                if [[ -z "$2" || "$2" =~ ^- ]]; then
                    error "参数 $1 需要指定端口号"
                fi
                ss_port="$2"
                shift 2
                ;;
            -w|--password)
                if [[ -z "$2" || "$2" =~ ^- ]]; then
                    error "参数 $1 需要指定密码"
                fi
                ss_password="$2"
                shift 2
                ;;
            -m|--method)
                if [[ -z "${2:-}" || "$2" =~ ^- ]]; then
                    error "参数 $1 需要指定加密方式"
                fi
                get_key_bytes "$2" >/dev/null
                ss_method="$2"
                shift 2
                ;;
            -f|--force)
                force_install=true
                shift
                ;;
            -h|--help)
                cat << EOF
Shadowsocks-rust 管理脚本 v${SCRIPT_VERSION}

用法:
  $0 [选项]

选项:
  -p, --port <端口>     指定端口 (1-65535)
  -w, --password <密码> 指定 Base64 编码的密钥
  -m, --method <方式>   2022-blake3-aes-128-gcm 或 2022-blake3-chacha20-poly1305
  -f, --force           强制重新安装 (覆盖现有安装)
  -h, --help            显示此帮助信息

示例:
  # 交互式安装
  $0
  
  # 一键安装 (指定端口和随机密码，默认 AES-128-GCM)
  $0 --port 8388 --password \$(openssl rand -base64 16)

  # 使用 ChaCha20-Poly1305
  $0 --port 8388 --password \$(openssl rand -base64 32) --method 2022-blake3-chacha20-poly1305

  # 强制重新安装
  $0 --port 8388 --password <base64_password> --force

EOF
                exit 0
                ;;
            *)
                error "未知参数: $1. 使用 -h 或 --help 查看帮助信息。"
                ;;
        esac
    done

    # 一键安装模式
    if [[ -n "$ss_port" && -n "$ss_password" ]]; then
        non_interactive=true
        info "=== 进入一键安装模式 ==="

        # 验证参数
        if [[ ! "$ss_port" =~ ^[0-9]+$ || "$ss_port" -lt $MIN_PORT || "$ss_port" -gt $MAX_PORT ]]; then
            error "端口 $ss_port 无效，必须在 ${MIN_PORT}-${MAX_PORT} 范围内"
        fi
        
        validate_password "$ss_password" "$(get_key_bytes "$ss_method")"

        # 检查是否已安装
        if [[ -f "$BINARY_PATH" && "$force_install" != true ]]; then
            error "shadowsocks-rust 已安装。使用 --force 参数强制重新安装。"
        fi

        info "开始检查依赖、下载并安装..."
        install_flow true "$ss_port" "$ss_password" "$ss_method"

        info "显示最终配置..."
        view_config

        success "=== 一键安装完成 ==="
        exit 0
        
    elif [[ -n "$ss_port" || -n "$ss_password" ]]; then
        error "一键安装模式需要同时提供 --port 和 --password 参数。"
    else
        # 交互模式
        main_menu
    fi
}

# 执行主函数
main "$@"
