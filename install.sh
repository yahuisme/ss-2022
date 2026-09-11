#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155

# Shadowsocks Rust 2022 安装管理脚本
# 安装、更新、卸载、配置和 systemd 服务管理。

set -euo pipefail

# --- 脚本配置与变量 ---
readonly SCRIPT_VERSION="26.09.11"
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
readonly DOWNLOAD_TIMEOUT=60
readonly MAX_RETRIES=3
readonly SERVICE_START_WAIT=1
readonly SERVICE_START_ATTEMPTS=5

# --- 颜色定义 ---
readonly C_RESET=$'\033[0m'
readonly C_RED=$'\033[91m'
readonly C_GREEN=$'\033[92m'
readonly C_YELLOW=$'\033[93m'
readonly C_BLUE=$'\033[94m'
readonly C_CYAN=$'\033[96m'
readonly C_MAGENTA=$'\033[95m'

# --- 临时目录和失败恢复 ---
TMP_DIR=""

init_temp_dir() {
    TMP_DIR=$(mktemp -d -t ss-rust.XXXXXX) ||
        error "无法创建临时目录。"
}

cleanup() {
    if [[ -f "${TMP_DIR}/KEEP" ]]; then
        warn "恢复材料保留在: $TMP_DIR"
    elif [[ -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR" || warn "无法清理临时目录: $TMP_DIR"
    fi
}

cleanup_uninstall_residue() {
    # 清理中断操作可能留下的临时目录、原子替换文件和 systemd drop-in。
    # 不删除其他会话或回滚失败留下的恢复目录。
    find /usr/local/bin -maxdepth 1 -type f -user root -name 'ss-rust.new.*' -delete || return 1
    rm -rf /etc/systemd/system/ss-rust.service.d /run/ss-rust || return 1
}

BACKUP_ACTIVE=false
INSTALL_COMMITTED=false

restore_install_state() {
    [[ "$BACKUP_ACTIVE" == true ]] || return 0
    local failed=false name target mode
    # 首次安装失败：先停止并禁用新服务，避免删除 unit 后遗留运行进程。
    if [[ ! -f "${TMP_DIR}/old-service" && -f "$SYSTEMD_SERVICE_FILE" ]]; then
        if ! systemctl stop ss-rust || ! systemctl disable ss-rust; then
            warn "无法停止或禁用新服务，请手动恢复: $TMP_DIR"
            return 1
        fi
    fi
    for name in binary version config service; do
        case "$name" in
            binary) target="$BINARY_PATH"; mode=755 ;;
            version) target="$VERSION_FILE"; mode=644 ;;
            config) target="$CONFIG_PATH"; mode=644 ;;
            service) target="$SYSTEMD_SERVICE_FILE"; mode=644 ;;
        esac
        if [[ -f "${TMP_DIR}/old-$name" ]]; then
            install -m "$mode" "${TMP_DIR}/old-$name" "$target" || failed=true
        else
            rm -f "$target" || failed=true
        fi
    done
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload || failed=true
        if [[ -f "${TMP_DIR}/was-enabled" ]]; then
            systemctl enable ss-rust || failed=true
        elif [[ -f "${TMP_DIR}/was-disabled" ]]; then
            systemctl disable ss-rust || failed=true
        fi
        if [[ -f "${TMP_DIR}/old-service" ]]; then
            if [[ -f "${TMP_DIR}/was-active" ]]; then
                systemctl restart ss-rust && systemctl is-active --quiet ss-rust || failed=true
            else
                systemctl stop ss-rust || failed=true
            fi
        fi
    fi
    if [[ "$failed" == true ]]; then
        warn "回滚未完成，请手动恢复: $TMP_DIR"
        return 1
    fi
}

on_exit() {
    local status=$?
    if [[ $status -ne 0 && "$BACKUP_ACTIVE" == true && "$INSTALL_COMMITTED" != true ]]; then
        warn "操作失败，正在恢复原有安装..."
        : > "${TMP_DIR}/KEEP" || { warn "无法标记恢复材料: $TMP_DIR"; return 1; }
        if restore_install_state; then
            rm -f "${TMP_DIR}/KEEP" || return 1
        fi
    fi
    # 仅主 shell 退出时清理；菜单子 shell 退出不清理（TMP_DIR 跨菜单操作共享）
    [[ $$ == "$BASHPID" ]] && cleanup
    return "$status"
}

trap 'on_exit' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

backup_install_state() {
    INSTALL_COMMITTED=false
    BACKUP_ACTIVE=false
    if [[ -f "${TMP_DIR}/KEEP" ]]; then
        error "有未恢复的备份，请先处理: $TMP_DIR"
    fi
    mkdir -p "$TMP_DIR" || error "创建临时目录失败。"
    rm -f "${TMP_DIR}/old-"{binary,version,config,service} "${TMP_DIR}/was-"{active,enabled,disabled} || error "清理旧快照失败。"
    if [[ -f "$BINARY_PATH" ]]; then cp -p "$BINARY_PATH" "${TMP_DIR}/old-binary" || error "备份旧程序失败，已中止操作。"; fi
    if [[ -f "$VERSION_FILE" ]]; then cp -p "$VERSION_FILE" "${TMP_DIR}/old-version" || error "备份版本文件失败，已中止操作。"; fi
    if [[ -f "$CONFIG_PATH" ]]; then cp -p "$CONFIG_PATH" "${TMP_DIR}/old-config" || error "备份配置文件失败，已中止操作。"; fi
    if [[ -f "$SYSTEMD_SERVICE_FILE" ]]; then cp -p "$SYSTEMD_SERVICE_FILE" "${TMP_DIR}/old-service" || error "备份服务文件失败，已中止操作。"; fi
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ss-rust 2>/dev/null; then
        : > "${TMP_DIR}/was-active" || error "保存服务状态失败。"
    fi
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-enabled --quiet ss-rust 2>/dev/null; then
            : > "${TMP_DIR}/was-enabled" || error "保存服务状态失败。"
        else
            : > "${TMP_DIR}/was-disabled" || error "保存服务状态失败。"
        fi
    fi
    BACKUP_ACTIVE=true
}

# 按实际输出 fd 判断：重定向到 stderr 后，fd 1 即 stderr 的目标。
# shellcheck disable=SC2059 # printf 包装器，格式串均来自脚本常量
cprintf() {
    local arg
    local -a args=()
    if [[ -t 1 && -z "${NO_COLOR+x}" && "${TERM:-dumb}" != dumb ]]; then
        printf "$@"
    else
        for arg in "$@"; do
            arg=${arg//${C_RESET}/}
            arg=${arg//${C_RED}/}
            arg=${arg//${C_GREEN}/}
            arg=${arg//${C_YELLOW}/}
            arg=${arg//${C_BLUE}/}
            arg=${arg//${C_CYAN}/}
            arg=${arg//${C_MAGENTA}/}
            args+=("$arg")
        done
        printf "${args[@]}"
    fi
}

# --- 日志函数 ---
info() { cprintf '%b[信息]%b %s\n' "$C_BLUE" "$C_RESET" "$1" >&2; }
success() { cprintf '%b[成功]%b %s\n' "$C_GREEN" "$C_RESET" "$1" >&2; }
warn() { cprintf '%b[警告]%b %s\n' "$C_YELLOW" "$C_RESET" "$1" >&2; }
error() {
    local msg="$1"
    local code="${2:-1}"
    cprintf '%b[错误]%b %s\n' "$C_RED" "$C_RESET" "$msg" >&2
    # 根据错误内容提供简单建议
    case "$msg" in
        *"网络"*|*"下载"*) cprintf '%b[提示]%b 检查网络连接或更换DNS\n' "$C_YELLOW" "$C_RESET" >&2 ;;
        *"权限"*|*"root"*) cprintf '%b[提示]%b 请使用 sudo 运行脚本\n' "$C_YELLOW" "$C_RESET" >&2 ;;
        *"端口"*) cprintf '%b[提示]%b 尝试使用其他端口号\n' "$C_YELLOW" "$C_RESET" >&2 ;;
    esac
    exit "$code"
}

# --- 界面助手 ---
draw_divider() {
    printf '%s\n' "────────────────────────────────────"
}

menu_item() { # <颜色> <编号> <说明>
    local color="$1" num="$2" label="$3"
    cprintf "  %b%-2s%b %s\n" "$color" "$num" "$C_RESET" "$label"
}

# --- 安全网络请求函数 ---
readonly CURL_USER_AGENT="ss-rust-manager/$SCRIPT_VERSION"

safe_curl() {
    local url="$1"

    curl -s -fL --retry "$MAX_RETRIES" \
        --connect-timeout "$NETWORK_TIMEOUT" \
        --max-time "$NETWORK_TIMEOUT" \
        --tlsv1.2 \
        --user-agent "$CURL_USER_AGENT" \
        "$url"
}

download_file() {
    local output="$1"
    local url="$2"

    curl -fsSL --retry "$MAX_RETRIES" \
        --connect-timeout "$NETWORK_TIMEOUT" \
        --max-time "$DOWNLOAD_TIMEOUT" \
        --tlsv1.2 \
        --user-agent "$CURL_USER_AGENT" \
        -o "$output" "$url"
}

decode_base64() {
    if base64 --help 2>&1 | grep -q -- '--strict'; then
        base64 --decode --strict
    else
        base64 --decode
    fi
}

# --- 基础检查函数 ---
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        error "此脚本必须以 root 权限运行，请使用 sudo。"
    fi
}

check_systemd() {
    command -v systemctl >/dev/null 2>&1 ||
        error "未找到 systemd/systemctl，此脚本无法安装或管理服务。"
}

check_tty() {
    if ! ( : </dev/tty ) 2>/dev/null; then
        error "交互模式需要可用的 TTY，请使用完整参数执行非交互安装。"
    fi
}

# --- 端口可用性检查 ---
check_port_available() {
    local port="$1"
    local port_in_use=false

    if command -v ss >/dev/null 2>&1; then
        if ss -H -ltn "sport = :$port" 2>/dev/null | grep -q . || \
           ss -H -lun "sport = :$port" 2>/dev/null | grep -q .; then
            port_in_use=true
        fi
    fi
    # ss 不可用或版本过旧（iproute2 < 4.9 无 -H，调用失败）时回退 netstat，避免静默跳过检查
    if [[ "$port_in_use" == false ]] && command -v netstat >/dev/null 2>&1; then
        if netstat -tuln 2>/dev/null | awk -v p=":$port" '$4 ~ p"$" || $4 ~ p" " {found=1} END {exit !found}'; then
            port_in_use=true
        fi
    fi
    if [[ "$port_in_use" == true ]]; then
        error "端口 ${port} 已被占用，请选择其他端口。"
    fi
}

validate_port() {
    local port="$1"
    # 拒绝前导 0 与 0 本身：避免 bash 八进制解析歧义，且端口应无前导零
    [[ "$port" =~ ^[1-9][0-9]{0,4}$ && "$port" -le "$MAX_PORT" ]] ||
        error "端口 $port 无效，必须在 ${MIN_PORT}-${MAX_PORT} 范围内。"
}

validate_version() {
    local version="$1"
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] ||
        error "版本号格式无效: $version"
}

# --- 密码验证函数 ---
validate_password() {
    local password="$1"
    local key_bytes="$2"
    
    # 检查是否为严格有效的 Base64
    if [[ ! "$password" =~ ^[A-Za-z0-9+/]+={0,2}$ || $((${#password} % 4)) -ne 0 ]]; then
        error "密码必须是有效的 Base64 编码字符串。"
    fi
    local decoded_file canonical_password
    decoded_file=$(mktemp "${TMP_DIR}/decoded-key.XXXXXX") || error "创建临时文件失败。"
    if ! printf '%s' "$password" | decode_base64 >"$decoded_file" 2>/dev/null; then
        rm -f "$decoded_file"
        error "密码必须是有效的 Base64 编码字符串。"
    fi

    # 检查解码后的长度
    local decoded_len
    decoded_len=$(wc -c <"$decoded_file") || error "读取密钥长度失败。"
    if [[ "$decoded_len" -ne "$key_bytes" ]]; then
        rm -f "$decoded_file"
        error "密码解码后的长度必须为 ${key_bytes} 字节，当前为 ${decoded_len} 字节。"
    fi
    canonical_password=$(base64 <"$decoded_file" | tr -d '\n') || error "编码密钥失败。"
    rm -f "$decoded_file"
    [[ "$password" == "$canonical_password" ]] || \
        error "密码必须使用规范的 Base64 编码格式。"
}

get_key_bytes() {
    case "$1" in
        2022-blake3-aes-128-gcm) echo "$AES_KEY_BYTES" ;;
        2022-blake3-chacha20-poly1305) echo "$CHACHA_KEY_BYTES" ;;
        *) error "不支持的加密方式: $1" ;;
    esac
}

validate_config_values() {
    local port="$1" password="$2" method="$3" key_bytes

    validate_port "$port"
    key_bytes=$(get_key_bytes "$method") || error "获取密钥长度失败。"
    validate_password "$password" "$key_bytes"
}

# 宽松校验：用于读取/更新既有配置，不强制规范 Base64（shadowsocks-rust 运行时接受无填充 key），
# 避免用户手动修改过的合法配置阻断更新、修改或查看。
validate_existing_password() {
    local password="$1" key_bytes="$2"

    # 仅检查字符集与解码长度；不要求 4 的倍数长度（无 padding 的标准 base64 合法；
    # base64url 字符 -_ 非法，上游 STANDARD 字母表与下方正则均拒绝）
    if [[ ! "$password" =~ ^[A-Za-z0-9+/]+={0,2}$ ]]; then
        error "配置中的密码不是有效的 Base64 字符串，请使用选项 4 重新设置密码。"
    fi
    local decoded_len
    decoded_len=$(printf '%s' "$password" | decode_base64 2>/dev/null | wc -c)
    if [[ "$decoded_len" -ne "$key_bytes" ]]; then
        error "配置中的密码解码后长度（${decoded_len} 字节）与加密方式要求的 ${key_bytes} 字节不匹配，请使用选项 4 重新设置密码。"
    fi
}

validate_existing_config_values() {
    local port="$1" password="$2" method="$3" key_bytes

    validate_port "$port"
    key_bytes=$(get_key_bytes "$method") || error "获取密钥长度失败。"
    validate_existing_password "$password" "$key_bytes"
}

validate_ipv4() {
    local ip="$1" octet
    local -a octets
    [[ "$ip" =~ ^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$ ]] || return 1
    IFS=. read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        ((10#$octet <= 255)) || return 1
    done
}

validate_ipv6() {
    local ip="$1" tail group left right count=0 compressed=false
    local -a groups
    [[ "$ip" == *:* ]] || return 1
    if [[ "$ip" == *.* ]]; then
        tail=${ip##*:}
        validate_ipv4 "$tail" || return 1
        ip="${ip%:*}:0:0"
    fi
    [[ "$ip" =~ ^[0-9a-fA-F:]+$ && "$ip" != *:::* ]] || return 1
    if [[ "$ip" == *::* ]]; then
        compressed=true
        left=${ip%%::*}; right=${ip#*::}
        [[ "$right" != *::* ]] || return 1
        ip="${left}${left:+:}${right}"
        ip=${ip%:}
    else
        [[ "$ip" != :* && "$ip" != *: ]] || return 1
    fi
    if [[ -n "$ip" ]]; then
        IFS=: read -ra groups <<< "$ip"
        for group in "${groups[@]}"; do
            [[ "$group" =~ ^[0-9a-fA-F]{1,4}$ ]] || return 1
            count=$((count + 1))
        done
    fi
    if [[ "$compressed" == true ]]; then
        ((count < 8))
    else
        ((count == 8))
    fi
}

get_public_ip() {
    # 优先使用缓存的公网地址，避免每次查看配置都发起网络请求
    local cached_ip=""
    if [[ -f "${INSTALL_DIR}/.public-ip" ]]; then
        # 缓存超过 1 天则刷新，避免 VPS 公网 IP 变更后长期显示旧地址
        if [[ -z "$(find "${INSTALL_DIR}/.public-ip" -mmin +1440 2>/dev/null)" ]]; then
            cached_ip=$(<"${INSTALL_DIR}/.public-ip")
        fi
    fi
    if validate_ipv4 "$cached_ip" || { [[ "$cached_ip" == \[*\] ]] && validate_ipv6 "${cached_ip:1:${#cached_ip}-2}"; }; then
        echo "$cached_ip"
        return 0
    fi

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
                    [[ $((10#$octet)) -le 255 ]] || valid=false
                done
                if [[ "$valid" == true ]]; then
                    echo "$ip"
                    { [[ -d "${INSTALL_DIR}" ]] && printf '%s\n' "$ip" 2>/dev/null > "${INSTALL_DIR}/.public-ip"; } || true
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
            if validate_ipv6 "$ip"; then
                echo "[$ip]"
                { [[ -d "${INSTALL_DIR}" ]] && printf '%s\n' "[$ip]" 2>/dev/null > "${INSTALL_DIR}/.public-ip"; } || true
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
    # 使用静态链接的 musl 构建，不依赖系统 glibc 版本，兼容老发行版。
    case "$(uname -m)" in
        x86_64) echo "x86_64-unknown-linux-musl" ;;
        aarch64) echo "aarch64-unknown-linux-musl" ;;
        armv7l) echo "armv7-unknown-linux-musleabihf" ;;
        *) error "不支持的CPU架构: $(uname -m). 支持的架构: x86_64, aarch64, armv7l" ;;
    esac
}

check_dependencies() {
    info "正在检查必要的依赖工具..."
    local os_type="$1"
    local dependencies=("curl" "jq" "tar" "xz" "openssl")
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
            read -r -p " -> 是否需要现在自动安装它们? (Y/n): " choice < /dev/tty || error "输入已终止。"
            if [[ "$choice" =~ ^[Nn]$ ]]; then
                error "缺少必要的依赖，脚本无法继续运行。"
            fi
        fi
        install_dependencies "$os_type" "${missing_deps[@]}" || error "安装依赖失败。"
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
            apt-get -o DPkg::Lock::Timeout=600 update -y || error "更新软件源失败。"
            apt-get -o DPkg::Lock::Timeout=600 install -y "${packages[@]}" || error "安装依赖失败。"
            ;;
        centos)
            yum install -y epel-release &>/dev/null || true
            yum install -y "${packages[@]}" || error "安装依赖失败。"
            ;;
    esac
    
    success "依赖安装完成。"
}

get_latest_version() {
    info "正在获取 shadowsocks-rust 的最新版本号..."
    local latest_version
    
    if ! latest_version=$(safe_curl "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" | jq -r '.tag_name // empty'); then
        error "获取最新版本失败，请检查网络连接或稍后重试。"
    fi

    if [[ -z "$latest_version" ]]; then
        error "获取最新版本失败，请检查网络连接或稍后重试。"
    fi
    
    latest_version="${latest_version#v}"
    validate_version "$latest_version"
    echo "$latest_version"
}

download_and_install() {
    local version="$1"
    local arch="$2"
    local download_url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${version}/shadowsocks-v${version}.${arch}.tar.xz"
    local download_path="${TMP_DIR}/ss-rust.tar.xz"
    local checksum_path="${TMP_DIR}/ss-rust.tar.xz.sha256"

    info "正在下载 shadowsocks-rust v${version}..."
    
    if ! download_file "$download_path" "$download_url"; then
        error "下载失败，请检查网络连接或稍后重试。"
    fi

    info "正在下载校验文件..."
    if ! download_file "$checksum_path" "${download_url}.sha256"; then
        error "下载校验文件失败，已停止安装。"
    fi

    info "正在验证下载文件..."
    if [[ ! -s "$download_path" ]]; then
        error "下载的文件无效或为空。"
    fi
    # 提取校验和：取首行首个字段（read 原生处理，兼容所有 awk 方言与 CRLF）
    local checksum
    read -r checksum _ < "$checksum_path" || error "下载的校验文件无效或为空。"
    if [[ ! "$checksum" =~ ^[0-9A-Fa-f]{64}$ ]]; then
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
    mkdir -p "$INSTALL_DIR" || error "创建安装目录失败。"
    local new_binary
    new_binary=$(mktemp "${BINARY_PATH}.new.XXXXXX") || error "创建临时文件失败。"
    install -m 755 "${TMP_DIR}/ssserver" "$new_binary" || error "安装程序失败。"
    mv -f "$new_binary" "$BINARY_PATH" || error "替换程序失败。"

    # 创建版本文件
    local new_version
    new_version=$(mktemp "${VERSION_FILE}.new.XXXXXX") || error "创建临时文件失败。"
    printf '%s\n' "$version" > "$new_version" || error "写入版本失败。"
    chmod 644 "$new_version" || error "设置版本权限失败。"
    chown root:root "$new_version" || error "设置版本所有者失败。"
    mv -f "$new_version" "$VERSION_FILE" || error "替换版本失败。"

    info "程序 v${version} 已写入。"
}

# --- 配置写入函数 ---
write_config() {
    local port="$1"
    local password="$2"
    local method="$3"
    
    # 确保安装目录存在
    mkdir -p "$INSTALL_DIR" || error "创建安装目录失败。"
    
    # 生成配置文件
    local tmp_config
    tmp_config=$(mktemp "${CONFIG_PATH}.tmp.XXXXXX") || error "创建临时文件失败。"

    local source=/dev/null
    local -a jq_mode=(-n)
    if [[ -f "$CONFIG_PATH" ]]; then
        jq -se 'length == 1 and (.[0] | type == "object")' "$CONFIG_PATH" >/dev/null || error "原配置不是单个 JSON 对象。"
        source="$CONFIG_PATH"
        jq_mode=()
    fi
    jq -e "${jq_mode[@]}" \
        --argjson server_port "$port" \
        --arg password "$password" \
        --arg method "$method" \
        'if . == null then {
            "server": "::",
            "server_port": $server_port,
            "password": $password,
            "method": $method,
            "fast_open": false,
            "mode": "tcp_and_udp",
            "timeout": 300,
            "no_delay": true
        } elif type == "object" then . else error("invalid config") end
        | .server_port = $server_port | .password = $password | .method = $method' \
        "$source" > "$tmp_config" || error "生成配置失败。"
    
    # 设置严格的文件权限（nobody 用户运行需可读；root 拥有）
    chmod 644 "$tmp_config" || error "设置配置权限失败。"
    chown root:root "$tmp_config" || error "设置配置所有者失败。"
    mv -f "$tmp_config" "$CONFIG_PATH" || error "替换配置失败。"
}

generate_config() {
    local port=${1:-}
    local password=${2:-}
    local method=${3:-$DEFAULT_ENCRYPTION_METHOD}
    local key_bytes

    if [[ -z "${3:-}" && -z "$port" ]]; then
        printf '%s\n' "  1. 2022-blake3-aes-128-gcm" "  2. 2022-blake3-chacha20-poly1305" "  有 AES 加速优先 AES，否则选 ChaCha。" >&2
        read -r -p " -> 加密方式 [1-2] (默认: 1): " method_choice < /dev/tty || error "输入已终止。"
        [[ "$method_choice" == "2" ]] && method="2022-blake3-chacha20-poly1305"
        [[ -z "$method_choice" || "$method_choice" == "1" || "$method_choice" == "2" ]] || error "无效的加密方式选项"
    fi
    key_bytes=$(get_key_bytes "$method") || error "获取密钥长度失败。"

    info "正在生成配置文件..."
    info "使用加密方式: ${method}"

    # 端口验证和输入
    if [[ -z "$port" ]]; then
        while true; do
            read -r -p " -> 请输入端口 [${MIN_PORT}-${MAX_PORT}] (默认: ${DEFAULT_PORT}): " port < /dev/tty || error "输入已终止。"
            port=${port:-$DEFAULT_PORT}
            if [[ "$port" =~ ^[1-9][0-9]{0,4}$ && "$port" -le $MAX_PORT ]]; then
                if ( check_port_available "$port" 2>/dev/null ); then
                    break
                fi
                warn "端口 ${port} 已被占用，请换一个端口。"
            else
                warn "输入无效，请输入一个 ${MIN_PORT} 到 ${MAX_PORT} 之间的数字。"
            fi
        done
    else
        info "使用指定的端口: $port"
        validate_port "$port"
        check_port_available "$port"
    fi

    # 密码验证和输入（校验失败可重新输入，与端口输入一致）
    if [[ -z "$password" ]]; then
        while true; do
            read -r -s -p " -> 密钥 (${key_bytes} 字节的规范 Base64，输入不回显；回车随机): " password_input < /dev/tty || error "输入已终止。"
            printf '\n' >&2
            if [[ -z "$password_input" ]]; then
                info "为 ${method} 生成 ${key_bytes} 字节随机密码..."
                password=$(openssl rand -base64 "$key_bytes") || error "生成随机密码失败。"
                success "已生成随机密码。"
                break
            fi
            if ( validate_password "$password_input" "$key_bytes" ) 2>/dev/null; then
                password="$password_input"
                break
            fi
            warn "密码无效：必须是 ${key_bytes} 字节的规范 Base64 编码（可留空随机生成）。"
        done
    else
        info "使用指定的密码。"
        validate_password "$password" "$key_bytes"
    fi
    
    validate_config_values "$port" "$password" "$method"

    # 写入新配置
    write_config "$port" "$password" "$method" || error "写入配置失败。"
    success "配置文件已创建于 $CONFIG_PATH"
}

create_systemd_service() {
    info "正在创建 systemd 服务..."
    cat > "$SYSTEMD_SERVICE_FILE" << EOF || error "写入服务失败。"
[Unit]
Description=Shadowsocks-rust Server Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=$BINARY_PATH -c $CONFIG_PATH
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=3
LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "$SYSTEMD_SERVICE_FILE" || error "设置服务权限失败。"
    if ! systemctl daemon-reload; then
        error "systemd daemon-reload 失败。"
    fi
    if ! systemctl enable ss-rust; then
        error "ss-rust 服务设置开机自启失败。"
    fi
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
            cprintf '%b\n' "\\n${C_YELLOW}=== 服务状态 ===${C_RESET}"
            systemctl status --full --no-pager ss-rust || true
            cprintf '%b\n' "\\n${C_YELLOW}=== 最新日志 ===${C_RESET}"
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
    if command -v systemctl >/dev/null 2>&1; then
        if [[ -f "$SYSTEMD_SERVICE_FILE" ]] || systemctl is-enabled --quiet ss-rust 2>/dev/null || systemctl is-active --quiet ss-rust 2>/dev/null; then
            info "正在停止并禁用服务..."
            if ! systemctl stop ss-rust &>/dev/null; then
                if [[ ! -f "$SYSTEMD_SERVICE_FILE" ]]; then
                    # 服务文件缺失（可能被手动删除），直接终止残留进程
                    warn "服务文件缺失，正在直接终止 ss-rust 进程..."
                    pkill -x ss-rust &>/dev/null || true
                else
                    error "无法停止 ss-rust 服务，已中止卸载。"
                fi
            fi
            if systemctl is-active --quiet ss-rust 2>/dev/null; then
                pkill -x ss-rust &>/dev/null || true
                if systemctl is-active --quiet ss-rust 2>/dev/null; then
                    error "ss-rust 服务仍在运行，已中止卸载。"
                fi
            fi
            systemctl disable ss-rust &>/dev/null || error "无法禁用服务，已中止卸载。"
        fi
    fi

    # 删除所有相关文件、配置和临时备份
    info "正在删除所有相关文件和配置..."
    rm -f "$BINARY_PATH" "$SYSTEMD_SERVICE_FILE" || error "删除程序或服务失败。"
    rm -rf "$INSTALL_DIR" || error "删除配置失败。"

    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload || error "systemd 重载失败。"
        systemctl reset-failed ss-rust >/dev/null 2>&1 || true
    fi
    cleanup_uninstall_residue || error "清理卸载残留失败。"

    success "卸载完成；恢复目录不自动删除。"
}

install_flow() {
    local configure="$1" port="${2:-}" password="${3:-}" method="${4:-$DEFAULT_ENCRYPTION_METHOD}" version="${5:-}"
    local os_type arch

    check_systemd
    os_type=$(detect_os) || error "检测系统失败。"
    check_dependencies "$os_type" || error "检查依赖失败。"
    arch=$(detect_arch) || error "检测架构失败。"
    backup_install_state || error "备份失败。"
    # 残留处理：unit 存在但程序不存在（中断的卸载/手动删除残留）→ 移除旧 unit，让下方重建正式服务
    if [[ -f "$SYSTEMD_SERVICE_FILE" && ! -f "$BINARY_PATH" ]]; then
        warn "检测到残留的 systemd 服务文件（程序不存在），正在移除并重新创建服务..."
        rm -f "$SYSTEMD_SERVICE_FILE" || error "删除残留服务失败。"
        systemctl daemon-reload >/dev/null 2>&1 || error "重载服务失败。"
    fi
    if [[ -f "$SYSTEMD_SERVICE_FILE" ]]; then
        if systemctl is-active --quiet ss-rust 2>/dev/null; then
            info "正在暂时停止旧服务，以安全替换程序..."
            systemctl stop ss-rust || error "无法停止旧服务，已中止操作。"
        fi
    elif pgrep -x ss-rust >/dev/null 2>&1; then
        # 服务文件缺失但进程仍在运行（异常残留），直接终止
        warn "检测到残留的 ss-rust 进程（服务文件缺失），正在终止..."
        pkill -x ss-rust || error "无法终止残留的 ss-rust 进程，已中止操作。"
    fi
    version=${version:-$(get_latest_version)} || error "获取版本失败。"
    download_and_install "$version" "$arch" || error "安装程序失败。"

    if [[ "$configure" == true ]]; then
        if [[ -n "$port" || -n "$password" ]]; then
            generate_config "$port" "$password" "$method" || error "生成配置失败。"
        else
            # 交互安装必须不传第三个参数，否则 generate_config 会误判为已指定加密方式。
            generate_config || error "生成配置失败。"
        fi
    fi
    # 仅首次安装时创建服务并设为自启；更新/重装保留用户既有的 unit 与自启状态。
    if [[ ! -f "$SYSTEMD_SERVICE_FILE" ]]; then
        create_systemd_service || error "创建服务失败。"
        manage_service "restart" || error "启动服务失败。"
    elif [[ -f "${TMP_DIR}/was-active" ]]; then
        manage_service "restart" || error "启动服务失败。"
    else
        info "服务在操作前处于停止状态，完成后保持停止。"
    fi
    INSTALL_COMMITTED=true
}

do_install() {
    if [[ -f "$BINARY_PATH" ]]; then
        warn "检测到 shadowsocks-rust 已安装。"
        read -r -p " -> 是否要重新安装? (y/N): " choice < /dev/tty || error "输入已终止。"
        if [[ ! "$choice" =~ ^[Yy]$ ]]; then
            info "安装已取消。"
            return
        fi
        if [[ -f "$CONFIG_PATH" ]]; then
            read -r -p " -> 是否保留当前配置? (Y/n): " keep_choice < /dev/tty || error "输入已终止。"
            if [[ "$keep_choice" =~ ^[Nn]$ ]]; then
                info "将覆盖现有安装并重新配置..."
                install_flow true || error "安装失败。"
            else
                info "将重新安装并保留现有配置..."
                install_flow false || error "安装失败。"
            fi
        else
            install_flow true || error "安装失败。"
        fi
    else
        install_flow true || error "安装失败。"
    fi

    success "安装完成；已有服务保留原运行状态。"
    view_config
}

do_update() {
    if [[ ! -f "$BINARY_PATH" ]]; then
        error "shadowsocks-rust 未安装。请先执行安装。"
    fi

    local current_version latest_version config_line
    [[ -s "$VERSION_FILE" ]] || error "版本文件缺失或为空，无法执行更新。"
    current_version=$(<"$VERSION_FILE")
    validate_version "$current_version"
    config_line=$(load_config) || return 1
    IFS=$'\t' read -r current_port current_password current_method <<< "$config_line"
    validate_existing_config_values "$current_port" "$current_password" "$current_method"
    latest_version=$(get_latest_version) || error "获取版本失败。"

    if [[ "$current_version" == "$latest_version" ]]; then
        info "您当前已是最新版本: v$current_version"
        return
    fi

    info "发现新版本，准备从 v$current_version 更新到 v$latest_version..."
    
    install_flow false "" "" "$DEFAULT_ENCRYPTION_METHOD" "$latest_version" || error "更新失败。"
    success "更新完成！"
}

do_uninstall() {
    if [[ ! -f "$BINARY_PATH" && ! -d "$INSTALL_DIR" && ! -f "$SYSTEMD_SERVICE_FILE" ]]; then
        warn "未发现任何 shadowsocks-rust 相关文件，无需卸载。"
        return
    fi

    warn "将删除程序、服务及全部配置；恢复目录不自动删除。"
    read -r -p " -> 确认卸载 shadowsocks-rust? (Y/n，回车确认): " choice < /dev/tty || error "输入已终止。"
    if [[ "$choice" =~ ^[Nn]$ ]]; then
        info "已取消卸载操作。"
        return
    fi

    run_uninstall_logic
}

load_config() {
    [[ -f "$CONFIG_PATH" ]] || error "找不到配置文件，请先执行安装。"
    jq -cer 'if type == "object" and (.server_port|type)=="number" and (.server_port|floor)==.server_port and (.password|type)=="string" and (.method|type)=="string" then [.server_port, .password, .method] | @tsv else error("invalid config") end' "$CONFIG_PATH" 2>/dev/null ||
        error "配置文件格式错误，无法读取必要信息。"
}

do_modify_config() {
    info "加载当前配置..."
    local current_port current_password current_method key_bytes new_port new_password config_line
    config_line=$(load_config) || return 1
    IFS=$'\t' read -r current_port current_password current_method <<< "$config_line"
    validate_existing_config_values "$current_port" "$current_password" "$current_method"
    key_bytes=$(get_key_bytes "$current_method") || error "获取密钥长度失败。"

    info "当前配置："
    info "  端口: $current_port"
    info "  密钥: $current_password"
    info "  加密方式: $current_method"
    echo ""
    info "请输入新配置 (直接回车则保留当前值)"

    local new_method method_choice
    printf '%s\n' "  1. 2022-blake3-aes-128-gcm" "  2. 2022-blake3-chacha20-poly1305" "  有 AES 加速优先 AES，否则选 ChaCha。" >&2
    while true; do
        read -r -p " -> 加密方式 [1-2] (回车保留): " method_choice < /dev/tty || error "输入已终止。"
        if [[ -z "$method_choice" ]]; then
            new_method="$current_method"
            break
        elif [[ "$method_choice" = "1" ]]; then
            new_method="2022-blake3-aes-128-gcm"
            break
        elif [[ "$method_choice" = "2" ]]; then
            new_method="2022-blake3-chacha20-poly1305"
            break
        else
            warn "无效的加密方式选项，请输入 1、2 或直接回车。"
        fi
    done
    key_bytes=$(get_key_bytes "$new_method") || error "获取密钥长度失败。"

    # 端口输入和验证
    while true; do
        read -r -p " -> 新端口 [${MIN_PORT}-${MAX_PORT}] (当前: ${current_port}): " new_port < /dev/tty || error "输入已终止。"
        new_port=${new_port:-$current_port}
        if [[ "$new_port" =~ ^[1-9][0-9]{0,4}$ && "$new_port" -le $MAX_PORT ]]; then
            if [[ "$new_port" != "$current_port" ]] && ! ( check_port_available "$new_port" 2>/dev/null ); then
                warn "端口 ${new_port} 已被占用，请换一个端口。"
                continue
            fi
            break
        else
            warn "输入无效，请输入一个 ${MIN_PORT} 到 ${MAX_PORT} 之间的数字。"
        fi
    done

    # 密码输入和验证
    info "新密钥须为 ${key_bytes} 字节的规范 Base64；回车保留，切换加密方式时回车则随机生成。"
    read -r -s -p " -> 新密钥 (输入不回显；random 随机): " new_password_input < /dev/tty || error "输入已终止。"
    printf '\n' >&2
    if [[ -z "$new_password_input" ]]; then
        if [[ "$new_method" != "$current_method" ]]; then
            info "加密方式已更改，正在生成符合新加密方式的随机密码..."
            new_password=$(openssl rand -base64 "$key_bytes") || error "生成随机密码失败。"
            success "已生成新的随机密码。"
        else
            new_password=$current_password
        fi
    elif [[ "$new_password_input" == "random" ]]; then
        info "正在生成新的随机密码..."
        new_password=$(openssl rand -base64 "$key_bytes") || error "生成随机密码失败。"
        success "已生成新密钥。"
    else
        new_password=$new_password_input
    fi

    # 密码未变时沿用宽松校验：无填充等 ss-rust 运行时接受的合法 key 不应阻断仅改端口/方法
    if [[ "$new_password" == "$current_password" ]]; then
        validate_existing_config_values "$new_port" "$new_password" "$new_method"
    else
        validate_config_values "$new_port" "$new_password" "$new_method"
    fi

    # 检查是否有变化
    if [[ "$new_port" == "$current_port" && "$new_password" == "$current_password" && "$new_method" == "$current_method" ]]; then
        info "配置无变化，操作已取消。"
        return
    fi

    # 写入新配置
    backup_install_state || error "备份失败。"
    info "正在写入新配置..."
    write_config "$new_port" "$new_password" "$new_method" || error "写入配置失败。"

    if [[ -f "${TMP_DIR}/was-active" ]]; then
        info "正在重启服务以应用新配置..."
        manage_service "restart" || error "启动服务失败。"
    else
        info "服务当前处于停止状态，配置已更新，将在下次启动时生效。"
    fi
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
    local encoded_userinfo encoded_name

    encoded_userinfo=$(printf '%s:%s' "$method" "$password" |
        base64 | tr '+/' '-_' | tr -d '=\n') || return 1
    encoded_name=$(printf '%s' "$node_name" | jq -sRr @uri) || return 1
    printf 'ss://%s@%s:%s#%s\n' \
        "$encoded_userinfo" "$ip_address" "$port" "$encoded_name"
}

# shellcheck disable=SC2120
view_config() {
    local ip_address="${1:-}"
    local port password method node_name ss_link config_line
    config_line=$(load_config) || return 1
    IFS=$'\t' read -r port password method <<< "$config_line"
    validate_existing_config_values "$port" "$password" "$method"
    node_name="$(hostname)-ss2022"

    [[ -n "$ip_address" ]] || ip_address=$(get_public_ip) || ip_address=""
    if [[ -n "$ip_address" && "$ip_address" == *:* && "$ip_address" != \[*\] ]]; then
        ip_address="[$ip_address]"
    fi

    {
        echo ""
        draw_divider
        cprintf '%b\n' "  ${C_CYAN}Shadowsocks-2022 配置信息${C_RESET}"
        draw_divider
        cprintf '%b\n' "  ${C_YELLOW}节点名称:${C_RESET}       ${node_name}"
        if [[ -n "$ip_address" ]]; then
            cprintf '%b\n' "  ${C_YELLOW}服务器地址:${C_RESET}     ${ip_address}"
        else
            cprintf '%b\n' "  ${C_YELLOW}服务器地址:${C_RESET}     请手动填写服务器地址"
        fi
        cprintf '%b\n' "  ${C_YELLOW}端口:${C_RESET}           ${port}"
        cprintf '%b\n' "  ${C_YELLOW}密码:${C_RESET}           ${password}"
        cprintf '%b\n' "  ${C_YELLOW}加密方式:${C_RESET}       ${method}"
        draw_divider
        echo ""
        if [[ -n "$ip_address" ]]; then
            ss_link=$(generate_ss_url "$ip_address" "$port" "$password" "$method" "$node_name") || error "生成链接失败。"
            cprintf '%b\n' "  ${C_GREEN}SS链接:${C_RESET}"
            cprintf '%b\n' "  ${ss_link}"
        else
            cprintf '%b\n' "  ${C_YELLOW}SS链接:${C_RESET} 无法生成，请手动填写服务器地址"
        fi
        echo ""
        if [[ -n "$ip_address" ]]; then
            cprintf '%b\n' "  ${C_BLUE}提示:${C_RESET} 用支持 SS-2022 的客户端导入链接；先启动服务并放行 TCP/UDP 端口。"
        fi
        draw_divider
    } >&2
}

main_menu() {
    while true; do
        clear >/dev/null 2>&1 || true
        cprintf '%b\n' "${C_CYAN} Shadowsocks-rust 管理脚本${C_RESET}"
        cprintf '%b\n' "${C_YELLOW} Version: v${SCRIPT_VERSION}${C_RESET}"
        draw_divider

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
        cprintf '%b\n' "  状态: ${status_info}"
        draw_divider

        menu_item "$C_GREEN" "1." "安装"
        menu_item "$C_CYAN" "2." "更新"
        menu_item "$C_RED" "3." "卸载"
        draw_divider
        menu_item "$C_YELLOW" "4." "修改加密方式/端口/密钥"
        menu_item "$C_CYAN" "5." "查看配置信息"
        draw_divider
        menu_item "$C_CYAN" "6." "启动服务"
        menu_item "$C_RED" "7." "停止服务"
        menu_item "$C_CYAN" "8." "重启服务"
        menu_item "$C_MAGENTA" "9." "查看服务状态"
        draw_divider
        menu_item "$C_YELLOW" "0." "退出脚本"
        draw_divider

        read -r -p "请输入您的选项 [0-9]: " choice < /dev/tty || { info "输入终止，退出脚本。"; exit 0; }

        case "$choice" in
            # 菜单操作在子 shell 中执行：内部 error() 只终止本次操作，不退出整个脚本。
            # 子 shell 内显式设置 EXIT trap：操作失败(error/set -e)时同样触发回滚与状态恢复。
            # 子 shell 失败退出码用 || true 吸收，避免 set -e 使菜单整体退出。
            1) ( trap 'on_exit' EXIT; do_install ) || true ;;
            2) ( trap 'on_exit' EXIT; do_update ) || true ;;
            3) ( trap 'on_exit' EXIT; do_uninstall ) || true ;;
            4) ( trap 'on_exit' EXIT; do_modify_config ) || true ;;
            5) ( trap 'on_exit' EXIT; view_config ) || true ;;
            6) ( trap 'on_exit' EXIT; manage_service "start" ) || true ;;
            7) ( trap 'on_exit' EXIT; manage_service "stop" ) || true ;;
            8) ( trap 'on_exit' EXIT; manage_service "restart" ) || true ;;
            9) ( trap 'on_exit' EXIT; manage_service "status" ) || true ;;
            0) 
                info "感谢使用！"
                exit 0 
                ;;
            *) 
                warn "无效的选项，请输入正确的数字 (0-9)。" 
                ;;
        esac

        echo ""
        read -r -p "按回车键返回主菜单..." < /dev/tty || break
    done
}

# --- 脚本入口 ---
main() {
    # 优先检查并响应帮助选项，普通用户查阅说明不应被 root 权限拦截
    local arg argc=$#
    for arg in "$@"; do
        if [[ "$arg" == -u || "$arg" == --uninstall ]] && [[ $argc -ne 1 ]]; then
            error "卸载选项必须单独使用。" 2
        fi
        if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
            if [[ $# -ne 1 ]]; then
                error "选项 $arg 不接受多余参数" 2
            fi
            cat << EOF
Shadowsocks-rust 管理脚本 v${SCRIPT_VERSION}

用法:
  $0 [选项]

选项:
  -p, --port <端口>     指定端口 (1-65535)
  -w, --password <密码> 指定 Base64 编码的密钥
  -m, --method <方式>   2022-blake3-aes-128-gcm 或 2022-blake3-chacha20-poly1305
  -u, --uninstall       完全卸载 shadowsocks-rust（无需交互确认）
  -h, --help            显示此帮助信息

示例:
  # 交互式安装
  $0

  # 一键安装 (指定端口和随机密码，默认 AES-128-GCM)
  $0 --port 8388 --password \$(openssl rand -base64 16)

  # 使用 ChaCha20-Poly1305
  $0 --port 8388 --password \$(openssl rand -base64 32) --method 2022-blake3-chacha20-poly1305
EOF
            exit 0
        fi
    done

    check_root

    local ss_port=""
    local ss_password=""
    local ss_method="$DEFAULT_ENCRYPTION_METHOD"

    # 参数解析
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p|--port)
                if [[ -z "${2:-}" || "$2" =~ ^- ]]; then
                    error "参数 $1 需要指定端口号" 2
                fi
                ss_port="$2"
                shift 2
                ;;
            -w|--password)
                if [[ -z "${2:-}" || "${2:-}" =~ ^- ]]; then
                    error "参数 $1 需要指定密码" 2
                fi
                ss_password="$2"
                shift 2
                ;;
            -m|--method)
                if [[ -z "${2:-}" || "$2" =~ ^- ]]; then
                    error "参数 $1 需要指定加密方式" 2
                fi
                get_key_bytes "$2" >/dev/null
                ss_method="$2"
                shift 2
                ;;
            -u|--uninstall)
                if [[ $# -ne 1 ]]; then
                    error "选项 $1 不接受多余参数" 2
                fi
                init_temp_dir
                run_uninstall_logic || error "卸载失败。"
                exit 0
                ;;
            *)
                error "未知参数: $1. 使用 -h 或 --help 查看帮助信息。" 2
                ;;
        esac
    done

    init_temp_dir

    # 一键安装模式
    if [[ -n "$ss_port" && -n "$ss_password" ]]; then
        non_interactive=true
        info "=== 进入一键安装模式 ==="

        # 验证参数
        validate_port "$ss_port"
        
        validate_password "$ss_password" "$(get_key_bytes "$ss_method")"

        # 检查是否已安装或存在残留（程序/配置/服务文件任一存在都视为已安装）
        if [[ -f "$BINARY_PATH" || -f "$CONFIG_PATH" || -f "$SYSTEMD_SERVICE_FILE" ]]; then
            error "检测到 shadowsocks-rust 已安装或存在残留文件，请先执行 --uninstall 清理后再安装。"
        fi

        info "开始检查依赖、下载并安装..."
        install_flow true "$ss_port" "$ss_password" "$ss_method" || error "安装失败。"

        info "显示最终配置..."
        view_config
        exit 0
        
    elif [[ $argc -gt 0 ]]; then
        error "一键安装需要同时提供 --port 和 --password。" 2
    else
        check_tty
        main_menu
    fi
}

# 执行主函数
main "$@"
