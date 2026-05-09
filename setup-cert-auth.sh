#!/bin/bash
set -euo pipefail

# ============================================================
# ocserv 证书认证自动配置脚本（仅支持 Linux）
# 功能：交互式菜单，支持证书新建/续期和吊销操作
# 用法：sudo ./setup-cert-auth.sh
# ============================================================

# 检查 root 权限
if [[ $EUID -ne 0 ]]; then
    echo "[-] 此脚本需要 root 权限，请使用 sudo 运行"
    exit 1
fi

# 前置条件：切换至 /etc/ocserv 目录
if [[ "$(pwd)" != "/etc/ocserv" ]]; then
    if [[ -d "/etc/ocserv" ]]; then
        cd /etc/ocserv
    else
        echo "[-] 目录 /etc/ocserv 不存在，请先安装并配置 ocserv"
        exit 1
    fi
fi

# 前置条件：检查当前目录是否存在 ocserv.conf 和 ocpasswd
for file in ocserv.conf ocpasswd; do
    if [[ ! -f "$file" ]]; then
        echo "[-] 当前目录缺少文件: $file，脚本终止"
        exit 1
    fi
done

WORK_DIR="${1:-$(pwd)}"

OCSERV_CONF="$WORK_DIR/ocserv.conf"
OCPASSWD="$WORK_DIR/ocpasswd"
CA_DIR="$WORK_DIR/ca"
CERT_DIR="$WORK_DIR/user-certs"

# ---------- 颜色输出 ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; }

# ============================================================
# 前置条件：检测包管理器并安装依赖工具
# ============================================================

# 统一检测包管理器
PKG_MANAGER=""
if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt-get"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
else
    error "未检测到 apt-get 或 yum 包管理器，请手动安装以下依赖后重新运行脚本："
    error "  - fzf"
    error "  - certtool (gnutls-bin / gnutls-utils)"
    error "  - openssl"
    exit 1
fi
info "检测到包管理器: $PKG_MANAGER"

check_fzf() {
    if command -v fzf &>/dev/null; then
        info "fzf 已安装: $(fzf --version)"
        return
    fi
    info "使用 $PKG_MANAGER 安装 fzf..."
    if [[ "$PKG_MANAGER" == "apt-get" ]]; then
        apt-get update -qq && apt-get install -y -qq fzf &>/dev/null
    else
        yum install -y fzf &>/dev/null
    fi
    if ! command -v fzf &>/dev/null; then
        error "fzf 安装失败，请手动安装后重新运行脚本"
        exit 1
    fi
    info "fzf 安装成功"
}

install_certtool() {
    if command -v certtool &>/dev/null; then
        info "certtool 已安装: $(certtool --version 2>&1 | head -1)"
        return
    fi
    if [[ "$PKG_MANAGER" == "apt-get" ]]; then
        info "使用 apt-get 安装 gnutls-bin..."
        apt-get update -qq && apt-get install -y -qq gnutls-bin &>/dev/null
    else
        info "使用 yum 安装 gnutls-utils..."
        yum install -y gnutls-utils &>/dev/null
    fi
    if ! command -v certtool &>/dev/null; then
        error "certtool 安装失败，请手动安装后重新运行脚本"
        exit 1
    fi
    info "certtool 安装成功"
}

install_openssl() {
    if command -v openssl &>/dev/null; then
        info "openssl 已安装: $(openssl version)"
        return
    fi
    if [[ "$PKG_MANAGER" == "apt-get" ]]; then
        info "使用 apt-get 安装 openssl..."
        apt-get update -qq && apt-get install -y -qq openssl &>/dev/null
    else
        info "使用 yum 安装 openssl..."
        yum install -y openssl &>/dev/null
    fi
    if ! command -v openssl &>/dev/null; then
        error "openssl 安装失败，请手动安装后重新运行脚本"
        exit 1
    fi
    info "openssl 安装成功"
}

get_openssl_major() {
    local ver
    ver=$(openssl version 2>/dev/null | grep -oP '(?<=OpenSSL )\d+' 2>/dev/null | head -1 || true)
    if [[ -z "$ver" ]]; then
        ver=$(openssl version 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\./) {split($i,a,"."); print a[1]; exit}}')
    fi
    echo "${ver:-0}"
}

check_fzf
install_certtool
install_openssl

OPENSSL_MAJOR="$(get_openssl_major)"
if [[ -z "$OPENSSL_MAJOR" ]]; then
    OPENSSL_MAJOR=0
fi

# ============================================================
# 工具函数
# ============================================================

check_cert_expiry_days() {
    local cert_file="$1"
    if [[ ! -f "$cert_file" ]]; then
        echo "none"
        return
    fi
    local end_date now_ts end_ts days_left
    end_date=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
    if [[ -z "$end_date" ]]; then
        echo "error"
        return
    fi
    end_ts=$(date -d "$end_date" +%s 2>/dev/null || echo "0")
    now_ts=$(date +%s)
    days_left=$(( (end_ts - now_ts) / 86400 ))
    echo "$days_left"
}

is_cert_revoked() {
    local cert_file="$1"
    if [[ ! -f "$CA_DIR/crl.pem" ]]; then
        return 1
    fi
    local serial
    serial=$(openssl x509 -in "$cert_file" -noout -serial 2>/dev/null | sed 's/serial=//')
    if [[ -z "$serial" ]]; then
        return 1
    fi
    local revoked_serials
    revoked_serials=$(openssl crl -in "$CA_DIR/crl.pem" -noout -text 2>/dev/null | \
        awk '/Revoked Certificates:/,/Signature Algorithm:/{
            if(/Serial Number:/){
                if(NF>2) print $NF;
                else {getline; print $0}
            }
        }' | tr -d ' :')
    if [[ -z "$revoked_serials" ]]; then
        return 1
    fi
    if echo "$revoked_serials" | grep -qi "^${serial}$"; then
        return 0
    fi
    return 1
}

check_ca_status() {
    if [[ ! -f "$CA_DIR/ca-cert.pem" || ! -f "$CA_DIR/ca-key.pem" ]]; then
        echo "missing"
        return
    fi
    local days_left
    days_left=$(check_cert_expiry_days "$CA_DIR/ca-cert.pem")
    echo "$days_left"
}

regenerate_user_cert() {
    local username="$1"
    local user_dir="$CERT_DIR/$username"
    mkdir -p "$user_dir"

    local key_file="$user_dir/${username}-key.pem"
    local cert_file="$user_dir/${username}-cert.pem"
    local p12_file="$user_dir/${username}.p12"
    local ios_p12_file="$user_dir/ios-${username}.p12"
    local tmpl_file="$user_dir/${username}.tmpl"

    local cert_serial
    cert_serial=$(openssl rand -hex 10 2>/dev/null || echo "0$(date +%s%N | md5sum | head -c 19)")
    cert_serial="0${cert_serial:1}"

    if ! openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
        -out "$key_file" 2>/dev/null; then
        error "  [$username] 私钥生成失败"
        return 1
    fi

    cat > "$tmpl_file" <<EOF
cn = "$username"
uid = "$username"
serial = 0x${cert_serial}
expiration_days = 3650
signing_key
encryption_key
tls_www_client
EOF

    if ! certtool --generate-certificate \
        --load-privkey "$key_file" \
        --load-ca-certificate "$CA_DIR/ca-cert.pem" \
        --load-ca-privkey "$CA_DIR/ca-key.pem" \
        --template "$tmpl_file" \
        --outfile "$cert_file" 2>/dev/null; then
        error "  [$username] 证书签名失败"
        return 1
    fi

    if ! openssl pkcs12 -export \
        -inkey "$key_file" \
        -in "$cert_file" \
        -certfile "$CA_DIR/ca-cert.pem" \
        -name "$username" \
        -out "$p12_file" \
        -passout pass: 2>/dev/null; then
        if ! certtool --to-p12 \
            --load-privkey "$key_file" \
            --load-certificate "$cert_file" \
            --load-ca-certificate "$CA_DIR/ca-cert.pem" \
            --outder \
            --outfile "$p12_file" 2>/dev/null; then
            error "  [$username] 标准 p12 生成失败"
            return 1
        fi
    fi

    local openssl_args=(-export -descert)
    if [[ "$OPENSSL_MAJOR" -ge 3 ]]; then
        openssl_args+=(-legacy)
    fi
    openssl_args+=(
        -inkey "$key_file"
        -in "$cert_file"
        -certfile "$CA_DIR/ca-cert.pem"
        -name "$username"
        -out "$ios_p12_file"
        -passout pass:
    )
    if ! openssl pkcs12 "${openssl_args[@]}" 2>/dev/null; then
        error "  [$username] iOS p12 生成失败"
        return 1
    fi

    chmod 600 "$key_file" 2>/dev/null || true

    if [[ ! -s "$p12_file" || ! -s "$ios_p12_file" ]]; then
        error "  [$username] p12 文件为空"
        return 1
    fi

    return 0
}

revoke_single_user_cert() {
    local username="$1"
    local user_dir="$CERT_DIR/$username"
    local cert_file="$user_dir/${username}-cert.pem"

    if [[ ! -f "$cert_file" ]]; then
        error "  [$username] 找不到证书文件，跳过"
        return 1
    fi

    if is_cert_revoked "$cert_file"; then
        warn "  [$username] 证书已吊销，跳过"
        return 1
    fi

    info "  [$username] 正在吊销证书..."

    if ! printf '3650\n\n' | certtool --generate-crl \
        --load-ca-certificate "$CA_DIR/ca-cert.pem" \
        --load-ca-privkey "$CA_DIR/ca-key.pem" \
        $( [[ -f "$CA_DIR/crl.pem" ]] && echo "--load-crl $CA_DIR/crl.pem" || true ) \
        --load-certificate "$cert_file" \
        --outfile "$CA_DIR/crl-new.pem" 2>/dev/null; then
        error "  [$username] 吊销命令执行失败"
        return 1
    fi

    mv "$CA_DIR/crl-new.pem" "$CA_DIR/crl.pem" || { error "  [$username] CRL 文件替换失败"; return 1; }

    rm -f "$user_dir"/*.p12 "$user_dir"/*-cert.pem "$user_dir"/*-key.pem 2>/dev/null || true

    info "  [$username] 证书已吊销"
    return 0
}

# ============================================================
# 初始化：确保 CA、CRL、用户列表可用
# ============================================================
init_common() {
    info "检查配置文件..."
    info "配置文件位于: $WORK_DIR"

    # CA 证书
    info "检查 CA 证书状态..."
    mkdir -p "$CA_DIR"

    local ca_status
    ca_status=$(check_ca_status)

    if [[ "$ca_status" == "missing" ]]; then
        info "CA 证书不存在，将生成新 CA"
        if ! openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
            -out "$CA_DIR/ca-key.pem" 2>/dev/null; then
            error "CA 私钥生成失败"
            exit 1
        fi
        chmod 600 "$CA_DIR/ca-key.pem"

        local ca_serial
        ca_serial=$(openssl rand -hex 10 2>/dev/null || date +%s%N | md5sum | head -c 20)
        ca_serial="0${ca_serial:1}"
        certtool --generate-self-signed \
            --load-privkey "$CA_DIR/ca-key.pem" \
            --template /dev/stdin \
            --outfile "$CA_DIR/ca-cert.pem" <<EOF
cn = "Thehkus IT Root CA"
organization = "Thehkus IT"
serial = 0x${ca_serial}
expiration_days = 11680
ca
signing_key
cert_signing_key
crl_signing_key
EOF
        info "CA 证书已生成: $CA_DIR/ca-cert.pem"
    elif [[ "$ca_status" == "error" ]]; then
        error "CA 证书文件损坏或格式错误"
        exit 1
    elif [[ "$ca_status" -le 0 ]]; then
        error "CA 证书已过期（${ca_status#-} 天前过期）"
        error "CA 证书过期需要重新生成，现有用户证书将全部失效"
        # 备份旧 CA
        local backup_suffix
        backup_suffix=$(date +%Y%m%d%H%M%S)
        mkdir -p "$CA_DIR/backup-$backup_suffix"
        cp -a "$CA_DIR/ca-cert.pem" "$CA_DIR/ca-key.pem" "$CA_DIR/backup-$backup_suffix/" 2>/dev/null || true
        warn "旧 CA 已备份到 $CA_DIR/backup-$backup_suffix/"

        if ! openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
            -out "$CA_DIR/ca-key.pem" 2>/dev/null; then
            error "CA 私钥生成失败"
            exit 1
        fi
        chmod 600 "$CA_DIR/ca-key.pem"

        ca_serial=$(openssl rand -hex 10 2>/dev/null || date +%s%N | md5sum | head -c 20)
        ca_serial="0${ca_serial:1}"
        certtool --generate-self-signed \
            --load-privkey "$CA_DIR/ca-key.pem" \
            --template /dev/stdin \
            --outfile "$CA_DIR/ca-cert.pem" <<EOF
cn = "Thehkus IT Root CA"
organization = "Thehkus IT"
serial = 0x${ca_serial}
expiration_days = 11680
ca
signing_key
cert_signing_key
crl_signing_key
EOF
        info "新 CA 证书已生成: $CA_DIR/ca-cert.pem"

        # 重新生成 CRL（旧 CRL 由已替换的 CA 密钥签名，无法继续使用）
        if [[ -f "$CA_DIR/crl.pem" ]]; then
            local crl_backup_suffix
            crl_backup_suffix=$(date +%Y%m%d%H%M%S)
            cp "$CA_DIR/crl.pem" "$CA_DIR/crl.pem.bak.$crl_backup_suffix" 2>/dev/null || true
        fi
        printf '3650\n\n' | certtool --generate-crl \
            --load-ca-certificate "$CA_DIR/ca-cert.pem" \
            --load-ca-privkey "$CA_DIR/ca-key.pem" \
            --outfile "$CA_DIR/crl.pem" 2>/dev/null
        info "CRL 已重新生成"
    else
        info "CA 证书有效，剩余 ${ca_status} 天"
        if [[ "$ca_status" -lt 90 ]]; then
            warn "CA 证书将在 $ca_status 天后过期，建议提前重新生成"
        fi
    fi

    # CRL
    if [[ ! -f "$CA_DIR/crl.pem" ]]; then
        info "生成初始 CRL..."
        printf '3650\n\n' | certtool --generate-crl \
            --load-ca-certificate "$CA_DIR/ca-cert.pem" \
            --load-ca-privkey "$CA_DIR/ca-key.pem" \
            --outfile "$CA_DIR/crl.pem"
    fi

    # 提取用户
    info "从 ocpasswd 提取用户名..."
    usernames=()
    while IFS=: read -r user _ _; do
        [[ -z "$user" || "$user" =~ ^# ]] && continue
        if [[ ! "$user" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            warn "跳过非法用户名: $user"
            continue
        fi
        usernames+=("$user")
    done < "$OCPASSWD"

    local count=${#usernames[@]}
    info "共提取 $count 个用户: ${usernames[*]}"

    if [[ $count -eq 0 ]]; then
        error "ocpasswd 中未找到任何用户"
        exit 1
    fi

    mkdir -p "$CERT_DIR"
}

# ============================================================
# 选项 1：证书新建和续期
# ============================================================
do_cert_manage() {
    info "=== 证书新建 / 续期 ==="

    # 显示状态
    echo ""
    echo "  用户证书状态："
    echo "  $(printf '%-16s %-12s %-24s' "用户" "状态" "有效期")"
    echo "  ---------------------------------------------------------------"

    local cert_valid=0 cert_expired=0 cert_new=0 cert_failed=0

    for username in "${usernames[@]}"; do
        local user_dir="$CERT_DIR/$username"
        local cert_file="$user_dir/${username}-cert.pem"

        if [[ -f "$cert_file" ]]; then
            if is_cert_revoked "$cert_file"; then
                printf "  %-16s %-12s %-24s\n" "$username" "已吊销" "证书已被吊销"
                cert_failed=$((cert_failed + 1))
                continue
            fi
            local days_left
            days_left=$(check_cert_expiry_days "$cert_file")
            if [[ "$days_left" == "error" ]]; then
                printf "  %-16s %-12s %-24s\n" "$username" "错误" "证书文件损坏"
                cert_failed=$((cert_failed + 1))
            elif [[ "$days_left" -le 0 ]]; then
                local abs_days=${days_left#-}
                printf "  %-16s %-12s %-24s\n" "$username" "已过期" "${abs_days} 天前过期"
                cert_expired=$((cert_expired + 1))
            else
                local end_date end_fmt
                end_date=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
                end_fmt=$(date -d "$end_date" "+%Y-%m-%d %H:%M" 2>/dev/null || echo "未知")
                printf "  %-16s %-12s %-24s\n" "$username" "有效" "到期: $end_fmt ($days_left 天)"
                cert_valid=$((cert_valid + 1))
            fi
        else
            printf "  %-16s %-12s %-24s\n" "$username" "不存在" "需要生成"
            cert_new=$((cert_new + 1))
        fi
    done

    echo ""

    local renew_count=$((cert_expired + cert_new + cert_failed))
    if [[ $renew_count -gt 0 ]]; then
        info "需要处理 $renew_count 个证书（续期/新建）..."
    fi

    local cert_renewed=0
    for username in "${usernames[@]}"; do
        local user_dir="$CERT_DIR/$username"
        local cert_file="$user_dir/${username}-cert.pem"
        local days_left=""
        local needs_action=false
        local action_desc=""

        if [[ -f "$cert_file" ]]; then
            if is_cert_revoked "$cert_file"; then
                info "  [$username] 证书已吊销，清理旧文件"
                rm -f "$user_dir"/*.p12 "$user_dir"/*-cert.pem "$user_dir"/*-key.pem 2>/dev/null || true
                needs_action=true
                action_desc="吊销后重新生成"
            else
                days_left=$(check_cert_expiry_days "$cert_file")
                if [[ "$days_left" == "error" || "$days_left" -le 0 ]]; then
                    needs_action=true
                    if [[ "$days_left" == "error" ]]; then
                        action_desc="证书损坏，重新生成"
                    else
                        action_desc="证书过期，续期"
                    fi
                fi
            fi
        else
            needs_action=true
            action_desc="生成新证书"
        fi

        if [[ "$needs_action" == true ]]; then
            info "  [$username] $action_desc..."
            if regenerate_user_cert "$username"; then
                if [[ "$action_desc" == *"吊销"* ]]; then
                    info "  [$username] 吊销后重新生成完成"
                elif [[ -z "$days_left" ]]; then
                    info "  [$username] 生成完成"
                else
                    info "  [$username] 续期完成"
                fi
                cert_renewed=$((cert_renewed + 1))
            else
                cert_failed=$((cert_failed + 1))
            fi
        fi

        rm -f "$user_dir/${username}.tmpl" 2>/dev/null || true
    done

    find "$CERT_DIR" -name "*.tmpl" -delete 2>/dev/null || true

    for old_dir in "$CERT_DIR"/*/; do
        [[ -d "$old_dir" ]] || continue
        rm -f "$old_dir/client-key.pem" "$old_dir/client-cert.pem" \
              "$old_dir/client.p12" "$old_dir/ios-client.p12" 2>/dev/null || true
    done

    echo ""
    if [[ $cert_renewed -gt 0 ]]; then
        info "证书处理完成: 有效 $cert_valid, 新建/续期 $cert_renewed, 失败 $cert_failed"
    else
        info "证书处理完成: 全部有效 ($cert_valid), 无需操作"
    fi

    # ocserv.conf 配置
    info "检查 ocserv.conf 配置..."

    local conf_already_ok=true
    local missing_items=""

    if ! grep -qF 'auth = "plain[passwd=/etc/ocserv/ocpasswd]"' "$OCSERV_CONF"; then
        conf_already_ok=false
        missing_items="${missing_items}  - plain 密码认证\n"
    fi
    if ! grep -q '^enable-auth = "certificate"' "$OCSERV_CONF"; then
        conf_already_ok=false
        missing_items="${missing_items}  - enable-auth = certificate\n"
    fi
    if ! grep -q "^ca-cert[[:space:]]*=.*${CA_DIR}/ca-cert.pem" "$OCSERV_CONF"; then
        conf_already_ok=false
        missing_items="${missing_items}  - ca-cert 路径\n"
    fi
    if ! grep -q '^cert-user-oid[[:space:]]*=' "$OCSERV_CONF"; then
        conf_already_ok=false
        missing_items="${missing_items}  - cert-user-oid\n"
    fi
    if ! grep -q "^crl[[:space:]]*=.*${CA_DIR}/crl.pem" "$OCSERV_CONF"; then
        conf_already_ok=false
        missing_items="${missing_items}  - crl 路径\n"
    fi

    if $conf_already_ok; then
        info "ocserv.conf 配置已完整，无需修改"
    else
        info "以下配置需要更新:"
        echo -e "$missing_items"
        info "修改 ocserv.conf 配置..."

        if [[ ! -f "$OCSERV_CONF.bak" ]]; then
            local BACKUP="$OCSERV_CONF.bak.$(date +%Y%m%d%H%M%S)"
            cp "$OCSERV_CONF" "$BACKUP"
            cp "$OCSERV_CONF" "$OCSERV_CONF.bak"
            info "已备份: $BACKUP"
        else
            info "配置已有备份 ($OCSERV_CONF.bak)，跳过重复备份"
        fi

        local PLAIN_AUTH='auth = "plain[passwd=/etc/ocserv/ocpasswd]"'
        if ! grep -qF 'auth = "plain[passwd=/etc/ocserv/ocpasswd]"' "$OCSERV_CONF"; then
            if grep -q '^\s*#\s*auth = "plain\[passwd=' "$OCSERV_CONF"; then
                sed -i '0,/^\s*#\s*auth = "plain\[passwd=/{s|^\(\s*#\s*\)\(auth = "plain\[passwd=.*\)|\2|}' "$OCSERV_CONF"
            else
                local first_auth_comment
                first_auth_comment=$(grep -n '^\s*#\s*auth' "$OCSERV_CONF" | head -1 | cut -d: -f1)
                if [[ -n "$first_auth_comment" ]]; then
                    sed -i "${first_auth_comment}a\\${PLAIN_AUTH}" "$OCSERV_CONF"
                else
                    local first_active
                    first_active=$(grep -n '^[^#]' "$OCSERV_CONF" | head -1 | cut -d: -f1)
                    if [[ -n "$first_active" ]]; then
                        sed -i "$((first_active - 1))i\\${PLAIN_AUTH}" "$OCSERV_CONF"
                    else
                        echo "$PLAIN_AUTH" >> "$OCSERV_CONF"
                    fi
                fi
            fi
        fi

        if ! grep -q '^enable-auth = "certificate"' "$OCSERV_CONF"; then
            if grep -q '^\s*#\s*enable-auth = "certificate"' "$OCSERV_CONF"; then
                sed -i '0,/^\s*#\s*enable-auth = "certificate"/{s|^\(\s*#\s*\)\(enable-auth = "certificate"\)|\2|}' "$OCSERV_CONF"
            else
                local first_enable_comment
                first_enable_comment=$(grep -n '^\s*#\s*enable-auth' "$OCSERV_CONF" | head -1 | cut -d: -f1)
                if [[ -n "$first_enable_comment" ]]; then
                    sed -i "${first_enable_comment}a\\enable-auth = \"certificate\"" "$OCSERV_CONF"
                else
                    echo 'enable-auth = "certificate"' >> "$OCSERV_CONF"
                fi
            fi
        fi

        if grep -q '^ca-cert[[:space:]]*=' "$OCSERV_CONF"; then
            sed -i "0,/^ca-cert[[:space:]]*=.*/s|^ca-cert[[:space:]]*=.*|ca-cert = $CA_DIR/ca-cert.pem|" "$OCSERV_CONF"
        elif grep -q '^#.*ca-cert[[:space:]]*=' "$OCSERV_CONF"; then
            sed -i "0,/^#.*ca-cert[[:space:]]*=.*/s|^#.*ca-cert[[:space:]]*=.*|ca-cert = $CA_DIR/ca-cert.pem|" "$OCSERV_CONF"
        fi

        if grep -q '^cert-user-oid[[:space:]]*=' "$OCSERV_CONF"; then
            sed -i "0,/^cert-user-oid[[:space:]]*=.*/s|^cert-user-oid[[:space:]]*=.*|cert-user-oid = 0.9.2342.19200300.100.1.1|" "$OCSERV_CONF"
        elif grep -q '^#.*cert-user-oid[[:space:]]*=' "$OCSERV_CONF"; then
            sed -i "0,/^#.*cert-user-oid[[:space:]]*=.*/s|^#.*cert-user-oid[[:space:]]*=.*|cert-user-oid = 0.9.2342.19200300.100.1.1|" "$OCSERV_CONF"
        else
            if grep -q '^enable-auth = "certificate"' "$OCSERV_CONF"; then
                sed -i '/^enable-auth = "certificate"/a\cert-user-oid = 0.9.2342.19200300.100.1.1' "$OCSERV_CONF"
            fi
        fi

        if grep -q '^crl[[:space:]]*=' "$OCSERV_CONF"; then
            sed -i "0,/^crl[[:space:]]*=.*/s|^crl[[:space:]]*=.*|crl = $CA_DIR/crl.pem|" "$OCSERV_CONF"
        elif grep -q '^#.*crl[[:space:]]*=' "$OCSERV_CONF"; then
            sed -i "0,/^#.*crl[[:space:]]*=.*/s|^#.*crl[[:space:]]*=.*|crl = $CA_DIR/crl.pem|" "$OCSERV_CONF"
        fi

        if ! grep -q '^config-per-user[[:space:]]*=' "$OCSERV_CONF"; then
            if grep -q '^#.*config-per-user[[:space:]]*=' "$OCSERV_CONF"; then
                sed -i "0,/^#.*config-per-user[[:space:]]*=.*/s|^#.*config-per-user[[:space:]]*=.*|config-per-user = $WORK_DIR/config-per-user/|" "$OCSERV_CONF"
            fi
        fi

        info "ocserv.conf 配置已更新"
    fi

    if grep -q "^config-per-user[[:space:]]*=" "$OCSERV_CONF"; then
        if [[ -d "$WORK_DIR/config-per-user" ]]; then
            info "用户配置目录已存在: $WORK_DIR/config-per-user/"
        else
            mkdir -p "$WORK_DIR/config-per-user"
            info "已创建用户配置目录: $WORK_DIR/config-per-user/"
            warn "如需为不同用户分配不同网络权限，请在上述目录中创建以用户名命名的文件"
        fi
    fi

    echo ""
    echo "=============================================="
    echo "  证书配置完成"
    echo "=============================================="
    echo ""
    echo "  客户端连接示例:"
    echo "    密码登录: openconnect <服务器>"
    echo "    证书登录: openconnect --certificate user-certs/<用户名>/<用户名>.p12 <服务器>"
    echo "    iOS:      将 ios-<用户名>.p12 导入 iPhone，通过 AnyConnect 连接"
    echo ""
    echo "  重启 ocserv 使配置生效:"
    echo "    systemctl restart ocserv"
    echo "=============================================="
}

# ============================================================
# 选项 3：查看用户证书状态
# ============================================================
do_cert_status() {
    info "=== 用户证书状态 ==="
    echo ""
    echo "  用户证书状态："
    echo "  $(printf '%-16s %-12s %-24s' "用户" "状态" "有效期")"
    echo "  ---------------------------------------------------------------"

    local cert_valid=0 cert_expired=0 cert_new=0 cert_revoked=0 cert_error=0

    for username in "${usernames[@]}"; do
        local user_dir="$CERT_DIR/$username"
        local cert_file="$user_dir/${username}-cert.pem"

        if [[ -f "$cert_file" ]]; then
            if is_cert_revoked "$cert_file"; then
                printf "  %-16s %-12s %-24s\n" "$username" "已吊销" "证书已被吊销"
                cert_revoked=$((cert_revoked + 1))
            else
                local days_left
                days_left=$(check_cert_expiry_days "$cert_file")
                if [[ "$days_left" == "error" ]]; then
                    printf "  %-16s %-12s %-24s\n" "$username" "错误" "证书文件损坏"
                    cert_error=$((cert_error + 1))
                elif [[ "$days_left" -le 0 ]]; then
                    local abs_days=${days_left#-}
                    printf "  %-16s %-12s %-24s\n" "$username" "已过期" "${abs_days} 天前过期"
                    cert_expired=$((cert_expired + 1))
                else
                    local end_date end_fmt
                    end_date=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
                    end_fmt=$(date -d "$end_date" "+%Y-%m-%d %H:%M" 2>/dev/null || echo "未知")
                    printf "  %-16s %-12s %-24s\n" "$username" "有效" "到期: $end_fmt ($days_left 天)"
                    cert_valid=$((cert_valid + 1))
                fi
            fi
        else
            printf "  %-16s %-12s %-24s\n" "$username" "不存在" "需要生成"
            cert_new=$((cert_new + 1))
        fi
    done

    echo ""
    echo "  汇总: 有效 $cert_valid, 已过期 $cert_expired, 不存在 $cert_new, 已吊销 $cert_revoked, 错误 $cert_error"
    echo "=============================================="
}

# ============================================================
# 选项 2：吊销证书
# ============================================================
do_cert_revoke() {
    info "=== 吊销用户证书 ==="

    # 构建 fzf 输入列表（用户 + "All Users"）
    local fzf_input=()
    for username in "${usernames[@]}"; do
        local user_dir="$CERT_DIR/$username"
        local cert_file="$user_dir/${username}-cert.pem"
        local status=""

        if [[ -f "$cert_file" ]]; then
            if is_cert_revoked "$cert_file"; then
                status="已吊销"
            else
                local days_left
                days_left=$(check_cert_expiry_days "$cert_file")
                if [[ "$days_left" == "error" ]]; then
                    status="错误"
                elif [[ "$days_left" -le 0 ]]; then
                    status="已过期"
                else
                    status="有效($days_left天)"
                fi
            fi
        else
            status="不存在"
        fi

        fzf_input+=("  $username  $status")
    done

    # 调用 fzf 多选
    local height
    height=$(( ${#fzf_input[@]} + 7 ))
    if [[ $height -gt 30 ]]; then
        height=30
    fi

    local selected
    selected=$(printf '%s\n' "${fzf_input[@]}" | fzf --multi \
        --cycle \
        --reverse \
        --bind "space:toggle,tab:deselect-all,ctrl-a:select-all" \
        --header $'Select user:\n  ↑↓ navigate  SPACE select  TAB cancel  CTRL+A select all  ENTER confirm\n' \
        --header-first \
        --preview 'echo {}' \
        --preview-window bottom:1 \
        --height "$height" \
        --color "bg:-1,hl:196,fg+:bold,bg+:-1,hl+:196" \
        --pointer "→" \
        --marker "●" \
        --layout=reverse 2>/dev/tty) || true

    if [[ -z "$selected" ]]; then
        echo ""
        echo "  未选择任何用户，操作已取消"
        return
    fi

    # 解析选择结果
    local revoke_targets=()
    while IFS= read -r line; do
        local trimmed
        trimmed=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        local uname
        uname=$(echo "$trimmed" | awk '{print $1}')

        [[ -z "$uname" ]] && continue

        # 验证是有效用户
        for u in "${usernames[@]}"; do
            if [[ "$u" == "$uname" ]]; then
                revoke_targets+=("$uname")
                break
            fi
        done
    done <<< "$selected"

    if [[ ${#revoke_targets[@]} -eq 0 ]]; then
        echo ""
        echo "  未选择任何有效用户，操作已取消"
        return
    fi

    # 确认
    echo ""
    echo "  确认吊销以下用户证书（此操作不可逆）:"
    for username in "${revoke_targets[@]}"; do
        echo "    - $username"
    done
    echo ""
    read -rp "  确认继续？(y/n): " confirm || { echo ""; echo "  已取消"; return; }
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "  已取消"
        return
    fi

    echo ""
    local success=0
    local skipped=0
    for username in "${revoke_targets[@]}"; do
        if revoke_single_user_cert "$username"; then
            success=$((success + 1))
        else
            skipped=$((skipped + 1))
        fi
    done

    echo ""
    info "吊销完成: 成功 $success, 跳过 $skipped"
    info "请执行: systemctl restart ocserv"
    echo "=============================================="
}

# ============================================================
# 主菜单
# ============================================================
init_common

echo ""
echo "=============================================="
echo "  ocserv 证书认证管理"
echo "=============================================="
echo ""

while true; do
    echo "  1) 证书新建 / 续期"
    echo "  2) 吊销用户证书"
    echo "  3) 查看用户证书状态"
    echo "  0) 退出"
    echo ""
    read -rp "  请选择操作 [0-3]: " menu_choice || continue

    case "$menu_choice" in
        1)
            do_cert_manage
            ;;
        2)
            do_cert_revoke
            ;;
        3)
            do_cert_status
            ;;
        0)
            echo "  退出"
            exit 0
            ;;
        *)
            warn "  无效选择，请重新输入"
            ;;
    esac
done
