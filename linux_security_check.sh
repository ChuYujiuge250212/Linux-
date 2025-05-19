#!/bin/bash
#
# Linux系统安全检查脚本
# 该脚本只进行检查并记录到文本文件中，不会对系统进行任何修改
#

# 设置输出文件
OUTPUT_FILE="linux_security_check_$(date +%Y%m%d_%H%M%S).txt"
LOG_DIR="/tmp"
FULL_OUTPUT_PATH="$LOG_DIR/$OUTPUT_FILE"

# 创建输出文件
touch "$FULL_OUTPUT_PATH"

# 输出函数
log() {
    echo -e "\n\n====================================================" >> "$FULL_OUTPUT_PATH"
    echo -e ">>> $1" >> "$FULL_OUTPUT_PATH"
    echo -e "====================================================\n" >> "$FULL_OUTPUT_PATH"
}

section() {
    echo -e "\n\n##############################################################" >> "$FULL_OUTPUT_PATH"
    echo -e "#                                                            #" >> "$FULL_OUTPUT_PATH"
    echo -e "#                    $1                    #" >> "$FULL_OUTPUT_PATH"
    echo -e "#                                                            #" >> "$FULL_OUTPUT_PATH"
    echo -e "##############################################################\n" >> "$FULL_OUTPUT_PATH"
}

# 开始信息
section "Linux系统安全检查报告"
echo "检查时间: $(date)" >> "$FULL_OUTPUT_PATH"
echo "主机名: $(hostname)" >> "$FULL_OUTPUT_PATH"
echo "输出文件路径: $FULL_OUTPUT_PATH" >> "$FULL_OUTPUT_PATH"

# 1. 系统基本信息
section "1. 系统基本信息"

log "操作系统版本"
{
    echo ">>> 操作系统信息:"
    uname -a
    echo -e "\n>>> 发行版信息:"
    if [ -f /etc/os-release ]; then
        cat /etc/os-release
    elif [ -f /etc/lsb-release ]; then
        cat /etc/lsb-release
    elif [ -f /etc/redhat-release ]; then
        cat /etc/redhat-release
    else
        echo "无法确定具体发行版信息"
    fi
    echo -e "\n>>> 内核版本:"
    uname -r
} >> "$FULL_OUTPUT_PATH"

log "系统运行时间和负载"
{
    uptime
} >> "$FULL_OUTPUT_PATH"

log "系统时间与NTP同步状态"
{
    date
    if command -v timedatectl &> /dev/null; then
        timedatectl status
    fi
    if command -v ntpq &> /dev/null; then
        echo -e "\n>>> NTP服务状态:"
        ntpq -p
    elif command -v chronyc &> /dev/null; then
        echo -e "\n>>> Chrony服务状态:"
        chronyc sources
    else
        echo "NTP/Chrony 服务未安装"
    fi
} >> "$FULL_OUTPUT_PATH"

log "主机网络信息"
{
    echo ">>> IP配置:"
    ip addr
    echo -e "\n>>> 路由表:"
    ip route
    echo -e "\n>>> DNS配置:"
    cat /etc/resolv.conf
    echo -e "\n>>> 主机名配置:"
    cat /etc/hostname
    echo -e "\n>>> hosts文件:"
    cat /etc/hosts
} >> "$FULL_OUTPUT_PATH"

# 2. 资源使用情况
section "2. 资源使用情况"

log "CPU使用情况"
{
    echo ">>> CPU信息:"
    grep "model name" /proc/cpuinfo | head -1
    echo "CPU核心数: $(grep -c processor /proc/cpuinfo)"
    echo -e "\n>>> CPU负载情况:"
    top -bn1 | head -20
} >> "$FULL_OUTPUT_PATH"

log "内存使用情况"
{
    echo ">>> 内存总体使用情况:"
    free -h
    echo -e "\n>>> 详细内存信息:"
    cat /proc/meminfo | head -20
} >> "$FULL_OUTPUT_PATH"

log "磁盘使用情况"
{
    echo ">>> 磁盘空间使用情况:"
    df -h
    echo -e "\n>>> 磁盘分区情况:"
    fdisk -l 2>/dev/null || echo "需要root权限查看完整分区信息"
    echo -e "\n>>> 文件系统详情:"
    mount | column -t
} >> "$FULL_OUTPUT_PATH"

log "网络资源使用情况"
{
    echo ">>> 网络连接状态:"
    if command -v ss &> /dev/null; then
        ss -tuln
        echo -e "\n>>> 活跃连接:"
        ss -tan state established
    else
        netstat -tuln
        echo -e "\n>>> 活跃连接:"
        netstat -tan | grep ESTABLISHED
    fi
    echo -e "\n>>> 网络接口流量:"
    if command -v ifstat &> /dev/null; then
        ifstat -a 1 1
    else
        cat /proc/net/dev
    fi
} >> "$FULL_OUTPUT_PATH"

# 3. 系统用户情况
section "3. 系统用户情况"

log "用户账户信息"
{
    echo ">>> 系统用户列表:"
    cut -d: -f1,3,7 /etc/passwd
    echo -e "\n>>> 系统组列表:"
    cut -d: -f1,3 /etc/group
    echo -e "\n>>> 当前登录用户:"
    who
    echo -e "\n>>> 最近登录记录:"
    last | head -20
} >> "$FULL_OUTPUT_PATH"

log "特权用户信息"
{
    echo ">>> 具有root权限的用户:"
    grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1 }'
    echo -e "\n>>> sudo权限配置:"
    if [ -f /etc/sudoers ]; then
        grep -v "^#\|^$" /etc/sudoers
        if [ -d /etc/sudoers.d ]; then
            echo -e "\n>>> /etc/sudoers.d/ 目录内容:"
            for file in /etc/sudoers.d/*; do
                echo "File: $file"
                grep -v "^#\|^$" "$file" 2>/dev/null || echo "无法读取 $file (可能需要root权限)"
            done
        fi
    else
        echo "无法读取 /etc/sudoers (可能需要root权限)"
    fi
} >> "$FULL_OUTPUT_PATH"

log "空密码和弱密码用户检查"
{
    echo ">>> 用户密码设置状态检查:"
    echo "注意: 完整检查需要root权限"
    if [ -f /etc/shadow ] && [ -r /etc/shadow ]; then
        echo "无密码账户检查:"
        grep -v -E "^#\|^$" /etc/shadow | awk -F: '($2 == "" || $2 == "!" || $2 == "*" || $2 == "!!") { print $1 }'
    else
        echo "无法读取 /etc/shadow (需要root权限)"
    fi
} >> "$FULL_OUTPUT_PATH"

# 4. 身份鉴别安全
section "4. 身份鉴别安全"

log "密码策略配置"
{
    echo ">>> PAM配置检查:"
    if [ -d /etc/pam.d ]; then
        echo "密码复杂度策略检查 (/etc/pam.d/common-password 或 /etc/pam.d/system-auth):"
        cat /etc/pam.d/common-password 2>/dev/null || cat /etc/pam.d/system-auth 2>/dev/null || echo "无法找到密码策略文件"
    fi
    
    echo -e "\n>>> 密码过期策略检查 (/etc/login.defs):"
    grep -E "PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE" /etc/login.defs 2>/dev/null || echo "无法找到密码过期策略"
    
    if command -v chage &> /dev/null; then
        echo -e "\n>>> 随机选择一个用户检查密码策略 (示例):"
        username=$(grep -v -E "^#\|^$" /etc/passwd | head -1 | cut -d: -f1)
        chage -l "$username" 2>/dev/null || echo "需要root权限检查用户密码策略详情"
    fi
} >> "$FULL_OUTPUT_PATH"

log "登录控制策略"
{
    echo ">>> 登录失败锁定策略检查:"
    if [ -f /etc/pam.d/login ]; then
        grep "pam_tally2" /etc/pam.d/login 2>/dev/null || grep "pam_faillock" /etc/pam.d/login 2>/dev/null || echo "未找到登录失败锁定配置"
    fi
    
    echo -e "\n>>> SSH登录限制配置 (/etc/ssh/sshd_config):"
    if [ -f /etc/ssh/sshd_config ]; then
        grep -E "^PermitRootLogin|^PasswordAuthentication|^PubkeyAuthentication|^MaxAuthTries|^AllowUsers|^DenyUsers" /etc/ssh/sshd_config 2>/dev/null || echo "SSH配置文件中未找到相关限制"
    fi
} >> "$FULL_OUTPUT_PATH"

log "多因素认证配置"
{
    echo ">>> 检查是否存在多因素认证配置:"
    if command -v google-authenticator &> /dev/null; then
        echo "找到 Google Authenticator 配置"
        grep "auth required pam_google_authenticator.so" /etc/pam.d/* 2>/dev/null || echo "未找到Google Authenticator的PAM配置"
    else
        echo "未安装 Google Authenticator"
    fi
    
    echo -e "\n>>> 检查TOTP/HOTP配置:"
    grep "pam_oath" /etc/pam.d/* 2>/dev/null || echo "未找到OATH (TOTP/HOTP) 配置"
    
    echo -e "\n>>> 检查USB密钥配置:"
    if [ -d /usr/share/pam-configs/u2f ] || grep "pam_u2f" /etc/pam.d/* 2>/dev/null; then
        echo "找到U2F配置"
    else
        echo "未找到U2F配置"
    fi
} >> "$FULL_OUTPUT_PATH"

# 5. 访问控制安全
section "5. 访问控制安全"

log "文件权限检查"
{
    echo ">>> 关键系统文件权限检查:"
    for file in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/ssh/sshd_config /etc/sudoers; do
        if [ -f "$file" ]; then
            ls -l "$file"
        fi
    done
    
    echo -e "\n>>> SUID/SGID文件检查 (限制输出前10个):"
    find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null | head -10
    
    echo -e "\n>>> 全局可写目录检查 (限制输出前10个):"
    find / -type d -perm -0002 -not -path "/proc/*" -not -path "/sys/*" -exec ls -ld {} \; 2>/dev/null | head -10
} >> "$FULL_OUTPUT_PATH"

log "用户权限分离检查"
{
    echo ">>> 检查用户角色分离情况:"
    echo "管理员组 (sudo/wheel) 成员:"
    grep -E "^sudo:|^wheel:" /etc/group 2>/dev/null | cut -d: -f4
    
    echo -e "\n>>> 其他特权组成员检查:"
    for group in adm dip disk lp mail news staff; do
        if grep -q "^$group:" /etc/group; then
            echo "$group 组成员: $(grep "^$group:" /etc/group | cut -d: -f4)"
        fi
    done
} >> "$FULL_OUTPUT_PATH"

log "强制访问控制检查"
{
    echo ">>> SELinux/AppArmor状态检查:"
    if command -v getenforce &> /dev/null; then
        echo "SELinux状态: $(getenforce 2>/dev/null || echo '需要root权限')"
    else
        echo "SELinux工具未安装"
    fi
    
    if command -v aa-status &> /dev/null; then
        echo -e "\nAppArmor状态:"
        aa-status 2>/dev/null || echo "需要root权限检查AppArmor状态"
    else
        echo -e "\nAppArmor工具未安装"
    fi
} >> "$FULL_OUTPUT_PATH"

# 6. 安全审计
section "6. 安全审计"

log "系统日志配置"
{
    echo ">>> rsyslog配置检查:"
    if [ -f /etc/rsyslog.conf ]; then
        grep -v "^#\|^$" /etc/rsyslog.conf | grep -E "auth|authpriv|daemon|kern|lpr|mail|mark|news|security|syslog|user|uucp|local"
    fi
    
    echo -e "\n>>> journald配置检查:"
    if [ -f /etc/systemd/journald.conf ]; then
        grep -v "^#\|^$" /etc/systemd/journald.conf
    fi
    
    echo -e "\n>>> 日志保留策略检查:"
    if [ -f /etc/logrotate.conf ]; then
        grep -v "^#\|^$" /etc/logrotate.conf | head -20
    fi
} >> "$FULL_OUTPUT_PATH"

log "审计子系统状态"
{
    echo ">>> auditd状态检查:"
    if command -v auditctl &> /dev/null; then
        systemctl status auditd 2>/dev/null || echo "需要root权限检查auditd服务状态"
        echo -e "\n>>> 审计规则:"
        auditctl -l 2>/dev/null || echo "需要root权限查看审计规则"
    else
        echo "auditd未安装"
    fi
} >> "$FULL_OUTPUT_PATH"

log "日志完整性检查"
{
    echo ">>> 检查主要日志文件:"
    for log in /var/log/syslog /var/log/auth.log /var/log/secure /var/log/messages; do
        if [ -f "$log" ]; then
            echo "$log 文件大小和权限:"
            ls -la "$log"
        fi
    done
    
    echo -e "\n>>> 检查日志完整性机制:"
    if [ -d /etc/logrotate.d ]; then
        echo "logrotate配置存在"
    fi
    
    if command -v aide &> /dev/null; then
        echo "AIDE文件完整性检查工具已安装"
    else
        echo "AIDE文件完整性检查工具未安装"
    fi
} >> "$FULL_OUTPUT_PATH"

# 7. 剩余信息保护
section "7. 剩余信息保护"

log "内存和交换空间保护"
{
    echo ">>> 检查系统内存保护策略:"
    if [ -f /etc/sysctl.conf ]; then
        echo "内存保护sysctl配置:"
        grep -E "kernel.randomize_va_space|vm.mmap_min_addr|kernel.kptr_restrict|kernel.dmesg_restrict" /etc/sysctl.conf 2>/dev/null || echo "未找到相关内存保护配置"
    fi
    
    echo -e "\n>>> 交换分区加密检查:"
    grep -E "swap.*encrypt" /etc/fstab 2>/dev/null || echo "未发现加密交换分区配置"
    
    echo -e "\n>>> 当前ASLR状态:"
    cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "无法读取ASLR状态"
} >> "$FULL_OUTPUT_PATH"

log "文件系统保护"
{
    echo ">>> 临时文件目录权限:"
    ls -ld /tmp /var/tmp
    
    echo -e "\n>>> 粘滞位(sticky bit)设置检查:"
    find / -type d -perm -1000 -exec ls -ld {} \; 2>/dev/null | head -5
    
    echo -e "\n>>> 文件系统加密检查:"
    if command -v cryptsetup &> /dev/null; then
        cryptsetup status 2>/dev/null || echo "需要root权限检查加密卷状态"
    else
        echo "未安装cryptsetup工具"
    fi
    
    if grep -q "dm-crypt" /proc/crypto 2>/dev/null; then
        echo "系统支持dm-crypt加密"
    fi
} >> "$FULL_OUTPUT_PATH"

log "敏感数据保护"
{
    echo ">>> 检查配置文件中的明文凭据 (示例检查):"
    grep -l "password\|user\|username\|pass\|pw" /etc/*.conf 2>/dev/null | head -10
    
    echo -e "\n>>> 检查home目录权限:"
    ls -ld /home/*
    
    echo -e "\n>>> 检查是否安装了数据销毁工具:"
    for tool in shred wipe secure-delete; do
        if command -v "$tool" &> /dev/null; then
            echo "$tool 已安装"
        else
            echo "$tool 未安装"
        fi
    done
} >> "$FULL_OUTPUT_PATH"

# 8. 入侵防范安全
section "8. 入侵防范安全"

log "防火墙状态"
{
    echo ">>> iptables防火墙规则检查:"
    if command -v iptables &> /dev/null; then
        iptables -L -n 2>/dev/null || echo "需要root权限查看iptables规则"
    else
        echo "iptables命令未安装"
    fi
    
    echo -e "\n>>> firewalld状态检查:"
    if command -v firewall-cmd &> /dev/null; then
        firewall-cmd --state 2>/dev/null
        echo -e "\n>>> 活跃区域:"
        firewall-cmd --get-active-zones 2>/dev/null || echo "需要root权限查看firewalld状态"
    else
        echo "firewalld未安装"
    fi
    
    echo -e "\n>>> ufw状态检查:"
    if command -v ufw &> /dev/null; then
        ufw status 2>/dev/null || echo "需要root权限查看ufw状态"
    else
        echo "ufw未安装"
    fi
} >> "$FULL_OUTPUT_PATH"

log "入侵检测系统"
{
    echo ">>> 检查是否安装了入侵检测系统:"
    for ids in aide tripwire ossec-hids snort suricata; do
        if command -v "$ids" &> /dev/null || [ -d "/var/lib/$ids" ] || [ -d "/etc/$ids" ]; then
            echo "$ids 已安装"
        else
            echo "$ids 未安装"
        fi
    done
    
    echo -e "\n>>> 文件完整性监控状态:"
    if command -v aide &> /dev/null; then
        if [ -f /var/lib/aide/aide.db.gz ]; then
            echo "AIDE数据库存在"
        else
            echo "AIDE数据库不存在"
        fi
    fi
} >> "$FULL_OUTPUT_PATH"

log "异常登录检测"
{
    echo ">>> 最近失败的登录尝试:"
    lastb | head -20 2>/dev/null || echo "需要root权限查看登录失败记录"
    
    echo -e "\n>>> 检查可疑IP登录:"
    last | grep -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -10
    
    echo -e "\n>>> SSH密钥登录配置:"
    if [ -f /etc/ssh/sshd_config ]; then
        grep -E "^PubkeyAuthentication|^PasswordAuthentication" /etc/ssh/sshd_config
    fi
} >> "$FULL_OUTPUT_PATH"

# 9. 恶意代码防范
section "9. 恶意代码防范"

log "防病毒软件状态"
{
    echo ">>> 检查防病毒软件安装状态:"
    for av in clamav rkhunter chkrootkit; do
        if command -v "$av" &> /dev/null; then
            echo "$av 已安装"
            case "$av" in
                clamav)
                    clamscan --version 2>/dev/null
                    echo "上次更新: $(stat -c %y /var/lib/clamav/main.cvd 2>/dev/null || echo '无法获取')"
                    ;;
                rkhunter)
                    rkhunter --version 2>/dev/null
                    ;;
                chkrootkit)
                    chkrootkit -V 2>/dev/null
                    ;;
            esac
        else
            echo "$av 未安装"
        fi
    done
} >> "$FULL_OUTPUT_PATH"

log "可疑进程检查"
{
    echo ">>> 检查可疑进程:"
    ps auxf | grep -v grep | grep -E "bash -i|sh -i|netcat|nc -l|cryptominer"
    
    echo -e "\n>>> 检查异常监听端口:"
    if command -v netstat &> /dev/null; then
        netstat -tulpn 2>/dev/null | grep LISTEN || echo "需要root权限获取完整监听端口信息"
    elif command -v ss &> /dev/null; then
        ss -tulpn 2>/dev/null | grep LISTEN || echo "需要root权限获取完整监听端口信息"
    fi
} >> "$FULL_OUTPUT_PATH"

log "系统完整性检查"
{
    echo ">>> 检查可疑的cron作业:"
    for user in $(cut -f1 -d: /etc/passwd); do
        if [ -f "/var/spool/cron/crontabs/$user" ]; then
            echo "用户 $user 的cron作业:"
            cat "/var/spool/cron/crontabs/$user" 2>/dev/null || echo "无法读取 (需要root权限)"
        fi
    done
    
    echo -e "\n>>> 系统计划任务:"
    for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly; do
        if [ -d "$crondir" ]; then
            echo "目录 $crondir 中的任务:"
            ls -la "$crondir"
        fi
    done
    
    if [ -f /etc/crontab ]; then
        echo -e "\n>>> 主crontab文件:"
        cat /etc/crontab
    fi
} >> "$FULL_OUTPUT_PATH"

# 10. 资源控制安全
section "10. 资源控制安全"

log "进程资源限制"
{
    echo ">>> 系统级资源限制配置检查:"
    if [ -f /etc/security/limits.conf ]; then
        grep -v "^#\|^$" /etc/security/limits.conf
    fi
    
    echo -e "\n>>> 当前系统资源限制:"
    ulimit -a
    
    echo -e "\n>>> 系统最大打开文件数配置:"
    cat /proc/sys/fs/file-max 2>/dev/null
} >> "$FULL_OUTPUT_PATH"

log "磁盘配额"
{
    echo ">>> 检查是否启用了磁盘配额:"
    if command -v quotacheck &> /dev/null; then
        echo "磁盘配额工具已安装"
        mount | grep usrquota
        mount | grep grpquota
    else
        echo "磁盘配额工具未安装"
    fi
} >> "$FULL_OUTPUT_PATH"

log "服务控制机制"
{
    echo ">>> 检查系统控制服务状态:"
    if command -v systemctl &> /dev/null; then
        echo "运行中服务列表:"
        systemctl list-units --type=service --state=running | head -20
    else
        echo "使用传统服务管理，显示运行中进程:"
        ps -ef | head -20
    fi
    
    echo -e "\n>>> CPU和内存控制组配置:"
    if [ -d /sys/fs/cgroup ]; then
        ls -la /sys/fs/cgroup/
        if [ -d /sys/fs/cgroup/memory ]; then
            echo -e "\n内存控制组配置样例:"
            ls -la /sys/fs/cgroup/memory | head -5
        fi
    else
        echo "控制组未挂载或使用非标准位置"
    fi
} >> "$FULL_OUTPUT_PATH"

# 11. 更多Linux安全检查
section "11. 更多Linux安全检查"

log "内核安全机制"
{
    echo ">>> 内核安全模块检查:"
    if command -v modprobe &> /dev/null; then
        lsmod | grep -E "selinux|apparmor|tomoyo|smack|yama|capability"
    fi
    
    echo -e "\n>>> sysctl安全配置检查:"
    sysctl -a 2>/dev/null | grep -E "fs.suid_dumpable|kernel.randomize_va_space|kernel.kptr_restrict|kernel.yama|kernel.dmesg_restrict" || echo "需要root权限检查完整sysctl配置"
} >> "$FULL_OUTPUT_PATH"

log "容器和虚拟化安全"
{
    echo ">>> 检查容器运行时:"
    for container in docker podman lxc lxd; do
        if command -v "$container" &> /dev/null; then
            echo "$container 已安装"
            if [ "$container" = "docker" ] && command -v docker &> /dev/null; then
                echo "Docker版本: $(docker --version 2>/dev/null)"
                echo "运行中的容器:"
                docker ps 2>/dev/null || echo "需要root权限或docker组成员资格查看运行中的容器"
            elif [ "$container" = "podman" ] && command -v podman &> /dev/null; then
                echo "Podman版本: $(podman --version 2>/dev/null)"
                echo "运行中的容器:"
                podman ps 2>/dev/null || echo "需要适当权限查看运行中的容器"
            fi
        else
            echo "$container 未安装"
        fi
    done
    
    echo -e "\n>>> 检查虚拟化平台:"
    if command -v virsh &> /dev/null; then
        echo "libvirt已安装"
        virsh list --all 2>/dev/null || echo "需要root权限查看虚拟机"
    else
        echo "libvirt未安装"
    fi
    
    echo -e "\n>>> 检查虚拟化技术:"
    if [ -f /proc/cpuinfo ]; then
        grep -E "vmx|svm" /proc/cpuinfo | head -1 || echo "CPU可能不支持硬件虚拟化"
    fi
} >> "$FULL_OUTPUT_PATH"

log "安全修补程序状态"
{
    echo ">>> 检查系统更新状态:"
    if command -v apt &> /dev/null; then
        echo "Debian/Ubuntu系统:"
        apt list --upgradable 2>/dev/null | head -10
    elif command -v yum &> /dev/null; then
        echo "RHEL/CentOS系统:"
        yum check-update --security 2>/dev/null | head -10 || echo "需要root权限检查安全更新"
    elif command -v dnf &> /dev/null; then
        echo "Fedora/新版CentOS系统:"
        dnf check-update --security 2>/dev/null | head -10 || echo "需要root权限检查安全更新"
    else
        echo "未识别的包管理系统"
    fi
    
    echo -e "\n>>> 内核版本检查:"
    uname -r
} >> "$FULL_OUTPUT_PATH"

log "网络服务安全"
{
    echo ">>> 检查常见网络服务安全配置:"
    if [ -f /etc/ssh/sshd_config ]; then
        echo "SSH服务配置:"
        grep -v "^#\|^$" /etc/ssh/sshd_config | head -20
    fi
    
    echo -e "\n>>> Web服务器配置检查:"
    for webconf in "/etc/apache2/apache2.conf" "/etc/httpd/conf/httpd.conf" "/etc/nginx/nginx.conf"; do
        if [ -f "$webconf" ]; then
            echo "找到Web服务器配置: $webconf"
            head -20 "$webconf"
        fi
    done
    
    echo -e "\n>>> 检查常见SSL/TLS配置:"
    for ssldir in "/etc/ssl" "/etc/pki/tls"; do
        if [ -d "$ssldir" ]; then
            echo "SSL/TLS配置目录: $ssldir"
            ls -la "$ssldir"
        fi
    done
    
    echo -e "\n>>> 检查开放端口及关联服务:"
    if command -v ss &> /dev/null; then
        ss -tulpn | grep LISTEN | sort -n -k 5
    elif command -v netstat &> /dev/null; then
        netstat -tulpn | grep LISTEN | sort -n -k 4
    fi
} >> "$FULL_OUTPUT_PATH"

log "文件完整性检查"
{
    echo ">>> 重要系统二进制文件检查:"
    for bin in /bin/ls /bin/bash /bin/sh /usr/bin/sudo /usr/bin/passwd; do
        if [ -f "$bin" ]; then
            echo "$bin 文件信息:"
            ls -la "$bin"
            if command -v md5sum &> /dev/null; then
                md5sum "$bin" 2>/dev/null
            fi
        fi
    done
    
    echo -e "\n>>> 检查文件完整性检测系统:"
    if command -v aide &> /dev/null; then
        echo "AIDE已安装"
        if [ -f /etc/aide/aide.conf ]; then
            echo "AIDE配置文件存在:"
            grep -v "^#\|^$" /etc/aide/aide.conf | head -10
        fi
    else
        echo "AIDE未安装"
    fi
    
    if command -v tripwire &> /dev/null; then
        echo "Tripwire已安装"
    else
        echo "Tripwire未安装"
    fi
} >> "$FULL_OUTPUT_PATH"

log "特权命令审计"
{
    echo ">>> 检查特权命令执行记录:"
    
    if [ -f /var/log/auth.log ]; then
        echo "从auth.log中提取sudo命令执行记录 (最新20条):"
        grep "sudo:" /var/log/auth.log | tail -20
    elif [ -f /var/log/secure ]; then
        echo "从secure日志中提取sudo命令执行记录 (最新20条):"
        grep "sudo:" /var/log/secure | tail -20
    fi
    
    echo -e "\n>>> 检查setuid/setgid程序:"
    find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null | head -20
} >> "$FULL_OUTPUT_PATH"

# 12. 数据备份与恢复
section "12. 数据备份与恢复"

log "备份系统配置"
{
    echo ">>> 检查系统备份配置:"
    for backup in rsnapshot bacula amanda duplicity restic borgbackup; do 
        if command -v "$backup" &> /dev/null; then
            echo "$backup 备份工具已安装"
        fi
    done
    
    if [ -f /etc/rsnapshot.conf ]; then
        echo -e "\n>>> rsnapshot备份配置:"
        grep -v "^#\|^$" /etc/rsnapshot.conf | head -20
    fi
    
    # 检查系统定时备份任务
    echo -e "\n>>> 检查备份相关计划任务:"
    for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly; do
        if [ -d "$crondir" ]; then
            echo "$crondir 中的备份相关任务:"
            grep -l "backup\|dump\|save\|archive" "$crondir"/* 2>/dev/null
        fi
    done
} >> "$FULL_OUTPUT_PATH"

log "数据恢复机制"
{
    echo ">>> 检查文件系统快照配置:"
    if command -v lvcreate &> /dev/null; then
        echo "LVM卷管理器已安装，支持LVM快照"
        if command -v vgs &> /dev/null; then
            echo "卷组信息:"
            vgs 2>/dev/null || echo "需要root权限查看卷组信息"
        fi
    fi
    
    if command -v btrfs &> /dev/null; then
        echo "BTRFS文件系统工具已安装，支持BTRFS快照"
        if grep -q "btrfs" /proc/mounts; then
            echo "系统中存在BTRFS挂载点"
        fi
    fi
    
    if command -v zfs &> /dev/null; then
        echo "ZFS文件系统工具已安装，支持ZFS快照"
        if command -v zpool &> /dev/null; then
            echo "ZFS池信息:"
            zpool list 2>/dev/null || echo "需要root权限查看ZFS池信息"
        fi
    fi
} >> "$FULL_OUTPUT_PATH"

# 13. 网络安全
section "13. 网络安全"

log "网络拓扑和隔离"
{
    echo ">>> 检查网络接口配置:"
    ip addr
    
    echo -e "\n>>> 检查路由表:"
    ip route
    
    echo -e "\n>>> 检查ARP表:"
    ip neigh
    
    echo -e "\n>>> 检查网络命名空间 (网络隔离):"
    if ip netns list &>/dev/null; then
        ip netns list 2>/dev/null || echo "需要root权限查看网络命名空间"
    else
        echo "无网络命名空间或命令不支持"
    fi
    
    echo -e "\n>>> 检查是否启用了IP转发 (路由功能):"
    cat /proc/sys/net/ipv4/ip_forward
} >> "$FULL_OUTPUT_PATH"

log "DDoS防护配置"
{
    echo ">>> 检查SYN flood防护设置:"
    if [ -f /proc/sys/net/ipv4/tcp_syncookies ]; then
        echo "SYN cookies状态: $(cat /proc/sys/net/ipv4/tcp_syncookies)"
    fi
    
    echo -e "\n>>> 检查连接速率限制配置:"
    if command -v iptables &> /dev/null; then
        iptables -L -n | grep -i "limit" 2>/dev/null || echo "未发现明显的速率限制规则或需要root权限"
    fi
    
    echo -e "\n>>> 检查防火墙DDoS防护规则:"
    if command -v firewall-cmd &> /dev/null; then
        firewall-cmd --direct --get-all-rules 2>/dev/null || echo "需要root权限查看firewalld规则"
    fi
} >> "$FULL_OUTPUT_PATH"

log "VPN和加密通信"
{
    echo ">>> 检查VPN服务配置:"
    for vpn in openvpn strongswan wireguard libreswan; do
        if command -v "$vpn" &> /dev/null || [ -d "/etc/$vpn" ]; then
            echo "$vpn 已安装"
            if [ "$vpn" = "openvpn" ] && [ -d "/etc/openvpn" ]; then
                echo "OpenVPN配置目录内容:"
                ls -la /etc/openvpn/
            elif [ "$vpn" = "wireguard" ] && [ -d "/etc/wireguard" ]; then
                echo "WireGuard配置目录内容:"
                ls -la /etc/wireguard/ 2>/dev/null || echo "需要root权限查看配置"
            fi
        else
            echo "$vpn 未安装"
        fi
    done
    
    echo -e "\n>>> 检查SSH加密算法配置:"
    if [ -f /etc/ssh/sshd_config ]; then
        grep -E "Ciphers|MACs|KexAlgorithms|HostKeyAlgorithms" /etc/ssh/sshd_config
    fi
} >> "$FULL_OUTPUT_PATH"

# 14. 安全基线检查
section "14. 安全基线检查"

log "CIS基线检查示例"
{
    echo ">>> 检查一些CIS基线推荐配置:"
    
    echo "1. 检查是否禁用了不必要的文件系统:"
    for fs in cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat; do
        if lsmod | grep -q "$fs"; then
            echo "$fs 文件系统模块已加载"
        else
            echo "$fs 文件系统模块未加载 (符合安全建议)"
        fi
    done
    
    echo -e "\n2. 检查是否设置了密码复杂度要求:"
    if [ -f /etc/pam.d/common-password ]; then
        grep "pam_pwquality.so\|pam_cracklib.so" /etc/pam.d/common-password || echo "未找到密码复杂度配置"
    elif [ -f /etc/pam.d/system-auth ]; then
        grep "pam_pwquality.so\|pam_cracklib.so" /etc/pam.d/system-auth || echo "未找到密码复杂度配置"
    fi
    
    echo -e "\n3. 检查是否启用了远程日志记录:"
    if [ -f /etc/rsyslog.conf ]; then
        grep "@" /etc/rsyslog.conf || echo "未找到明显的远程日志配置"
    fi
} >> "$FULL_OUTPUT_PATH"

log "DISA STIG检查示例"
{
    echo ">>> 检查一些DISA STIG基线推荐配置:"
    
    echo "1. 检查auditd配置是否符合STIG建议:"
    if [ -f /etc/audit/auditd.conf ]; then
        grep "max_log_file\|space_left_action\|action_mail_acct" /etc/audit/auditd.conf
    else
        echo "未找到auditd配置文件"
    fi
    
    echo -e "\n2. 检查是否设置了最大失败登录尝试次数限制:"
    if [ -f /etc/pam.d/system-auth ]; then
        grep "pam_tally2.so\|pam_faillock.so" /etc/pam.d/system-auth || echo "未找到登录尝试限制配置"
    elif [ -f /etc/pam.d/common-auth ]; then
        grep "pam_tally2.so\|pam_faillock.so" /etc/pam.d/common-auth || echo "未找到登录尝试限制配置" 
    fi
    
    echo -e "\n3. 检查是否设置了会话超时:"
    if [ -f /etc/profile ]; then
        grep "TMOUT" /etc/profile || echo "未在/etc/profile中找到会话超时设置"
    fi
    if [ -f /etc/bash.bashrc ]; then
        grep "TMOUT" /etc/bash.bashrc || echo "未在/etc/bash.bashrc中找到会话超时设置"
    fi
} >> "$FULL_OUTPUT_PATH"

# 15. 漏洞扫描
section "15. 漏洞扫描"

log "系统漏洞检查"
{
    echo ">>> 检查是否安装了漏洞扫描工具:"
    for scanner in lynis openvas openscap nessus nikto; do
        if command -v "$scanner" &> /dev/null || [ -d "/usr/share/$scanner" ] || [ -d "/opt/$scanner" ]; then
            echo "$scanner 已安装"
        else
            echo "$scanner 未安装"
        fi
    done
    
    echo -e "\n>>> 如果有Lynis，运行基本检查:"
    if command -v lynis &> /dev/null; then
        echo "Lynis版本: $(lynis --version 2>/dev/null)"
        echo "要运行完整的Lynis扫描，请以root用户执行: lynis audit system"
    fi
} >> "$FULL_OUTPUT_PATH"

log "软件组件漏洞检查"
{
    echo ">>> 检查是否安装了软件组件扫描工具:"
    for scanner in trivy grype dependency-check; do
        if command -v "$scanner" &> /dev/null; then
            echo "$scanner 已安装"
        else
            echo "$scanner 未安装"
        fi
    done
    
    echo -e "\n>>> 检查系统关键软件版本:"
    echo "内核版本: $(uname -r)"
    if command -v openssl &> /dev/null; then
        echo "OpenSSL版本: $(openssl version)"
    fi
    if command -v ssh &> /dev/null; then
        echo "SSH客户端版本: $(ssh -V 2>&1)"
    fi
    if command -v apache2 &> /dev/null; then
        echo "Apache版本: $(apache2 -v | head -1 2>/dev/null)"
    elif command -v httpd &> /dev/null; then
        echo "Apache版本: $(httpd -v | head -1 2>/dev/null)"
    fi
    if command -v nginx &> /dev/null; then
        echo "Nginx版本: $(nginx -v 2>&1)"
    fi
} >> "$FULL_OUTPUT_PATH"

# 16. 安全配置管理
section "16. 安全配置管理"

log "自动化安全管理"
{
    echo ">>> 检查是否安装了配置管理工具:"
    for tool in ansible puppet chef salt-minion; do
        if command -v "$tool" &> /dev/null; then
            echo "$tool 已安装"
            if [ "$tool" = "ansible" ]; then
                ansible --version | head -1 2>/dev/null
            elif [ "$tool" = "puppet" ]; then
                puppet --version 2>/dev/null
            elif [ "$tool" = "chef" ]; then
                chef-client --version 2>/dev/null
            elif [ "$tool" = "salt-minion" ]; then
                salt-minion --version 2>/dev/null
            fi
        else
            echo "$tool 未安装"
        fi
    done
    
    echo -e "\n>>> 检查是否存在配置管理文件:"
    for file in /etc/ansible /etc/puppet /etc/chef /etc/salt; do
        if [ -d "$file" ]; then
            echo "$file 目录存在"
            ls -la "$file" | head -5
        fi
    done
} >> "$FULL_OUTPUT_PATH"

log "变更监控机制"
{
    echo ">>> 检查是否安装了文件监控工具:"
    for monitor in inotify-tools incron auditd; do
        if command -v "$monitor" &> /dev/null || [ -d "/etc/$monitor" ]; then
            echo "$monitor 已安装"
        else
            echo "$monitor 未安装"
        fi
    done
    
    echo -e "\n>>> 检查是否存在文件监控配置:"
    if [ -f /etc/audit/rules.d/audit.rules ]; then
        echo "Audit文件监控规则:"
        grep "path=" /etc/audit/rules.d/audit.rules 2>/dev/null | head -10 || echo "未找到文件监控规则或需要root权限"
    fi
    
    if [ -d /etc/incron.d ]; then
        echo -e "\nIncron配置:"
        ls -la /etc/incron.d/
    fi
} >> "$FULL_OUTPUT_PATH"

# 17. 报告总结
section "17. 系统安全检查总结"

# 报告完成信息
{
    echo "安全检查已完成。"
    echo "检查时间: $(date)"
    echo "结果保存在: $FULL_OUTPUT_PATH"
    echo ""
    echo "这个报告只是进行了基本的系统安全检查和记录，并未对系统进行任何修改。"
    echo "请根据报告结果评估您的系统安全状况，并采取必要的安全加固措施。"
    echo ""
    echo "常见安全加固建议:"
    echo "1. 保持系统和软件包更新"
    echo "2. 实施最小权限原则"
    echo "3. 加强密码策略"
    echo "4. 配置防火墙和网络安全"
    echo "5. 启用入侵检测和防护机制"
    echo "6. 实施文件完整性监控"
    echo "7. 定期备份关键数据"
    echo "8. 监控系统日志"
    echo "9. 禁用或删除不必要的服务和账户"
    echo "10. 实施安全配置基线"
} >> "$FULL_OUTPUT_PATH"

echo "安全检查完成，结果已保存到 $FULL_OUTPUT_PATH"
echo "请使用文本编辑器查看详细报告"
