#!/bin/bash
# @Author: zhoubin
# @Email: 2350686113@qq.com
# @Date: 2021-06-21
# @Last modified by: zhoubin
# @Last modified by time: 2020-06-21
# @Descriptions: 系统初始化脚本

__ScriptVersion="2021.06.21"
__ScriptName="init-system.sh"
__ScriptFullName="$0"
__ScriptArgs="$#"

BASE_DIR=$(cd "$(dirname "$0")";pwd)
BS_TRUE=1
BS_FALSE=0

#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  __detect_color_support
#   DESCRIPTION:  Try to detect color support.
#----------------------------------------------------------------------------------------------------------------------
_COLORS=${BS_COLORS:-$(tput colors 2>/dev/null || echo 0)}
__detect_color_support() {
    # shellcheck disable=SC2181
    if [ $? -eq 0 ] && [ "$_COLORS" -gt 2 ]; then
        RC='\033[1;31m'
        GC='\033[1;32m'
        BC='\033[1;34m'
        YC='\033[1;33m'
        EC='\033[0m'
    else
        RC=""
        GC=""
        BC=""
        YC=""
        EC=""
    fi
}
__detect_color_support

#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  echoerr
#   DESCRIPTION:  错误信息输出
#----------------------------------------------------------------------------------------------------------------------
echoerror() {
    printf "${RC} * ERROR${EC}: %s\\n" "$@" 1>&2;
}

#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  echoinfo
#   DESCRIPTION:  正常信息输出
#----------------------------------------------------------------------------------------------------------------------
echoinfo() {
    printf "${GC} *  INFO${EC}: %s\\n" "$@";
}

#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  echowarn
#   DESCRIPTION:  告警信息输出.
#----------------------------------------------------------------------------------------------------------------------
echowarn() {
    printf "${YC} *  WARN${EC}: %s\\n" "$@";
}

#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  echodebug
#   DESCRIPTION: 调试信息输出.
#----------------------------------------------------------------------------------------------------------------------
echodebug() {
    if [ "$_ECHO_DEBUG" -eq $BS_TRUE ]; then
        printf "${BC} * DEBUG${EC}: %s\\n" "$@";
    fi
}

# 设置日志输出文件以及日志输出管道
LOGFILE="/tmp/$( echo "$__ScriptName" | sed s/.sh/.log/g )"
LOGPIPE="/tmp/$( echo "$__ScriptName" | sed s/.sh/.logpipe/g )"

# 删除残留的旧管道
rm "$LOGPIPE" 2>/dev/null

# 创建日志输出管道
# On FreeBSD we have to use mkfifo instead of mknod
if ! (mknod "$LOGPIPE" p >/dev/null 2>&1 || mkfifo "$LOGPIPE" >/dev/null 2>&1); then
    echoerror "Failed to create the named pipe required to log"
    exit 1
fi

# 将日志管道中的信息写入到日志文件中
tee < "$LOGPIPE" "$LOGFILE" &

# 关闭标准输出，然后将其重新打开并重定向到日志输出管道
exec 1>&-
exec 1>"$LOGPIPE"
# 关闭错误输出，然后将其重新打开并重定向到日志输出管道
exec 2>&-
exec 2>"$LOGPIPE"

# whoami alternative for SunOS
if [ -f /usr/xpg4/bin/id ]; then
    whoami='/usr/xpg4/bin/id -un'
else
    whoami='whoami'
fi

# Root permissions are required to run this script
if [ "$($whoami)" != "root" ]; then
    echoerror "Script requires root privileges to execute. Please re-run this script as root."
    exit 1
fi

#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  __gather_os_info
#   DESCRIPTION:  Discover operating system information
#----------------------------------------------------------------------------------------------------------------------
__gather_os_info() {
    OS_NAME=$(uname -s 2>/dev/null)
    OS_NAME_L=$( echo "$OS_NAME" | tr '[:upper:]' '[:lower:]' )
    OS_VERSION=$(uname -r)
    # shellcheck disable=SC2034
    OS_VERSION_L=$( echo "$OS_VERSION" | tr '[:upper:]' '[:lower:]' )
    IPADDR=$(ip addr | grep global | awk -F '[ /]+' '{print $3}')
}
__gather_os_info

#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  __yum_install_noinput
#   DESCRIPTION:  (DRY) yum install with noinput options
#----------------------------------------------------------------------------------------------------------------------
__yum_install_noinput(){
    for package in "${@}"; do
        echoinfo "正在安装软件 ${package} ."
        yum install -y "${package}" || return $?

        [[ $? -eq $BS_TRUE ]] && echoerror "${package} 安装失败！" || echoinfo "${package} 安装完成."
    done
}


__yum_install_base() {
        echoinfo "正在安装常用的软件..."
    __yum_install_noinput net-tools vim wget lrzsz tree bash-completion epel-release ntpdate || return 1
}

__disable_firewalld(){
    echoinfo "正在关闭防火墙" 
    systemctl disable --now firewalld || return 1

    [[ $? -eq $BS_TRUE ]] && echoerror "防火墙关闭失败" || echoinfo "防火墙已关闭"
}

__disable_selinux(){
    echoinfo "正在关闭 SeLinux"
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config || return 1

    [[ $? -eq $BS_TRUE ]] && echoerror "SeLinux 关闭失败" || echoinfo " SELINUX 已关闭"
}

__modify_yum_repo(){
    echoinfo "正在修改 YUM 仓库镜像"
    mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.backup
    wget -O /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo || return 1
    wget -O /etc/yum.repos.d/epel.repo http://mirrors.aliyun.com/repo/epel-7.repo || return 1
    wget -O /etc/yum.repos.d/CentOS7-Base-163.repo http://mirrors.163.com/.help/CentOS7-Base-163.repo || return 1

    yum clean all && yum makecache || return 1

    [[ $? -eq $BS_TRUE ]] && echoerror "YUM repo 修改失败" || echoinfo "YUM repo 已修改完成"
}

__modify_ps_style(){
    echoinfo "正在修改 PS1 样式."
    echo "export PS1='\[\e[37;40m\][\[\e[32;40m\]\u\[\e[37;40m\]@\[\e[33;40m\]\h \[\e[35;40m\]\W\[\e[0m\]]\\$ '" >>/etc/profile
}

__modify_history_format(){
    echoinfo "正在修改历史命令记录格式."
    echo "export HISTTIMEFORMAT=\"%Y-%m-%d %H:%M:%S  \$(whoami)  \"" >> /etc/profile
    echo "export PROMPT_COMMAND='{ msg=\$(history 1 | { read x y; echo \$y; }); logger \"[euid=\$(whoami)]\":\$(who am i):[\$(pwd)]\"\$msg\";}'" >> /etc/profile
}

__modify_session_timeout(){
    echoinfo "正在修改会话超时时间."
    echo "export TMOUT=300" >> /etc/profile
}

__modify_limit(){
    echoinfo "正在修改文件限制."
    echo "*   soft    nofile      65535" >> /etc/security/limits.conf
    echo "*   hard    nofile      65535" >> /etc/security/limits.conf
    echo "*   soft    nproc       65535" >> /etc/security/limits.conf
    echo "*   hard    nproc       65535" >> /etc/security/limits.conf
}

__add_ssh_banner(){
    echoinfo "正在修改 SSH 登录提示语."
    sed -i 's_#Banner none_Banner /etc/ssh/alert_' /etc/ssh/sshd_config

    echo "***************************************************************************" > /etc/ssh/alert
    echo "      警告: 你正在登录到重要服务器，所有从操作将被记录。请谨慎操作 !!!     " >> /etc/ssh/alert
    echo "***************************************************************************"  >> /etc/ssh/alert

    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" > /etc/motd
    echo "!!!                                                                     !!!" >> /etc/motd
    echo "!!!       You have successfully logged on to the $HOSTNAME Server,      !!!" >> /etc/motd
    echo "!!!       All your actions will be recorded, please be carefully!       !!!" >> /etc/motd
    echo "!!!                                                                     !!!" >> /etc/motd
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" >> /etc/motd
}

__add_ntpdate_cron(){
    echoinfo "正在添加时间同步定时任务."
    echo '05 01 * * * /usr/sbin/ntpdate time2.aliyun.com >/dev/null' >> /var/spool/cron/root
    echo '/usr/sbin/ntpdate time2.aliyun.com' >> /etc/rc.local
}

__turn_off_usedns(){
    echoinfo "正在关闭 SSHD 服务使用 DNS 解析"
    sed -i 's/#UseDNS yes/UseDNS no/g' /etc/ssh/sshd_config
}

__modify_passwd_policy(){
    echoinfo "正在设置密码策略."

    echoinfo "修改密码最长有效期为 90 天"
    sed -i "s/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS   90" /etc/login.defs

    echoinfo "修改密码最小长度为 8"
    sed -i "s/^PASS_MIN_LEN.*$/PASS_MIN_LEN   8" /etc/login.defs

    echoinfo "修改密码到期前 15 天开始提醒."
    sed -i "s/^PASS_WARN_AGE.*$/PASS_WARN_AGE   15" /etc/login.defs
}

__display_os_info(){
    echoinfo "正在配置隐藏系统版本信息."
    if [[ -f /etc/issue ]];then
        mv /etc/issue /etc/issue.bak
    else
        echowarn "跳过 issue"
    fi

    if [[ -f /etc/issue.net ]];then
        mv /etc/issue.net /etc/issue.net.bak
    else
        echowarn "跳过 issue.net"
    fi 
}

__set_locked_account(){
    echoinfo "设置半小时内连续登录失败5次时锁定账户."
    echo 'auth        required      pam_tally2.so deny=5 unlock_time=1800 even_deny_root root_unlock_time=1800' >> /etc/pam.d/system-auth
}

__modify_sshd_security_config(){
    echoinfo "正在设置禁止 root 用户远程登录."
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config

    echoinfo "设置禁止空密码登录."
    sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config

    echoinfo "关闭 ssh 的 tcp 转发."
    sed -i 's/#AllowTcpForwarding yes/AllowTcpForwarding no/' /etc/ssh/sshd_config
    
    echoinfo "关闭 s/Key(质疑-应答)认证方式"
    sed -i 's/#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config

    echoinfo "重启 sshd 服务"
    systemctl restart sshd || return 1
    [[ $? -eq $BS_TRUE ]] && echoerror "sshd 服务重启失败." || echoinfo "sshd 服务重启完成."
}

__configuration_node_exporter(){
    echo "正在配置 Node Exporter systemd 服务"
    echo "[Unit]" > /usr/lib/systemd/system/node_exporter.service 
    echo "Description=node_exporter" >> /usr/lib/systemd/system/node_exporter.service 
    echo "After=network.target" >> /usr/lib/systemd/system/node_exporter.service 
    echo "" >> /usr/lib/systemd/system/node_exporter.service 
    echo "[Service]" >> /usr/lib/systemd/system/node_exporter.service 
    echo "Restart=on-failure" >> /usr/lib/systemd/system/node_exporter.service 
    echo "ExecStart=/usr/local/node_exporter/node_exporter" >> /usr/lib/systemd/system/node_exporter.service 
    echo "" >> /usr/lib/systemd/system/node_exporter.service 
    echo "[Install]" >> /usr/lib/systemd/system/node_exporter.service 
    echo "WantedBy=multi-user.target" >> /usr/lib/systemd/system/node_exporter.service 

    systemctl enable --now node_exporter || return 1
    [[ $? -eq $BS_TRUE ]] && echoerror "配置 node_exporter 服务失败." || echoinfo "配置 node_exporter 服务完成."
}

init_system_configuration(){
    echoinfo "正在执行系统初始化配置..."
    __yum_install_base || return 1
    __disable_firewalld || return 1
    __disable_selinux  || return 1
    __modify_yum_repo || return 1
    __modify_ps_style || return 1
    __modify_history_format || return 1
    __modify_session_timeout || return 1
    __modify_limit || return 1
    __add_ssh_banner || return 1
    __add_ntpdate_cron || return 1
    __turn_off_usedns || return 1
    #__modify_passwd_policy || return 1
    __display_os_info || return 1
    __set_locked_account || return 1
    __modify_sshd_security_config || return 1

    [[ $? -eq $BS_TRUE ]] && echoerror "初始化系统时遇到错误，详细信息请查看日志 /tmp/${__ScriptName}.log" || echoinfo "系统初始化配置完成，详细信息请查看日志 /tmp/${__ScriptName}.log."
}

install_node_exporter(){
    echoinfo "正在安装 Node Exporter."
    tar_files=$(ls $BASE_DIR/src/node_exporter-*.linux-amd64.tar.gz 2> /dev/null)
    if [[ -e "$tar_files" ]];then
        cd $BASE_DIR/src
        tar xf node_exporter-*.tar.gz -C /usr/local/

        src_dir=$(ls -d /usr/local/node_exporter-*.linux-amd64 2> /dev/null)
        mv $src_dir /usr/local/node_exporter
        __configuration_node_exporter || return 1
    else
        echoerror "$BASE_DIR/src/node_exporter-*.tar.gz 文件不存在." 
        sleep 1
        continue
    fi
    
    systemctl status node_exporter 2>&1 > /dev/null || return 1
    [[ $? -eq $BS_TRUE ]] && echoerror "node_exporter 安装失败." || echoinfo "node_exporter 安装完成"  
}

install_jdk8(){
    echoinfo "正在安装 jdk8."
    [[ ! -d /usr/local/java ]] && mkdir -p /usr/local/java
    tar_files=$(ls $BASE_DIR/src/jdk-*.tar.gz 2> /dev/null)
    if [[ -e "$tar_files" ]];then
        cd $BASE_DIR/src
        tar xf jdk-*.tar.gz -C /usr/local/java
        echo ""
        echo "#!/bin/bash" > /etc/profile.d/java.sh
        echo "" >> /etc/profile.d/java.sh
        echo "export JAVA_HOME=/usr/local/java/jdk1.8.0_202" >> /etc/profile.d/java.sh
        echo "export CLASSPATH=\$CLASSPATH:\$JAVA_HOME/lib:\$JAVA_HOME/jre/lib" >> /etc/profile.d/java.sh
        echo "export PATH=\$JAVA_HOME/bin:\$JAVA_HOME/jre/bin:\$PATH:\$HOME/bin" >> /etc/profile.d/java.sh
    else
        echoerror "jdk 压缩包不存在"
        sleep 1
        continue
    fi

    source /etc/profile.d/java.sh
    java -version 2>&1 >/dev/null || return 1
    [[ $? -eq $BS_TRUE ]] && echoerror "jdk8 安装失败." || echoinfo "jdk8 安装完成"
}

install_minion(){
    echoinfo "正在安装 Slat Minion."
    while :;do echo
        read -p "请输入 Salt-master 的地址(Deafult: 192.168.64.19): " SALT_MASTER
        SALT_MASTER=${SALT_MASTER:-"192.168.64.19"}
        if [[ "$SALT_MASTER" =~ ^([1-9]{1,3})\.([1-9]{1,3})\.([1-9]{1,3})\.([1-9]{1,3})$ ]];then
            flags=$(echo $SALT_MASTER | awk -F '.'  '$1<=255 && $2<=255 && $3<=255 && $4<=255 {print "yes"}')
            if [[ ${flags:-no} == "yes" ]];then
                break
            else
                echoerror "IP 地址不合法，请重新输入"
                continue
            fi
        else
            echoerror "IP 地址格式错误，请重新输入！"
        fi
    done
    echo ""
    echoinfo "当前配置的 Salt Master 地址为: [$SALT_MASTER]"

    echoinfo "正在添加 Salt YUM 仓库"
    __yum_install_noinput https://repo.saltstack.com/yum/redhat/salt-repo-latest.el7.noarch.rpm || return 1

    echoinfo "正在更新 YUM 仓库缓存"
    __yum_install_noinput salt-minion || return 1

    echoinfo "正在配置salt-minion"
    sed -i "s/#master: .*$/master: $SALT_MASTER/" /etc/salt/minion
    sed -i "s/#id:$/id: $IPADDR/" /etc/salt/minion

    echoinfo "正在启动 Salt Minion"
    systemctl enable --now salt-minion || return 1

    [[ $? -eq $BS_TRUE ]] && echoerror "Salt-minion 安装失败." || echoinfo "Salt-minion 安装完成"
}

__menu(){
    echo "*********************************************************"
    echo "*          1.  init_system_configuration                *"
    echo "*          2.  install_node_exporter                    *"
    echo "*          3.  install_jdk8                             *"
    echo "*          4.  install_salt-minion                      *"
    echo "*          q.  quit                                     *"
    echo "*********************************************************"
}

while true
do
    __menu

    read -p "请输入你的选择: " opt

    case $opt in
        1)
            init_system_configuration
            ;;
        2)
            install_node_exporter
            ;;
        3)
            install_jdk8
            ;;
        4)
            install_minion
            ;;
        q)
            sleep 1
            break
            ;;
        *)
            echo -e "\033[;31m输入错误，请重新输入.\033[0m"
            sleep 1
            continue
            ;;
    esac
done
