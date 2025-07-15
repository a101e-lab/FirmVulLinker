#!/bin/bash

# 嵌入式固件特征提取分析工具 - 一键安装脚本
# 版本: 1.0

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查命令是否存在
check_command() {
    if command -v "$1" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# 检查必要的系统组件
check_prerequisites() {
    log_info "检查系统依赖..."
    
    local errors=0
    
    # 检查Docker
    if ! check_command docker; then
        log_error "Docker没安装"
        ((errors++))
    else
        log_success "Docker已安装"
    fi
    
    # 检查Python版本
    if check_command python3; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
        
        if [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -ge 8 ]; then
            log_success "Python版本检查通过: $PYTHON_VERSION"
        else
            log_error "Python版本过低: $PYTHON_VERSION，需要Python 3.8+"
            ((errors++))
        fi
    else
        log_error "Python3没安装"
        ((errors++))
    fi
    
    # 检查pip3
    if ! check_command pip3; then
        log_error "pip3没安装"
        ((errors++))
    else
        log_success "pip3已安装"
    fi
    
    # 检查git
    if ! check_command git; then
        log_error "git没安装"
        ((errors++))
    else
        log_success "git已安装"
    fi
    
    if [ $errors -gt 0 ]; then
        log_error "系统依赖检查失败，请先安装缺失的组件"
        exit 1
    fi
}

# 安装系统依赖
install_system_dependencies() {
    log_info "安装系统依赖包..."
    
    # 检测系统类型并安装相应依赖
    if command -v apt-get >/dev/null 2>&1; then
        # Ubuntu/Debian 系统
        log_info "检测到基于 apt 的系统，安装依赖..."
        sudo apt-get update
        sudo apt-get install -y libfuzzy-dev libssl-dev build-essential python3-dev
    elif command -v yum >/dev/null 2>&1; then
        # CentOS/RHEL 系统
        log_info "检测到基于 yum 的系统，安装依赖..."
        sudo yum install -y ssdeep-devel openssl-devel gcc python3-devel
    elif command -v dnf >/dev/null 2>&1; then
        # Fedora 系统
        log_info "检测到基于 dnf 的系统，安装依赖..."
        sudo dnf install -y ssdeep-devel openssl-devel gcc python3-devel
    else
        log_warning "未检测到支持的包管理器，请手动安装以下依赖："
        echo "  - libfuzzy-dev (或 ssdeep-devel)"
        echo "  - libssl-dev (或 openssl-devel)"
        echo "  - build-essential (或 gcc)"
        echo "  - python3-dev"
        read -p "是否已手动安装所需依赖？(y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_error "请先安装系统依赖"
            return 1
        fi
    fi
    
    if [ $? -eq 0 ]; then
        log_success "系统依赖安装完成"
    else
        log_error "系统依赖安装失败"
        return 1
    fi
}

# 安装Python依赖
install_python_dependencies() {
    log_info "安装Python依赖包..."
    
    pip3 install --user ssdeep pyOpenSSL pycryptodome mysql-connector-python argparse
    
    if [ $? -eq 0 ]; then
        log_success "Python依赖安装完成"
    else
        log_error "Python依赖安装失败"
        return 1
    fi
}

# 初始化Git子模块
init_submodules() {
    log_info "初始化Git子模块..."
    
    if [ -d ".git" ]; then
        git submodule update --init --recursive
        if [ $? -eq 0 ]; then
            log_success "Git子模块初始化完成"
        else
            log_error "Git子模块初始化失败"
            return 1
        fi
        
        # 设置firmwalker权限
        if [ -f "firmwalker_pro/firmwalker.sh" ]; then
            chmod +x firmwalker_pro/firmwalker.sh
            log_success "firmwalker.sh权限设置完成"
        else
            log_warning "未找到firmwalker_pro/firmwalker.sh文件"
        fi
    else
        log_warning "当前目录不是Git仓库，跳过子模块初始化"
    fi
}

# 拉取Docker镜像
pull_docker_images() {
    log_info "拉取Docker镜像..."
    
    # 检查Docker是否运行
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker未运行或当前用户无权限访问Docker"
        return 1
    fi
    
    # 拉取SATC镜像
    log_info "拉取SATC镜像..."
    docker pull smile0304/satc:latest
    if [ $? -eq 0 ]; then
        log_success "SATC镜像拉取完成"
    else
        log_error "SATC镜像拉取失败"
        return 1
    fi
    
    # 拉取Binwalk镜像
    log_info "拉取Binwalk镜像..."
    docker pull fitzbc/binwalk
    if [ $? -eq 0 ]; then
        log_success "Binwalk镜像拉取完成"
    else
        log_error "Binwalk镜像拉取失败"
        return 1
    fi
}

# 安装sdhash
install_sdhash() {
    log_info "安装sdhash..."
    
    if [ -f "./install_sdhash.sh" ]; then
        chmod +x ./install_sdhash.sh
        ./install_sdhash.sh
        if [ $? -eq 0 ]; then
            log_success "sdhash安装完成"
        else
            log_error "sdhash安装失败"
            return 1
        fi
    else
        log_error "未找到install_sdhash.sh脚本"
        return 1
    fi
}

# 设置Ghidra
setup_ghidra() {
    log_info "设置Ghidra..."
    
    if [ -f "ghidra_11.0.1_PUBLIC.tar.gz" ]; then
        log_info "解压Ghidra..."
        tar -xzf ghidra_11.0.1_PUBLIC.tar.gz
        if [ $? -eq 0 ]; then
            log_success "Ghidra解压完成"
        else
            log_error "Ghidra解压失败"
            return 1
        fi
    else
        log_warning "未找到ghidra_11.0.1_PUBLIC.tar.gz文件"
        return 1
    fi
}

# 启动MySQL数据库
setup_mysql() {
    log_info "启动MySQL数据库..."
    
    if [ -d "mysql" ]; then
        cd mysql
        if [ -f "docker-compose.yml" ] || [ -f "docker-compose.yaml" ]; then
            docker compose up -d
            if [ $? -eq 0 ]; then
                log_success "MySQL容器启动完成"
                cd ..
            else
                log_error "MySQL容器启动失败"
                cd ..
                return 1
            fi
        else
            log_error "未找到docker-compose.yml文件"
            cd ..
            return 1
        fi
    else
        log_error "未找到mysql目录"
        return 1
    fi
}

# 验证安装
verify_installation() {
    log_info "验证安装..."
    
    local errors=0
    
    # 检查Python包
    log_info "检查Python包..."
    python3 -c "import ssdeep, OpenSSL, Crypto, mysql.connector, argparse" 2>/dev/null
    if [ $? -eq 0 ]; then
        log_success "Python包验证通过"
    else
        log_error "Python包验证失败"
        ((errors++))
    fi
    
    # 检查Docker镜像
    log_info "检查Docker镜像..."
    if docker images | grep -q "smile0304/satc"; then
        log_success "SATC镜像验证通过"
    else
        log_error "SATC镜像验证失败"
        ((errors++))
    fi
    
    if docker images | grep -q "fitzbc/binwalk"; then
        log_success "Binwalk镜像验证通过"
    else
        log_error "Binwalk镜像验证失败"
        ((errors++))
    fi
    
    # 检查sdhash
    if check_command sdhash; then
        log_success "sdhash验证通过"
    else
        log_error "sdhash验证失败"
        ((errors++))
    fi
    
    if [ $errors -eq 0 ]; then
        log_success "所有组件验证通过！"
        return 0
    else
        log_error "验证发现 $errors 个错误"
        return 1
    fi
}

# 主函数
main() {
    echo "======================================================"
    echo "    嵌入式固件特征提取分析工具 - 一键安装脚本"
    echo "======================================================"
    echo ""
    
    # 检查系统依赖
    check_prerequisites
    
    # 安装步骤
    local steps=(
        "install_system_dependencies:安装系统依赖"
        "install_python_dependencies:安装Python依赖"
        "init_submodules:初始化Git子模块"
        "pull_docker_images:拉取Docker镜像"
        "install_sdhash:安装sdhash"
        "setup_ghidra:设置Ghidra"
        "setup_mysql:启动MySQL数据库"
        "verify_installation:验证安装"
    )
    
    local total_steps=${#steps[@]}
    local current_step=1
    
    for step_info in "${steps[@]}"; do
        IFS=':' read -r step_func step_name <<< "$step_info"
        
        echo ""
        log_info "[$current_step/$total_steps] $step_name"
        echo "------------------------------------------------------"
        
        $step_func
        if [ $? -ne 0 ]; then
            log_error "步骤失败: $step_name"
            
            # 对于某些非关键步骤，询问是否继续
            if [ "$step_func" = "setup_ghidra" ] || [ "$step_func" = "verify_installation" ]; then
                read -p "是否继续？(y/N): " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    log_info "安装已停止"
                    exit 1
                fi
            else
                log_info "安装已停止"
                exit 1
            fi
        fi
        
        ((current_step++))
    done
    
    echo ""
    echo "======================================================"
    log_success "安装完成！"
    echo "======================================================"
    echo ""
    log_info "使用说明："
    echo "  基本用法: python main.py -f /path/to/firmware.bin"
    echo "  启用SATC: python main.py -f /path/to/firmware.bin --satc"
    echo ""
}

# 执行主函数
main "$@" 