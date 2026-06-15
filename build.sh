#!/bin/bash

# veo 跨平台编译脚本
# 支持 Windows, Linux, macOS 多架构编译
# 包含体积优化和版本信息嵌入

set -e  # 遇到错误立即退出

# ============================================================================
# 配置区域
# ============================================================================

# 项目信息
PROJECT_NAME="veo"
MAIN_FILE="./cmd/main.go"
OUTPUT_DIR="dist"

# 版本信息 (可以从git获取或手动设置)
VERSION=${VERSION:-"v1.0.0"}
BUILD_TIME=$(date +"%Y-%m-%d_%H:%M:%S")
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")

# 编译优化参数
LDFLAGS="-s -w"  # -s 去除符号表, -w 去除调试信息
LDFLAGS="${LDFLAGS} -X main.version=${VERSION}"
LDFLAGS="${LDFLAGS} -X main.buildTime=${BUILD_TIME}"
LDFLAGS="${LDFLAGS} -X main.gitCommit=${GIT_COMMIT}"
LDFLAGS="${LDFLAGS} -X main.gitBranch=${GIT_BRANCH}"

# 编译标志
BUILDFLAGS="-trimpath"  # 去除文件路径信息，减小体积

# 支持的平台和架构
SUPPORTED_PLATFORMS=(
    "windows/amd64"
    "windows/arm64"
    "windows/386"
    "linux/amd64"
    "linux/arm64"
    "linux/arm"
    "linux/mips64"
    "linux/mips64le"
    "darwin/amd64"
    "darwin/arm64"
    "freebsd/amd64"
    "freebsd/arm64"
)

# 获取平台的文件扩展名
get_platform_extension() {
    local platform=$1
    local os=$(echo $platform | cut -d'/' -f1)
    
    if [[ "$os" == "windows" ]]; then
        echo ".exe"
    else
        echo ""
    fi
}

# 检查平台是否支持
is_platform_supported() {
    local platform=$1
    for supported in "${SUPPORTED_PLATFORMS[@]}"; do
        if [[ "$platform" == "$supported" ]]; then
            return 0
        fi
    done
    return 1
}

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================================
# 工具函数
# ============================================================================

# 打印带颜色的信息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${PURPLE}[STEP]${NC} $1"
}

# 显示帮助信息
show_help() {
    cat << EOF
veo 编译脚本

用法: $0 [选项] [平台]

选项:
    -h, --help          显示此帮助信息
    -c, --clean         清理编译输出目录
    -a, --all          编译所有支持的平台
    -p, --parallel     并行编译 (默认)
    -s, --sequential   顺序编译
    -o, --output DIR   指定输出目录 (默认: dist)
    -v, --version VER  指定版本号 (默认: v1.0.0)
    --no-compress      不使用UPX压缩
    --with-debug       包含调试信息
    --race             启用竞态检测
    --list-platforms   仅输出支持的平台列表
    
平台格式: OS/ARCH
支持的平台:
    windows/amd64, windows/arm64, windows/386
    linux/amd64, linux/arm64, linux/arm, linux/mips64, linux/mips64le
    darwin/amd64, darwin/arm64
    freebsd/amd64, freebsd/arm64

示例:
    $0                          # 编译当前平台
    $0 -a                       # 编译所有平台
    $0 windows/amd64            # 编译指定平台
    $0 -c                       # 清理输出目录
    $0 -v v2.0.0 -a            # 指定版本编译所有平台

EOF
}

# 获取文件大小（人类可读格式）
get_file_size() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        stat -f%z "$1" | awk '{
            if ($1 > 1024*1024*1024) printf "%.1fGB", $1/1024/1024/1024
            else if ($1 > 1024*1024) printf "%.1fMB", $1/1024/1024
            else if ($1 > 1024) printf "%.1fKB", $1/1024
            else printf "%dB", $1
        }'
    else
        # Linux
        stat -c%s "$1" | awk '{
            if ($1 > 1024*1024*1024) printf "%.1fGB", $1/1024/1024/1024
            else if ($1 > 1024*1024) printf "%.1fMB", $1/1024/1024
            else if ($1 > 1024) printf "%.1fKB", $1/1024
            else printf "%dB", $1
        }'
    fi
}

# 检查依赖
check_dependencies() {
    print_step "检查编译依赖..."
    
    # 检查 Go
    if ! command -v go &> /dev/null; then
        print_error "Go 未安装或不在 PATH 中"
        exit 1
    fi
    
    GO_VERSION=$(go version | awk '{print $3}')
    print_info "Go 版本: ${GO_VERSION}"
    
    # 检查 git (可选)
    if command -v git &> /dev/null; then
        print_info "Git 可用，将包含 commit 信息"
    else
        print_warning "Git 不可用，将使用默认 commit 信息"
    fi
    
    # 检查 UPX (可选)
    if command -v upx &> /dev/null && [[ "$USE_UPX" == "true" ]]; then
        UPX_VERSION=$(upx --version | head -n1 | awk '{print $2}')
        print_info "UPX 版本: ${UPX_VERSION}"
        print_info "将使用 UPX 压缩二进制文件"
    else
        if [[ "$USE_UPX" == "true" ]]; then
            print_warning "UPX 不可用，跳过压缩步骤"
        fi
        USE_UPX="false"
    fi
}

# 清理输出目录
clean_output() {
    if [[ -d "$OUTPUT_DIR" ]]; then
        print_step "清理输出目录: $OUTPUT_DIR"
        rm -rf "$OUTPUT_DIR"
        print_success "清理完成"
    fi
}

# 创建输出目录
create_output_dir() {
    if [[ ! -d "$OUTPUT_DIR" ]]; then
        mkdir -p "$OUTPUT_DIR"
        print_info "创建输出目录: $OUTPUT_DIR"
    fi
}

# 编译单个平台
build_platform() {
    local platform=$1
    local extension=$(get_platform_extension "$platform")
    
    local os=$(echo $platform | cut -d'/' -f1)
    local arch=$(echo $platform | cut -d'/' -f2)
    local output_name="${PROJECT_NAME}_${os}_${arch}${extension}"
    local output_path="${OUTPUT_DIR}/${output_name}"
    
    print_step "编译 ${os}/${arch}..."
    
    # 设置环境变量
    export GOOS=$os
    export GOARCH=$arch
    export CGO_ENABLED=0  # 禁用CGO以支持交叉编译
    
    # 添加特定架构的编译标志
    local build_flags="$BUILDFLAGS"
    if [[ "$ENABLE_RACE" == "true" && "$os" != "windows" ]]; then
        build_flags="${build_flags} -race"
        export CGO_ENABLED=1  # race detector 需要 CGO
    fi
    
    # macOS特殊优化：更激进的LDFLAGS
    local ldflags="$LDFLAGS"
    if [[ "$os" == "darwin" ]]; then
        # macOS特有的体积优化
        ldflags="${ldflags} -extldflags '-sectcreate __TEXT __info_plist /dev/null'"
        ldflags="${ldflags} -extldflags '-dead_strip'"
        ldflags="${ldflags} -extldflags '-dead_strip_dylibs'"
        print_info "应用macOS专用体积优化..."
    fi
    
    # 执行编译
    local start_time=$(date +%s)
    
    if go build $build_flags -ldflags="$ldflags" -o "$output_path" "$MAIN_FILE"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        local file_size=$(get_file_size "$output_path")
        
        # macOS后处理优化
        if [[ "$os" == "darwin" ]]; then
            print_info "执行macOS后处理优化..."
            
            # 去除额外的符号表信息
            if command -v strip >/dev/null 2>&1; then
                local original_size=$(get_file_size "$output_path")
                strip -x "$output_path" 2>/dev/null || true
                local stripped_size=$(get_file_size "$output_path")
                print_info "符号表优化: ${original_size} → ${stripped_size}"
                file_size=$stripped_size
            fi
            
            # 去除调试段信息（如果dsymutil可用）
            if command -v dsymutil >/dev/null 2>&1; then
                dsymutil --minimize "$output_path" 2>/dev/null || true
            fi
            
            print_success "✅ ${output_name} (${duration}s, ${file_size}) [macOS优化]"
        else
            # UPX 压缩 (非macOS平台)
            if [[ "$USE_UPX" == "true" ]]; then
                print_info "使用 UPX 压缩 ${output_name}..."
                local original_size=$(get_file_size "$output_path")
                if upx --best --lzma "$output_path" >/dev/null 2>&1; then
                    local compressed_size=$(get_file_size "$output_path")
                    print_success "✅ ${output_name} (${duration}s, ${original_size} → ${compressed_size})"
                else
                    print_warning "UPX 压缩失败，保留原文件"
                    print_success "✅ ${output_name} (${duration}s, ${file_size})"
                fi
            else
                print_success "✅ ${output_name} (${duration}s, ${file_size})"
            fi
        fi
        
        return 0
    else
        print_error "❌ ${output_name} 编译失败"
        return 1
    fi
}

# 并行编译
parallel_build() {
    local platforms=("$@")
    local max_jobs=${MAX_PARALLEL_JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}
    
    print_info "并行编译 (最大并发: $max_jobs)"
    
    # 并行编译各平台
    local pids=()
    for platform in "${platforms[@]}"; do
        build_platform "$platform" &
        pids+=($!)
        
        # 控制并发数量
        if [[ ${#pids[@]} -ge $max_jobs ]]; then
            wait "${pids[0]}"
            pids=("${pids[@]:1}")
        fi
    done
    
    # 等待所有后台任务完成
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
}

# 顺序编译
sequential_build() {
    local platforms=("$@")
    
    print_info "顺序编译"
    
    local success_count=0
    local fail_count=0
    
    for platform in "${platforms[@]}"; do
        if build_platform "$platform"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    done
    
    print_info "编译完成: 成功 $success_count, 失败 $fail_count"
}

# 显示编译结果
show_results() {
    print_step "编译结果:"
    
    if [[ ! -d "$OUTPUT_DIR" ]]; then
        print_warning "输出目录不存在"
        return
    fi
    
    local total_size=0
    echo ""
    printf "%-30s %-10s %-15s\n" "文件名" "大小" "修改时间"
    echo "--------------------------------------------------------"
    
    for file in "$OUTPUT_DIR"/*; do
        if [[ -f "$file" ]]; then
            local filename=$(basename "$file")
            local size=$(get_file_size "$file")
            local mtime=$(stat -c%y "$file" 2>/dev/null | cut -d' ' -f1,2 | cut -d'.' -f1 || stat -f%Sm "$file" 2>/dev/null)
            printf "%-30s %-10s %-15s\n" "$filename" "$size" "$mtime"
            
            # 计算总大小 (仅Linux/有GNU stat)
            if command -v stat >/dev/null && stat -c%s "$file" >/dev/null 2>&1; then
                local bytes=$(stat -c%s "$file")
                total_size=$((total_size + bytes))
            fi
        fi
    done
    
    echo "--------------------------------------------------------"
    if [[ $total_size -gt 0 ]]; then
        local total_size_human=$(echo $total_size | awk '{
            if ($1 > 1024*1024*1024) printf "%.1fGB", $1/1024/1024/1024
            else if ($1 > 1024*1024) printf "%.1fMB", $1/1024/1024
            else if ($1 > 1024) printf "%.1fKB", $1/1024
            else printf "%dB", $1
        }')
        printf "%-30s %-10s\n" "总计" "$total_size_human"
    fi
    echo ""
}

# 显示版本信息
show_version_info() {
    print_step "版本信息:"
    echo "  版本: $VERSION"
    echo "  构建时间: $BUILD_TIME"
    echo "  Git提交: $GIT_COMMIT"
    echo "  Git分支: $GIT_BRANCH"
    echo ""
}

list_supported_platforms() {
    echo "${SUPPORTED_PLATFORMS[*]}"
}

# ============================================================================
# 主程序
# ============================================================================

# 默认参数
CLEAN_ONLY=false
BUILD_ALL=false
PARALLEL_BUILD=true
USE_UPX=true
INCLUDE_DEBUG=false
ENABLE_RACE=false
SPECIFIC_PLATFORM=""

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        --list-platforms)
            list_supported_platforms
            exit 0
            ;;
        -c|--clean)
            CLEAN_ONLY=true
            shift
            ;;
        -a|--all)
            BUILD_ALL=true
            shift
            ;;
        -p|--parallel)
            PARALLEL_BUILD=true
            shift
            ;;
        -s|--sequential)
            PARALLEL_BUILD=false
            shift
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        --no-compress)
            USE_UPX=false
            shift
            ;;
        --with-debug)
            INCLUDE_DEBUG=true
            shift
            ;;
        --race)
            ENABLE_RACE=true
            shift
            ;;
        -*)
            print_error "未知选项: $1"
            show_help
            exit 1
            ;;
        *)
            if [[ -z "$SPECIFIC_PLATFORM" ]]; then
                SPECIFIC_PLATFORM="$1"
            else
                print_error "只能指定一个平台"
                exit 1
            fi
            shift
            ;;
    esac
done

# 调整编译标志
if [[ "$INCLUDE_DEBUG" == "true" ]]; then
    LDFLAGS=$(echo "$LDFLAGS" | sed 's/-s -w//')  # 移除调试信息删除标志
    print_info "保留调试信息"
fi

# 显示脚本头部信息
echo ""
print_info "🚀 veo 跨平台编译脚本"
print_info "================================================"

# 如果只是清理，执行清理后退出
if [[ "$CLEAN_ONLY" == "true" ]]; then
    clean_output
    exit 0
fi

# 显示版本信息
show_version_info

# 检查依赖
check_dependencies

# 创建输出目录
create_output_dir

# 确定要编译的平台
declare -a BUILD_PLATFORMS

if [[ "$BUILD_ALL" == "true" ]]; then
    # 编译所有平台
    for platform in "${SUPPORTED_PLATFORMS[@]}"; do
        BUILD_PLATFORMS+=("$platform")
    done
elif [[ -n "$SPECIFIC_PLATFORM" ]]; then
    # 编译指定平台
    if is_platform_supported "$SPECIFIC_PLATFORM"; then
        BUILD_PLATFORMS=("$SPECIFIC_PLATFORM")
    else
        print_error "不支持的平台: $SPECIFIC_PLATFORM"
        print_info "支持的平台: ${SUPPORTED_PLATFORMS[*]}"
        exit 1
    fi
else
    # 编译当前平台
    current_os=$(go env GOOS)
    current_arch=$(go env GOARCH)
    current_platform="${current_os}/${current_arch}"
    BUILD_PLATFORMS=("$current_platform")
fi

print_info "准备编译 ${#BUILD_PLATFORMS[@]} 个平台: ${BUILD_PLATFORMS[*]}"

# 开始编译
start_time=$(date +%s)

if [[ "$PARALLEL_BUILD" == "true" && ${#BUILD_PLATFORMS[@]} -gt 1 ]]; then
    # 导出函数和变量，供子进程使用
    export -f build_platform print_step print_success print_error print_info get_file_size get_platform_extension
    export PROJECT_NAME MAIN_FILE OUTPUT_DIR LDFLAGS BUILDFLAGS USE_UPX ENABLE_RACE
    export RED GREEN YELLOW BLUE PURPLE CYAN NC
    
    parallel_build "${BUILD_PLATFORMS[@]}"
else
    sequential_build "${BUILD_PLATFORMS[@]}"
fi

end_time=$(date +%s)
total_duration=$((end_time - start_time))

# 显示结果
show_results

print_success "🎉 编译完成! 总耗时: ${total_duration}s"
print_info "输出目录: $OUTPUT_DIR"

# 提示下一步操作
echo ""
print_info "💡 下一步操作:"
print_info "  测试运行: ./${OUTPUT_DIR}/${PROJECT_NAME}_$(go env GOOS)_$(go env GOARCH) --help"
print_info "  创建发布包: ./release.sh"
print_info "  清理构建: $0 --clean" 
