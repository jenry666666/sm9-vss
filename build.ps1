# 修复 Windows PowerShell 控制台中文输出乱码：切换为 UTF-8 编码
try { 
    chcp 65001 | Out-Null
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    [Console]::InputEncoding = [System.Text.Encoding]::UTF8
} catch {}
$OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"

Write-Host "=== 构建 SM9-vss 实验环境 ===" -ForegroundColor Green
Write-Host ""

# 检查 Docker 是否运行
Write-Host "检查 Docker 环境..." -ForegroundColor Cyan
docker version | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "✖ Docker 未运行或未安装，请先启动 Docker Desktop" -ForegroundColor Red
    exit 1
}
Write-Host "✓ Docker 环境正常" -ForegroundColor Green
Write-Host ""

# 检查 Dockerfile
$dockerfile = "Dockerfile"
if (-not (Test-Path $dockerfile) -and (Test-Path "DockerFile")) { 
    $dockerfile = "DockerFile" 
}
if (-not (Test-Path $dockerfile)) {
    Write-Host "✖ 未找到 Dockerfile" -ForegroundColor Red
    exit 1
}

Write-Host "1. 构建 Docker 镜像 (这可能需要几分钟)..." -ForegroundColor Yellow
Write-Host "   使用 Dockerfile: $dockerfile" -ForegroundColor Gray
$buildStartTime = Get-Date

docker build -f $dockerfile -t sm9-vss-experiment:latest .
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "✖ 镜像构建失败" -ForegroundColor Red
    exit $LASTEXITCODE
}

$buildEndTime = Get-Date
$buildDuration = ($buildEndTime - $buildStartTime).TotalSeconds
Write-Host ""
Write-Host "✅ 镜像构建完成 (耗时: $([math]::Round($buildDuration, 1)) 秒)" -ForegroundColor Green

Write-Host "2. 启动容器..." -ForegroundColor Yellow

$currentDir = (Get-Location).Path
$containerName = "sm9-vss-app"

# 检查容器是否已存在
$existingContainer = docker ps -a --filter "name=$containerName" --format "{{.Names}}"
if ($existingContainer -eq $containerName) {
    Write-Host "   检测到已存在的容器，正在停止并删除..." -ForegroundColor Gray
    docker stop $containerName 2>$null | Out-Null
    docker rm $containerName 2>$null | Out-Null
}

Write-Host "   容器名称: $containerName" -ForegroundColor Gray
Write-Host "   端口映射: 8080:8080" -ForegroundColor Gray
Write-Host "   工作目录: $currentDir" -ForegroundColor Gray
Write-Host ""
Write-Host "正在启动容器..." -ForegroundColor Cyan
Write-Host ""

docker run -it --rm `
    --name $containerName `
    -p "8080:8080" `
    -v "${currentDir}/configs:/app/configs:ro" `
    -v "${currentDir}/logs:/app/logs" `
    -v "${currentDir}/src:/app/src:ro" `
    -v "${currentDir}/examples:/app/examples:ro" `
    -e "PYTHONPATH=/app" `
    -e "LOG_LEVEL=INFO" `
    -w /app `
    sm9-vss-experiment:latest

