# 修复 Windows PowerShell 控制台中文输出乱码：切换为 UTF-8 编码
try { chcp 65001 > $null } catch {}
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = New-Object System.Text.UTF8Encoding $false

Write-Host "=== 构建 SM9-VSS 实验环境 ===" -ForegroundColor Green
Write-Host "1. 构建 Docker 镜像..." -ForegroundColor Yellow

$dockerfile = "Dockerfile"
if (-not (Test-Path $dockerfile) -and (Test-Path "DockerFile")) { $dockerfile = "DockerFile" }

docker build -f $dockerfile -t sm9-vss-experiment:latest .
if ($LASTEXITCODE -ne 0) {
    Write-Host "✖ 镜像构建失败" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "✅ 镜像构建完成" -ForegroundColor Green
Write-Host "2. 启动容器..." -ForegroundColor Yellow

$currentDir = (Get-Location).Path
$containerName = "sm9-vss-project"

docker run -it --rm `
    --name $containerName `
    -v "${currentDir}:/app" `
    -w /app `
    sm9-vss-experiment:latest

