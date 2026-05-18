param(
    [string]$BindHost = "0.0.0.0",
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Get-PythonCommand {
    $pythonCandidates = @(Get-Command python -All -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
    $realPython = $pythonCandidates | Where-Object { $_ -notlike "*WindowsApps*" } | Select-Object -First 1

    if ($realPython) {
        return @{
            Executable = $realPython
            BaseArgs = @()
        }
    }

    if (Get-Command py -ErrorAction SilentlyContinue) {
        return @{
            Executable = "py"
            BaseArgs = @("-3")
        }
    }

    if (Get-Command python -ErrorAction SilentlyContinue) {
        return @{
            Executable = "python"
            BaseArgs = @()
        }
    }

    throw "Python 3가 설치되어 있지 않습니다."
}

function Invoke-BasePython {
    param(
        [hashtable]$Python,
        [string[]]$Args
    )

    & $Python.Executable @($Python.BaseArgs) @Args
    if ($LASTEXITCODE -ne 0) {
        throw "Python 실행 중 오류가 발생했습니다."
    }
}

function Invoke-VenvPython {
    param(
        [string]$VenvPython,
        [string[]]$Args
    )

    & $VenvPython @Args
    if ($LASTEXITCODE -ne 0) {
        throw "가상환경 Python 실행 중 오류가 발생했습니다."
    }
}

$python = Get-PythonCommand
$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$requirementsHashFile = Join-Path $PSScriptRoot ".venv\requirements.sha256"

if (-not (Test-Path $venvPython)) {
    Write-Host "[1/4] 가상환경 생성 중..."
    Invoke-BasePython -Python $python -Args @("-m", "venv", ".venv")
}

New-Item -ItemType Directory -Force -Path "uploads\avatars" | Out-Null
New-Item -ItemType Directory -Force -Path "backups\iptables" | Out-Null

$currentRequirementsHash = (Get-FileHash "requirements.txt" -Algorithm SHA256).Hash
$installedRequirementsHash = if (Test-Path $requirementsHashFile) {
    (Get-Content $requirementsHashFile -Raw).Trim()
} else {
    ""
}

if ($currentRequirementsHash -ne $installedRequirementsHash) {
    Write-Host "[2/4] 패키지 설치 중..."
    Invoke-VenvPython -VenvPython $venvPython -Args @("-m", "pip", "install", "--upgrade", "pip")
    Invoke-VenvPython -VenvPython $venvPython -Args @("-m", "pip", "install", "-r", "requirements.txt")
    Set-Content -Path $requirementsHashFile -Value $currentRequirementsHash
} else {
    Write-Host "[2/4] 패키지 설치 건너뜀 (변경 없음)"
}

if (-not (Test-Path ".env")) {
    Write-Host "[3/4] .env 생성 중..."
    $secret = & $python.Executable @($python.BaseArgs) -c "import secrets; print(secrets.token_urlsafe(64))"
    if ($LASTEXITCODE -ne 0) {
        throw "SECRET_KEY 생성에 실패했습니다."
    }

    $envTemplate = Get-Content ".env.example" -Raw
    $envTemplate = $envTemplate -replace "(?m)^SECRET_KEY=$", "SECRET_KEY=$secret"
    Set-Content -Path ".env" -Value $envTemplate
} else {
    Write-Host "[3/4] 기존 .env 사용"
}

Write-Host "[4/4] 백엔드 실행 중..."
Invoke-VenvPython -VenvPython $venvPython -Args @("-m", "uvicorn", "main:app", "--reload", "--host", $BindHost, "--port", "$Port")
