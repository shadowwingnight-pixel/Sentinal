param([string]$Python = "")
$ErrorActionPreference = "Stop"
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$versionPath = Join-Path $repoRoot "scripts\windows_version.txt"
if (-not $Python) { $Python = Join-Path $repoRoot ".venv\Scripts\python.exe" }
if (-not (Test-Path -LiteralPath $Python)) { throw "Python not found. Create .venv with Python 3.13+ first." }
Push-Location $repoRoot
try {
    & $Python -c "import sys; assert sys.platform == 'win32' and sys.version_info >= (3,13)"
    if ($LASTEXITCODE -ne 0) { throw "Windows and Python 3.13+ are required." }
    & $Python -m pip install --disable-pip-version-check --timeout 20 --retries 1 -r requirements-build.txt
    if ($LASTEXITCODE -ne 0) { throw "Build dependency installation failed." }
    & $Python -m pip install --no-build-isolation --no-deps -e .
    if ($LASTEXITCODE -ne 0) { throw "Local package installation failed." }
    & $Python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw "Tests failed. Build stopped." }
    foreach ($folder in @("build", "dist")) {
        $target = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $folder))
        if ($target -notin @((Join-Path $repoRoot "build"), (Join-Path $repoRoot "dist"))) {
            throw "Refusing cleanup outside repository build directories."
        }
        if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
    }
    & $Python -m PyInstaller --noconfirm --clean --onefile --windowed --name Sentinal `
        --paths src --collect-data customtkinter --exclude-module pytest --exclude-module unittest `
        --version-file $versionPath `
        --specpath build --workpath build\pyinstaller --distpath dist scripts\windows_entry.py
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed." }
    if (-not (Test-Path -LiteralPath "dist\Sentinal.exe")) { throw "Final executable missing." }
    Write-Output "Built $repoRoot\dist\Sentinal.exe"
} finally { Pop-Location }
