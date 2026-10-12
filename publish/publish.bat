@echo off
setlocal enabledelayedexpansion

pushd "%~dp0.."

set "DIRTY="
for /f "delims=" %%i in ('git status --porcelain 2^>nul') do set "DIRTY=1"

if defined DIRTY (
    echo ERROR: working tree is dirty ^(uncommitted or untracked changes^). Commit or stash before releasing.
    popd
    exit /b 1
)

for /f "delims=" %%i in ('git rev-parse HEAD') do set "LOCAL=%%i"

if exist tmp rd /s /q tmp
git clone https://github.com/GrowVolution/WebFluid tmp
if errorlevel 1 goto :failed

cd tmp
for /f "delims=" %%i in ('git rev-parse HEAD') do set "CLONED=%%i"

if not "!LOCAL!"=="!CLONED!" (
    echo ERROR: the published branch is at !CLONED:~0,8!, your working tree at !LOCAL:~0,8!.
    echo Push and merge your release commit before publishing.
    goto :failed
)

pip install -r requirements.txt
if errorlevel 1 goto :failed

python -m build
if errorlevel 1 goto :failed
twine upload dist/*
if errorlevel 1 goto :failed

cd stubs
python -m build
if errorlevel 1 goto :failed
twine upload dist/*
if errorlevel 1 goto :failed

cd ..\..
rd /s /q tmp
echo Published.

popd
endlocal
exit /b 0

:failed
cd /d "%~dp0..\.."
rd /s /q tmp 2>nul
echo Release aborted.
popd
endlocal
exit /b 1
