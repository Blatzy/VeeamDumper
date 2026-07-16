@echo off
setlocal enabledelayedexpansion

set "PROJECT=Veeam-Cred-Extractor.csproj"
set "CONFIG=Release"
set "PLATFORM=x64"
set "OUTPUT=build"

echo ==================================================================
echo                     VeeamDumper - Build Script
echo ==================================================================
echo.

:: ===================== Locate MSBuild =====================
set "MSBUILD="

:: VS2022
for %%p in (
    "%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
) do (
    if exist %%~p (
        set "MSBUILD=%%~p"
        goto :found
    )
)

:: VS2019
for %%p in (
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
) do (
    if exist %%~p (
        set "MSBUILD=%%~p"
        goto :found
    )
)

:: VS2017
for %%p in (
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2017\Community\MSBuild\15.0\Bin\MSBuild.exe"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2017\Professional\MSBuild\15.0\Bin\MSBuild.exe"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2017\Enterprise\MSBuild\15.0\Bin\MSBuild.exe"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2017\BuildTools\MSBuild\15.0\Bin\MSBuild.exe"
) do (
    if exist %%~p (
        set "MSBUILD=%%~p"
        goto :found
    )
)

:: .NET Framework SDK fallback
if exist "%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" (
    set "MSBUILD=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"
    goto :found
)
if exist "%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe" (
    set "MSBUILD=%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe"
    goto :found
)

echo [ERROR] MSBuild not found. Install Visual Studio or Build Tools.
exit /b 1

:found
echo [INFO] MSBuild: %MSBUILD%
echo [INFO] Config:  %CONFIG%
echo [INFO] Platform: %PLATFORM%
echo [INFO] Output:  %OUTPUT%\
echo.

:: ===================== Clean =====================
echo [STEP 1/3] Cleaning...
if exist "%OUTPUT%" rmdir /s /q "%OUTPUT%"
"%MSBUILD%" "%PROJECT%" /t:Clean /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% /v:quiet /nologo
if errorlevel 1 (
    echo [ERROR] Clean failed.
    exit /b 1
)
echo [OK] Clean done.
echo.

:: ===================== Build =====================
echo [STEP 2/3] Building...
"%MSBUILD%" "%PROJECT%" /t:Build /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% /p:OutputPath=..\%OUTPUT%\ /v:minimal /nologo
if errorlevel 1 (
    echo [ERROR] Build failed.
    exit /b 1
)
echo [OK] Build done.
echo.

:: ===================== Verify =====================
echo [STEP 3/3] Verifying output...
if exist "%OUTPUT%\VeeamDumper.exe" (
    echo [OK] VeeamDumper.exe ready in %OUTPUT%\
    echo.
    echo ==================================================================
    echo   BUILD SUCCESSFUL
    echo   Output: %CD%\%OUTPUT%\VeeamDumper.exe
    echo ==================================================================
) else (
    echo [ERROR] VeeamDumper.exe not found in output directory.
    exit /b 1
)

endlocal
