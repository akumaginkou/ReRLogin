@echo off
rem ===========================================================================
rem Build ReRLogin's external dependencies (x64) into RLogin\RLogin\.
rem Mirrors docs\Compile.txt. Must be run from the repo root inside a VS x64
rem developer environment is NOT required up-front: this script locates and
rem imports vcvars64.bat itself.
rem
rem Produces (relative to RLogin\RLogin\):
rem   openssl-3.5.6\libcrypto.lib, libssl.lib   (+ include, crypto\include)
rem   zlib-1.3.2\x64\zlib.lib                    (+ zlib.h at zlib-1.3.2\)
rem   libiconv-1.18\lib\x64\iconv.lib            (+ include)
rem   nettle-2.0\                                (headers only)
rem ===========================================================================
setlocal enabledelayedexpansion

set "OPENSSL=openssl-3.5.6"
set "ZLIB=zlib-1.3.2"
set "ICONV=libiconv-1.18"
set "NETTLE=nettle-2.0"

rem ---- locate Visual Studio and import the x64 dev environment --------------
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (echo ERROR: vswhere not found & exit /b 1)
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH (echo ERROR: VS with C++ tools not found & exit /b 1)
echo Using Visual Studio at: %VSPATH%
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" || (echo ERROR: vcvars64 failed & exit /b 1)

rem ---- patch tool from Git for Windows --------------------------------------
set "PATCH=%ProgramFiles%\Git\usr\bin\patch.exe"
if not exist "%PATCH%" set "PATCH=%ProgramW6432%\Git\usr\bin\patch.exe"

pushd RLogin\RLogin || exit /b 1

rem ---- download sources (skip if already extracted) -------------------------
if not exist "%OPENSSL%" (
  echo Downloading OpenSSL...
  curl -L -o openssl.tar.gz https://www.openssl.org/source/openssl-3.5.6.tar.gz || exit /b 1
  tar xzf openssl.tar.gz || exit /b 1
)
if not exist "%ZLIB%" (
  echo Downloading zlib...
  curl -L -o zlib.tar.gz https://zlib.net/fossils/zlib-1.3.2.tar.gz || curl -L -o zlib.tar.gz https://zlib.net/zlib-1.3.2.tar.gz || exit /b 1
  tar xzf zlib.tar.gz || exit /b 1
)
if not exist "%ICONV%" (
  echo Downloading libiconv...
  curl -L -o iconv.tar.gz https://ftp.gnu.org/pub/gnu/libiconv/libiconv-1.18.tar.gz || exit /b 1
  tar xzf iconv.tar.gz || exit /b 1
  curl -L -o libiconv-1.18.patch http://nanno.bf1.jp/softlib/man/rlogin/libiconv-1.18.patch || exit /b 1
)
if not exist "%NETTLE%" (
  echo Downloading nettle...
  curl -L -o nettle.zip http://nanno.bf1.jp/softlib/man/rlogin/nettle-2.0.zip || exit /b 1
  tar xf nettle.zip || exit /b 1
)

rem ---- OpenSSL (static, x64) -------------------------------------------------
if not exist "%OPENSSL%\libcrypto.lib" (
  echo Building OpenSSL...
  pushd "%OPENSSL%"
  perl Configure VC-WIN64A no-shared no-module enable-legacy || (echo ERROR: openssl Configure & popd & exit /b 1)
  nmake || (echo ERROR: openssl nmake & popd & exit /b 1)
  popd
)

rem ---- zlib (static, x64) ---------------------------------------------------
if not exist "%ZLIB%\x64\zlib.lib" (
  echo Building zlib...
  pushd "%ZLIB%"
  nmake -f win32\Makefile.msc AS="ml64" CFLAGS="/MT /Ox /Ob2 /Oi /Ot /GS- /Gy -W1 /nologo -Fdzlib -I." || (echo ERROR: zlib nmake & popd & exit /b 1)
  if not exist x64 mkdir x64
  move /y *.obj x64 >nul 2>&1
  move /y *.lib x64 >nul 2>&1
  move /y *.dll x64 >nul 2>&1
  move /y *.exp x64 >nul 2>&1
  move /y *.res x64 >nul 2>&1
  move /y *.pdb x64 >nul 2>&1
  move /y *.exe x64 >nul 2>&1
  popd
)

rem ---- libiconv (static, x64) ----------------------------------------------
if not exist "%ICONV%\lib\x64\iconv.lib" (
  echo Building libiconv...
  pushd "%ICONV%"
  if exist "%PATCH%" (
    "%PATCH%" -p1 -i ..\libiconv-1.18.patch || echo WARNING: patch returned non-zero
  ) else (
    echo WARNING: patch.exe not found, skipping libiconv patch
  )
  pushd lib
  nmake -f Makefile.ms x64 || (echo ERROR: libiconv nmake & popd & popd & exit /b 1)
  popd
  popd
)

popd
echo === build-deps DONE ===
endlocal
