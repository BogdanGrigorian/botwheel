@echo off
setlocal EnableExtensions

rem ===========================================================================
rem  gen-key.cmd - generate a fresh 32-byte at-rest key for the embedded vault
rem                database (the AtRestCrypto "SRV1." row wrapper).
rem
rem  Usage:  gen-key.cmd [key-file] [--force] [--print]
rem
rem    key-file   file to write the base64 key to
rem               (default: java\botwheel-db.key next to this script - the path
rem               the bot picks up when run with "mvnw exec:java" from java\)
rem    --force    overwrite an existing key (old one is kept as <key-file>.bak)
rem    --print    also echo the key to the console - it then lives in terminal
rem               scrollback and any captured log. Prefer reading the file.
rem
rem  The key is 32 bytes from a CSPRNG, base64 encoded (44 chars). It is NOT a
rem  passphrase you can invent: AtRestCrypto rejects anything that does not
rem  base64-decode to exactly 32 bytes.
rem
rem  WARNING: swapping the key makes every existing "SRV1." row unreadable (the
rem  GCM tag check fails). Users must re-upload their vault from the Mini App,
rem  or a migration must re-wrap each row with the new key.
rem
rem  Needs PowerShell (present on every supported Windows). No Node.js.
rem
rem  Exit codes: 0 ok, 2 bad usage, 3 tooling problem,
rem              4 key file exists without --force, 5 verification failed.
rem ===========================================================================

set "SCRIPT_DIR=%~dp0"
set "KEYFILE=%SCRIPT_DIR%java\botwheel-db.key"
set "KEYSET="
set "FORCE="
set "PRINT="

:parse
if "%~1"=="" goto :parsed
set "ARG=%~1"
if /I "%ARG%"=="--help" goto :usage
if /I "%ARG%"=="-h" goto :usage
if /I "%ARG%"=="/?" goto :usage
if /I "%ARG%"=="--force" goto :arg_force
if /I "%ARG%"=="-f" goto :arg_force
if /I "%ARG%"=="--print" goto :arg_print
if /I "%ARG%"=="-p" goto :arg_print
rem  A leading - or / can never start a real path here, so treat it as a flag.
set "ARG1=%ARG:~0,1%"
if "%ARG1%"=="-" goto :badarg
if "%ARG1%"=="/" goto :badarg
if defined KEYSET goto :badarg
goto :arg_file

:badarg
echo ERROR: unexpected argument "%ARG%" 1>&2
goto :usagefail

:arg_force
set "FORCE=1"
shift
goto :parse

:arg_print
set "PRINT=1"
shift
goto :parse

:arg_file
set "KEYFILE=%~f1"
set "KEYSET=1"
shift
goto :parse

:parsed
if "%KEYFILE%"=="" (
    echo ERROR: key file path is empty. 1>&2
    exit /b 2
)

rem --- prepare the target directory ------------------------------------------
for %%I in ("%KEYFILE%") do set "KEYDIR=%%~dpI"
if not exist "%KEYDIR%" mkdir "%KEYDIR%" 2>nul
if not exist "%KEYDIR%" (
    echo ERROR: cannot create directory "%KEYDIR%" 1>&2
    exit /b 3
)

rem --- never silently clobber an existing key --------------------------------
if not exist "%KEYFILE%" goto :generate
if not defined FORCE goto :exists
copy /y "%KEYFILE%" "%KEYFILE%.bak" >nul
if errorlevel 1 (
    echo ERROR: could not back up the existing key to "%KEYFILE%.bak" 1>&2
    exit /b 3
)
echo Existing key kept as "%KEYFILE%.bak"

:generate
where powershell >nul 2>nul
if errorlevel 1 goto :nops

rem  32 random bytes from the OS CSPRNG, base64, written as plain ASCII with no
rem  trailing newline (the bot trims anyway, but keep the file exact).
rem  Fill a byte[] and call GetBytes(byte[]) - the GetBytes(int) overload only
rem  exists on .NET Core, not on the .NET Framework behind Windows PowerShell.
powershell -NoProfile -NonInteractive -Command "$b = New-Object byte[] 32; ([System.Security.Cryptography.RandomNumberGenerator]::Create()).GetBytes($b); $k = [Convert]::ToBase64String($b); Set-Content -LiteralPath $env:KEYFILE -Value $k -NoNewline -Encoding Ascii"
if errorlevel 1 goto :writefail

rem --- verify what actually landed on disk -----------------------------------
if not exist "%KEYFILE%" goto :writefail
powershell -NoProfile -NonInteractive -Command "try { $b = [Convert]::FromBase64String((Get-Content -LiteralPath $env:KEYFILE -Raw).Trim()) } catch { exit 1 }; if ($b.Length -eq 32) { exit 0 } else { exit 1 }"
if errorlevel 1 goto :badkey

if not defined PRINT goto :done
for /f "usebackq delims=" %%K in ("%KEYFILE%") do set "KEY=%%K"
echo.
echo KEY: %KEY%
echo   ^(this is now in your terminal history - clear it if that matters^)

:done
echo.
echo Generated at-rest key: "%KEYFILE%"
echo   32 random bytes, base64 (44 chars), no trailing newline.
echo.
echo Next steps:
echo   - keep this file OFF the database volume and OUT of git
echo     ^(java\.gitignore already covers java\botwheel-db*.key^)
echo   - the bot picks it up via telegram.db.key.file / TELEGRAM_DB_KEY_FILE,
echo     or paste the value into telegram.db.key / TELEGRAM_DB_KEY
echo   - restart the bot, then have users re-upload their vault from the Mini App
exit /b 0

:exists
echo ERROR: key file already exists: "%KEYFILE%" 1>&2
echo   Refusing to overwrite - every existing SRV1. row is wrapped with this key. 1>&2
echo   Re-run with --force to replace it ^(the old key is saved as .bak first^). 1>&2
exit /b 4

:nops
echo ERROR: powershell.exe not found on PATH. 1>&2
echo   Nothing was written to "%KEYFILE%". 1>&2
exit /b 3

:writefail
echo ERROR: failed to write the key file: "%KEYFILE%" 1>&2
exit /b 3

:badkey
echo ERROR: verification failed - "%KEYFILE%" is not base64 for exactly 32 bytes. 1>&2
del /f /q "%KEYFILE%" >nul 2>nul
echo   The unusable file was deleted. Check that PowerShell works, then re-run. 1>&2
exit /b 5

:usagefail
set "USAGEFAIL=1"
echo. 1>&2
:usage
echo Usage:  gen-key.cmd [key-file] [--force] [--print]
echo.
echo   key-file   where to write the base64 key
echo              (default: java\botwheel-db.key next to this script)
echo   --force    overwrite an existing key, keeping it as ^<key-file^>.bak
echo   --print    also echo the key to the console
echo.
echo The key is 32 CSPRNG bytes, base64 encoded. Swapping it makes existing
echo SRV1. rows unreadable - users must re-upload their vault from the Mini App.
if defined USAGEFAIL exit /b 2
exit /b 0
