@echo off
setlocal EnableExtensions

rem ===========================================================================
rem  import-csv.cmd - turn an Excel-exported credentials CSV into an encrypted
rem                   vault container (VLT3) the bot can seed from.
rem
rem  Usage:  import-csv.cmd <csv-file> [vault-out] [--browser-vault]
rem                         [--fresh] [--dedupe] [--passphrase <file>]
rem                         [--salt <base64url>]
rem
rem    csv-file      comma separated, Excel quoting, first row = header (skipped):
rem                  legacy:  Description 1, Description 2, Username, Password, Email, Note
rem                  browser: name, url, username, password, note   (--browser-vault)
rem    vault-out     vault container to add the records to
rem                  (default: vault.txt next to this script). When it already exists
rem                  the file is opened with the passphrase and the CSV rows are
rem                  APPENDED to its records; that vault's header (KDF + salt) is
rem                  reused, so the records already inside it keep decrypting. The
rem                  previous file is kept as <vault>.bak. A vault that cannot be
rem                  opened (wrong passphrase, damaged) aborts without writing.
rem    --fresh       ignore an existing vault and build a new one (keeps <vault>.bak)
rem    --dedupe      skip rows whose title + login + e-mail are already in the vault
rem    --browser-vault
rem                  read a browser password export (Edge/Chrome/Firefox). The one
rem                  'username' column lands in the e-mail field when it looks like
rem                  an address, in the login field otherwise. Also detected
rem                  automatically when the header is exactly the one above.
rem    --passphrase  file holding the vault passphrase as raw text
rem                  (default: passphrase.key next to this script)
rem    --salt        reuse an existing vault salt (base64url) when starting fresh
rem
rem  Mapping (legacy):  title <- Description 2
rem                      url   <- Description 1 (plus a URL found in Description 2)
rem                      login <- Username
rem                      email <- Email
rem                      password <- Password
rem                      note  <- Note
rem
rem  Mapping (browser): title <- name
rem                      url   <- url (plus a URL found in name)
rem                      login / email <- username, sorted by shape
rem                      password <- password
rem                      note  <- note
rem
rem  Required: the title and the password. Rows missing either are not imported -
rem  they are written unchanged to <csv-file>-invalid.csv.
rem
rem  What it does: every record is encrypted on its own (r1.<...>) with the vault
rem  key, then all of them are gzipped into
rem  "VLT3:<base64url(header||gzip(records))>.<8-hex-revision>" - exactly the
rem  container the Mini App opens and the bot sends back as vault.txt. The key is
rem  derived from the passphrase with Argon2id (64 MiB / 3 / 1).
rem
rem  What it does NOT do: it never touches the database and never applies the
rem  bot's at-rest (SRV1.) wrapper - the text it writes is the container itself;
rem  VaultStore wraps it when it stores the rows.
rem
rem  Next: point telegram.seed.file at this file and the bot ingests it (splitting
rem  it into one row per record) the first time that user runs /start.
rem
rem  Needs a JDK (javac/java) plus the compiled crypto port in
rem  java\target\classes and Bouncy Castle in the local Maven repo.
rem ===========================================================================

set "SCRIPT_DIR=%~dp0"
set "CSV="
set "VAULT=%SCRIPT_DIR%vault.txt"
set "VAULT_SET="
set "PASSFILE=%SCRIPT_DIR%passphrase.key"
set "PASS_SET="
set "SALT="
set "BROWSERARG="
set "FRESHARG="
set "DEDUPEARG="

:parse
if "%~1"=="" goto :parsed
set "ARG=%~1"
if /I "%ARG%"=="--help" goto :usage
if /I "%ARG%"=="-h" goto :usage
if /I "%ARG%"=="/?" goto :usage
if /I "%ARG%"=="--passphrase" goto :arg_pass
if /I "%ARG%"=="-p" goto :arg_pass
if /I "%ARG%"=="--salt" goto :arg_salt
if /I "%ARG%"=="--browser-vault" goto :arg_browser
if /I "%ARG%"=="-b" goto :arg_browser
if /I "%ARG%"=="--fresh" goto :arg_fresh
if /I "%ARG%"=="--dedupe" goto :arg_dedupe
rem  A leading - can never start a real path here, so treat it as a flag.
set "ARG1=%ARG:~0,1%"
if "%ARG1%"=="-" goto :badarg
if not defined CSV goto :arg_csv
if not defined VAULT_SET goto :arg_vault
goto :badarg

:badarg
echo ERROR: unexpected argument "%ARG%" 1>&2
goto :usagefail

:arg_pass
if "%~2"=="" goto :missingval
set "PASSFILE=%~f2"
if not exist "%PASSFILE%" if exist "%SCRIPT_DIR%%~2" set "PASSFILE=%SCRIPT_DIR%%~2"
set "PASS_SET=1"
shift
shift
goto :parse

:arg_salt
if "%~2"=="" goto :missingval
set "SALT=%~2"
shift
shift
goto :parse

:arg_browser
set "BROWSERARG=--browser-vault"
shift
goto :parse

:arg_fresh
set "FRESHARG=--fresh"
shift
goto :parse

:arg_dedupe
set "DEDUPEARG=--dedupe"
shift
goto :parse

:arg_csv
set "CSV=%~f1"
if not exist "%CSV%" if exist "%SCRIPT_DIR%%~1" set "CSV=%SCRIPT_DIR%%~1"
shift
goto :parse

:arg_vault
set "VAULT=%~f1"
set "VAULT_SET=1"
shift
goto :parse

:missingval
echo ERROR: "%ARG%" needs a value. 1>&2
goto :usagefail

:parsed
if not defined CSV goto :usagefail
if not exist "%CSV%" (
    echo ERROR: CSV file not found: "%CSV%" 1>&2
    exit /b 2
)
if not exist "%PASSFILE%" (
    echo ERROR: passphrase file not found: "%PASSFILE%" 1>&2
    echo   Write the vault passphrase into it ^(one line, raw text^) and retry. 1>&2
    exit /b 2
)

rem --- the compiled crypto port ----------------------------------------------
set "CLASSES_DIR=%SCRIPT_DIR%java\target\classes"
if exist "%CLASSES_DIR%\com\botwheel\CryptoCore.class" goto :haveclasses

echo java\target\classes is missing - building it ^(mvnw -q compile^) ...
pushd "%SCRIPT_DIR%java"
call "%SCRIPT_DIR%java\mvnw.cmd" -q compile
set "MVNRC=%ERRORLEVEL%"
popd
if not "%MVNRC%"=="0" goto :buildfail
if not exist "%CLASSES_DIR%\com\botwheel\CryptoCore.class" goto :buildfail

:haveclasses
rem --- Bouncy Castle: needed for Argon2id, "provided" scope so not in the fat jar
rem  Two nested loops on purpose: FindFirstFile only expands wildcards in the
rem  file name, so "…\bcprov-jdk18on\*\bcprov-jdk18on-*.jar" would match nothing.
if defined BC_JAR goto :havebc
for /d %%D in ("%USERPROFILE%\.m2\repository\org\bouncycastle\bcprov-jdk18on\*") do if not defined BC_JAR for %%J in ("%%~fD\bcprov-jdk18on-*.jar") do if not defined BC_JAR set "BC_JAR=%%~fJ"
if not defined BC_JAR goto :nobc

:havebc
set "SALTARG="
if defined SALT set "SALTARG=--salt %SALT%"

rem --- compile the importer into a scratch folder -----------------------------
set "CLASSES=%TEMP%\import-csv-classes"
if not exist "%CLASSES%" mkdir "%CLASSES%" 2>nul
if not exist "%CLASSES%" (
    echo ERROR: cannot create scratch folder "%CLASSES%" 1>&2
    exit /b 3
)

javac -encoding UTF-8 -cp "%CLASSES_DIR%;%BC_JAR%" -d "%CLASSES%" "%SCRIPT_DIR%ImportCsv.java"
if errorlevel 1 goto :compilefail

java -cp "%CLASSES_DIR%;%BC_JAR%;%CLASSES%" ImportCsv "%CSV%" "%VAULT%" --passphrase "%PASSFILE%" %BROWSERARG% %FRESHARG% %DEDUPEARG% %SALTARG%
exit /b %ERRORLEVEL%

:nobc
echo ERROR: Bouncy Castle (Argon2id) not found in the local Maven repo. 1>&2
echo   expected: "%USERPROFILE%\.m2\repository\org\bouncycastle\bcprov-jdk18on\...\bcprov-jdk18on-*.jar" 1>&2
echo   fetch it with: java\mvnw -q dependency:resolve     ^(or set BC_JAR to the jar^) 1>&2
exit /b 3

:buildfail
echo ERROR: could not compile the crypto port in java\ - is a JDK on PATH? 1>&2
exit /b 3

:compilefail
echo ERROR: could not compile "ImportCsv.java" - is a JDK on PATH? 1>&2
exit /b 3

:usagefail
set "USAGEFAIL=1"
echo. 1>&2
:usage
echo Usage:  import-csv.cmd ^<csv-file^> [vault-out] [--browser-vault] [--fresh] [--dedupe]
echo                      [--passphrase ^<file^>] [--salt ^<base64url^>]
echo.
echo   csv-file          CSV exported from Excel or a browser password manager
echo                     ^(header row skipped^):
echo                       legacy:  Description 1,Description 2,Username,Password,Email,Note
echo                       browser: name,url,username,password,note   ^(--browser-vault^)
echo   vault-out         vault container to add the records to (default: vault.txt)
echo                     if it exists the rows are APPENDED to it and the old file
echo                     is kept as ^<vault^>.bak
echo   --fresh           start a new vault, ignoring the existing one
echo   --dedupe          skip rows that are already in the vault
echo   --browser-vault   browser export: username goes to the e-mail field when it
echo                     looks like an address, to the login field otherwise
echo   --passphrase      file with the vault passphrase as raw text
echo                     (default: passphrase.key)
echo   --salt            reuse an existing vault salt when starting fresh
echo.
echo Each record is encrypted on its own ^(r1.^) and the vault is written as a
echo VLT3 container with a key derived from the passphrase with Argon2id.
echo Invalid rows ^(no title / no password^) go to ^<csv-file^>-invalid.csv.
if defined USAGEFAIL exit /b 2
exit /b 0
