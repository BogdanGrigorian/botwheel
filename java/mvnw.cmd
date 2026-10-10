@echo off
setlocal

set "BASE_DIR=%~dp0"
if "%BASE_DIR:~-1%"=="\" set "BASE_DIR=%BASE_DIR:~0,-1%"
set "WRAPPER_DIR=%BASE_DIR%\.mvn\wrapper"
set "WRAPPER_JAR=%WRAPPER_DIR%\maven-wrapper.jar"
set "WRAPPER_PROPS=%WRAPPER_DIR%\maven-wrapper.properties"

if not exist "%WRAPPER_JAR%" (
  echo Maven Wrapper jar not found, downloading...
  for /f "tokens=2 delims==" %%u in ('findstr /b "wrapperUrl=" "%WRAPPER_PROPS%"') do set "WRAPPER_URL=%%u"
  if not defined WRAPPER_URL (
    echo Error: wrapperUrl not found in %WRAPPER_PROPS%
    exit /b 1
  )
  powershell -NoProfile -Command "Invoke-WebRequest -Uri '%WRAPPER_URL%' -OutFile '%WRAPPER_JAR%'"
  if errorlevel 1 (
    echo Error: failed to download Maven Wrapper jar
    exit /b 1
  )
)

if defined JAVA_HOME (
  if exist "%JAVA_HOME%\bin\java.exe" (
    set "JAVA_EXE=%JAVA_HOME%\bin\java.exe"
  ) else (
    echo Error: JAVA_HOME is set but java.exe not found at %JAVA_HOME%\bin\java.exe
    exit /b 1
  )
) else (
  set "JAVA_EXE=java"
)

"%JAVA_EXE%" -classpath "%WRAPPER_JAR%" "-Dmaven.multiModuleProjectDirectory=%BASE_DIR%" org.apache.maven.wrapper.MavenWrapperMain %*
exit /b %errorlevel%
