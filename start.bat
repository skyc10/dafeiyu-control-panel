@echo off
chcp 65001 >nul
setlocal

rem 大肥鱼管理面板 · 双击启动
rem 只负责把 Python 拉起来；所有逻辑在 server.py 内。

set "PYTHON=C:\Users\陈\AppData\Local\Programs\Python\Python312\python.exe"
set "PANEL=%~dp0server.py"

if not exist "%PYTHON%" (
  echo [错误] 未找到 Python: %PYTHON%
  echo        请确认安装路径，或修改 start.bat 里的 PYTHON 变量。
  pause
  exit /b 1
)

if not exist "%PANEL%" (
  echo [错误] 未找到 server.py：%PANEL%
  pause
  exit /b 1
)

echo 正在启动大肥鱼管理面板...
echo 访问地址：http://127.0.0.1:18100/
echo 关闭此窗口即可停止面板（机器人容器不受影响）。
echo.

"%PYTHON%" "%PANEL%"

echo.
echo 面板已退出。
pause
