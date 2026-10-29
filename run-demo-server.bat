@echo off
cd /d "%~dp0"
java -cp "target\packet-analyzer-1.0.0.jar" vn.edu.packet.ServerMain 127.0.0.1 9000 --demo
pause
