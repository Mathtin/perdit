# Perdit Messaging System
This is a brand new messaging system using RSA encryption. Main advantage of this messager - period of time I wrote it: less then a month as a course project! Yep, that is it.

##What do you need to build
This project using Windows sockets in it's current condition and cryptopp library, and was compiled using GNU toolchain with help of MSYS2 (MINGW).`
So next few things you'll need to build this project:

1. Windows
2. MINGW
3. MAKE
4. cryptopp.dll

Or you can just download lates release, compiled for x86_64 windows operating system.

##How to build
Clone this project to your local workstation, open BuildRelease.bat and wait.

##How to use Client
Use command promt or create lnk for .exe and add two arguments: ip and port of server. 
```
.../Release>PerditClient.exe 127.0.0.1 6767
```
No further instructions, just use it!

##How to use Server
Just open it and use. Nothing to specific about it.`
Note: default port is 6767
