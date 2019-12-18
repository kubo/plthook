call "C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" %1
nmake /f Makefile.win32 check clean DLL_CFLAGS=%2 EXE_CFLAGS=%3
