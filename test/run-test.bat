call "c:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" %1
nmake /f Makefile.win32 check clean DLL_CFLAGS=%2 EXE_CFLAGS=%3
