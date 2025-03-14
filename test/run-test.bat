if "%1" == "2019" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" %2
) else (
    @rem "TODO: Implement 2025 support in the future"
    call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" %2
)
nmake /f Makefile.win32 check clean DLL_CFLAGS=%3 EXE_CFLAGS=%4
