# Linux
CC = gcc
CC_SHARED = gcc -shared -fPIC
EXEEXT =
SOEXT = so
LIBS = -ldl
PLTHOOK_C = plthook.c

# Mingw32
CC = gcc
CC_SHARED = gcc -shared
EXEEXT = .exe
SOEXT = dll
LIBS = -ldbghelp
PLTHOOK_C = plthook_win32.c

all: libtest.$(SOEXT) testprog$(EXEEXT)

libtest.$(SOEXT): libtest.c libtest.h
	$(CC_SHARED) -DLIBTEST_DLL -o libtest.$(SOEXT) libtest.c -lm

testprog$(EXEEXT): testprog.c ../$(PLTHOOK_C) libtest.h
	$(CC) -o testprog$(EXEEXT) -I.. testprog.c ../$(PLTHOOK_C) -L. -ltest $(LIBS)

check: libtest.$(SOEXT) testprog$(EXEEXT)
	LD_LIBRARY_PATH=. ./testprog$(EXEEXT)

clean:
	$(RM) libtest.$(SOEXT) testprog$(EXEEXT)
