#
# This Makefile works only with GNU make.
#

UNAME_S := $(shell uname -s)

ifeq ($(findstring MINGW32_NT,$(UNAME_S)),MINGW32_NT)
  # Mingw32
  CC = gcc
  CC_SHARED = gcc -shared
  EXEEXT = .exe
  SOEXT = dll
  LIBS = -ldbghelp
  PLTHOOK_C = plthook_win32.c
endif

ifeq ($(findstring CYGWIN_NT,$(UNAME_S)),CYGWIN_NT)
  # Cygwin
  CC = gcc
  CC_SHARED = gcc -shared
  EXEEXT = .exe
  SOEXT = dll
  LIBS = -ldbghelp
  PLTHOOK_C = plthook_win32.c
endif

ifeq ($(UNAME_S),Darwin)
  # OS X
  CC = gcc
  CC_SHARED = gcc -shared -fPIC -Wno-deprecated-declarations
  EXEEXT =
  SOEXT = so
  LIBS = -ldl
  PLTHOOK_C = plthook_osx.c
endif

ifndef PLTHOOK_C
  # Linux
  CC = gcc
  CC_SHARED = gcc -shared -fPIC
  EXEEXT =
  SOEXT = so
  LIBS = -ldl -lm
  PLTHOOK_C = plthook_elf.c
  OTHER_TESTS = linux_specific_tests
endif

all: libtest.$(SOEXT) testprog$(EXEEXT)

libtest.$(SOEXT): libtest.c libtest.h
	$(CC_SHARED) $(CFLAGS) -DLIBTEST_DLL -o libtest.$(SOEXT) libtest.c -lm

testprog$(EXEEXT): testprog.c ../$(PLTHOOK_C) libtest.h
	$(CC) $(CFLAGS) -o testprog$(EXEEXT) -I.. testprog.c ../$(PLTHOOK_C) -L. -ltest $(LIBS)

check: run_test $(OTHER_TESTS)

run_test: clean libtest.$(SOEXT) testprog$(EXEEXT)
	LD_LIBRARY_PATH=. ./testprog$(EXEEXT) open
	LD_LIBRARY_PATH=. ./testprog$(EXEEXT) open_by_handle

linux_specific_tests:
	@echo ============ check Partial RELRO ============
	$(MAKE) run_test CFLAGS=-Wl,-z,relro
	@echo ============ check Full RELRO ============
	$(MAKE) run_test CFLAGS=-Wl,-z,relro,-z,now
	@echo ============ check 32-bit ============
	$(MAKE) run_test CFLAGS=-m32
	@echo ============ check Partial RELRO 32-bit ============
	$(MAKE) run_test "CFLAGS=-m32 -Wl,-z,relro"
	@echo ============ check Full RELRO 32-bit ============
	$(MAKE) run_test "CFLAGS=-m32 -Wl,-z,relro,-z,now"

clean:
	$(RM) libtest.$(SOEXT) testprog$(EXEEXT)
