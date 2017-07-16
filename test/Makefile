#
# This Makefile works only with GNU make.
#

UNAME_S := $(shell uname -s)

CC = gcc
CFLAGS_SHARED = -shared -fPIC
CFLAGS = $(CFLAGS_WARNING) $(EXTRA_CFLAGS)
CFLAGS_WARNING = -Wall
EXEEXT =
SOEXT = so
LIBS = -ldl -lm
PLTHOOK_C = plthook_elf.c
TESTS = basic_tests
QEMU_CMD =

ifeq ($(UNAME_S),Linux)
  # Linux
  TESTS = linux_tests
  ifneq ($(TARGET_PLATFORM),)
    CC = $(TARGET_PLATFORM)-gcc
    QEMU_CMD = qemu-$(shell echo $(TARGET_PLATFORM) | sed -e 's/-.*//') -L /usr/$(TARGET_PLATFORM)
  else ifeq ($(CROSS),1)
    # Prerequisite packages on Ubuntu:
    #   either qemu-user or qemu-user-static
    #   gcc-arm-linux-gnueabi
    #   gcc-arm-linux-gnueabihf
    TESTS = linux_cross_tests
  else ifeq ($(shell uname -m),x86_64)
    # Prerequisite packages on Ubuntu:
    #   gcc-multilib
    TESTS += linux_m32_tests
  endif
endif

ifeq ($(findstring MINGW32_NT,$(UNAME_S)),MINGW32_NT)
  # Mingw32
  CFLAGS_SHARED = -shared
  EXEEXT = .exe
  SOEXT = dll
  LIBS = -ldbghelp
  PLTHOOK_C = plthook_win32.c
endif

ifeq ($(findstring CYGWIN_NT,$(UNAME_S)),CYGWIN_NT)
  # Cygwin
  CFLAGS_SHARED = -shared
  EXEEXT = .exe
  SOEXT = dll
  LIBS = -ldbghelp
  PLTHOOK_C = plthook_win32.c
endif

ifeq ($(UNAME_S),Darwin)
  # OS X
  CFLAGS_SHARED = -shared -fPIC -Wno-deprecated-declarations
  LIBS = -ldl
  PLTHOOK_C = plthook_osx.c
endif

all: libtest.$(SOEXT) testprog$(EXEEXT)

libtest.$(SOEXT): libtest.c libtest.h
	$(CC) $(CFLAGS_SHARED) $(CFLAGS) -DLIBTEST_DLL -o libtest.$(SOEXT) libtest.c -lm

testprog$(EXEEXT): testprog.c ../$(PLTHOOK_C) libtest.h
	$(CC) $(CFLAGS) -o testprog$(EXEEXT) -I.. testprog.c ../$(PLTHOOK_C) -L. -ltest $(LIBS)

run_tests: clean libtest.$(SOEXT) testprog$(EXEEXT)
	cp libtest.$(SOEXT) testprog$(EXEEXT) ~/
	cd && LD_LIBRARY_PATH=. $(QEMU_CMD) ./testprog$(EXEEXT) open
	cd && LD_LIBRARY_PATH=. $(QEMU_CMD) ./testprog$(EXEEXT) open_by_handle

check: $(TESTS)

basic_tests: run_tests

linux_tests:
	@echo ------------ check ------------
	$(MAKE) run_tests "EXTRA_CFLAGS="
	@echo ------------ check Partial RELRO ------------
	$(MAKE) run_tests "EXTRA_CFLAGS=-Wl,-z,relro"
	@echo ------------ check Full RELRO ------------
	$(MAKE) run_tests "EXTRA_CFLAGS=-Wl,-z,relro,-z,now"

linux_m32_tests:
	@echo ------------ check 32-bit ------------
	$(MAKE) run_tests "EXTRA_CFLAGS=-m32"
	@echo ------------ check 32-bit Partial RELRO ------------
	$(MAKE) run_tests "EXTRA_CFLAGS=-m32 -Wl,-z,relro"
	@echo ------------ check 32-bit Full RELRO ------------
	$(MAKE) run_tests "EXTRA_CFLAGS=-m32 -Wl,-z,relro,-z,now"

linux_cross_tests:
	@echo ============ arm-linux-gnueabi ============
	$(MAKE) check TARGET_PLATFORM=arm-linux-gnueabi
	@echo ============ arm-linux-gnueabihf ============
	$(MAKE) check TARGET_PLATFORM=arm-linux-gnueabihf

clean:
	$(RM) libtest.$(SOEXT) testprog$(EXEEXT)
