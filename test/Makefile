#
# This Makefile works only with GNU make.
#

UNAME_S := $(shell uname -s)

CC = gcc -g
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
  TESTS = relro_pie_tests
  ifneq ($(TARGET_PLATFORM),)
    CC = $(TARGET_PLATFORM)-gcc
    QEMU_CMD = qemu-$(or $(QEMU_ARCH),$(shell echo $(TARGET_PLATFORM) | sed -e 's/-.*//')) -L /usr/$(TARGET_PLATFORM)
  else ifeq ($(CROSS),1)
    # Prerequisite packages on Ubuntu:
    #   either qemu-user or qemu-user-static
    #   gcc-arm-linux-gnueabi
    #   gcc-arm-linux-gnueabihf
    TESTS = linux_cross_tests
  else ifeq ($(shell uname -m),x86_64)
    # Prerequisite packages on Ubuntu:
    #   gcc-multilib libc6-dbg:i386 valgrind
    TESTS += relro_pie_m32_tests
    TESTS += relro_pie_tests_on_valgrind
  endif
endif

ifeq ($(UNAME_S),FreeBSD)
  # FreeBSD
  TESTS = relro_pie_tests
  LIBS = -lm -lutil
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
	$(CC) $(CFLAGS_EXE) $(CFLAGS) -o testprog$(EXEEXT) -I.. testprog.c ../$(PLTHOOK_C) -L. -ltest $(LIBS)

run_tests: clean libtest.$(SOEXT) testprog$(EXEEXT)
	cp libtest.$(SOEXT) testprog$(EXEEXT) ~/
	cd && LD_LIBRARY_PATH=. $(QEMU_CMD) ./testprog$(EXEEXT) open
	cd && LD_LIBRARY_PATH=. $(QEMU_CMD) ./testprog$(EXEEXT) open_by_handle

check: $(TESTS)

basic_tests: run_tests

relro_pie_tests:
	@echo ------------ check ------------
	$(MAKE) run_tests "EXTRA_CFLAGS="
	@echo ------------ check Partial RELRO ------------
	$(MAKE) run_tests "EXTRA_CFLAGS=-Wl,-z,relro"
	@echo ------------ check Full RELRO ------------
	$(MAKE) run_tests "EXTRA_CFLAGS=-Wl,-z,relro,-z,now"
	@echo ------------ check PIE ------------
	$(MAKE) run_tests "CFLAGS_EXE=-fPIE -pie"

relro_pie_m32_tests:
	@echo ------------ check 32-bit ------------
	$(MAKE) run_tests "EXTRA_CFLAGS=-m32"
	@echo ------------ check 32-bit Partial RELRO ------------
	$(MAKE) run_tests "EXTRA_CFLAGS=-m32 -Wl,-z,relro"
	@echo ------------ check 32-bit Full RELRO ------------
	$(MAKE) run_tests "EXTRA_CFLAGS=-m32 -Wl,-z,relro,-z,now"
	@echo ------------ check 32-bit PIE ------------
	$(MAKE) run_tests "EXTRA_CFLAGS=-m32" "CFLAGS_EXE=-fPIE -pie"

relro_pie_tests_on_valgrind:
	@echo ------------ check on valgrind ------------
	$(MAKE) run_tests "EXTRA_CFLAGS=" QEMU_CMD=valgrind
	@echo ------------ check Full RELRO on valgrind  ------------
	$(MAKE) run_tests "EXTRA_CFLAGS=-Wl,-z,relro,-z,now" QEMU_CMD=valgrind
	@echo ------------ check 32-bit on valgrind ------------
	$(MAKE) run_tests "EXTRA_CFLAGS=-m32" QEMU_CMD=valgrind
	@echo ------------ check 32-bit Full RELRO on valgrind ------------
	$(MAKE) run_tests "EXTRA_CFLAGS=-m32 -Wl,-z,relro,-z,now" QEMU_CMD=valgrind

linux_cross_tests:
	@echo
	@echo ============ arm-linux-gnueabi ============
	$(MAKE) check TARGET_PLATFORM=arm-linux-gnueabi
	@echo
	@echo ============ arm-linux-gnueabihf ============
	$(MAKE) check TARGET_PLATFORM=arm-linux-gnueabihf
	@echo
	@echo ============ aarch64-linux-gnu ============
	$(MAKE) check TARGET_PLATFORM=aarch64-linux-gnu
	@echo
	@echo ============ powerpc-linux-gnu ============
	$(MAKE) check TARGET_PLATFORM=powerpc-linux-gnu QEMU_ARCH=ppc
	@echo
	@echo ============ powerpc64le-linux-gnu ============
	$(MAKE) check TARGET_PLATFORM=powerpc64le-linux-gnu QEMU_ARCH=ppc64le

clean:
	$(RM) libtest.$(SOEXT) testprog$(EXEEXT)
