#
# This Makefile works only with GNU make.
#

UNAME_S := $(shell uname -s)

CFLAGS_SHARED = -shared -fPIC
CFLAGS = $(CFLAGS_WARNING) $(EXTRA_CFLAGS) $(OPT_CFLAGS)
CFLAGS_WARNING = -Wall
EXEEXT =
SOEXT = so
LIBS = -ldl -lm
PLTHOOK_C = plthook_elf.c
TESTS = run_tests
QEMU_CMD =

ifeq ($(UNAME_S),Linux)
  # Linux
  TESTS = relro_pie_tests
  ifneq ($(TARGET_PLATFORM),)
    CC = $(TARGET_PLATFORM)-gcc
    QEMU_CMD = qemu-$(or $(QEMU_ARCH),$(shell echo $(TARGET_PLATFORM) | sed -e 's/-.*//')) -L /usr/$(TARGET_PLATFORM)
  endif
endif

ifeq ($(UNAME_S),FreeBSD)
  # FreeBSD
  TESTS = relro_pie_tests
  LIBS = -lm -lutil
  SKIP_OPEN_BY_ADDRESS_TEST = 1
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
	LD_LIBRARY_PATH=. $(QEMU_CMD) ./testprog$(EXEEXT) open
	LD_LIBRARY_PATH=. $(QEMU_CMD) ./testprog$(EXEEXT) open_by_handle
	test "$(SKIP_OPEN_BY_ADDRESS_TEST)" || env LD_LIBRARY_PATH=. $(QEMU_CMD) ./testprog$(EXEEXT) open_by_address

check: $(TESTS)

relro_pie_tests:
	@echo ------------ check ------------
	$(MAKE) run_tests "EXTRA_CFLAGS="
	@echo ------------ check Partial RELRO ------------
	$(MAKE) run_tests "EXTRA_CFLAGS=-Wl,-z,relro"
	@echo ------------ check Full RELRO ------------
	$(MAKE) run_tests "EXTRA_CFLAGS=-Wl,-z,relro,-z,now"
	@echo ------------ check PIE ------------
	$(MAKE) run_tests "CFLAGS_EXE=-fPIE -pie"
	@echo ------------ check PIE Partial RELRO ------------
	$(MAKE) run_tests "CFLAGS_EXE=-fPIE -pie" "EXTRA_CFLAGS=-Wl,-z,relro"
	@echo ------------ check PIE Full RELRO ------------
	$(MAKE) run_tests "CFLAGS_EXE=-fPIE -pie" "EXTRA_CFLAGS=-Wl,-z,relro,-z,now"
	@echo ------------ check Partial RELRO + -fno-plt ------------
	@touch dummy.c
	@if $(CC) -c dummy.c -fno-plt; then \
	  $(MAKE) run_tests "EXTRA_CFLAGS=-Wl,-z,relro -fno-plt"; \
	else \
	  echo "skip: -fno-plt isn't supported"; \
	fi

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

clean:
	$(RM) libtest.$(SOEXT) testprog$(EXEEXT)
