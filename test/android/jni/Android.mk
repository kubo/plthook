LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := libtest
LOCAL_SRC_FILES := ../../libtest.c
LOCAL_CFLAGS := -fno-builtin-ceil
TARGET_PLATFORM := android-22

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE    := testprog
LOCAL_SRC_FILES := ../../testprog.c ../../../plthook_elf.c
LOCAL_C_INCLUDES := ../.. ../../..
LOCAL_SHARED_LIBRARIES := libtest

include $(BUILD_EXECUTABLE)
