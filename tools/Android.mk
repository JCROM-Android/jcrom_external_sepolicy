##
# checkseapp and checkfc
#

include $(CLEAR_VARS)

LOCAL_MODULE := checkseapp
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../libsepol/include/
LOCAL_CFLAGS := -DLINK_SEPOL_STATIC
LOCAL_SRC_FILES := tools/check_seapp.c
LOCAL_STATIC_LIBRARIES := libsepol
LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_HOST_EXECUTABLE)

###################################
include $(CLEAR_VARS)

LOCAL_MODULE := checkfc
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../libsepol/include \
                    $(LOCAL_PATH)/../libselinux/include
LOCAL_SRC_FILES := tools/checkfc.c
LOCAL_STATIC_LIBRARIES := libsepol libselinux
LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_HOST_EXECUTABLE)
