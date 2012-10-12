ifeq ($(HAVE_SELINUX),true)

LOCAL_PATH:= $(call my-dir)

include $(call all-makefiles-under,$(LOCAL_PATH))

include $(CLEAR_VARS)

# SELinux policy version.
# Must be <= /selinux/policyvers reported by the Android kernel.
# Must be within the compatibility range reported by checkpolicy -V.
POLICYVERS ?= 24

MLS_SENS=1
MLS_CATS=1024

# Quick edge case error detection for PRODUCT_SEPOLICY_REPLACE.
# Builds the singular path for each replace file.
LOCAL_SEPOLICY_REPLACE_PATHS :=
$(foreach pf, $(PRODUCT_SEPOLICY_REPLACE), \
  $(if $(filter $(pf), $(PRODUCT_SEPOLICY_UNION)), \
    $(error Ambiguous request for sepolicy $(pf). Appears in both \
      PRODUCT_SEPOLICY_REPLACE and PRODUCT_SEPOLICY_UNION), \
  ) \
  $(eval _paths := $(wildcard $(addsuffix /$(pf), $(PRODUCT_SEPOLICY_DIRS)))) \
  $(eval _occurences := $(words $(_paths))) \
  $(if $(filter 0,$(_occurences)), \
    $(error No sepolicy file found for $(pf) in $(PRODUCT_SEPOLICY_DIRS)), \
  ) \
  $(if $(filter 1, $(_occurences)), \
    $(eval LOCAL_SEPOLICY_REPLACE_PATHS += $(_paths)), \
    $(error Multiple occurences of replace file $(pf) in $(_paths)) \
  ) \
  $(if $(filter 0, $(words $(wildcard $(addsuffix /$(pf), $(LOCAL_PATH))))), \
    $(error Specified the sepolicy file $(pf) in PRODUCT_SEPOLICY_REPLACE, \
      but none found in $(LOCAL_PATH)), \
  ) \
)

# Builds paths for all requested policy files w.r.t
# both PRODUCT_SEPOLICY_REPLACE and PRODUCT_SEPOLICY_UNION
# product variables.
# $(1): the set of policy name paths to build
build_policy = $(foreach type, $(1), \
  $(foreach expanded_type, $(notdir $(wildcard $(addsuffix /$(type), $(LOCAL_PATH)))), \
    $(if $(filter $(expanded_type), $(PRODUCT_SEPOLICY_REPLACE)), \
      $(wildcard $(addsuffix $(expanded_type), $(dir $(LOCAL_SEPOLICY_REPLACE_PATHS)))), \
      $(LOCAL_PATH)/$(expanded_type) \
    ) \
  ) \
  $(foreach union_policy, $(wildcard $(addsuffix /$(type), $(PRODUCT_SEPOLICY_DIRS))), \
    $(if $(filter $(notdir $(union_policy)), $(PRODUCT_SEPOLICY_UNION)), \
      $(union_policy), \
    ) \
  ) \
)

##################################
include $(CLEAR_VARS)

LOCAL_MODULE := sepolicy
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)

include $(BUILD_SYSTEM)/base_rules.mk

sepolicy_policy.conf := $(intermediates)/policy.conf
$(sepolicy_policy.conf): PRIVATE_MLS_SENS := $(MLS_SENS)
$(sepolicy_policy.conf): PRIVATE_MLS_CATS := $(MLS_CATS)
$(sepolicy_policy.conf) : $(call build_policy, security_classes initial_sids access_vectors global_macros mls_macros mls policy_capabilities te_macros attributes *.te roles users initial_sid_contexts fs_use genfs_contexts port_contexts)
	@mkdir -p $(dir $@)
	$(hide) m4 -D mls_num_sens=$(PRIVATE_MLS_SENS) -D mls_num_cats=$(PRIVATE_MLS_CATS) -s $^ > $@

$(LOCAL_BUILT_MODULE) : $(sepolicy_policy.conf) $(HOST_OUT_EXECUTABLES)/checkpolicy
	@mkdir -p $(dir $@)
	$(hide) $(HOST_OUT_EXECUTABLES)/checkpolicy -M -c $(POLICYVERS) -o $@ $<

sepolicy_policy.conf :=

###################################
include $(CLEAR_VARS)

LOCAL_MODULE := checkfc
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES += external/libsepol/include external/libselinux/include
LOCAL_SRC_FILES := checkfc.c
LOCAL_STATIC_LIBRARIES := libsepol libselinux
LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_HOST_EXECUTABLE)

##################################
include $(CLEAR_VARS)

LOCAL_MODULE := file_contexts
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)

include $(BUILD_SYSTEM)/base_rules.mk

ALL_FC_FILES := $(call build_policy, file_contexts)

file_contexts := $(intermediates)/file_contexts
$(file_contexts):  $(ALL_FC_FILES) sepolicy $(HOST_OUT_EXECUTABLES)/checkfc
	@mkdir -p $(dir $@)
	$(hide) m4 -s $(ALL_FC_FILES) > $@
	$(hide) $(HOST_OUT_EXECUTABLES)/checkfc $(TARGET_ROOT_OUT)/sepolicy $@

file_contexts :=

##################################
include $(CLEAR_VARS)
LOCAL_MODULE := seapp_contexts
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)

include $(BUILD_SYSTEM)/base_rules.mk

seapp_contexts.tmp := $(intermediates)/seapp_contexts.tmp
$(seapp_contexts.tmp): $(call build_policy, seapp_contexts)
	@mkdir -p $(dir $@)
	$(hide) m4 -s $^ > $@

$(LOCAL_BUILT_MODULE) : $(seapp_contexts.tmp) $(TARGET_ROOT_OUT)/sepolicy $(HOST_OUT_EXECUTABLES)/checkseapp
	@mkdir -p $(dir $@)
	$(HOST_OUT_EXECUTABLES)/checkseapp -p $(TARGET_ROOT_OUT)/sepolicy -o $@ $<

seapp_contexts.tmp :=
##################################
include $(CLEAR_VARS)

LOCAL_MODULE := property_contexts
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)

include $(BUILD_SYSTEM)/base_rules.mk

property_contexts := $(intermediates)/property_contexts
$(property_contexts): $(call build_policy, property_contexts)
	@mkdir -p $(dir $@)
	$(hide) m4 -s $^ > $@

property_contexts :=
##################################

##################################
include $(CLEAR_VARS)

LOCAL_MODULE := selinux-network.sh
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_PATH := $(TARGET_OUT_EXECUTABLES)

include $(BUILD_PREBUILT)

##################################
include $(CLEAR_VARS)

LOCAL_MODULE := mac_permissions.xml
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/security

LOCAL_SRC_FILES := $(LOCAL_MODULE)

include $(BUILD_PREBUILT)

##################################

endif #ifeq ($(HAVE_SELINUX),true)
