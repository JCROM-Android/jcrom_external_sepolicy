LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

# Force permissive domains to be unconfined+enforcing?
#
# During development, this should be set to false.
# Permissive means permissive.
#
# When we're close to a release and SELinux new policy development
# is frozen, we should flip this to true. This forces any currently
# permissive domains into unconfined+enforcing.
#
FORCE_PERMISSIVE_TO_UNCONFINED:=false

ifeq ($(TARGET_BUILD_VARIANT),user)
  # User builds are always forced unconfined+enforcing
  FORCE_PERMISSIVE_TO_UNCONFINED:=true
endif

# SELinux policy version.
# Must be <= /selinux/policyvers reported by the Android kernel.
# Must be within the compatibility range reported by checkpolicy -V.
POLICYVERS ?= 26

MLS_SENS=1
MLS_CATS=1024

# Ensure specified policy directories exist.
$(foreach pd, $(BOARD_SEPOLICY_REPLACE) $(BOARD_SEPOLICY_UNION), \
  $(if $(filter 0, $(words $(wildcard $(pd)))), \
    $(error Specified policy directory $(pd) does not exist), \
  ) \
)

# Builds paths for all requested policy files w.r.t
# both BOARD_SEPOLICY_REPLACE and BOARD_SEPOLICY_UNION
# product variables.
# $(1): the set of policy name paths to build
build_policy = $(foreach type, $(1), \
  $(filter-out $(BOARD_SEPOLICY_IGNORE), \
    $(foreach base_file, $(wildcard $(addsuffix /$(type), $(LOCAL_PATH))), \
      $(eval _basename := $(notdir $(base_file))) \
      $(eval _replace_files := $(wildcard $(addsuffix /$(_basename), $(BOARD_SEPOLICY_REPLACE)))) \
      $(lastword  $(base_file) $(_replace_files)) \
    ) \
    $(wildcard $(addsuffix /$(type), $(BOARD_SEPOLICY_UNION))) \
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
	$(hide) m4 -D mls_num_sens=$(PRIVATE_MLS_SENS) -D mls_num_cats=$(PRIVATE_MLS_CATS) \
		-D target_build_variant=$(TARGET_BUILD_VARIANT) \
		-D force_permissive_to_unconfined=$(FORCE_PERMISSIVE_TO_UNCONFINED) \
		-s $^ > $@
	$(hide) sed '/dontaudit/d' $@ > $@.dontaudit

$(LOCAL_BUILT_MODULE) : $(sepolicy_policy.conf) $(HOST_OUT_EXECUTABLES)/checkpolicy
	@mkdir -p $(dir $@)
	$(hide) $(HOST_OUT_EXECUTABLES)/checkpolicy -M -c $(POLICYVERS) -o $@ $<
	$(hide) $(HOST_OUT_EXECUTABLES)/checkpolicy -M -c $(POLICYVERS) -o $(dir $<)/$(notdir $@).dontaudit $<.dontaudit

built_sepolicy := $(LOCAL_BUILT_MODULE)
sepolicy_policy.conf :=

###################################
include $(CLEAR_VARS)

LOCAL_MODULE := file_contexts
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)

include $(BUILD_SYSTEM)/base_rules.mk

ALL_FC_FILES := $(call build_policy, file_contexts)

$(LOCAL_BUILT_MODULE): PRIVATE_SEPOLICY := $(built_sepolicy)
$(LOCAL_BUILT_MODULE):  $(ALL_FC_FILES) $(built_sepolicy) $(HOST_OUT_EXECUTABLES)/checkfc
	@mkdir -p $(dir $@)
	$(hide) m4 -s $(ALL_FC_FILES) > $@
	$(hide) $(HOST_OUT_EXECUTABLES)/checkfc $(PRIVATE_SEPOLICY) $@

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

$(LOCAL_BUILT_MODULE): PRIVATE_SEPOLICY := $(built_sepolicy)
$(LOCAL_BUILT_MODULE) : $(seapp_contexts.tmp) $(built_sepolicy) $(HOST_OUT_EXECUTABLES)/checkseapp
	@mkdir -p $(dir $@)
	$(HOST_OUT_EXECUTABLES)/checkseapp -p $(PRIVATE_SEPOLICY) -o $@ $<

seapp_contexts.tmp :=
##################################
include $(CLEAR_VARS)

LOCAL_MODULE := property_contexts
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)

include $(BUILD_SYSTEM)/base_rules.mk

ALL_PC_FILES := $(call build_policy, property_contexts)

$(LOCAL_BUILT_MODULE): PRIVATE_SEPOLICY := $(built_sepolicy)
$(LOCAL_BUILT_MODULE):  $(ALL_PC_FILES) $(built_sepolicy) $(HOST_OUT_EXECUTABLES)/checkfc
	@mkdir -p $(dir $@)
	$(hide) m4 -s $(ALL_PC_FILES) > $@
	$(hide) $(HOST_OUT_EXECUTABLES)/checkfc -p $(PRIVATE_SEPOLICY) $@

property_contexts :=
built_sepolicy :=
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

include $(BUILD_SYSTEM)/base_rules.mk

# Build keys.conf
mac_perms_keys.tmp := $(intermediates)/keys.tmp
$(mac_perms_keys.tmp) : $(call build_policy, keys.conf)
	@mkdir -p $(dir $@)
	$(hide) m4 -s $^ > $@

ALL_MAC_PERMS_FILES := $(call build_policy, $(LOCAL_MODULE))

$(LOCAL_BUILT_MODULE) : $(mac_perms_keys.tmp) $(HOST_OUT_EXECUTABLES)/insertkeys.py $(ALL_MAC_PERMS_FILES)
	@mkdir -p $(dir $@)
	$(hide) DEFAULT_SYSTEM_DEV_CERTIFICATE="$(dir $(DEFAULT_SYSTEM_DEV_CERTIFICATE))" \
		$(HOST_OUT_EXECUTABLES)/insertkeys.py -t $(TARGET_BUILD_VARIANT) -c $(TOP) $< -o $@ $(ALL_MAC_PERMS_FILES)

mac_perms_keys.tmp :=
##################################

build_policy :=

include $(call all-makefiles-under,$(LOCAL_PATH))
