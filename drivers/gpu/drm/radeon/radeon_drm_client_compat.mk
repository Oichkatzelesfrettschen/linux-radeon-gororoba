# SPDX-License-Identifier: MIT

radeon_drm_client_event_api_header := $(srctree)/include/drm/drm_client_event.h
radeon_drm_client_suspend_console_lock_declaration := drm_client_dev_suspend(struct drm_device *dev, bool holds_console_lock)
radeon_drm_client_resume_console_lock_declaration := drm_client_dev_resume(struct drm_device *dev, bool holds_console_lock)

ifeq ($(wildcard $(radeon_drm_client_event_api_header)),)
$(error missing DRM client event API header: $(radeon_drm_client_event_api_header))
endif

radeon_drm_client_event_api_text := $(file <$(radeon_drm_client_event_api_header))
radeon_drm_client_suspend_console_lock_arg_present := $(if $(findstring $(radeon_drm_client_suspend_console_lock_declaration),$(radeon_drm_client_event_api_text)),1,0)
radeon_drm_client_resume_console_lock_arg_present := $(if $(findstring $(radeon_drm_client_resume_console_lock_declaration),$(radeon_drm_client_event_api_text)),1,0)

ifneq ($(radeon_drm_client_suspend_console_lock_arg_present),$(radeon_drm_client_resume_console_lock_arg_present))
$(error DRM client suspend and resume disagree on the console lock argument: $(radeon_drm_client_event_api_header))
endif

ccflags-y += -DRADEON_DRM_CLIENT_CONSOLE_LOCK_ARG_PRESENT=$(radeon_drm_client_suspend_console_lock_arg_present)

ifdef RADEON_DRM_CLIENT_COMPAT_QUERY
.PHONY: radeon-drm-client-compat-query
radeon-drm-client-compat-query:
	@printf '%s\n' \
		'RADEON_DRM_CLIENT_CONSOLE_LOCK_ARG_PRESENT=$(radeon_drm_client_suspend_console_lock_arg_present)' \
		'ccflags-y=$(ccflags-y)'
endif
