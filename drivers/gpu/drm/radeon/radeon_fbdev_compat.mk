# SPDX-License-Identifier: MIT

radeon_fb_helper_api_header := $(srctree)/include/drm/drm_fb_helper.h
radeon_fb_helper_alloc_info_declaration := drm_fb_helper_alloc_info(struct drm_fb_helper *fb_helper)

ifeq ($(wildcard $(radeon_fb_helper_api_header)),)
$(error missing DRM fb helper API header: $(radeon_fb_helper_api_header))
endif

radeon_drm_fb_helper_alloc_info_present := $(if $(findstring $(radeon_fb_helper_alloc_info_declaration),$(file <$(radeon_fb_helper_api_header))),1,0)

ccflags-y += -DRADEON_DRM_FB_HELPER_ALLOC_INFO_PRESENT=$(radeon_drm_fb_helper_alloc_info_present)

ifdef RADEON_FBDEV_COMPAT_QUERY
.PHONY: radeon-fbdev-compat-query
radeon-fbdev-compat-query:
	@printf '%s\n' \
		'RADEON_DRM_FB_HELPER_ALLOC_INFO_PRESENT=$(radeon_drm_fb_helper_alloc_info_present)' \
		'ccflags-y=$(ccflags-y)'
endif
