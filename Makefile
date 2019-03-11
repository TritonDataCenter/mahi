#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

#
# Copyright (c) 2019, Joyent, Inc.
#

#
# Makefile: basic Makefile for template API service
#
# This Makefile is a template for new repos. It contains only repo-specific
# logic and uses included makefiles to supply common targets (javascriptlint,
# jsstyle, restdown, etc.), which are used by other repos as well. You may well
# need to rewrite most of this file, but you shouldn't need to touch the
# included makefiles.
#
# If you find yourself adding support for new targets that could be useful for
# other projects too, you should add these to the original versions of the
# included Makefiles (in eng.git) so that other teams can use them too.
#

#
## Tools
#
NODEUNIT	:= ./node_modules/.bin/nodeunit
NAME		:= mahi

#
## Files
#
DOC_FILES	 = index.md
JS_FILES	:= $(shell \
    find lib test -name '*.js' -not -name 'jsonparsestream.js')
JSON_FILES	 = package.json \
    sapi_manifests/mahi/template \
    sapi_manifests/mahi2/template
JSL_CONF_NODE	 = tools/jsl.node.conf
JSL_FILES_NODE	 = $(JS_FILES)
JSSTYLE_FILES	 = $(JS_FILES)
JSSTYLE_FLAGS	 = -f tools/jsstyle.conf
SMF_MANIFESTS_IN = smf/manifests/mahi.xml.in \
    smf/manifests/mahi-redis.xml.in \
    smf/manifests/mahi-server.xml.in \
    smf/manifests/mahi-replicator.xml.in


#
# Variables
#
NODE_PREBUILT_TAG       = zone
NODE_PREBUILT_VERSION	:= v0.10.48
# sdc-minimal-multiarch-lts 15.4.1
NODE_PREBUILT_IMAGE 	= 18b094b0-eb01-11e5-80c1-175dac7ddf02

ENGBLD_USE_BUILDIMAGE	= true
ENGBLD_REQUIRE :=	$(shell git submodule update --init deps/eng)
include ./deps/eng/tools/mk/Makefile.defs
TOP ?= $(error Unable to access eng.git submodule Makefiles.)

ifeq ($(shell uname -s),SunOS)
	include ./deps/eng/tools/mk/Makefile.node_prebuilt.defs
	include ./deps/eng/tools/mk/Makefile.agent_prebuilt.defs
else
	include ./deps/eng/tools/mk/Makefile.node.defs
endif
include ./deps/eng/tools/mk/Makefile.smf.defs
RELEASE_TARBALL	:= $(NAME)-pkg-$(STAMP).tar.gz
RELSTAGEDIR     := /tmp/$(NAME)-$(STAMP)

BASE_IMAGE_UUID = 04a48d7d-6bb5-4e83-8c3b-e60a99e0f48f
BUILDIMAGE_NAME = manta-authcache
BUILDIMAGE_DESC	= Manta authcache
BUILDIMAGE_PKGSRC = redis-3.0.5
AGENTS		= amon config registrar

#
# Repo-specific targets
#
.PHONY: all
all: $(SMF_MANIFESTS) | $(NODEUNIT) scripts
	$(NPM) install

$(NODEUNIT): | $(NPM_EXEC)
	$(NPM) install

CLEAN_FILES += $(NODEUNIT) ./node_modules/nodeunit
DISTCLEAN_FILES += node_modules

.PHONY: test
test: $(NODEUNIT)
	find test -name '*.test.js' | xargs -n 1 $(NODEUNIT)

.PHONY: setup
setup: | $(NPM_EXEC)
	$(NPM) install

.PHONY: scripts
scripts: deps/manta-scripts/.git
	mkdir -p $(BUILD)/scripts
	cp deps/manta-scripts/*.sh $(BUILD)/scripts

.PHONY: release
release: all docs $(SMF_MANIFESTS) deps/sdc-scripts/.git
	@echo "Building $(RELEASE_TARBALL)"
	@mkdir -p $(RELSTAGEDIR)/root/opt/smartdc/mahi
	@mkdir -p $(RELSTAGEDIR)/root/opt/smartdc/boot
	@mkdir -p $(RELSTAGEDIR)/site
	@touch $(RELSTAGEDIR)/site/.do-not-delete-me
	@mkdir -p $(RELSTAGEDIR)/root
	cp -r   $(TOP)/build \
		$(TOP)/boot \
		$(TOP)/bin \
		$(TOP)/lib \
		$(TOP)/v1 \
		$(TOP)/node_modules \
		$(TOP)/package.json \
		$(TOP)/sapi_manifests \
		$(TOP)/sdc \
		$(TOP)/smf \
		$(TOP)/etc \
		$(RELSTAGEDIR)/root/opt/smartdc/mahi/
	mv $(RELSTAGEDIR)/root/opt/smartdc/mahi/build/scripts \
		$(RELSTAGEDIR)/root/opt/smartdc/mahi/boot
	cp -R $(TOP)/deps/sdc-scripts/* $(RELSTAGEDIR)/root/opt/smartdc/boot/
	cp -R $(TOP)/boot/* $(RELSTAGEDIR)/root/opt/smartdc/boot/
	ln -s /opt/smartdc/$(NAME)/boot/scripts \
		$(RELSTAGEDIR)/root/opt/smartdc/boot/scripts
	(cd $(RELSTAGEDIR) && $(TAR) -I pigz -cf $(TOP)/$(RELEASE_TARBALL) root site)
	@rm -rf $(RELSTAGEDIR)

.PHONY: publish
publish: release
	mkdir -p $(ENGBLD_BITS_DIR)/$(NAME)
	cp $(TOP)/$(RELEASE_TARBALL) $(ENGBLD_BITS_DIR)/$(NAME)/$(RELEASE_TARBALL)

include ./deps/eng/tools/mk/Makefile.deps
ifeq ($(shell uname -s),SunOS)
	include ./deps/eng/tools/mk/Makefile.node_prebuilt.targ
	include ./deps/eng/tools/mk/Makefile.agent_prebuilt.targ
endif
include ./deps/eng/tools/mk/Makefile.smf.targ
include ./deps/eng/tools/mk/Makefile.targ
