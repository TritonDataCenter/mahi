#
# Copyright (c) 2012, Joyent, Inc. All rights reserved.
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
#DOC_FILES	 = index.restdown boilerplateapi.restdown
JS_FILES	:= $(shell ls *.js) $(shell find lib -name '*.js')
JSON_FILES	 = package.json sapi_manifests/mahi/template sapi_manifests/mahi2/template
JSL_CONF_NODE	 = tools/jsl.node.conf
JSL_FILES_NODE	 = $(JS_FILES)
JSSTYLE_FILES	 = $(JS_FILES)
JSSTYLE_FLAGS	 = -f tools/jsstyle.conf
REPO_MODULES	 = src/node-dummy
SMF_MANIFESTS_IN = smf/manifests/mahi.xml.in smf/manifests/mahi-redis.xml.in smf/manifests/mahi-server.xml.in smf/manifests/mahi-replicator.xml.in


#
# Variables
#
NAME 			= mahi
NODE_PREBUILT_TAG       = zone
NODE_PREBUILT_VERSION	:= v0.10.25

include ./tools/mk/Makefile.defs
ifeq ($(shell uname -s),SunOS)
	include ./tools/mk/Makefile.node_prebuilt.defs
else
	include ./tools/mk/Makefile.node.defs
endif
include ./tools/mk/Makefile.smf.defs
RELEASE_TARBALL	:= $(NAME)-pkg-$(STAMP).tar.bz2
RELSTAGEDIR     := /tmp/$(STAMP)

#
# Repo-specific targets
#
.PHONY: all
all: $(SMF_MANIFESTS) | $(NODEUNIT) $(REPO_DEPS) scripts
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
release: all docs $(SMF_MANIFESTS)
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
	ln -s /opt/smartdc/mahi/boot/scripts \
		$(RELSTAGEDIR)/root/opt/smartdc/boot/scripts
	(cd $(RELSTAGEDIR) && $(TAR) -jcf $(TOP)/$(RELEASE_TARBALL) root site)
	@rm -rf $(RELSTAGEDIR)

.PHONY: publish
publish: release
	@if [[ -z "$(BITS_DIR)" ]]; then \
		echo "error: 'BITS_DIR' must be set for 'publish' target"; \
		exit 1; \
	fi
	mkdir -p $(BITS_DIR)/mahi
	cp $(TOP)/$(RELEASE_TARBALL) $(BITS_DIR)/mahi/$(RELEASE_TARBALL)

include ./tools/mk/Makefile.deps
ifeq ($(shell uname -s),SunOS)
	include ./tools/mk/Makefile.node_prebuilt.targ
else
	include ./tools/mk/Makefile.node.targ
endif
include ./tools/mk/Makefile.smf.targ
include ./tools/mk/Makefile.targ
