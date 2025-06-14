__nmk_dir=$(CURDIR)/scripts/nmk/scripts/
export __nmk_dir

#
# No need to try to remake our Makefiles
Makefile: ;
Makefile.%: ;
scripts/%.mak: ;
$(__nmk_dir)%.mk: ;

#
# Import the build engine
include $(__nmk_dir)include.mk
include $(__nmk_dir)macro.mk

ifeq ($(origin HOSTCFLAGS), undefined)
        HOSTCFLAGS := $(CFLAGS) $(USERCFLAGS)
endif

CFLAGS	+=	-DFLUID
CFLAGS	+=	-DDOCKER

CFLAGS	+=	-pthread -libverbs
CFLAGS	+=	-Wno-unused-function
CFLAGS	+=	-Wno-unused-variable
CFLAGS	+=	-Wno-unused-but-set-variable
# 让编译不考虑定义但是未使用的变量
CFLAGS	+=	-Wno-error=unused-but-set-variable
CFLAGS	+=	-Wno-error=declaration-after-statement

#
# Supported Architectures
ifneq ($(filter-out x86 arm aarch64 ppc64 s390 mips loongarch64 riscv64,$(ARCH)),)
        $(error "The architecture $(ARCH) isn't supported")
endif

# The PowerPC 64 bits architecture could be big or little endian.
# They are handled in the same way.
ifeq ($(SUBARCH),ppc64)
        error := $(error ppc64 big endian is not yet supported)
endif

#
# Architecture specific options.
ifeq ($(ARCH),arm)
        ARMV		:= $(shell echo $(SUBARCH) | sed -nr 's/armv([[:digit:]]).*/\1/p; t; i7')

        ifeq ($(ARMV),6)
                ARCHCFLAGS += -march=armv6
        endif

        ifeq ($(ARMV),7)
                ARCHCFLAGS += -march=armv7-a+fp
        endif

        ifeq ($(ARMV),8)
                # Running 'setarch linux32 uname -m' returns armv8l on travis aarch64.
                # This tells CRIU to handle armv8l just as armv7hf. Right now this is
                # only used for compile testing. No further verification of armv8l exists.
                ARCHCFLAGS += -march=armv7-a
                ARMV := 7
        endif

        DEFINES		:= -DCONFIG_ARMV$(ARMV) -DCONFIG_VDSO_32

        PROTOUFIX	:= y
	# For simplicity - compile code in Arm mode without interwork.
	# We could choose Thumb mode as default instead - but a dirty
	# experiment shows that with 90Kb PIEs Thumb code doesn't save
	# even one page. So, let's stick so far to Arm mode as it's more
	# universal around all different Arm variations, until someone
	# will find any use for Thumb mode. -dima
        CFLAGS_PIE	:= -marm
endif

ifeq ($(ARCH),aarch64)
        DEFINES		:= -DCONFIG_AARCH64
endif

ifeq ($(ARCH),ppc64)
        LDARCH		:= powerpc:common64
        DEFINES		:= -DCONFIG_PPC64 -D__SANE_USERSPACE_TYPES__
endif

ifeq ($(ARCH),x86)
        LDARCH		:= i386:x86-64
        DEFINES		:= -DCONFIG_X86_64
endif

ifeq ($(ARCH),mips)
        DEFINES		:= -DCONFIG_MIPS
endif

ifeq ($(ARCH),loongarch64)
        DEFINES		:= -DCONFIG_LOONGARCH64
endif

ifeq ($(ARCH),riscv64)
        DEFINES		:= -DCONFIG_RISCV64
endif

#
# CFLAGS_PIE:
#
# Ensure with -fno-optimize-sibling-calls that we don't create GOT
# (Global Offset Table) relocations with gcc compilers that don't have
# commit "S/390: Fix 64 bit sibcall".
ifeq ($(ARCH),s390)
        ARCH		:= s390
        DEFINES		:= -DCONFIG_S390
        CFLAGS_PIE	:= -fno-optimize-sibling-calls
endif

CFLAGS_PIE		+= -DCR_NOGLIBC
export CFLAGS_PIE

LDARCH ?= $(ARCH)
export LDARCH
export PROTOUFIX DEFINES

#
# Independent options for all tools.
DEFINES			+= -D_FILE_OFFSET_BITS=64
DEFINES			+= -D_LARGEFILE64_SOURCE
DEFINES			+= -D_GNU_SOURCE

WARNINGS		:= -Wall -Wformat-security -Wdeclaration-after-statement -Wstrict-prototypes

# -Wdangling-pointer results in false warning when we add a list element to
# local list head variable. It is false positive because before leaving the
# function we always check that local list head variable is empty, thus
# insuring that pointer to it is not dangling anywhere, but gcc can't
# understand it.
# Note: There is similar problem with kernel list, where this warning is also
# disabled: https://github.com/torvalds/linux/commit/49beadbd47c2
WARNINGS		+= -Wno-dangling-pointer -Wno-unknown-warning-option

CFLAGS-GCOV		:= --coverage -fno-exceptions -fno-inline -fprofile-update=atomic
export CFLAGS-GCOV

ifeq ($(ARCH),mips)
WARNINGS		:= -rdynamic
endif

ifeq ($(ARCH),loongarch64)
WARNINGS		+= -Wno-implicit-function-declaration
endif

ifneq ($(GCOV),)
        LDFLAGS         += -lgcov
        CFLAGS          += $(CFLAGS-GCOV)
endif

ifeq ($(ASAN),1)
	CFLAGS-ASAN	:= -fsanitize=address
	export		CFLAGS-ASAN
	CFLAGS		+= $(CFLAGS-ASAN)
endif

ifneq ($(WERROR),0)
        WARNINGS	+= -Werror
endif

ifeq ($(DEBUG),1)
        DEFINES		+= -DCR_DEBUG
        CFLAGS		+= -O0 -ggdb3
else
        CFLAGS		+= -O2 -g
endif

ifeq ($(GMON),1)
        CFLAGS		+= -pg
        GMONLDOPT	+= -pg
export GMON GMONLDOPT
endif

AFLAGS			+= -D__ASSEMBLY__
CFLAGS			+= $(USERCFLAGS) $(ARCHCFLAGS) $(WARNINGS) $(DEFINES) -iquote include/
HOSTCFLAGS		+= $(WARNINGS) $(DEFINES) -iquote include/
export AFLAGS CFLAGS USERCLFAGS HOSTCFLAGS

# Default target
all: criu lib crit cuda_plugin
.PHONY: all

#
# Version headers.
include Makefile.versions

VERSION_HEADER		:= criu/include/version.h
GITID_FILE		:= .gitid
GITID		:= $(shell if [ -d ".git" ]; then git describe --always; fi)

# Git repository wasn't inited in CRIU folder
ifeq ($(GITID),)
        GITID := 0
else
        GITID_FILE_VALUE := $(shell if [ -f '$(GITID_FILE)' ]; then if [ `cat '$(GITID_FILE)'` = $(GITID) ]; then echo y; fi; fi)
        ifneq ($(GITID_FILE_VALUE),y)
                .PHONY: $(GITID_FILE)
        endif
endif

$(GITID_FILE):
	$(call msg-gen, $@)
	$(Q) echo "$(GITID)" > $(GITID_FILE)

$(VERSION_HEADER): Makefile.versions $(GITID_FILE)
	$(call msg-gen, $@)
	$(Q) echo "/* Autogenerated, do not edit */"			 	 > $@
	$(Q) echo "#ifndef __CR_VERSION_H__"					>> $@
	$(Q) echo "#define __CR_VERSION_H__"					>> $@
	$(Q) echo "#define CRIU_VERSION \"$(CRIU_VERSION)\""			>> $@
	$(Q) echo "#define CRIU_VERSION_MAJOR " $(CRIU_VERSION_MAJOR)		>> $@
	$(Q) echo "#define CRIU_VERSION_MINOR " $(CRIU_VERSION_MINOR)		>> $@
ifneq ($(CRIU_VERSION_SUBLEVEL),)
	$(Q) echo "#define CRIU_VERSION_SUBLEVEL " $(CRIU_VERSION_SUBLEVEL)	>> $@
endif
ifneq ($(CRIU_VERSION_EXTRA),)
	$(Q) echo "#define CRIU_VERSION_EXTRA " $(CRIU_VERSION_EXTRA)		>> $@
endif
	$(Q) echo "#define CRIU_GITID \"$(GITID)\""				>> $@
	$(Q) echo "#endif /* __CR_VERSION_H__ */"				>> $@

criu-deps	+= $(VERSION_HEADER)

#
# Setup proper link for asm headers in common code.
include/common/asm: include/common/arch/$(ARCH)/asm
	$(call msg-gen, $@)
	$(Q) ln -s ./arch/$(ARCH)/asm $@

criu-deps	+= include/common/asm

#
# Configure variables.
export CONFIG_HEADER := include/common/config.h
ifeq ($(filter tags etags cscope clean lint indent fetch-clang-format help mrproper,$(MAKECMDGOALS)),)
include Makefile.config
else
# To clean all files, enable make/build options here
export CONFIG_COMPAT := y
export CONFIG_GNUTLS := y
export CONFIG_HAS_LIBBPF := y
endif

#
# Protobuf images first, they are not depending
# on anything else.
$(eval $(call gen-built-in,images))
criu-deps	+= images/built-in.o

#
# Compel get used by CRIU, build it earlier
include Makefile.compel

#
# Next the socket CR library
#
SOCCR_A := soccr/libsoccr.a
soccr/Makefile: ;
soccr/%: $(CONFIG_HEADER) .FORCE
	$(Q) $(MAKE) $(build)=soccr $@
soccr/built-in.o: $(CONFIG_HEADER) .FORCE
	$(Q) $(MAKE) $(build)=soccr all
$(SOCCR_A): |soccr/built-in.o
criu-deps	+= $(SOCCR_A)

#
# CRIU building done in own directory
# with slightly different rules so we
# can't use nmk engine directly (we
# build syscalls library and such).
#
# But note that we're already included
# the nmk so we can reuse it there.
criu/Makefile: ;
criu/Makefile.packages: ;
criu/Makefile.crtools: ;
criu/%: $(criu-deps) .FORCE
	$(Q) $(MAKE) $(build)=criu $@
criu: $(criu-deps)
	$(Q) $(MAKE) $(build)=criu all
.PHONY: criu

unittest: $(criu-deps)
	$(Q) $(MAKE) $(build)=criu unittest
.PHONY: unittest


#
# Libraries next once criu is ready
# (we might generate headers and such
# when building criu itself).
lib/Makefile: ;
lib/%: criu .FORCE
	$(Q) $(MAKE) $(build)=lib $@
lib: criu
	$(Q) $(MAKE) $(build)=lib all
.PHONY: lib

clean mrproper:
	$(Q) $(MAKE) $(build)=images $@
	$(Q) $(MAKE) $(build)=criu $@
	$(Q) $(MAKE) $(build)=soccr $@
	$(Q) $(MAKE) $(build)=lib $@
	$(Q) $(MAKE) $(build)=crit $@
	$(Q) $(MAKE) $(build)=compel $@
	$(Q) $(MAKE) $(build)=compel/plugins $@
.PHONY: clean mrproper

clean-amdgpu_plugin:
	$(Q) $(MAKE) -C plugins/amdgpu clean
.PHONY: clean-amdgpu_plugin

clean-cuda_plugin:
	$(Q) $(MAKE) -C plugins/cuda clean
.PHONY: clean-cuda_plugin

clean-top:
	$(Q) $(MAKE) -C Documentation clean
	$(Q) $(MAKE) $(build)=test/compel clean
	$(Q) $(RM) .gitid
.PHONY: clean-top

clean: clean-top clean-amdgpu_plugin clean-cuda_plugin

mrproper-top: clean-top clean-amdgpu_plugin clean-cuda_plugin
	$(Q) $(RM) $(CONFIG_HEADER)
	$(Q) $(RM) $(VERSION_HEADER)
	$(Q) $(RM) $(COMPEL_VERSION_HEADER)
	$(Q) $(RM) include/common/asm
	$(Q) $(RM) compel/include/asm
	$(Q) $(RM) cscope.*
	$(Q) $(RM) tags TAGS
.PHONY: mrproper-top

mrproper: mrproper-top

#
# Non-CRIU stuff.
#

docs:
	$(Q) $(MAKE) -s -C Documentation all
.PHONY: docs

zdtm: all
	$(Q) $(MAKE) -C test/zdtm all
.PHONY: zdtm

test: zdtm
	$(Q) $(MAKE) -C test
.PHONY: test

amdgpu_plugin: criu
	$(Q) $(MAKE) -C plugins/amdgpu all
.PHONY: amdgpu_plugin

cuda_plugin: criu
	$(Q) $(MAKE) -C plugins/cuda all
.PHONY: cuda_plugin

crit: lib
	$(Q) $(MAKE) -C crit
.PHONY: crit

#
# Generating tar requires tag matched CRIU_VERSION.
# If not found then simply use GIT's describe with
# "v" prefix stripped.
head-name := $(shell git tag -l v$(CRIU_VERSION))
ifeq ($(head-name),)
        head-name := $(shell git describe 2>/dev/null)
endif
# If no git tag could describe current commit,
# use pre-defined CRIU_VERSION with GITID (if any).
ifeq ($(head-name),)
        ifneq ($(GITID),)
                head-name := $(CRIU_VERSION)-$(GITID)
        else
                head-name := $(CRIU_VERSION)
        endif
endif
tar-name := $(shell echo $(head-name) | sed -e 's/^v//g')
criu-$(tar-name).tar.bz2:
	git archive --format tar --prefix 'criu-$(tar-name)/' $(head-name) | bzip2 > $@
dist tar: criu-$(tar-name).tar.bz2 ;
.PHONY: dist tar

TAGS_FILES_REGEXP := . -name '*.[hcS]' ! -path './.*' \( ! -path './test/*' -o -path './test/zdtm/lib/*' \)
tags:
	$(call msg-gen, $@)
	$(Q) $(RM) tags
	$(Q) $(FIND) $(TAGS_FILES_REGEXP) -print | xargs $(CTAGS) -a
.PHONY: tags

etags:
	$(call msg-gen, $@)
	$(Q) $(RM) TAGS
	$(Q) $(FIND) $(TAGS_FILES_REGEXP) -print | xargs $(ETAGS) -a
.PHONY: etags


cscope:
	$(call msg-gen, $@)
	$(Q) $(FIND) $(TAGS_FILES_REGEXP) ! -type l -print > cscope.files
	$(Q) $(CSCOPE) -bkqu
.PHONY: cscope

gcov:
	$(E) " GCOV"
	$(Q) test -d gcov || mkdir gcov && \
	geninfo --output-filename gcov/criu.info --no-recursion criu/ && \
	cd gcov && \
	genhtml --rc lcov_branch_coverage=1 --output-directory html criu.info
	@echo "Code coverage report is in `pwd`/gcov/html/ directory."
.PHONY: gcov

docker-build:
	$(MAKE) -C scripts/build/ x86_64
.PHONY: docker-build

docker-test:
	docker run --rm --privileged -v /lib/modules:/lib/modules --network=host --cgroupns=host criu-x86_64 \
		./test/zdtm.py run -a --keep-going --ignore-taint
.PHONY: docker-test

help:
	@echo '    Targets:'
	@echo '      all             - Build all [*] targets'
	@echo '    * criu            - Build criu'
	@echo '    * crit            - Build crit'
	@echo '      zdtm            - Build zdtm test-suite'
	@echo '      docs            - Build documentation'
	@echo '      install         - Install CRIU (see INSTALL.md)'
	@echo '      uninstall       - Uninstall CRIU'
	@echo '      dist            - Create a source tarball'
	@echo '      clean           - Clean most, but leave enough to navigate'
	@echo '      mrproper        - Delete all compiled/generated files'
	@echo '      tags            - Generate tags file (ctags)'
	@echo '      etags           - Generate TAGS file (etags)'
	@echo '      cscope          - Generate cscope database'
	@echo '      test            - Run zdtm test-suite'
	@echo '      gcov            - Make code coverage report'
	@echo '      unittest        - Run unit tests'
	@echo '      lint            - Run code linters'
	@echo '      indent          - Indent C code'
	@echo '      amdgpu_plugin   - Make AMD GPU plugin'
	@echo '      cuda_plugin     - Make NVIDIA CUDA plugin'
.PHONY: help

ruff:
	@ruff --version
	ruff check ${RUFF_FLAGS} --config=scripts/ruff.toml \
		test/zdtm.py \
		test/inhfd/*.py \
		test/others/rpc/config_file.py \
		lib/pycriu/images/pb2dict.py \
		lib/pycriu/images/images.py \
		scripts/criu-ns \
		test/others/criu-ns/run.py \
		crit/*.py \
		crit/crit/*.py \
		scripts/uninstall_module.py \
		coredump/ coredump/coredump \
		scripts/github-indent-warnings.py

shellcheck:
	shellcheck --version
	shellcheck scripts/*.sh
	shellcheck scripts/ci/*.sh scripts/ci/apt-install
	shellcheck -x test/others/crit/*.sh
	shellcheck -x test/others/libcriu/*.sh
	shellcheck -x test/others/crit/*.sh test/others/criu-coredump/*.sh
	shellcheck -x test/others/config-file/*.sh
	shellcheck -x test/others/action-script/*.sh

codespell:
	codespell

lint: ruff shellcheck codespell
	# Do not append \n to pr_perror, pr_pwarn or fail
	! git --no-pager grep -E '^\s*\<(pr_perror|pr_pwarn|fail)\>.*\\n"'
	# Do not use %m with pr_* or fail
	! git --no-pager grep -E '^\s*\<(pr_(err|perror|warn|pwarn|debug|info|msg)|fail)\>.*%m'
	# Do not use errno with pr_perror, pr_pwarn or fail
	! git --no-pager grep -E '^\s*\<(pr_perror|pr_pwarn|fail)\>\(".*".*errno'
	# End pr_(err|warn|msg|info|debug) with \n
	! git --no-pager grep -En '^\s*\<pr_(err|warn|msg|info|debug)\>.*);$$' | grep -v '\\n'
	# No EOL whitespace for C files
	! git --no-pager grep -E '\s+$$' \*.c \*.h
.PHONY: lint ruff shellcheck codespell

codecov: SHELL := $(shell which bash)
codecov:
	curl -Os https://uploader.codecov.io/latest/linux/codecov
	chmod +x codecov
	./codecov
.PHONY: codecov

fetch-clang-format: .FORCE
	$(E) ".clang-format"
	$(Q) scripts/fetch-clang-format.sh

BASE ?= "HEAD~1"
OPTS ?= "--quiet"
indent:
	git clang-format --style file --extensions c,h $(OPTS) $(BASE)
.PHONY: indent

include Makefile.install

.DEFAULT_GOAL := all

# Disable implicit rules in _this_ Makefile.
.SUFFIXES:

#
# Optional local include.
-include Makefile.local
