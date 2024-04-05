# SPDX-License-Identifier: GPL-2.0 OR MIT

ifneq ($(KERNELRELEASE),)

include Kbuild

else

KDIR ?= /lib/modules/`uname -r`/build
LLVM ?= 1
CONFIG_RZFS_FS ?= m

RZFS_SYMLINKS = checksum checksum.rs phys phys.rs

default:
	@$(foreach LINK,$(RZFS_SYMLINKS),\
		ln -sf ../../lib/src/$(LINK) ; \
	)

	@# NOTE: Passing CONFIG_RZFS_FS allows for the re-use of Kbuild for both
	@#       in-tree and out-of-tree builds.
	$(MAKE) LLVM=$(LLVM) -C $(KDIR) M=$$PWD CONFIG_RZFS_FS=$(CONFIG_RZFS_FS)

clean:
	$(MAKE) LLVM=$(LLVM) -C $(KDIR) M=$$PWD clean
	rm -f $(RZFS_SYMLINKS)

endif
