# SPDX-License-Identifier: GPL-2.0 OR MIT

ifneq ($(KERNELRELEASE),)

include Kbuild

else

KDIR ?= /lib/modules/`uname -r`/build
LLVM ?= 1

default:
	$(MAKE) LLVM=$(LLVM) -C $(KDIR) M=$$PWD

clean:
	$(MAKE) LLVM=$(LLVM) -C $(KDIR) M=$$PWD clean

endif
