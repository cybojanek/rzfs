References
==========

* https://docs.kernel.org/next/rust/quick-start.html
* https://rust-for-linux.com/

Host Setup
==========

```bash
apt-get install       \
    clang-16          \
    gcc-12-plugin-dev \
    libclang-16-dev   \
    libelf-dev        \
    lld-16            \
    llvm-16           \
    pahole
```

Linux Source setup
===================

```bash
git clone https://github.com/Rust-for-Linux/linux.git
pushd linux

# Enable rust.
make LLVM=-16 rustavailable
rustup override set $(scripts/min-tool-version.sh rustc)
rustup component add rust-src

# Initialize configuration.
make LLVM=-16 x86_64_defconfig
make LLVM=-16 kvm_guest.config

# Apply patch from Rust For Linux Workaround below.

# Enable Rust and RZFS
make LLVM=-16 menuconfig

# Compile
make LLVM=-16

# If building out of tree, run this command in the kernel source directory.
make LLVM=-16 modules_prepare

# Then run this command in this directory
make LLVM=-16 KDIR=PATH_TO_LINUX_DIRECTORY
```

Qemu Setup
==========

```bash
zfs create -V 32G zroot/rzfs
mkfs.ext4 /dev/zvol/zroot/rzfs

mkdir rootfs
mount /dev/zvol/zroot/rzfs rootfs/
debootstrap --arch amd64 bookworm rootfs

chroot rootfs

# Enable DHCP
cat << EOF > /etc/network/interfaces.d/enp0s3
auto enp0s3
iface enp0s3 inet dhcp
EOF

# Install ssh.
apt-get install openssh-server
systemctl enable ssh

# Disable root password.
sed -i 's/root:\*:/root::/' /etc/shadow

# Allow empty root ssh.
echo "PermitEmptyPasswords yes" >> /etc/ssh/sshd_config
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

exit
umount rootfs

zfs snapshot zroot/rzfs@installed

qemu-system-x86_64                  \
    --enable-kvm                    \
    -m 2048M                        \
    -net nic -net user,hostfwd=tcp::2222-:22 \
    -nographic                      \
    -kernel arch/x86/boot/bzImage   \
    -hda /dev/zvol/zroot/rzfs \
    -append "root=/dev/sda rw console=ttyS0"
```

Rust For Linux Workaround
=========================

```diff
diff --git a/fs/Kconfig b/fs/Kconfig
index 89fdbefd1075..c98f67025639 100644
--- a/fs/Kconfig
+++ b/fs/Kconfig
@@ -338,6 +338,7 @@ source "fs/sysv/Kconfig"
 source "fs/ufs/Kconfig"
 source "fs/erofs/Kconfig"
 source "fs/vboxsf/Kconfig"
+source "fs/rzfs/Kconfig"
 
 endif # MISC_FILESYSTEMS
 
diff --git a/fs/Makefile b/fs/Makefile
index c09016257f05..01c25b72a831 100644
--- a/fs/Makefile
+++ b/fs/Makefile
@@ -130,3 +130,4 @@ obj-$(CONFIG_EFIVAR_FS)		+= efivarfs/
 obj-$(CONFIG_EROFS_FS)		+= erofs/
 obj-$(CONFIG_VBOXSF_FS)		+= vboxsf/
 obj-$(CONFIG_ZONEFS_FS)		+= zonefs/
+obj-$(CONFIG_RZFS_FS) 		+= rzfs/
diff --git a/fs/rzfs b/fs/rzfs
new file mode 120000
index 000000000000..1f724dd32beb
--- /dev/null
+++ b/fs/rzfs
@@ -0,0 +1 @@
+/storage/files/code/rzfs/module/linux
\ No newline at end of file
diff --git a/rust/Makefile b/rust/Makefile
index 9d2a16cc91cb..936b87c270b2 100644
--- a/rust/Makefile
+++ b/rust/Makefile
@@ -15,7 +15,7 @@ always-$(CONFIG_RUST) += libmacros.so
 no-clean-files += libmacros.so
 
 always-$(CONFIG_RUST) += bindings/bindings_generated.rs bindings/bindings_helpers_generated.rs
-obj-$(CONFIG_RUST) += alloc.o bindings.o kernel.o
+obj-$(CONFIG_RUST) += alloc.o bindings.o kernel.o zfs.o
 always-$(CONFIG_RUST) += exports_alloc_generated.h exports_bindings_generated.h \
     exports_kernel_generated.h
 
@@ -71,6 +71,12 @@ alloc-cfgs = \
     --cfg no_sync \
     --cfg no_thin
 
+zfs-flags := \
+    -Amissing_docs \
+    --cfg 'feature="kernel"' \
+    --cfg no_std \
+    --extern alloc
+
 quiet_cmd_rustdoc = RUSTDOC $(if $(rustdoc_host),H, ) $<
       cmd_rustdoc = \
 	OBJTREE=$(abspath $(objtree)) \
@@ -461,10 +467,14 @@ $(obj)/uapi.o: $(src)/uapi/lib.rs \
     $(obj)/uapi/uapi_generated.rs FORCE
 	$(call if_changed_dep,rustc_library)
 
+$(obj)/zfs.o: private rustc_target_flags = $(zfs-flags)
+$(obj)/zfs.o: $(src)/zfs/lib.rs $(obj)/compiler_builtins.o FORCE
+	$(call if_changed_dep,rustc_library)
+
 $(obj)/kernel.o: private rustc_target_flags = --extern alloc \
-    --extern build_error --extern macros --extern bindings --extern uapi
+    --extern build_error --extern macros --extern bindings --extern uapi --extern zfs
 $(obj)/kernel.o: $(src)/kernel/lib.rs $(obj)/alloc.o $(obj)/build_error.o \
-    $(obj)/libmacros.so $(obj)/bindings.o $(obj)/uapi.o FORCE
+    $(obj)/libmacros.so $(obj)/bindings.o $(obj)/uapi.o $(obj)/zfs.o FORCE
 	$(call if_changed_dep,rustc_library)
 
 endif # CONFIG_RUST
diff --git a/rust/zfs b/rust/zfs
new file mode 120000
index 000000000000..20eefafd14c0
--- /dev/null
+++ b/rust/zfs
@@ -0,0 +1 @@
+/storage/files/code/rzfs/lib/src
\ No newline at end of file
diff --git a/scripts/Makefile.build b/scripts/Makefile.build
index dae447a1ad30..4c3c02d4e4c5 100644
--- a/scripts/Makefile.build
+++ b/scripts/Makefile.build
@@ -272,7 +272,7 @@ rust_common_cmd = \
 	-Zallow-features=$(rust_allowed_features) \
 	-Zcrate-attr=no_std \
 	-Zcrate-attr='feature($(rust_allowed_features))' \
-	--extern alloc --extern kernel \
+	--extern alloc --extern kernel --extern zfs \
 	--crate-type rlib -L $(objtree)/rust/ \
 	--crate-name $(basename $(notdir $@)) \
 	--sysroot=/dev/null \
```