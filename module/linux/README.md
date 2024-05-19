References
==========

* https://docs.kernel.org/next/rust/quick-start.html
* https://rust-for-linux.com/

Host Setup
==========

```bash
apt-get install       \
    bison             \
    clang-18          \
    flex              \
    gcc-14-plugin-dev \
    libclang-18-dev   \
    libelf-dev        \
    lld-18            \
    llvm-18
```

Linux Source setup
===================

```bash
git clone https://github.com/Rust-for-Linux/linux.git
pushd linux

# Enable rust.
make LLVM=-18 rustavailable
rustup override set $(scripts/min-tool-version.sh rustc)
rustup component add rust-src

cargo install --locked --version $(scripts/min-tool-version.sh bindgen) bindgen-cli

# Initialize configuration.
make LLVM=-18 x86_64_defconfig
make LLVM=-18 kvm_guest.config

# Apply patch from Rust For Linux Workaround below.

# Enable Rust and RZFS
make LLVM=-18 menuconfig

# Compile
make LLVM=-18

# If building out of tree, run this command in the kernel source directory.
make LLVM=-18 modules_prepare

# Then run this command in this directory
make LLVM=-18 KDIR=PATH_TO_LINUX_DIRECTORY
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
diff --git a/scripts/Makefile.build b/scripts/Makefile.build
index 367cfeea74c5..bcfe1cd1a907 100644
--- a/scripts/Makefile.build
+++ b/scripts/Makefile.build
@@ -277,4 +277,6 @@ rust_common_cmd = \
        --crate-type rlib -L $(objtree)/rust/ \
        --crate-name $(basename $(notdir $@)) \
        --sysroot=/dev/null \
+       --cfg feature=\"allocator_api\" \
+       --cfg feature=\"kernel_linux\" \
        --out-dir $(dir $@) --emit=dep-info=$(depfile)
```