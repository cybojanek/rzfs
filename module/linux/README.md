    bison             \
    clang-18          \
    flex              \
    gcc-14-plugin-dev \
    libclang-18-dev   \
    lld-18            \
    llvm-18
make LLVM=-18 rustavailable
cargo install --locked --version $(scripts/min-tool-version.sh bindgen) bindgen-cli

make LLVM=-18 x86_64_defconfig
make LLVM=-18 kvm_guest.config
make LLVM=-18 menuconfig
make LLVM=-18
make LLVM=-18 modules_prepare
make LLVM=-18 KDIR=PATH_TO_LINUX_DIRECTORY