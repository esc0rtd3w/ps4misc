ifndef Ps4Sdk
ifdef ps4sdk
Ps4Sdk := $(ps4sdk)
endif
ifdef PS4SDK
Ps4Sdk := $(PS4SDK)
endif
ifndef Ps4Sdk
$(error Neither PS4SDK, Ps4Sdk nor ps4sdk set)
endif
endif

IncludePath := -I../../library/include -I. -Iinclude
LibraryPath := -L../../library/lib
Libraries := -lelfloader

target := ps4_bin

include $(Ps4Sdk)/make/ps4sdk.mk

#all::

#clang  /home/user/projects/ps4/ps4sdk/crt0.s build/main.c.o build/kmain.c.o  -O3 -Wall -m64 -L../../library/lib  -nostdlib -L/home/user/projects/ps4/ps4sdk/lib -Wl,-Ttext,0x20000 -Wl,-Tdata,0x40000 -lelfloader -lPs4_extension_kernel_execute_dynlib_prepare_dlclose -lPs4_extension_kernel_call_standard -lPs4_common_kernel -lPs4_common_user -lPs4_common_generic -lPs4LibCInternalAdaptive_stub -lPs4LibKernelAdaptive_stub -lSceLibcInternal_stub -lkernel_stub -lps4Kernel_stub -lPs4_base_stub_resolve_minimal -lPs4_base_kernel_dlsym_standard -lPs4_base_assembler_system_call_standard -lPs4_base_kernel_seek_elf_address_standard -lPs4_base_assembler_register_parameter_standard -o bin/user
