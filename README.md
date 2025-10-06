# S2BinLib

A static library that helps resolving memory from binary file and map to absolute memory address, targeting source 2 game engine.

This library mainly read data from original binary file instead of from memory, which solves the issue that utilities like patter scan may fail if the memory is modified or hooked.

## Features

- SIMD Optimized pattern scan
- Find vtable by name
- Find vfunc by VA and memory address
- Get all xrefs to a specific VA
- Find string
- Find export
- Find symbol
- Get module base address
- Install trampoline to vtable with enough bytes padded with NOP (for safetyhook to hook empty virtual function)

## Compiling

Prerequisites:
- Rust development environment

Run the following command to compile. 
```
cargo build --release
```

## Linking and building

On windows, if you are seeing linking error like `"__imp_NtReadFile"`, you also need to link `kernel32.dll`.