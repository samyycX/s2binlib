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

## Example

Example code:

```cpp
#include <s2binlib.h>

int main() {

  // Initialize the lib, the game type is csgo for cs2
  s2binlib_initialize("/home/csgo/cs2server/game", "csgo");

  // If you are using metamod, relocate these modules because its modified
	GET_V_IFACE_ANY(GetServerFactory, g_pSource2Server, ISource2Server, SOURCE2SERVER_INTERFACE_VERSION);
	GET_V_IFACE_CURRENT(GetEngineFactory, g_pEngineServer2, IVEngineServer2, SOURCE2ENGINETOSERVER_INTERFACE_VERSION);
  s2binlib_set_module_base_from_pointer("server", g_pSource2Server);
  s2binlib_set_module_base_from_pointer("engine2", g_pEngineServer2);

  // pattern scan
  void* result;
  s2binlib_pattern_scan("server", "01 02 03 AA BB CC ? ? DD", &result);

  // free after use, this will only release the file bytes in memory, dumped xref and other information will still be cached
  s2binlib_unload_all_binaries();

}