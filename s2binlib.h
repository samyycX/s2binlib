/************************************************************************************
 *  S2BinLib - A static library that helps resolving memory from binary file
 *  and map to absolute memory address, targeting source 2 game engine.
 *  Copyright (C) 2025  samyyc
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 ***********************************************************************************/

#ifndef S2BINLIB_H
#define S2BINLIB_H

#ifdef _WIN32
#define S2BINLIB_API
#else
#define S2BINLIB_API __attribute__((visibility("hidden")))
#endif

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

  /**
   * Initialize the global S2BinLib instance
   *
   * The operating system is automatically detected at runtime.
   * Can be called multiple times to reinitialize with different parameters.
   *
   * @param game_path Path to the game directory (null-terminated C string)
   * @param game_type Game type identifier (null-terminated C string)
   *
   * @return 0 on success
   *         -2 if invalid parameters or unsupported OS
   *         -5 if internal error
   *
   * @example
   *     int result = s2binlib_initialize("C:/Games/MyGame", "csgo");
   *     if (result != 0) {
   *         // Handle error
   *     }
   */
  S2BINLIB_API int s2binlib_initialize(const char *game_path, const char *game_type);

  /**
   * Initialize the global S2BinLib instance with a specific operating system
   *
   * Can be called multiple times to reinitialize with different parameters.
   *
   * @param game_path Path to the game directory (null-terminated C string)
   * @param game_type Game type identifier (null-terminated C string)
   * @param os Operating system identifier ("windows" or "linux") (null-terminated C string)
   *
   * @return 0 on success
   *         -2 if invalid parameters
   *         -5 if internal error
   *
   * @example
   *     int result = s2binlib_initialize_with_os("C:/Games/MyGame", "csgo", "windows");
   *     if (result != 0) {
   *         // Handle error
   *     }
   */
  S2BINLIB_API int s2binlib_initialize_with_os(const char *game_path, const char *game_type, const char *os);

  /**
   * Scan for a pattern in the specified binary
   *
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary to scan (e.g., "server", "client") (null-terminated C string)
   * @param pattern Pattern string with wildcards (e.g., "48 89 5C 24 ? 48 89 74 24 ?") (null-terminated C string)
   * @param result Pointer to store the resulting runtime memory address
   *
   * @return 0 on success (address written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to load binary
   *         -4 if pattern not found
   *         -5 if internal error
   *
   * @example
   *     void* address;
   *     int result = s2binlib_pattern_scan("server", "48 89 5C 24 ? 48 89 74", &address);
   *     if (result == 0) {
   *         printf("Found at: %p\n", address);
   *     }
   */
  S2BINLIB_API int s2binlib_pattern_scan(const char *binary_name, const char *pattern, void **result);

  /**
   * Pattern scan and return the relative virtual address (RVA)
   *
   * Scans for a byte pattern in the specified binary and returns the relative virtual address (RVA).
   * Pattern format: hex bytes separated by spaces, use '?' for wildcards
   * Example: "48 89 5C 24 ? 48 89 74 24 ?"
   *
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary to scan (null-terminated C string)
   * @param pattern Pattern string with wildcards (null-terminated C string)
   * @param result Pointer to store the resulting relative virtual address (RVA)
   *
   * @return 0 on success (address written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to load binary
   *         -4 if pattern not found
   *         -5 if internal error
   *
   * @example
   *     void* rva;
   *     int result = s2binlib_pattern_scan_rva("server", "48 89 5C 24 ?", &rva);
   *     if (result == 0) {
   *         printf("Pattern found at RVA: %p\n", rva);
   *     }
   */
  S2BINLIB_API int s2binlib_pattern_scan_rva(const char *binary_name, const char *pattern, void **result);

  /**
   * Callback function type for pattern_scan_all functions
   *
   * @param index The index of the current match (0-based)
   * @param address The found address (RVA or memory address depending on the function)
   * @param user_data User-provided data pointer
   * @return true to stop searching (found what you need), false to continue searching
   */
  typedef bool (*s2binlib_pattern_scan_callback)(size_t index, void *address, void *user_data);

  /**
   * Find all occurrences of a pattern in a binary and return their relative virtual addresses (RVAs)
   *
   * Scans the binary for all occurrences of the specified byte pattern and calls
   * the callback function for each match found. The callback receives relative virtual addresses (RVA).
   *
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary to scan
   * @param pattern Byte pattern with wildcards (e.g., "48 89 5C 24 ? 48 89 74")
   * @param callback Function pointer that will be called for each match
   * @param user_data User-provided pointer passed to each callback invocation
   *
   * @return 0 on success (at least one match found)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to load binary
   *         -4 if pattern not found
   *         -5 if internal error
   *
   * @note The callback should return true to stop searching, false to continue
   *
   * @example
   *     bool my_callback(size_t index, void* address, void* user_data) {
   *         printf("Match #%zu found at RVA: %p\n", index, address);
   *         int* count = (int*)user_data;
   *         (*count)++;
   *         return false; // Continue searching
   *     }
   *
   *     int count = 0;
   *     int result = s2binlib_pattern_scan_all_rva("server", "48 89 5C 24 ?", my_callback, &count);
   *     if (result == 0) {
   *         printf("Found %d matches\n", count);
   *     }
   */
  S2BINLIB_API int s2binlib_pattern_scan_all_rva(const char *binary_name, const char *pattern,
                                                 s2binlib_pattern_scan_callback callback, void *user_data);

  /**
   * Find all occurrences of a pattern in a binary and return their memory addresses
   *
   * Scans the binary for all occurrences of the specified byte pattern and calls
   * the callback function for each match found. The callback receives memory addresses
   * (adjusted with module base address).
   *
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary to scan
   * @param pattern Byte pattern with wildcards (e.g., "48 89 5C 24 ? 48 89 74")
   * @param callback Function pointer that will be called for each match
   * @param user_data User-provided pointer passed to each callback invocation
   *
   * @return 0 on success (at least one match found)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to load binary
   *         -4 if pattern not found
   *         -5 if internal error
   *
   * @note The callback should return true to stop searching, false to continue
   *
   * @example
   *     bool my_callback(size_t index, void* address, void* user_data) {
   *         printf("Match #%zu found at memory address: %p\n", index, address);
   *         int* count = (int*)user_data;
   *         (*count)++;
   *         return false; // Continue searching
   *     }
   *
   *     int count = 0;
   *     int result = s2binlib_pattern_scan_all("server", "48 89 5C 24 ?", my_callback, &count);
   *     if (result == 0) {
   *         printf("Found %d matches\n", count);
   *     }
   */
  S2BINLIB_API int s2binlib_pattern_scan_all(const char *binary_name, const char *pattern,
                                             s2binlib_pattern_scan_callback callback, void *user_data);

  /**
   * Find a vtable by class name in the specified binary
   *
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary to search (e.g., "server", "client") (null-terminated C string)
   * @param vtable_name Class name to search for (null-terminated C string)
   * @param result Pointer to store the resulting vtable runtime memory address
   *
   * @return 0 on success (address written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to load binary
   *         -4 if vtable not found
   *         -5 if internal error
   *
   * @example
   *     void* vtable_addr;
   *     int result = s2binlib_find_vtable("server", "CBaseEntity", &vtable_addr);
   *     if (result == 0) {
   *         printf("VTable at: %p\n", vtable_addr);
   *     }
   */
  S2BINLIB_API int s2binlib_find_vtable(const char *binary_name, const char *vtable_name, void **result);

  /**
   * Find a vtable by class name and return its relative virtual address (RVA)
   *
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary to search (null-terminated C string)
   * @param vtable_name Class name to search for (null-terminated C string)
   * @param result Pointer to store the resulting vtable relative virtual address (RVA)
   *
   * @return 0 on success (address written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to load binary
   *         -4 if vtable not found
   *         -5 if internal error
   *
   * @example
   *     void* vtable_rva;
   *     int result = s2binlib_find_vtable_rva("server", "CBaseEntity", &vtable_rva);
   *     if (result == 0) {
   *         printf("VTable RVA: %p\n", vtable_rva);
   *     }
   */
  S2BINLIB_API int s2binlib_find_vtable_rva(const char *binary_name, const char *vtable_name, void **result);

  /**
   * Find a vtable by mangled name and return its relative virtual address (RVA)
   *
   * Searches for a vtable using the mangled/decorated RTTI name directly.
   * Unlike s2binlib_find_vtable_rva which auto-decorates the name, this function
   * uses the provided name as-is.
   *
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary to search (null-terminated C string)
   * @param vtable_name Mangled RTTI name to search for (null-terminated C string)
   *                    - Windows: ".?AVClassName@@" format
   *                    - Linux: "{length}ClassName" format
   * @param result Pointer to store the resulting vtable relative virtual address (RVA)
   *
   * @return 0 on success (address written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to load binary
   *         -4 if vtable not found
   *         -5 if internal error
   *
   * @example
   *     // Windows mangled name example
   *     void* vtable_rva;
   *     int result = s2binlib_find_vtable_mangled_rva("server", ".?AVCBaseEntity@@", &vtable_rva);
   *     if (result == 0) {
   *         printf("VTable RVA: %p\n", vtable_rva);
   *     }
   *
   *     // Linux mangled name example
   *     int result = s2binlib_find_vtable_mangled_rva("server", "11CBaseEntity", &vtable_rva);
   */
  S2BINLIB_API int s2binlib_find_vtable_mangled_rva(const char *binary_name, const char *vtable_name, void **result);

  /**
   * Find a vtable by mangled name and return its runtime memory address
   *
   * Searches for a vtable using the mangled/decorated RTTI name directly and
   * returns its runtime memory address.
   *
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary to search (null-terminated C string)
   * @param vtable_name Mangled RTTI name to search for (null-terminated C string)
   *                    - Windows: ".?AVClassName@@" format
   *                    - Linux: "{length}ClassName" format
   * @param result Pointer to store the resulting vtable memory address
   *
   * @return 0 on success (address written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to load binary
   *         -4 if vtable not found
   *         -5 if internal error
   *
   * @example
   *     void* vtable_addr;
   *     int result = s2binlib_find_vtable_mangled("server", ".?AVCBaseEntity@@", &vtable_addr);
   *     if (result == 0) {
   *         printf("VTable at: %p\n", vtable_addr);
   *     }
   */
  S2BINLIB_API int s2binlib_find_vtable_mangled(const char *binary_name, const char *vtable_name, void **result);

  /**
   * Find a nested vtable (2 levels) by class names and return its relative virtual address (RVA)
   *
   * Searches for a vtable of a nested class (e.g., Class1::Class2).
   * The function automatically decorates the names according to the platform's
   * RTTI name mangling scheme:
   * - Windows: ".?AVClass2@Class1@@"
   * - Linux: "N{len1}Class1{len2}Class2E"
   *
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary to search (null-terminated C string)
   * @param class1_name Outer class name (null-terminated C string)
   * @param class2_name Inner/nested class name (null-terminated C string)
   * @param result Pointer to store the resulting vtable relative virtual address (RVA)
   *
   * @return 0 on success (address written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to load binary
   *         -4 if vtable not found
   *         -5 if internal error
   *
   * @example
   *     void* vtable_rva;
   *     int result = s2binlib_find_vtable_nested_2_rva("server", "CEntitySystem", "CEntitySubsystem", &vtable_rva);
   *     if (result == 0) {
   *         printf("Nested VTable RVA: %p\n", vtable_rva);
   *     }
   */
  S2BINLIB_API int s2binlib_find_vtable_nested_2_rva(const char *binary_name, const char *class1_name, const char *class2_name, void **result);

  /**
   * Find a nested vtable (2 levels) by class names and return its runtime memory address
   *
   * Searches for a vtable of a nested class (e.g., Class1::Class2) and returns
   * its runtime memory address.
   *
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary to search (null-terminated C string)
   * @param class1_name Outer class name (null-terminated C string)
   * @param class2_name Inner/nested class name (null-terminated C string)
   * @param result Pointer to store the resulting vtable memory address
   *
   * @return 0 on success (address written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to load binary
   *         -4 if vtable not found
   *         -5 if internal error
   *
   * @example
   *     void* vtable_addr;
   *     int result = s2binlib_find_vtable_nested_2("server", "CEntitySystem", "CEntitySubsystem", &vtable_addr);
   *     if (result == 0) {
   *         printf("Nested VTable at: %p\n", vtable_addr);
   *     }
   */
  S2BINLIB_API int s2binlib_find_vtable_nested_2(const char *binary_name, const char *class1_name, const char *class2_name, void **result);

  /**
   * Get the number of virtual functions in a vtable
   *
   * Returns the count of virtual functions (vfuncs) in the specified vtable.
   * This counts valid function pointers in the vtable until it encounters a null
   * or invalid pointer.
   *
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary to search (e.g., "server", "client")
   * @param vtable_name Name of the vtable/class to search for
   * @param result Pointer to store the resulting count of virtual functions
   *
   * @return 0 - Success, result contains the vfunc count
   *         -1 - S2BinLib not initialized
   *         -2 - Invalid input (null pointer or invalid UTF-8)
   *         -4 - Operation failed (vtable not found or other error)
   *         -5 - Failed to acquire lock
   *
   * @example
   *     size_t vfunc_count;
   *     int result = s2binlib_get_vtable_vfunc_count("server", "CBaseEntity", &vfunc_count);
   *     if (result == 0) {
   *         printf("VTable has %zu virtual functions\n", vfunc_count);
   *     }
   */
  S2BINLIB_API int s2binlib_get_vtable_vfunc_count(const char *binary_name, const char *vtable_name, size_t *result);

  /**
   * Get the number of virtual functions in a vtable by relative virtual address (RVA)
   *
   * Returns the count of virtual functions (vfuncs) in a vtable at the specified
   * relative virtual address. This counts valid function pointers in the vtable until it
   * encounters a null or invalid pointer.
   *
   * Unlike s2binlib_get_vtable_vfunc_count, this function takes a relative virtual address
   * directly instead of looking up the vtable by name.
   *
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary (e.g., "server", "client")
   * @param vtable_rva Relative virtual address of the vtable
   * @param result Pointer to store the resulting count of virtual functions
   *
   * @return 0 - Success, result contains the vfunc count
   *         -1 - S2BinLib not initialized
   *         -2 - Invalid input (null pointer or invalid UTF-8)
   *         -4 - Operation failed (invalid address or other error)
   *         -5 - Failed to acquire lock
   *
   * @example
   *     void* vtable_rva;
   *     // First get the vtable relative virtual address
   *     s2binlib_find_vtable_rva("server", "CBaseEntity", &vtable_rva);
   *
   *     // Then count its virtual functions
   *     size_t vfunc_count;
   *     int result = s2binlib_get_vtable_vfunc_count_by_rva("server", (uint64_t)vtable_rva, &vfunc_count);
   *     if (result == 0) {
   *         printf("VTable has %zu virtual functions\n", vfunc_count);
   *     }
   */
  S2BINLIB_API int s2binlib_get_vtable_vfunc_count_by_rva(const char *binary_name, uint64_t vtable_rva, size_t *result);

  /**
   * Find a symbol by name in the specified binary
   *
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary to search (e.g., "server", "client") (null-terminated C string)
   * @param symbol_name Symbol name to search for (null-terminated C string)
   * @param result Pointer to store the resulting symbol runtime memory address
   *
   * @return 0 on success (address written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if symbol not found
   *         -5 if internal error
   *
   * @example
   *     void* symbol_addr;
   *     int result = s2binlib_find_symbol("server", "CreateInterface", &symbol_addr);
   *     if (result == 0) {
   *         printf("Symbol at: %p\n", symbol_addr);
   *     }
   */
  S2BINLIB_API int s2binlib_find_symbol(const char *binary_name, const char *symbol_name, void **result);

  /**
   * Find a symbol by name and return its relative virtual address (RVA)
   *
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary to search (null-terminated C string)
   * @param symbol_name Symbol name to search for (null-terminated C string)
   * @param result Pointer to store the resulting relative virtual address (RVA)
   *
   * @return 0 on success (address written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if symbol not found
   *         -5 if internal error
   *
   * @example
   *     void* symbol_rva;
   *     int result = s2binlib_find_symbol_rva("server", "_Z13CreateInterfacev", &symbol_rva);
   *     if (result == 0) {
   *         printf("Symbol RVA: %p\n", symbol_rva);
   *     }
   */
  S2BINLIB_API int s2binlib_find_symbol_rva(const char *binary_name, const char *symbol_name, void **result);

  /**
   * Manually set the base address for a module from a pointer
   *
   * This allows overriding the automatic base address detection for a module.
   * The function will automatically detect the module base from the provided pointer.
   *
   * @param binary_name Name of the binary (e.g., "server", "client") (null-terminated C string)
   * @param pointer The pointer inside the specified module
   *
   * @return 0 on success
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -5 if internal error
   *
   * @example
   *     int result = s2binlib_set_module_base_from_pointer("server", 0x140001000);
   *     if (result == 0) {
   *         printf("Server base address set successfully\n");
   *     }
   */
  S2BINLIB_API int s2binlib_set_module_base_from_pointer(const char *binary_name, void *pointer);

  /**
   * Clear manually set base address for a module
   *
   * After calling this, the module will use automatic base address detection again.
   *
   * @param binary_name Name of the binary (e.g., "server", "client") (null-terminated C string)
   *
   * @return 0 on success
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -5 if internal error
   *
   * @example
   *     int result = s2binlib_clear_module_base_address("server");
   *     if (result == 0) {
   *         printf("Server base address cleared\n");
   *     }
   */
  S2BINLIB_API int s2binlib_clear_module_base_address(const char *binary_name);

  /**
   * Set a custom binary path for a specific binary and operating system
   *
   * This allows overriding the default binary path resolution for a specific binary.
   * You can specify different paths for Windows and Linux builds.
   *
   * @param binary_name Name of the binary (e.g., "server", "client") (null-terminated C string)
   * @param path The custom file path to the binary (null-terminated C string)
   * @param os Operating system identifier ("windows" or "linux") (null-terminated C string)
   *
   * @return 0 on success
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -4 if unsupported OS specified
   *         -5 if internal error
   *
   * @example
   *     int result = s2binlib_set_custom_binary_path("server", "/custom/path/server.dll", "windows");
   *     if (result == 0) {
   *         printf("Custom binary path set successfully\n");
   *     }
   */
  S2BINLIB_API int s2binlib_set_custom_binary_path(const char *binary_name, const char *path, const char *os);

  /**
   * Get the module base address
   *
   * Returns the base address of a loaded module. If a manual base address was set,
   * that value will be returned. Otherwise, attempts to find the base address from
   * the running process.
   *
   * @param binary_name Name of the binary (e.g., "server", "client") (null-terminated C string)
   * @param result Pointer to store the resulting base address
   *
   * @return 0 on success (address written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if module not found or not loaded
   *         -5 if internal error
   *
   * @example
   *     void* base_addr;
   *     int result = s2binlib_get_module_base_address("server", &base_addr);
   *     if (result == 0) {
   *         printf("Module base: %p\n", base_addr);
   *     }
   */
  S2BINLIB_API int s2binlib_get_module_base_address(const char *binary_name, void **result);

  /**
   * Check if a binary is already loaded
   *
   * @param binary_name Name of the binary to check (null-terminated C string)
   *
   * @return 1 if loaded
   *         0 if not loaded
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -5 if internal error
   *
   * @example
   *     int loaded = s2binlib_is_binary_loaded("server");
   *     if (loaded == 1) {
   *         printf("Server is loaded\n");
   *     }
   */
  S2BINLIB_API int s2binlib_is_binary_loaded(const char *binary_name);

  /**
   * Load a binary into memory
   *
   * Loads the specified binary file into memory for analysis.
   * If the binary is already loaded, this function does nothing.
   *
   * @param binary_name Name of the binary to load (null-terminated C string)
   *
   * @return 0 on success
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -5 if internal error
   *
   * @example
   *     int result = s2binlib_load_binary("server");
   *     if (result == 0) {
   *         printf("Server loaded successfully\n");
   *     }
   */
  S2BINLIB_API int s2binlib_load_binary(const char *binary_name);

  /**
   * Get the full path to a binary file
   *
   * Returns the full filesystem path where the binary file is expected to be located.
   *
   * @param binary_name Name of the binary (null-terminated C string)
   * @param buffer Buffer to store the path string
   * @param buffer_size Size of the buffer
   *
   * @return 0 on success (path written to buffer)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if buffer too small
   *         -5 if internal error
   *
   * @example
   *     char path[512];
   *     int result = s2binlib_get_binary_path("server", path, sizeof(path));
   *     if (result == 0) {
   *         printf("Binary path: %s\n", path);
   *     }
   */
  S2BINLIB_API int s2binlib_get_binary_path(const char *binary_name, char *buffer, size_t buffer_size);

  /**
   * Find an exported symbol by name and return its relative virtual address (RVA)
   *
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary to search (null-terminated C string)
   * @param export_name Export name to search for (null-terminated C string)
   * @param result Pointer to store the resulting relative virtual address (RVA)
   *
   * @return 0 on success (address written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to load binary
   *         -4 if export not found
   *         -5 if internal error
   *
   * @example
   *     void* export_rva;
   *     int result = s2binlib_find_export_rva("server", "CreateInterface", &export_rva);
   *     if (result == 0) {
   *         printf("Export RVA: %p\n", export_rva);
   *     }
   */
  S2BINLIB_API int s2binlib_find_export_rva(const char *binary_name, const char *export_name, void **result);

  /**
   * Find an exported symbol by name and return its runtime memory address
   *
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary to search (null-terminated C string)
   * @param export_name Export name to search for (null-terminated C string)
   * @param result Pointer to store the resulting memory address
   *
   * @return 0 on success (address written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to load binary or get base address
   *         -4 if export not found
   *         -5 if internal error
   *
   * @example
   *     void* export_addr;
   *     int result = s2binlib_find_export("server", "CreateInterface", &export_addr);
   *     if (result == 0) {
   *         printf("Export at: %p\n", export_addr);
   *     }
   */
  S2BINLIB_API int s2binlib_find_export(const char *binary_name, const char *export_name, void **result);

  /**
   * Read bytes from binary at a file offset
   *
   * Reads raw bytes from the binary file at the specified file offset into the provided buffer.
   *
   * @param binary_name Name of the binary to read from (null-terminated C string)
   * @param file_offset File offset to read from
   * @param buffer Buffer to store the read bytes
   * @param buffer_size Size of the buffer (number of bytes to read)
   *
   * @return 0 on success (bytes written to buffer)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to read
   *         -5 if internal error
   *
   * @example
   *     uint8_t buffer[16];
   *     int result = s2binlib_read_by_file_offset("server", 0x1000, buffer, sizeof(buffer));
   *     if (result == 0) {
   *         // Use buffer
   *     }
   */
  S2BINLIB_API int s2binlib_read_by_file_offset(const char *binary_name, uint64_t file_offset, uint8_t *buffer, size_t buffer_size);

  /**
   * Read bytes from binary at a relative virtual address (RVA)
   *
   * Reads raw bytes from the binary at the specified relative virtual address (RVA) into the provided buffer.
   *
   * @param binary_name Name of the binary to read from (null-terminated C string)
   * @param rva Relative virtual address to read from
   * @param buffer Buffer to store the read bytes
   * @param buffer_size Size of the buffer (number of bytes to read)
   *
   * @return 0 on success (bytes written to buffer)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to read
   *         -5 if internal error
   *
   * @example
   *     uint8_t buffer[16];
   *     int result = s2binlib_read_by_rva("server", 0x140001000, buffer, sizeof(buffer));
   *     if (result == 0) {
   *         // Use buffer
   *     }
   */
  S2BINLIB_API int s2binlib_read_by_rva(const char *binary_name, uint64_t rva, uint8_t *buffer, size_t buffer_size);

  /**
   * Read bytes from binary at a runtime memory address
   *
   * Reads raw bytes from the binary at the specified runtime memory address into the provided buffer.
   *
   * @param binary_name Name of the binary to read from (null-terminated C string)
   * @param mem_address Runtime memory address to read from
   * @param buffer Buffer to store the read bytes
   * @param buffer_size Size of the buffer (number of bytes to read)
   *
   * @return 0 on success (bytes written to buffer)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to read
   *         -5 if internal error
   *
   * @example
   *     uint8_t buffer[16];
   *     int result = s2binlib_read_by_mem_address("server", mem_addr, buffer, sizeof(buffer));
   *     if (result == 0) {
   *         // Use buffer
   *     }
   */
  S2BINLIB_API int s2binlib_read_by_mem_address(const char *binary_name, uint64_t mem_address, uint8_t *buffer, size_t buffer_size);

  /**
   * Find a virtual function by vtable name and index, return relative virtual address (RVA)
   *
   * Locates a vtable by its class name, then reads the virtual function pointer
   * at the specified index.
   *
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary to search (null-terminated C string)
   * @param vtable_name Class name whose vtable to search for (null-terminated C string)
   * @param vfunc_index Index of the virtual function in the vtable (0-based)
   * @param result Pointer to store the resulting relative virtual address (RVA)
   *
   * @return 0 on success (address written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to load binary
   *         -4 if vtable or vfunc not found
   *         -5 if internal error
   *
   * @example
   *     void* vfunc_rva;
   *     int result = s2binlib_find_vfunc_by_vtbname_rva("server", "CBaseEntity", 5, &vfunc_rva);
   *     if (result == 0) {
   *         printf("VFunc RVA: %p\n", vfunc_rva);
   *     }
   */
  S2BINLIB_API int s2binlib_find_vfunc_by_vtbname_rva(const char *binary_name, const char *vtable_name, size_t vfunc_index, void **result);

  /**
   * Find a virtual function by vtable name and index, return runtime address
   *
   * Locates a vtable by its class name, then reads the virtual function pointer
   * at the specified index and returns its runtime memory address.
   *
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary to search (null-terminated C string)
   * @param vtable_name Class name whose vtable to search for (null-terminated C string)
   * @param vfunc_index Index of the virtual function in the vtable (0-based)
   * @param result Pointer to store the resulting memory address
   *
   * @return 0 on success (address written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to load binary or get base address
   *         -4 if vtable or vfunc not found
   *         -5 if internal error
   *
   * @example
   *     void* vfunc_addr;
   *     int result = s2binlib_find_vfunc_by_vtbname("server", "CBaseEntity", 5, &vfunc_addr);
   *     if (result == 0) {
   *         printf("VFunc at: %p\n", vfunc_addr);
   *     }
   */
  S2BINLIB_API int s2binlib_find_vfunc_by_vtbname(const char *binary_name, const char *vtable_name, size_t vfunc_index, void **result);

  /**
   * Find a virtual function by vtable pointer and index, return relative virtual address (RVA)
   *
   * Given a runtime pointer to a vtable, reads the virtual function pointer
   * at the specified index. The appropriate binary is automatically detected.
   *
   * @param vtable_ptr Runtime pointer to the vtable
   * @param vfunc_index Index of the virtual function in the vtable (0-based)
   * @param result Pointer to store the resulting relative virtual address (RVA)
   *
   * @return 0 on success (address written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if binary not found for pointer
   *         -4 if failed to read vfunc
   *         -5 if internal error
   *
   * @example
   *     void* vfunc_rva;
   *     int result = s2binlib_find_vfunc_by_vtbptr_rva(vtable_ptr, 5, &vfunc_rva);
   *     if (result == 0) {
   *         printf("VFunc RVA: %p\n", vfunc_rva);
   *     }
   */
  S2BINLIB_API int s2binlib_find_vfunc_by_vtbptr_rva(void *vtable_ptr, size_t vfunc_index, void **result);

  /**
   * Find a virtual function by vtable pointer and index, return runtime address
   *
   * Given a runtime pointer to a vtable, reads the virtual function pointer
   * at the specified index. The appropriate binary is automatically detected.
   *
   * @param vtable_ptr Runtime pointer to the vtable
   * @param vfunc_index Index of the virtual function in the vtable (0-based)
   * @param result Pointer to store the resulting memory address
   *
   * @return 0 on success (address written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if binary not found for pointer
   *         -4 if failed to read vfunc
   *         -5 if internal error
   *
   * @example
   *     void* vfunc_addr;
   *     int result = s2binlib_find_vfunc_by_vtbptr(vtable_ptr, 5, &vfunc_addr);
   *     if (result == 0) {
   *         printf("VFunc at: %p\n", vfunc_addr);
   *     }
   */
  S2BINLIB_API int s2binlib_find_vfunc_by_vtbptr(void *vtable_ptr, size_t vfunc_index, void **result);

  /**
   * Get the RTTI type name for an object pointer
   *
   * Reads the vtable pointer from the provided object pointer and resolves the
   * RTTI type name associated with it. The resulting string is written into the
   * provided buffer as a null-terminated UTF-8 string.
   *
   * @param object_ptr Pointer to the object whose vtable to inspect
   * @param buffer Buffer to store the resulting type name
   * @param buffer_size Size of the buffer in bytes
   *
   * @return 0 on success
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters or conversion error
   *         -3 if buffer too small
   *         -4 if vtable info could not be resolved
   *         -5 if internal error
   *
   * @example
   *     char name[128];
   *     int result = s2binlib_get_object_ptr_vtable_name(object_ptr, name, sizeof(name));
   *     if (result == 0) {
   *         printf("Object type: %s\n", name);
   *     }
   */
  S2BINLIB_API int s2binlib_get_object_ptr_vtable_name(const void *object_ptr, char *buffer, size_t buffer_size);

  /**
   * Check whether an object pointer has a resolvable vtable
   *
   * @param object_ptr Pointer to the object to check
   *
   * @return 1 if a vtable is detected
   *         0 if no vtable is detected
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -5 if internal error
   *
   * @example
   *     int has_vtable = s2binlib_object_ptr_has_vtable(object_ptr);
   *     if (has_vtable == 1) {
   *         printf("Object has a vtable\n");
   *     }
   */
  S2BINLIB_API int s2binlib_object_ptr_has_vtable(const void *object_ptr);

  /**
   * Check whether an object's vtable inherits from a specific base class
   *
   * @param object_ptr Pointer to the object to inspect
   * @param base_class_name Name of the base class to search for (UTF-8, null-terminated)
   *
   * @return 1 if the base class is present
   *         0 if the base class is not present
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -4 if vtable info could not be resolved
   *         -5 if internal error
   *
   * @example
   *     int has_base = s2binlib_object_ptr_has_base_class(object_ptr, "CBaseEntity");
   *     if (has_base == 1) {
   *         printf("Object derives from CBaseEntity\n");
   *     }
   */
  S2BINLIB_API int s2binlib_object_ptr_has_base_class(const void *object_ptr, const char *base_class_name);

  /**
   * Find a string in the binary and return its relative virtual address (RVA)
   *
   * Searches for an exact string match in the binary (case-sensitive).
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary to search (null-terminated C string)
   * @param string String to search for (null-terminated C string)
   * @param result Pointer to store the resulting relative virtual address (RVA)
   *
   * @return 0 on success (address written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to load binary
   *         -4 if string not found
   *         -5 if internal error
   *
   * @example
   *     void* string_rva;
   *     int result = s2binlib_find_string_rva("server", "CBaseEntity", &string_rva);
   *     if (result == 0) {
   *         printf("String RVA: %p\n", string_rva);
   *     }
   */
  S2BINLIB_API int s2binlib_find_string_rva(const char *binary_name, const char *string, void **result);

  /**
   * Find a string in the binary and return its runtime memory address
   *
   * Searches for an exact string match in the binary (case-sensitive).
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary to search (null-terminated C string)
   * @param string String to search for (null-terminated C string)
   * @param result Pointer to store the resulting memory address
   *
   * @return 0 on success (address written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to load binary or get base address
   *         -4 if string not found
   *         -5 if internal error
   *
   * @example
   *     void* string_addr;
   *     int result = s2binlib_find_string("server", "CBaseEntity", &string_addr);
   *     if (result == 0) {
   *         printf("String at: %p\n", string_addr);
   *     }
   */
  S2BINLIB_API int s2binlib_find_string(const char *binary_name, const char *string, void **result);

  /**
   * Dump and cache all cross-references in a binary
   *
   * This function disassembles all executable sections of the binary once and builds
   * a complete cross-reference (xref) database. Subsequent queries are very fast.
   *
   * If the binary is not yet loaded, it will be loaded automatically.
   *
   * @param binary_name Name of the binary to analyze (null-terminated C string)
   *
   * @return 0 on success
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to load binary
   *         -4 if failed to dump xrefs
   *         -5 if internal error
   *
   * @example
   *     int result = s2binlib_dump_xrefs("server");
   *     if (result == 0) {
   *         printf("Xrefs cached successfully\n");
   *     }
   */
  S2BINLIB_API int s2binlib_dump_xrefs(const char *binary_name);

  /**
   * Get the count of cached cross-references for a target relative virtual address (RVA)
   *
   * Returns the number of code locations that reference the specified target address.
   * The binary must have been analyzed with s2binlib_dump_xrefs() first.
   *
   * Use this function to determine the buffer size needed for s2binlib_get_xrefs_cached().
   *
   * @param binary_name Name of the binary (null-terminated C string)
   * @param target_rva The target relative virtual address (RVA) to find references to
   *
   * @return Non-negative: Number of xrefs found
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if binary not analyzed (call s2binlib_dump_xrefs first)
   *         -5 if internal error
   *
   * @example
   *     // First, dump xrefs
   *     s2binlib_dump_xrefs("server");
   *
   *     // Get xref count
   *     int count = s2binlib_get_xrefs_count("server", (void*)0x140001000);
   *     if (count > 0) {
   *         void** xrefs = malloc(count * sizeof(void*));
   *         s2binlib_get_xrefs_cached("server", (void*)0x140001000, xrefs, count);
   *         // Use xrefs
   *         free(xrefs);
   *     }
   */
  S2BINLIB_API int s2binlib_get_xrefs_count(const char *binary_name, void *target_rva);

  /**
   * Get cached cross-references for a target relative virtual address (RVA) into a buffer
   *
   * Returns all code locations that reference the specified target address into the provided buffer.
   * The binary must have been analyzed with s2binlib_dump_xrefs() first.
   *
   * Use s2binlib_get_xrefs_count() to determine the required buffer size.
   *
   * @param binary_name Name of the binary (null-terminated C string)
   * @param target_rva The target relative virtual address (RVA) to find references to
   * @param buffer Buffer to store the xref addresses (array of uint64_t)
   * @param buffer_size Size of the buffer (number of uint64_t elements it can hold)
   *
   * @return Non-negative: Number of xrefs written to buffer
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if binary not analyzed (call s2binlib_dump_xrefs first)
   *         -4 if buffer too small
   *         -5 if internal error
   *
   * @example
   *     // First, dump xrefs
   *     s2binlib_dump_xrefs("server");
   *
   *     // Get xref count
   *     int count = s2binlib_get_xrefs_count("server", (void*)0x140001000);
   *     if (count > 0) {
   *         void** xrefs = malloc(count * sizeof(void*));
   *         int result = s2binlib_get_xrefs_cached("server", (void*)0x140001000, xrefs, count);
   *         if (result > 0) {
   *             for (int i = 0; i < result; i++) {
   *                 printf("Xref at: %p\n", xrefs[i]);
   *             }
   *         }
   *         free(xrefs);
   *     }
   */
  S2BINLIB_API int s2binlib_get_xrefs_cached(const char *binary_name, void *target_rva, void **buffer, size_t buffer_size);

  /**
   * Unload a specific binary from memory
   *
   * Removes the specified binary from the internal cache, freeing up memory.
   * This is useful when you no longer need a particular binary.
   *
   * @param binary_name Name of the binary to unload (e.g., "server", "client")
   *
   * @return 0 on success
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -5 if internal error (mutex lock failed)
   *
   * @example
   *     int result = s2binlib_unload_binary("server");
   *     if (result == 0) {
   *         printf("Binary unloaded successfully\n");
   *     }
   */
  S2BINLIB_API int s2binlib_unload_binary(const char *binary_name);

  /**
   * Unload all binaries from memory
   *
   * Removes all loaded binaries from the internal cache, freeing up memory.
   * This is useful for cleanup operations or when you need to start fresh.
   *
   * @return 0 on success
   *         -1 if S2BinLib not initialized
   *         -5 if internal error (mutex lock failed)
   *
   * @example
   *     int result = s2binlib_unload_all_binaries();
   *     if (result == 0) {
   *         printf("All binaries unloaded successfully\n");
   *     }
   */
  S2BINLIB_API int s2binlib_unload_all_binaries(void);

  /**
   * Install a JIT trampoline at a memory address
   *
   * Creates a JIT trampoline that can be used to hook or intercept function calls.
   * This function reads the original function pointer at the specified memory address,
   * creates a trampoline, and replaces the original pointer with the trampoline address.
   *
   * If a trampoline is already installed at the same address, this function does nothing
   * and returns success.
   *
   * @param mem_address Runtime memory address where to install the trampoline
   * @param trampoline_address_out Pointer to store the resulting trampoline address
   *
   * @return 0 on success
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to install trampoline
   *         -5 if internal error
   *
   * @warning This function modifies memory at the specified address and changes
   *          memory protection flags. The caller must ensure that:
   *          - The memory address is valid and writable
   *          - The address points to an 8-byte function pointer
   *          - No other threads are accessing the memory during the operation
   *
   * @example
   *     void* vtable_ptr = ...; // Get vtable pointer
   *     void* trampoline_address;
   *     int result = s2binlib_install_trampoline(vtable_ptr, &trampoline_address);
   *     if (result == 0) {
   *         printf("Trampoline installed successfully\n");
   *     }
   */
  S2BINLIB_API int s2binlib_install_trampoline(void *mem_address, void **trampoline_address_out);

  /**
   * @brief Follow cross-reference from memory address to memory address
   *
   * This function reads the instruction at the given memory address,
   * decodes it using iced-x86, and returns the target address if the
   * instruction contains a valid cross-reference.
   *
   * Valid xrefs include:
   * - RIP-relative memory operands (e.g., lea rax, [rip+0x1000])
   * - Near branches (call, jmp, jcc)
   * - Absolute memory operands
   *
   * @param mem_address Runtime memory address to analyze
   * @param target_address_out Pointer to store the target address
   *
   * @return 0 on success (target address written to target_address_out)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if no valid xref found or invalid instruction
   *         -5 if internal error
   *
   * @warning This function reads memory at the specified address.
   *          The caller must ensure that:
   *          - The memory address is valid and readable
   *          - The address points to executable code
   *
   * @example
   *     void* instruction_addr = ...; // Address of an instruction
   *     void* target_addr;
   *     int result = s2binlib_follow_xref_mem_to_mem(instruction_addr, &target_addr);
   *     if (result == 0) {
   *         printf("Xref target: %p\n", target_addr);
   *     }
   */
  S2BINLIB_API int s2binlib_follow_xref_mem_to_mem(const void *mem_address, void **target_address_out);

  /**
   * @brief Follow cross-reference from relative virtual address (RVA) to memory address
   *
   * This function reads the instruction at the given relative virtual address from the file,
   * decodes it using iced-x86, and returns the target memory address if the
   * instruction contains a valid cross-reference.
   *
   * Valid xrefs include:
   * - RIP-relative memory operands (e.g., lea rax, [rip+0x1000])
   * - Near branches (call, jmp, jcc)
   * - Absolute memory operands
   *
   * @param binary_name Name of the binary (e.g., "server", "client")
   * @param rva Relative virtual address (RVA) to analyze
   * @param target_address_out Pointer to store the target memory address
   *
   * @return 0 on success (target address written to target_address_out)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to load binary or no valid xref found
   *         -5 if internal error
   *
   * @example
   *     void* target_addr;
   *     int result = s2binlib_follow_xref_rva_to_mem("server", 0x140001000, &target_addr);
   *     if (result == 0) {
   *         printf("Xref target: %p\n", target_addr);
   *     }
   */
  S2BINLIB_API int s2binlib_follow_xref_rva_to_mem(const char *binary_name, uint64_t rva, void **target_address_out);

  /**
   * @brief Follow cross-reference from relative virtual address (RVA) to relative virtual address (RVA)
   *
   * This function reads the instruction at the given relative virtual address from the file,
   * decodes it using iced-x86, and returns the target relative virtual address if the
   * instruction contains a valid cross-reference.
   *
   * Valid xrefs include:
   * - RIP-relative memory operands (e.g., lea rax, [rip+0x1000])
   * - Near branches (call, jmp, jcc)
   * - Absolute memory operands
   *
   * @param binary_name Name of the binary (e.g., "server", "client")
   * @param rva Relative virtual address (RVA) to analyze
   * @param target_rva_out Pointer to store the target relative virtual address (RVA)
   *
   * @return 0 on success (target RVA written to target_rva_out)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if failed to load binary or no valid xref found
   *         -5 if internal error
   *
   * @example
   *     uint64_t target_rva;
   *     int result = s2binlib_follow_xref_rva_to_rva("server", 0x140001000, &target_rva);
   *     if (result == 0) {
   *         printf("Xref target RVA: 0x%llX\n", target_rva);
   *     }
   */
  S2BINLIB_API int s2binlib_follow_xref_rva_to_rva(const char *binary_name, uint64_t rva, uint64_t *target_rva_out);

  /**
   * @brief Find the NetworkVar_StateChanged vtable index by relative virtual address (RVA)
   *
   * This function scans the vtable at the given relative virtual address to find the
   * index of the NetworkVar_StateChanged virtual function. It analyzes each
   * virtual function in the vtable looking for the specific instruction pattern
   * that identifies the StateChanged function (cmp dword ptr [reg+56], 0xFF).
   *
   * @param vtable_rva Relative virtual address (RVA) of the vtable to analyze
   * @param result Pointer to store the resulting index (as uint64_t)
   *
   * @return 0 on success (index written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -4 if NetworkVar_StateChanged not found in vtable
   *         -5 if internal error
   *
   * @example
   *     uint64_t index;
   *     int result = s2binlib_find_networkvar_vtable_statechanged_rva(0x140001000, &index);
   *     if (result == 0) {
   *         printf("StateChanged index: %llu\n", index);
   *     }
   */
  S2BINLIB_API int s2binlib_find_networkvar_vtable_statechanged_rva(uint64_t vtable_rva, uint64_t *result);

  /**
   * @brief Find the NetworkVar_StateChanged vtable index by memory address
   *
   * This function converts the runtime memory address to a relative virtual address (RVA),
   * then scans the vtable to find the index of the NetworkVar_StateChanged
   * virtual function. It analyzes each virtual function in the vtable looking
   * for the specific instruction pattern that identifies the StateChanged function.
   *
   * @param vtable_mem_address Runtime memory address of the vtable
   * @param result Pointer to store the resulting index (as uint64_t)
   *
   * @return 0 on success (index written to result)
   *         -1 if S2BinLib not initialized
   *         -2 if invalid parameters
   *         -3 if address conversion failed
   *         -4 if NetworkVar_StateChanged not found in vtable
   *         -5 if internal error
   *
   * @example
   *     uint64_t index;
   *     int result = s2binlib_find_networkvar_vtable_statechanged(vtable_ptr, &index);
   *     if (result == 0) {
   *         printf("StateChanged index: %llu\n", index);
   *     }
   */
  S2BINLIB_API int s2binlib_find_networkvar_vtable_statechanged(uint64_t vtable_mem_address, uint64_t *result);

#ifdef __cplusplus
}
#endif

#endif // S2BINLIB_H