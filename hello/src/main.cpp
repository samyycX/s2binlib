#include <iostream>
#include <windows.h>
#include "s2binlib001.h"


int main(int argc, char** argv) {

    HMODULE hDll = LoadLibrary(TEXT("s2binlib.dll"));

    S2CreateInterfaceFn createInterface = (S2CreateInterfaceFn)GetProcAddress(hDll, "S2BinLib_CreateInterface");
    auto s2binlib = createInterface(S2BINLIB_INTERFACE_NAME);

    s2binlib->InitializeWithOs("F:/cs2server/game", "csgo", "windows");
    printf("%p\n", s2binlib);
    s2binlib->LoadBinary("server");

    void* createInterfaceRva;
    s2binlib->FindSymbolRva("server", "CreateInterface", &createInterfaceRva);
    void* vtable;
    s2binlib->FindVtableRva("server", "CBaseEntity", &vtable);
    printf("%p\n", createInterfaceRva);

    s2binlib->Destroy();

    return 0;
}
