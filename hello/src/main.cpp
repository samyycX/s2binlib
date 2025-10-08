#include <iostream>
#include "s2binlib.h"

int main(int argc, char** argv) {
    s2binlib_initialize("F:/cs2server/game", "csgo");
    void* vtable;
    s2binlib_find_vtable_va("engine2", "CServerSideClient", &vtable);
    printf("%p\n", vtable);
    return 0;
}
