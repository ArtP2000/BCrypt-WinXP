#include <Windows.h>
#include <gnutls/gnutls.h>

#ifdef _WIN64
#pragma comment (lib, "lib//gnutls-x64.lib")
#pragma comment (lib, "lib//tomcrypt-x64.lib")
#else
#pragma comment (lib, "lib//gnutls-x86.lib")
#pragma comment (lib, "lib//tomcrypt-x86.lib")
#endif


BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    int ret;
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinst);
        if ((ret = gnutls_global_init()) != GNUTLS_E_SUCCESS)
        {
            gnutls_perror(ret);
        }
        break;
    case DLL_PROCESS_DETACH:
        if (reserved) break;
        gnutls_global_deinit();
        break;
    }
    return TRUE;
}