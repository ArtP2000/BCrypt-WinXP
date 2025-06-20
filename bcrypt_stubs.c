#include "xcrypt.h"

NTSTATUS WINAPI BCryptAddContextFunction(ULONG table, const WCHAR* ctx, ULONG iface, const WCHAR* func, ULONG pos)
{
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptAddContextFunctionProvider(ULONG table, const WCHAR* ctx, ULONG iface, const WCHAR* func,
    const WCHAR* provider, ULONG pos)
{
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptRemoveContextFunction(ULONG table, const WCHAR* ctx, ULONG iface, const WCHAR* func)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptRemoveContextFunctionProvider(ULONG table, const WCHAR* ctx, ULONG iface, const WCHAR* func,
    const WCHAR* provider)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptEnumContextFunctions(ULONG table, const WCHAR* ctx, ULONG iface, ULONG* buflen,
    CRYPT_CONTEXT_FUNCTIONS** buffer)
{
    return STATUS_NOT_IMPLEMENTED;
}

void WINAPI BCryptFreeBuffer(void* buffer)
{
    free(buffer);
}

NTSTATUS WINAPI BCryptRegisterProvider(const WCHAR* provider, ULONG flags, CRYPT_PROVIDER_REG* reg)
{
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptUnregisterProvider(const WCHAR* provider)
{
    return STATUS_NOT_IMPLEMENTED;
}