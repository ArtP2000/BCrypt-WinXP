#include "xcrypt.h"

NTSTATUS WINAPI BCryptSetAuditingInterface()
{
    HANDLE TokenHandle = 0;

    NTSTATUS LastError = STATUS_SUCCESS;;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &TokenHandle))
    {
        if (GetLastError() > 0)
            LastError = GetLastError() | 0xC0070000;
        else
            LastError = GetLastError();

        if (TokenHandle)
            CloseHandle(TokenHandle);
        return LastError;
    }//end if (!OpenProcessToken

    BOOL pfResult = FALSE;
    PRIVILEGE_SET RequiredPrivileges;
    LUID lu;
    lu.HighPart = 0;
    lu.LowPart = 7;
    memset(&RequiredPrivileges, 0, sizeof(RequiredPrivileges));
    RequiredPrivileges.Control = 0;
    RequiredPrivileges.Privilege[0].Attributes = 0;
    RequiredPrivileges.Privilege[0].Luid = lu;
    if (!PrivilegeCheck(TokenHandle, &RequiredPrivileges, &pfResult))
    {
        if (GetLastError() > 0)
            LastError = GetLastError() | 0xC0070000;
        else
            LastError = GetLastError();

        if (TokenHandle)
            CloseHandle(TokenHandle);
        return LastError;
    }

    if (pfResult)
    {
        LastError = STATUS_SUCCESS;
    }

    return LastError;
}