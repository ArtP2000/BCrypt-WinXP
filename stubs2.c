#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>


NTSTATUS
WINAPI
BCryptConfigureContext(
	__in ULONG dwTable,
	__in LPCWSTR pszContext,
	__in PCRYPT_CONTEXT_CONFIG pConfig)
{
	return STATUS_SUCCESS;
}

NTSTATUS
WINAPI
BCryptConfigureContextFunction(
	__in ULONG dwTable,
	__in LPCWSTR pszContext,
	__in ULONG dwInterface,
	__in LPCWSTR pszFunction,
	__in PCRYPT_CONTEXT_FUNCTION_CONFIG pConfig)
{
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
WINAPI
BCryptCreateContext(
	__in ULONG dwTable,
	__in LPCWSTR pszContext,
	__in_opt PCRYPT_CONTEXT_CONFIG pConfig)
{
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
WINAPI
BCryptDeleteContext(
	__in ULONG dwTable,
	__in LPCWSTR pszContext)
{
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
WINAPI
BCryptEnumContextFunctionProviders(
	__in ULONG dwTable,
	__in LPCWSTR pszContext,
	__in ULONG dwInterface,
	__in LPCWSTR pszFunction,
	__inout ULONG* pcbBuffer,
	__deref_opt_inout_bcount_part_opt(*pcbBuffer, *pcbBuffer) PCRYPT_CONTEXT_FUNCTION_PROVIDERS* ppBuffer)
{
	return STATUS_SUCCESS;
}

NTSTATUS
WINAPI
BCryptEnumContexts(
	__in ULONG dwTable,
	__inout ULONG* pcbBuffer,
	__deref_opt_inout_bcount_part_opt(*pcbBuffer, *pcbBuffer) PCRYPT_CONTEXTS* ppBuffer)
{
	return STATUS_SUCCESS;
}

NTSTATUS
WINAPI
BCryptEnumProviders(
	__in    LPCWSTR pszAlgId,
	__out   ULONG* pImplCount,
	__out   BCRYPT_PROVIDER_NAME** ppImplList,
	__in    ULONG   dwFlags)
{
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
WINAPI
BCryptEnumRegisteredProviders(
	__inout ULONG* pcbBuffer,
	__deref_opt_inout_bcount_part_opt(*pcbBuffer, *pcbBuffer) PCRYPT_PROVIDERS* ppBuffer)
{
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
WINAPI
BCryptQueryContextConfiguration(
	__in ULONG dwTable,
	__in LPCWSTR pszContext,
	__inout ULONG* pcbBuffer,
	__deref_opt_inout_bcount_part_opt(*pcbBuffer, *pcbBuffer) PCRYPT_CONTEXT_CONFIG* ppBuffer)
{
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
WINAPI
BCryptQueryContextFunctionConfiguration(
	__in ULONG dwTable,
	__in LPCWSTR pszContext,
	__in ULONG dwInterface,
	__in LPCWSTR pszFunction,
	__inout ULONG* pcbBuffer,
	__deref_opt_inout_bcount_part_opt(*pcbBuffer, *pcbBuffer) PCRYPT_CONTEXT_FUNCTION_CONFIG* ppBuffer)
{
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
WINAPI
BCryptQueryContextFunctionProperty(
	__in ULONG dwTable,
	__in LPCWSTR pszContext,
	__in ULONG dwInterface,
	__in LPCWSTR pszFunction,
	__in LPCWSTR pszProperty,
	__inout ULONG* pcbValue,
	__deref_opt_inout_bcount_part_opt(*pcbValue, *pcbValue) PUCHAR* ppbValue)
{
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
WINAPI
BCryptQueryProviderRegistration(
	__in LPCWSTR pszProvider,
	__in ULONG dwMode,
	__in ULONG dwInterface,
	__inout ULONG* pcbBuffer,
	__deref_opt_inout_bcount_part_opt(*pcbBuffer, *pcbBuffer) PCRYPT_PROVIDER_REG* ppBuffer)
{
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
WINAPI
BCryptRegisterConfigChangeNotifyST(
	__in PVOID pEvent)
{
	return STATUS_SUCCESS;
}

NTSTATUS WINAPI
BCryptResolveProviders(
	__in_opt LPCWSTR pszContext,
	__in_opt ULONG dwInterface,
	__in_opt LPCWSTR pszFunction,
	__in_opt LPCWSTR pszProvider,
	__in ULONG dwMode,
	__in ULONG dwFlags,
	__inout ULONG* pcbBuffer,
	__deref_opt_inout_bcount_part_opt(*pcbBuffer, *pcbBuffer) PCRYPT_PROVIDER_REFS* ppBuffer)
{
	return STATUS_SUCCESS;
}

