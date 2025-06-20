#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>

#include <Windows.h>
#include <winternl.h>

#include <bcrypt.h>
#define LTC_NO_PROTOTYPES
#include "tomcrypt.h"
#include "bcrypt_internal.h"

#ifndef _WIN32_WCE
#define RtlGenRandom SystemFunction036
BOOLEAN NTAPI RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);
#pragma comment(lib, "advapi32.lib")
#endif /*_WIN32_WCE*/

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L) // ntsubauth
#define STATUS_NOT_IMPLEMENTED           ((NTSTATUS)0xC0000002L)
#define STATUS_NOT_SUPPORTED             ((NTSTATUS)0xC00000BBL)
#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)
#define STATUS_AUTH_TAG_MISMATCH         ((NTSTATUS)0xC000A002L)
#define STATUS_INVALID_BUFFER_SIZE       ((NTSTATUS)0xC0000206L)
#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED             ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_SIGNATURE         ((NTSTATUS)0xC000A000L)

#define MAX_HASH_OUTPUT_BYTES 64
#define MAX_HASH_BLOCK_BITS 1024

#define BCRYPT_PBKDF2_ALGORITHM     L"PBKDF2"
#define BCRYPT_KEY_DERIVATION_INTERFACE         0x00000007
#define BCRYPT_KEY_DERIVATION_OPERATION         0x00000040
#define BCRYPT_RNG_ALG_HANDLE               ((BCRYPT_ALG_HANDLE)0x00000081)
#define BCRYPT_HMAC_SHA1_ALG_HANDLE         ((BCRYPT_ALG_HANDLE)0x000000a1)
#define BCRYPT_HMAC_SHA256_ALG_HANDLE       ((BCRYPT_ALG_HANDLE)0x000000b1)
#define BCRYPT_HMAC_SHA384_ALG_HANDLE       ((BCRYPT_ALG_HANDLE)0x000000c1)
#define BCRYPT_HMAC_SHA512_ALG_HANDLE       ((BCRYPT_ALG_HANDLE)0x000000d1)
#define BCRYPT_SHA1_ALG_HANDLE              ((BCRYPT_ALG_HANDLE)0x00000031)
#define BCRYPT_SHA256_ALG_HANDLE            ((BCRYPT_ALG_HANDLE)0x00000041)
#define BCRYPT_SHA384_ALG_HANDLE            ((BCRYPT_ALG_HANDLE)0x00000051)
#define BCRYPT_SHA512_ALG_HANDLE            ((BCRYPT_ALG_HANDLE)0x00000061)

#define BCRYPT_KDF_RAW_SECRET       L"TRUNCATE"
#define KDF_SALT                0x0f
#define KDF_ITERATION_COUNT     0x10

/* Flags for BCryptCreateHash */
#define BCRYPT_HASH_REUSABLE_FLAG   0x00000020

/* ordered by class, keep in sync with enum alg_id */
static const struct
{
    const WCHAR* name;
    ULONG        class;
    ULONG        object_length;
    ULONG        hash_length;
    ULONG        block_bits;
}
builtin_algorithms[] =
{
    {  BCRYPT_3DES_ALGORITHM,       BCRYPT_CIPHER_INTERFACE,                522,    0,    0 },
    {  BCRYPT_AES_ALGORITHM,        BCRYPT_CIPHER_INTERFACE,                654,    0,    0 },
    {  BCRYPT_RC4_ALGORITHM,        BCRYPT_CIPHER_INTERFACE,                654,    0,    0 },
    {  BCRYPT_SHA256_ALGORITHM,     BCRYPT_HASH_INTERFACE,                  286,   32,  512 },
    {  BCRYPT_SHA384_ALGORITHM,     BCRYPT_HASH_INTERFACE,                  382,   48, 1024 },
    {  BCRYPT_SHA512_ALGORITHM,     BCRYPT_HASH_INTERFACE,                  382,   64, 1024 },
    {  BCRYPT_SHA1_ALGORITHM,       BCRYPT_HASH_INTERFACE,                  278,   20,  512 },
    {  BCRYPT_MD5_ALGORITHM,        BCRYPT_HASH_INTERFACE,                  274,   16,  512 },
    {  BCRYPT_MD4_ALGORITHM,        BCRYPT_HASH_INTERFACE,                  270,   16,  512 },
    {  BCRYPT_MD2_ALGORITHM,        BCRYPT_HASH_INTERFACE,                  270,   16,  128 },
    {  BCRYPT_RSA_ALGORITHM,        BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE, 0,      0,    0 },
    {  BCRYPT_DH_ALGORITHM,         BCRYPT_SECRET_AGREEMENT_INTERFACE,      0,      0,    0 },
    {  BCRYPT_ECDH_P256_ALGORITHM,  BCRYPT_SECRET_AGREEMENT_INTERFACE,      0,      0,    0 },
    {  BCRYPT_ECDH_P384_ALGORITHM,  BCRYPT_SECRET_AGREEMENT_INTERFACE,      0,      0,    0 },
    {  BCRYPT_RSA_SIGN_ALGORITHM,   BCRYPT_SIGNATURE_INTERFACE,             0,      0,    0 },
    {  BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_SIGNATURE_INTERFACE,             0,      0,    0 },
    {  BCRYPT_ECDSA_P384_ALGORITHM, BCRYPT_SIGNATURE_INTERFACE,             0,      0,    0 },
    {  BCRYPT_DSA_ALGORITHM,        BCRYPT_SIGNATURE_INTERFACE,             0,      0,    0 },
    {  BCRYPT_RNG_ALGORITHM,        BCRYPT_RNG_INTERFACE,                   0,      0,    0 },
    {  BCRYPT_PBKDF2_ALGORITHM,     BCRYPT_KEY_DERIVATION_INTERFACE,      618,      0,    0 },
};

static __inline BOOL is_symmetric_key(const struct key* key)
{
    return builtin_algorithms[key->alg_id].class == BCRYPT_CIPHER_INTERFACE
        || builtin_algorithms[key->alg_id].class == BCRYPT_KEY_DERIVATION_INTERFACE;
}

static __inline BOOL is_asymmetric_encryption_key(struct key* key)
{
    return builtin_algorithms[key->alg_id].class == BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE;
}

static __inline BOOL is_agreement_key(struct key* key)
{
    return builtin_algorithms[key->alg_id].class == BCRYPT_SECRET_AGREEMENT_INTERFACE;
}

static __inline BOOL is_signature_key(struct key* key)
{
    return builtin_algorithms[key->alg_id].class == BCRYPT_SIGNATURE_INTERFACE || key->alg_id == ALG_ID_RSA;
}

static __inline BOOL match_operation_type(ULONG type, ULONG class)
{
    if (!type) return TRUE;
    switch (class)
    {
    case BCRYPT_CIPHER_INTERFACE:                return type & BCRYPT_CIPHER_OPERATION;
    case BCRYPT_HASH_INTERFACE:                  return type & BCRYPT_HASH_OPERATION;
    case BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE: return type & BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION;
    case BCRYPT_SECRET_AGREEMENT_INTERFACE:      return type & BCRYPT_SECRET_AGREEMENT_OPERATION;
    case BCRYPT_SIGNATURE_INTERFACE:             return type & BCRYPT_SIGNATURE_OPERATION;
    case BCRYPT_RNG_INTERFACE:                   return type & BCRYPT_RNG_OPERATION;
    case BCRYPT_KEY_DERIVATION_INTERFACE:        return type & BCRYPT_KEY_DERIVATION_OPERATION;
    default: break;
    }
    return FALSE;
}

static const struct algorithm pseudo_algorithms[] =
{
    {{ MAGIC_ALG }, ALG_ID_MD2 },
    {{ MAGIC_ALG }, ALG_ID_MD4 },
    {{ MAGIC_ALG }, ALG_ID_MD5 },
    {{ MAGIC_ALG }, ALG_ID_SHA1 },
    {{ MAGIC_ALG }, ALG_ID_SHA256 },
    {{ MAGIC_ALG }, ALG_ID_SHA384 },
    {{ MAGIC_ALG }, ALG_ID_SHA512 },
    {{ MAGIC_ALG }, ALG_ID_RC4 },
    {{ MAGIC_ALG }, ALG_ID_RNG },
    {{ MAGIC_ALG }, ALG_ID_MD5, 0, BCRYPT_ALG_HANDLE_HMAC_FLAG },
    {{ MAGIC_ALG }, ALG_ID_SHA1, 0, BCRYPT_ALG_HANDLE_HMAC_FLAG },
    {{ MAGIC_ALG }, ALG_ID_SHA256, 0, BCRYPT_ALG_HANDLE_HMAC_FLAG },
    {{ MAGIC_ALG }, ALG_ID_SHA384, 0, BCRYPT_ALG_HANDLE_HMAC_FLAG },
    {{ MAGIC_ALG }, ALG_ID_SHA512, 0, BCRYPT_ALG_HANDLE_HMAC_FLAG },
    {{ MAGIC_ALG }, ALG_ID_RSA },
    {{ 0 }}, /* ECDSA */
    {{ 0 }}, /* AES_CMAC */
    {{ 0 }}, /* AES_GMAC */
    {{ MAGIC_ALG }, ALG_ID_MD2, 0, BCRYPT_ALG_HANDLE_HMAC_FLAG },
    {{ MAGIC_ALG }, ALG_ID_MD4, 0, BCRYPT_ALG_HANDLE_HMAC_FLAG },
    {{ MAGIC_ALG }, ALG_ID_3DES, CHAIN_MODE_CBC },
    {{ MAGIC_ALG }, ALG_ID_3DES, CHAIN_MODE_ECB },
    {{ MAGIC_ALG }, ALG_ID_3DES, CHAIN_MODE_CFB },
    {{ 0 }}, /* 3DES_112_CBC */
    {{ 0 }}, /* 3DES_112_ECB */
    {{ 0 }}, /* 3DES_112_CFB */
    {{ MAGIC_ALG }, ALG_ID_AES, CHAIN_MODE_CBC },
    {{ MAGIC_ALG }, ALG_ID_AES, CHAIN_MODE_ECB },
    {{ MAGIC_ALG }, ALG_ID_AES, CHAIN_MODE_CFB },
    {{ MAGIC_ALG }, ALG_ID_AES, CHAIN_MODE_CCM },
    {{ MAGIC_ALG }, ALG_ID_AES, CHAIN_MODE_GCM },
    {{ 0 }}, /* DES_CBC */
    {{ 0 }}, /* DES_ECB */
    {{ 0 }}, /* DES_CFB */
    {{ 0 }}, /* DESX_CBC */
    {{ 0 }}, /* DESX_ECB */
    {{ 0 }}, /* DESX_CFB */
    {{ 0 }}, /* RC2_CBC */
    {{ 0 }}, /* RC2_ECB */
    {{ 0 }}, /* RC2_CFB */
    {{ MAGIC_ALG }, ALG_ID_DH },
    {{ 0 }}, /* ECDH */
    {{ MAGIC_ALG }, ALG_ID_ECDH_P256 },
    {{ MAGIC_ALG }, ALG_ID_ECDH_P384 },
    {{ 0 }}, /* ECDH_P512 */
    {{ MAGIC_ALG }, ALG_ID_DSA },
    {{ MAGIC_ALG }, ALG_ID_ECDSA_P256 },
    {{ MAGIC_ALG }, ALG_ID_ECDSA_P384 },
    {{ 0 }}, /* ECDSA_P512 */
    {{ MAGIC_ALG }, ALG_ID_RSA_SIGN },
};

/* Algorithm pseudo-handles are denoted by having the lowest bit set.
 * An aligned algorithm pointer will never have this bit set.
 */
static __inline BOOL is_alg_pseudo_handle(BCRYPT_ALG_HANDLE handle)
{
    return (((ULONG_PTR)handle & 1) == 1);
}

static struct object* get_object(BCRYPT_HANDLE handle, ULONG magic)
{
    ULONG idx;

    if (!handle) return NULL;

    if (!is_alg_pseudo_handle(handle))
    {
        struct object* obj = handle;
        if (magic && obj->magic != magic) return NULL;
        return obj;
    }

    idx = (ULONG_PTR)handle >> 4;
    if (idx >= ARRAYSIZE(pseudo_algorithms) || !pseudo_algorithms[idx].hdr.magic)
    {
        return NULL;
    }
    return (struct object*)&pseudo_algorithms[idx];
}

static __inline struct algorithm* get_alg_object(BCRYPT_ALG_HANDLE handle)
{
    return (struct algorithm*)get_object(handle, MAGIC_ALG);
}

static __inline struct hash* get_hash_object(BCRYPT_HASH_HANDLE handle)
{
    return (struct hash*)get_object(handle, MAGIC_HASH);
}

static __inline struct key* get_key_object(BCRYPT_KEY_HANDLE handle)
{
    return (struct key*)get_object(handle, MAGIC_KEY);
}

static __inline struct secret* get_secret_object(BCRYPT_SECRET_HANDLE handle)
{
    return (struct secret*)get_object(handle, MAGIC_SECRET);
}

static struct algorithm* create_algorithm(enum alg_id id, enum chain_mode mode, DWORD flags)
{
    struct algorithm* ret;
    if (!(ret = calloc(1, sizeof(*ret)))) return NULL;
    ret->hdr.magic = MAGIC_ALG;
    ret->id = id;
    ret->mode = mode;
    ret->flags = flags;
    return ret;
}

static __inline void destroy_object(struct object* obj)
{
    SecureZeroMemory(&obj->magic, sizeof(obj->magic));
    free(obj);
}

static const struct ltc_hash_descriptor* get_hash_descriptor(enum alg_id alg_id)
{
    switch (alg_id)
    {
    case ALG_ID_MD2: return &md2_desc;
    case ALG_ID_MD4: return &md4_desc;
    case ALG_ID_MD5: return &md5_desc;
    case ALG_ID_SHA1: return &sha1_desc;
    case ALG_ID_SHA256: return &sha256_desc;
    case ALG_ID_SHA384: return &sha384_desc;
    case ALG_ID_SHA512: return &sha512_desc;
    default:
        return NULL;
    }
}

#define HASH_FLAG_HMAC      0x01
#define HASH_FLAG_REUSABLE  0x02
struct hash
{
    struct object     hdr;
    enum alg_id       alg_id;
    const struct ltc_hash_descriptor* desc;
    ULONG             flags;
    UCHAR* secret;
    ULONG             secret_len;
    hash_state        outer;
    hash_state        inner;
};

#define BLOCK_LENGTH_RC4        1
#define BLOCK_LENGTH_3DES       8
#define BLOCK_LENGTH_AES        16

