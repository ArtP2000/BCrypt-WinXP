#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>

#include "xcrypt.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>

#include "gnu.h"

#define STATUS_INTERNAL_ERROR            ((NTSTATUS)0xC00000E5L)

#if GUTLS_VERSION_MAJOR < 3 || (GNUTLS_VERSION_MAJOR == 3 && GNUTLS_VERSION_MINOR < 8)
#define GNUTLS_KEYGEN_DH 4
#endif

union key_data
{
    gnutls_cipher_hd_t cipher;
    struct
    {
        gnutls_privkey_t   privkey;
        gnutls_pubkey_t    pubkey;
        gnutls_dh_params_t dh_params;
    } a;
};

C_ASSERT(sizeof(union key_data) <= sizeof(((struct key*)0)->private));

static union key_data* key_data(struct key* key)
{
    return (union key_data*)key->private;
}

static int compat_gnutls_cipher_tag(gnutls_cipher_hd_t handle, void* tag, size_t tag_size)
{
    return GNUTLS_E_UNKNOWN_CIPHER_TYPE;
}

static int compat_gnutls_cipher_add_auth(gnutls_cipher_hd_t handle, const void* ptext, size_t ptext_size)
{
    return GNUTLS_E_UNKNOWN_CIPHER_TYPE;
}

static int compat_gnutls_pubkey_import_ecc_raw(gnutls_pubkey_t key, gnutls_ecc_curve_t curve,
    const gnutls_datum_t* x, const gnutls_datum_t* y)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static int compat_gnutls_pubkey_export_ecc_raw(gnutls_pubkey_t key, gnutls_ecc_curve_t* curve,
    gnutls_datum_t* x, gnutls_datum_t* y)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static int compat_gnutls_pubkey_export_dsa_raw(gnutls_pubkey_t key, gnutls_datum_t* p, gnutls_datum_t* q,
    gnutls_datum_t* g, gnutls_datum_t* y)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static int compat_gnutls_pubkey_export_rsa_raw(gnutls_pubkey_t key, gnutls_datum_t* m, gnutls_datum_t* e)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static int compat_gnutls_privkey_export_rsa_raw(gnutls_privkey_t key, gnutls_datum_t* m, gnutls_datum_t* e,
    gnutls_datum_t* d, gnutls_datum_t* p, gnutls_datum_t* q,
    gnutls_datum_t* u, gnutls_datum_t* e1, gnutls_datum_t* e2)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static int compat_gnutls_privkey_export_ecc_raw(gnutls_privkey_t key, gnutls_ecc_curve_t* curve,
    gnutls_datum_t* x, gnutls_datum_t* y, gnutls_datum_t* k)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static int compat_gnutls_privkey_import_ecc_raw(gnutls_privkey_t key, gnutls_ecc_curve_t curve,
    const gnutls_datum_t* x, const gnutls_datum_t* y,
    const gnutls_datum_t* k)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static int compat_gnutls_privkey_export_dsa_raw(gnutls_privkey_t key, gnutls_datum_t* p, gnutls_datum_t* q,
    gnutls_datum_t* g, gnutls_datum_t* y, gnutls_datum_t* x)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static gnutls_sign_algorithm_t compat_gnutls_pk_to_sign(gnutls_pk_algorithm_t pk, gnutls_digest_algorithm_t hash)
{
    return GNUTLS_SIGN_UNKNOWN;
}

static int compat_gnutls_pubkey_verify_hash2(gnutls_pubkey_t key, gnutls_sign_algorithm_t algo,
    unsigned int flags, const gnutls_datum_t* hash,
    const gnutls_datum_t* signature)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static int compat_gnutls_pubkey_import_rsa_raw(gnutls_pubkey_t key, const gnutls_datum_t* m, const gnutls_datum_t* e)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static int compat_gnutls_pubkey_import_dsa_raw(gnutls_pubkey_t key, const gnutls_datum_t* p, const gnutls_datum_t* q,
    const gnutls_datum_t* g, const gnutls_datum_t* y)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static int compat_gnutls_decode_rs_value(const gnutls_datum_t* sig_value, gnutls_datum_t* r, gnutls_datum_t* s)
{
    return GNUTLS_E_INTERNAL_ERROR;
}

static int compat_gnutls_privkey_import_rsa_raw(gnutls_privkey_t key, const gnutls_datum_t* m, const gnutls_datum_t* e,
    const gnutls_datum_t* d, const gnutls_datum_t* p, const gnutls_datum_t* q,
    const gnutls_datum_t* u, const gnutls_datum_t* e1, const gnutls_datum_t* e2)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static int compat_gnutls_privkey_decrypt_data(gnutls_privkey_t key, unsigned int flags, const gnutls_datum_t* cipher_text,
    gnutls_datum_t* plain_text)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static int compat_gnutls_pubkey_encrypt_data(gnutls_pubkey_t key, unsigned int flags, const gnutls_datum_t* cipher_text,
    gnutls_datum_t* plain_text)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static int compat_gnutls_x509_spki_init(gnutls_x509_spki_t* spki)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static void compat_gnutls_x509_spki_deinit(gnutls_x509_spki_t spki)
{
}

static int compat_gnutls_x509_spki_set_rsa_oaep_params(gnutls_x509_spki_t spki, gnutls_digest_algorithm_t dig,
    gnutls_datum_t* label)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static void compat_gnutls_x509_spki_set_rsa_pss_params(gnutls_x509_spki_t spki, gnutls_digest_algorithm_t dig,
    unsigned int salt_size)
{
}

static int compat_gnutls_pubkey_set_spki(gnutls_pubkey_t key, const gnutls_x509_spki_t spki, unsigned int flags)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static int compat_gnutls_privkey_set_spki(gnutls_privkey_t key, const gnutls_x509_spki_t spki, unsigned int flags)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static int compat_gnutls_privkey_derive_secret(gnutls_privkey_t privkey, gnutls_pubkey_t pubkey, const gnutls_datum_t* nonce,
    gnutls_datum_t* secret, unsigned int flags)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static int compat_gnutls_privkey_export_dh_raw(gnutls_privkey_t privkey, gnutls_dh_params_t params, gnutls_datum_t* y,
    gnutls_datum_t* x, unsigned int flags)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static int compat_gnutls_pubkey_export_dh_raw(gnutls_pubkey_t pubkey, gnutls_dh_params_t params, gnutls_datum_t* y,
    unsigned flags)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static int compat_gnutls_privkey_import_dh_raw(gnutls_privkey_t privkey, const gnutls_dh_params_t params,
    const gnutls_datum_t* y, const gnutls_datum_t* x)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static int compat_gnutls_pubkey_import_dh_raw(gnutls_pubkey_t pubkey, const gnutls_dh_params_t params,
    const gnutls_datum_t* y)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

static int compat_gnutls_privkey_generate2(gnutls_privkey_t privkey, gnutls_pk_algorithm_t alg, unsigned int bits,
    unsigned int flags, const gnutls_keygen_data_st* data, unsigned data_size)
{
    return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
}

struct buffer
{
    BYTE* buffer;
    DWORD  length;
    DWORD  pos;
    BOOL   error;
};

static void buffer_init(struct buffer* buffer)
{
    buffer->buffer = NULL;
    buffer->length = 0;
    buffer->pos = 0;
    buffer->error = FALSE;
}

static void buffer_free(struct buffer* buffer)
{
    free(buffer->buffer);
}

static void buffer_append(struct buffer* buffer, BYTE* data, DWORD len)
{
    if (!len) return;

    if (buffer->pos + len > buffer->length)
    {
        DWORD new_length = max(max(buffer->pos + len, buffer->length * 2), 64);
        BYTE* new_buffer;

        if (!(new_buffer = realloc(buffer->buffer, new_length)))
        {
            buffer->error = TRUE;
            return;
        }

        buffer->buffer = new_buffer;
        buffer->length = new_length;
    }

    memcpy(&buffer->buffer[buffer->pos], data, len);
    buffer->pos += len;
}

static void buffer_append_byte(struct buffer* buffer, BYTE value)
{
    buffer_append(buffer, &value, sizeof(value));
}

static void buffer_append_asn1_length(struct buffer* buffer, DWORD length)
{
    DWORD num_bytes;

    if (length < 128)
    {
        buffer_append_byte(buffer, length);
        return;
    }

    if (length <= 0xff) num_bytes = 1;
    else if (length <= 0xffff) num_bytes = 2;
    else if (length <= 0xffffff) num_bytes = 3;
    else num_bytes = 4;

    buffer_append_byte(buffer, 0x80 | num_bytes);
    while (num_bytes--) buffer_append_byte(buffer, length >> (num_bytes * 8));
}

static void buffer_append_asn1_integer(struct buffer* buffer, BYTE* data, DWORD len)
{
    DWORD leading_zero = (*data & 0x80) != 0;

    buffer_append_byte(buffer, 0x02);  /* tag */
    buffer_append_asn1_length(buffer, len + leading_zero);
    if (leading_zero) buffer_append_byte(buffer, 0);
    buffer_append(buffer, data, len);
}

static void buffer_append_asn1_sequence(struct buffer* buffer, struct buffer* content)
{
    if (content->error)
    {
        buffer->error = TRUE;
        return;
    }

    buffer_append_byte(buffer, 0x30);  /* tag */
    buffer_append_asn1_length(buffer, content->pos);
    buffer_append(buffer, content->buffer, content->pos);
}

static void buffer_append_asn1_r_s(struct buffer* buffer, BYTE* r, DWORD r_len, BYTE* s, DWORD s_len)
{
    struct buffer value;

    buffer_init(&value);
    buffer_append_asn1_integer(&value, r, r_len);
    buffer_append_asn1_integer(&value, s, s_len);
    buffer_append_asn1_sequence(buffer, &value);
    buffer_free(&value);
}

static gnutls_cipher_algorithm_t get_gnutls_cipher(const struct key* key)
{
    switch (key->alg_id)
    {
    case ALG_ID_3DES:
        switch (key->u.s.mode)
        {
        case CHAIN_MODE_CBC:
            return GNUTLS_CIPHER_3DES_CBC;
        default:
            break;
        }
        return GNUTLS_CIPHER_UNKNOWN;

    case ALG_ID_AES:
        switch (key->u.s.mode)
        {
        case CHAIN_MODE_GCM:
            if (key->u.s.secret_len == 16) return GNUTLS_CIPHER_AES_128_GCM;
            if (key->u.s.secret_len == 32) return GNUTLS_CIPHER_AES_256_GCM;
            break;
        case CHAIN_MODE_ECB: /* can be emulated with CBC + empty IV */
        case CHAIN_MODE_CBC:
            if (key->u.s.secret_len == 16) return GNUTLS_CIPHER_AES_128_CBC;
            if (key->u.s.secret_len == 24) return GNUTLS_CIPHER_AES_192_CBC;
            if (key->u.s.secret_len == 32) return GNUTLS_CIPHER_AES_256_CBC;
            break;
        case CHAIN_MODE_CFB:
            if (key->u.s.secret_len == 16) return GNUTLS_CIPHER_AES_128_CFB8;
            if (key->u.s.secret_len == 24) return GNUTLS_CIPHER_AES_192_CFB8;
            if (key->u.s.secret_len == 32) return GNUTLS_CIPHER_AES_256_CFB8;
            break;
        default:
            break;
        }
        return GNUTLS_CIPHER_UNKNOWN;

    default:
        return GNUTLS_CIPHER_UNKNOWN;
    }
}

NTSTATUS key_symmetric_vector_reset_gnu(struct key* args)
{
    struct key* key = args;

    if (!key_data(key)->cipher) return STATUS_SUCCESS;
    gnutls_cipher_deinit(key_data(key)->cipher);
    key_data(key)->cipher = NULL;
    return STATUS_SUCCESS;
}

static NTSTATUS init_cipher_handle(struct key* key)
{
    gnutls_cipher_algorithm_t cipher;
    gnutls_datum_t secret, vector;
    int ret;

    if (key_data(key)->cipher) return STATUS_SUCCESS;
    if ((cipher = get_gnutls_cipher(key)) == GNUTLS_CIPHER_UNKNOWN) return STATUS_NOT_SUPPORTED;

    secret.data = key->u.s.secret;
    secret.size = key->u.s.secret_len;

    vector.data = key->u.s.vector;
    vector.size = key->u.s.vector_len;

    if ((ret = gnutls_cipher_init(&key_data(key)->cipher, cipher, &secret, key->u.s.vector ? &vector : NULL)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    return STATUS_SUCCESS;
}

NTSTATUS key_symmetric_set_auth_data_gnu(struct key_symmetric_set_auth_data_params* args)
{
    const struct key_symmetric_set_auth_data_params* params = args;
    NTSTATUS status;
    int ret;

    if (!params->auth_data) return STATUS_SUCCESS;
    if ((status = init_cipher_handle(params->key))) return status;

    if ((ret = gnutls_cipher_add_auth(key_data(params->key)->cipher, params->auth_data, params->len)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }
    return STATUS_SUCCESS;
}

NTSTATUS key_symmetric_encrypt_gnu(struct key_symmetric_encrypt_params* args)
{
    const struct key_symmetric_encrypt_params* params = args;
    NTSTATUS status;
    int ret;

    if ((status = init_cipher_handle(params->key))) return status;

    if ((ret = gnutls_cipher_encrypt2(key_data(params->key)->cipher, params->input, params->input_len,
        params->output, params->output_len)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }
    return STATUS_SUCCESS;
}

NTSTATUS key_symmetric_decrypt_gnu(struct key_symmetric_decrypt_params* args)
{
    const struct key_symmetric_decrypt_params* params = args;
    NTSTATUS status;
    int ret;

    if ((status = init_cipher_handle(params->key))) return status;

    if ((ret = gnutls_cipher_decrypt2(key_data(params->key)->cipher, params->input, params->input_len,
        params->output, params->output_len)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }
    return STATUS_SUCCESS;
}

NTSTATUS key_symmetric_get_tag_gnu(struct key_symmetric_get_tag_params* args)
{
    const struct key_symmetric_get_tag_params* params = args;
    NTSTATUS status;
    int ret;

    if ((status = init_cipher_handle(params->key))) return status;

    if ((ret = gnutls_cipher_tag(key_data(params->key)->cipher, params->tag, params->len)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }
    return STATUS_SUCCESS;
}

NTSTATUS key_symmetric_destroy_gnu(struct key* args)
{
    struct key* key = args;

    if (key_data(key)->cipher) gnutls_cipher_deinit(key_data(key)->cipher);
    return STATUS_SUCCESS;
}

static ULONG export_gnutls_datum(UCHAR* buffer, ULONG buflen, gnutls_datum_t* d, BOOL zero_pad)
{
    ULONG size = d->size;
    UCHAR* src = d->data;
    ULONG offset = 0;

    assert(size <= buflen + 1);
    if (size == buflen + 1)
    {
        assert(!src[0]);
        src++;
        size--;
    }
    if (zero_pad)
    {
        offset = buflen - size;
        if (buffer) memset(buffer, 0, offset);
        size = buflen;
    }

    if (buffer) memcpy(buffer + offset, src, size - offset);
    return size;
}

#define EXPORT_SIZE(d,l,p) export_gnutls_datum( NULL, l, &d, p )

static NTSTATUS key_export_rsa_public(struct key* key, UCHAR* buf, ULONG len, ULONG* ret_len)
{
    BCRYPT_RSAKEY_BLOB* rsa_blob = (BCRYPT_RSAKEY_BLOB*)buf;
    gnutls_datum_t m, e;
    ULONG size = key->u.a.bitlen / 8;
    UCHAR* dst;
    int ret;

    if (key_data(key)->a.pubkey)
        ret = gnutls_pubkey_export_rsa_raw(key_data(key)->a.pubkey, &m, &e);
    else
        return STATUS_INVALID_PARAMETER;

    if (ret)
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    *ret_len = sizeof(*rsa_blob) + EXPORT_SIZE(e, size, 0) + EXPORT_SIZE(m, size, 1);
    if (len >= *ret_len && buf)
    {
        dst = (UCHAR*)(rsa_blob + 1);
        rsa_blob->cbPublicExp = export_gnutls_datum(dst, size, &e, 0);

        dst += rsa_blob->cbPublicExp;
        rsa_blob->cbModulus = export_gnutls_datum(dst, size, &m, 1);

        rsa_blob->Magic = BCRYPT_RSAPUBLIC_MAGIC;
        rsa_blob->BitLength = key->u.a.bitlen;
        rsa_blob->cbPrime1 = 0;
        rsa_blob->cbPrime2 = 0;
    }

    free(e.data); free(m.data);
    return STATUS_SUCCESS;
}

static NTSTATUS key_export_ecc_public(struct key* key, UCHAR* buf, ULONG len, ULONG* ret_len)
{
    BCRYPT_ECCKEY_BLOB* ecc_blob = (BCRYPT_ECCKEY_BLOB*)buf;
    gnutls_ecc_curve_t curve;
    gnutls_datum_t x, y;
    DWORD magic, size;
    UCHAR* dst;
    int ret;

    switch (key->alg_id)
    {
    case ALG_ID_ECDH_P256:
        magic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
        size = 32;
        break;

    case ALG_ID_ECDH_P384:
        magic = BCRYPT_ECDH_PUBLIC_P384_MAGIC;
        size = 48;
        break;

    case ALG_ID_ECDSA_P256:
        magic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
        size = 32;
        break;

    case ALG_ID_ECDSA_P384:
        magic = BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
        size = 48;
        break;

    default:
        return STATUS_NOT_IMPLEMENTED;
    }

    if (key_data(key)->a.pubkey)
        ret = gnutls_pubkey_export_ecc_raw(key_data(key)->a.pubkey, &curve, &x, &y);
    else
        return STATUS_INVALID_PARAMETER;

    if (ret)
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    if (curve != GNUTLS_ECC_CURVE_SECP256R1 && curve != GNUTLS_ECC_CURVE_SECP384R1)
    {
        free(x.data); free(y.data);
        return STATUS_NOT_IMPLEMENTED;
    }

    *ret_len = sizeof(*ecc_blob) + EXPORT_SIZE(x, size, 1) + EXPORT_SIZE(y, size, 1);
    if (len >= *ret_len && buf)
    {
        ecc_blob->dwMagic = magic;
        ecc_blob->cbKey = size;

        dst = (UCHAR*)(ecc_blob + 1);
        dst += export_gnutls_datum(dst, size, &x, 1);
        export_gnutls_datum(dst, size, &y, 1);
    }

    free(x.data); free(y.data);
    return STATUS_SUCCESS;
}

static NTSTATUS key_export_dsa_public(struct key* key, UCHAR* buf, ULONG len, ULONG* ret_len)
{
    BCRYPT_DSA_KEY_BLOB* dsa_blob = (BCRYPT_DSA_KEY_BLOB*)buf;
    gnutls_datum_t p, q, g, y;
    ULONG size = key->u.a.bitlen / 8;
    NTSTATUS status = STATUS_SUCCESS;
    UCHAR* dst;
    int ret;

    if (key->u.a.bitlen > 1024)
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    if (key_data(key)->a.pubkey)
        ret = gnutls_pubkey_export_dsa_raw(key_data(key)->a.pubkey, &p, &q, &g, &y);
    else
        return STATUS_INVALID_PARAMETER;

    if (ret)
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    if (EXPORT_SIZE(q, sizeof(dsa_blob->q), 1) > sizeof(dsa_blob->q))
    {
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }

    *ret_len = sizeof(*dsa_blob) + EXPORT_SIZE(p, size, 1) + EXPORT_SIZE(g, size, 1) + EXPORT_SIZE(y, size, 1);
    if (len >= *ret_len && buf)
    {
        dst = (UCHAR*)(dsa_blob + 1);
        dst += export_gnutls_datum(dst, size, &p, 1);
        dst += export_gnutls_datum(dst, size, &g, 1);
        export_gnutls_datum(dst, size, &y, 1);

        dst = dsa_blob->q;
        export_gnutls_datum(dst, sizeof(dsa_blob->q), &q, 1);

        dsa_blob->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC;
        dsa_blob->cbKey = size;
        memset(dsa_blob->Count, 0, sizeof(dsa_blob->Count)); /* FIXME */
        memset(dsa_blob->Seed, 0, sizeof(dsa_blob->Seed)); /* FIXME */
    }

done:
    free(p.data); free(q.data); free(g.data); free(y.data);
    return status;
}

static void reverse_bytes(UCHAR* buf, ULONG len)
{
    unsigned int i;
    UCHAR tmp;

    for (i = 0; i < len / 2; ++i)
    {
        tmp = buf[i];
        buf[i] = buf[len - i - 1];
        buf[len - i - 1] = tmp;
    }
}

#define Q_SIZE 20
static NTSTATUS key_export_dsa_capi_public(struct key* key, UCHAR* buf, ULONG len, ULONG* ret_len)
{
    BLOBHEADER* hdr = (BLOBHEADER*)buf;
    DSSPUBKEY* dsskey;
    gnutls_datum_t p, q, g, y;
    ULONG size = key->u.a.bitlen / 8;
    NTSTATUS status = STATUS_SUCCESS;
    UCHAR* dst;
    int ret;

    if (key->u.a.bitlen > 1024)
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    if (key_data(key)->a.pubkey)
        ret = gnutls_pubkey_export_dsa_raw(key_data(key)->a.pubkey, &p, &q, &g, &y);
    else if (key_data(key)->a.privkey)
        ret = gnutls_privkey_export_dsa_raw(key_data(key)->a.privkey, &p, &q, &g, &y, NULL);
    else
        return STATUS_INVALID_PARAMETER;

    if (ret)
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    if (EXPORT_SIZE(q, Q_SIZE, 1) > Q_SIZE)
    {
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }

    *ret_len = sizeof(*hdr) + sizeof(*dsskey) + sizeof(key->u.a.dss_seed) +
        EXPORT_SIZE(p, size, 1) + Q_SIZE + EXPORT_SIZE(g, size, 1) + EXPORT_SIZE(y, size, 1);
    if (len >= *ret_len && buf)
    {
        hdr->bType = PUBLICKEYBLOB;
        hdr->bVersion = 2;
        hdr->reserved = 0;
        hdr->aiKeyAlg = CALG_DSS_SIGN;

        dsskey = (DSSPUBKEY*)(hdr + 1);
        dsskey->magic = MAGIC_DSS1;
        dsskey->bitlen = key->u.a.bitlen;

        dst = (UCHAR*)(dsskey + 1);
        export_gnutls_datum(dst, size, &p, 1);
        reverse_bytes(dst, size);
        dst += size;

        export_gnutls_datum(dst, Q_SIZE, &q, 1);
        reverse_bytes(dst, Q_SIZE);
        dst += Q_SIZE;

        export_gnutls_datum(dst, size, &g, 1);
        reverse_bytes(dst, size);
        dst += size;

        export_gnutls_datum(dst, size, &y, 1);
        reverse_bytes(dst, size);
        dst += size;

        memcpy(dst, &key->u.a.dss_seed, sizeof(key->u.a.dss_seed));
    }

done:
    free(p.data); free(q.data); free(g.data); free(y.data);
    return status;
}

static gnutls_privkey_t create_privkey(gnutls_pk_algorithm_t pk_alg, unsigned int bitlen,
    const gnutls_keygen_data_st* data, unsigned int data_size)
{
    gnutls_privkey_t privkey;
    int ret;

    if ((ret = gnutls_privkey_init(&privkey)))
    {
        gnutls_perror(ret);
        return NULL;
    }

    if ((ret = gnutls_privkey_generate2(privkey, pk_alg, bitlen, 0, data, data_size)))
    {
        gnutls_perror(ret);
        gnutls_privkey_deinit(privkey);
        return NULL;
    }

    return privkey;
}

static gnutls_pubkey_t create_pubkey_from_privkey(gnutls_privkey_t privkey)
{
    gnutls_pubkey_t pubkey;
    int ret;

    if ((ret = gnutls_pubkey_init(&pubkey)))
    {
        gnutls_perror(ret);
        return NULL;
    }

    if ((ret = gnutls_pubkey_import_privkey(pubkey, privkey, 0, 0)))
    {
        gnutls_perror(ret);
        gnutls_pubkey_deinit(pubkey);
        return NULL;
    }

    return pubkey;
}

static gnutls_dh_params_t get_dh_params(gnutls_privkey_t privkey)
{
    gnutls_dh_params_t params;
    gnutls_datum_t x;
    int ret;

    if ((ret = gnutls_dh_params_init(&params)))
    {
        gnutls_perror(ret);
        return NULL;
    }

    if ((ret = gnutls_privkey_export_dh_raw(privkey, params, NULL, &x, 0)))
    {
        gnutls_perror(ret);
        gnutls_dh_params_deinit(params);
        return NULL;
    }

    free(x.data);
    return params;
}

NTSTATUS key_asymmetric_generate_gnu(struct key* args)
{
    struct key* key = args;
    gnutls_pk_algorithm_t pk_alg;
    gnutls_privkey_t privkey;
    gnutls_pubkey_t pubkey;
    unsigned int bitlen;

    if (key_data(key)->a.privkey) return STATUS_INVALID_HANDLE;

    switch (key->alg_id)
    {
    case ALG_ID_RSA:
    case ALG_ID_RSA_SIGN:
        pk_alg = GNUTLS_PK_RSA;
        bitlen = key->u.a.bitlen;
        break;

    case ALG_ID_DH:
        pk_alg = GNUTLS_PK_DH;
        bitlen = key->u.a.bitlen;
        break;

    case ALG_ID_DSA:
        pk_alg = GNUTLS_PK_DSA;
        bitlen = key->u.a.bitlen;
        break;

    case ALG_ID_ECDH_P256:
    case ALG_ID_ECDSA_P256:
        pk_alg = GNUTLS_PK_ECC; /* compatible with ECDSA and ECDH */
        bitlen = GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1);
        break;

    case ALG_ID_ECDH_P384:
    case ALG_ID_ECDSA_P384:
        pk_alg = GNUTLS_PK_ECC; /* compatible with ECDSA and ECDH */
        bitlen = GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP384R1);
        break;

    default:
        return STATUS_NOT_SUPPORTED;
    }

    if (key->alg_id == ALG_ID_DH && key_data(key)->a.dh_params)
    {
        gnutls_keygen_data_st data;

        data.type = GNUTLS_KEYGEN_DH;
        data.data = (unsigned char*)key_data(key)->a.dh_params;
        data.size = 0;
        if (!(privkey = create_privkey(pk_alg, bitlen, &data, 1))) return STATUS_INTERNAL_ERROR;
    }
    else if (!(privkey = create_privkey(pk_alg, bitlen, NULL, 0))) return STATUS_INTERNAL_ERROR;

    if (key->alg_id == ALG_ID_DH && !key_data(key)->a.dh_params &&
        !(key_data(key)->a.dh_params = get_dh_params(privkey)))
    {
        gnutls_privkey_deinit(privkey);
        return STATUS_INTERNAL_ERROR;
    }

    if (!(pubkey = create_pubkey_from_privkey(privkey)))
    {
        gnutls_privkey_deinit(privkey);
        return STATUS_INTERNAL_ERROR;
    }

    key_data(key)->a.privkey = privkey;
    key_data(key)->a.pubkey = pubkey;
    return STATUS_SUCCESS;
}

static NTSTATUS key_export_ecc(struct key* key, UCHAR* buf, ULONG len, ULONG* ret_len)
{
    BCRYPT_ECCKEY_BLOB* ecc_blob;
    gnutls_ecc_curve_t curve;
    gnutls_datum_t x, y, d;
    DWORD magic, size;
    UCHAR* dst;
    int ret;

    switch (key->alg_id)
    {
    case ALG_ID_ECDH_P256:
        magic = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
        size = 32;
        break;

    case ALG_ID_ECDH_P384:
        magic = BCRYPT_ECDH_PRIVATE_P384_MAGIC;
        size = 48;
        break;

    case ALG_ID_ECDSA_P256:
        magic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
        size = 32;
        break;

    case ALG_ID_ECDSA_P384:
        magic = BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
        size = 48;
        break;

    default:
        return STATUS_NOT_IMPLEMENTED;
    }

    if (!key_data(key)->a.privkey) return STATUS_INVALID_PARAMETER;

    if ((ret = gnutls_privkey_export_ecc_raw(key_data(key)->a.privkey, &curve, &x, &y, &d)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    if (curve != GNUTLS_ECC_CURVE_SECP256R1 && curve != GNUTLS_ECC_CURVE_SECP384R1)
    {
        free(x.data); free(y.data); free(d.data);
        return STATUS_NOT_IMPLEMENTED;
    }

    *ret_len = sizeof(*ecc_blob) + EXPORT_SIZE(x, size, 1) + EXPORT_SIZE(y, size, 1) + EXPORT_SIZE(d, size, 1);
    if (len >= *ret_len && buf)
    {
        ecc_blob = (BCRYPT_ECCKEY_BLOB*)buf;
        ecc_blob->dwMagic = magic;
        ecc_blob->cbKey = size;

        dst = (UCHAR*)(ecc_blob + 1);
        dst += export_gnutls_datum(dst, size, &x, 1);
        dst += export_gnutls_datum(dst, size, &y, 1);
        export_gnutls_datum(dst, size, &d, 1);
    }

    free(x.data); free(y.data); free(d.data);
    return STATUS_SUCCESS;
}

static NTSTATUS key_import_ecc(struct key* key, UCHAR* buf, ULONG len)
{
    BCRYPT_ECCKEY_BLOB* ecc_blob;
    gnutls_ecc_curve_t curve;
    gnutls_privkey_t handle;
    gnutls_datum_t x, y, k;
    int ret;

    switch (key->alg_id)
    {
    case ALG_ID_ECDH_P256:
    case ALG_ID_ECDSA_P256:
        curve = GNUTLS_ECC_CURVE_SECP256R1;
        break;

    case ALG_ID_ECDH_P384:
    case ALG_ID_ECDSA_P384:
        curve = GNUTLS_ECC_CURVE_SECP384R1;
        break;

    default:
        return STATUS_NOT_IMPLEMENTED;
    }

    if ((ret = gnutls_privkey_init(&handle)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    ecc_blob = (BCRYPT_ECCKEY_BLOB*)buf;
    x.data = (unsigned char*)(ecc_blob + 1);
    x.size = ecc_blob->cbKey;
    y.data = x.data + ecc_blob->cbKey;
    y.size = ecc_blob->cbKey;
    k.data = y.data + ecc_blob->cbKey;
    k.size = ecc_blob->cbKey;

    if ((ret = gnutls_privkey_import_ecc_raw(handle, curve, &x, &y, &k)))
    {
        gnutls_perror(ret);
        gnutls_privkey_deinit(handle);
        return STATUS_INTERNAL_ERROR;
    }

    if (key_data(key)->a.privkey) gnutls_privkey_deinit(key_data(key)->a.privkey);
    key_data(key)->a.privkey = handle;
    return STATUS_SUCCESS;
}

static NTSTATUS key_export_rsa(struct key* key, ULONG flags, UCHAR* buf, ULONG len, ULONG* ret_len)
{
    BCRYPT_RSAKEY_BLOB* rsa_blob;
    gnutls_datum_t m, e, d, p, q, u, e1, e2;
    ULONG size = key->u.a.bitlen / 8;
    BOOL full = (flags & KEY_EXPORT_FLAG_RSA_FULL);
    UCHAR* dst;
    int ret;

    if (!key_data(key)->a.privkey) return STATUS_INVALID_PARAMETER;

    if ((ret = gnutls_privkey_export_rsa_raw(key_data(key)->a.privkey, &m, &e, &d, &p, &q, &u, &e1, &e2)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    *ret_len = sizeof(*rsa_blob) + EXPORT_SIZE(e, size, 0) + EXPORT_SIZE(m, size, 1) +
        EXPORT_SIZE(p, size / 2, 1) + EXPORT_SIZE(q, size / 2, 1);

    if (full) *ret_len += EXPORT_SIZE(e1, size / 2, 1) + EXPORT_SIZE(e2, size / 2, 1) +
        EXPORT_SIZE(u, size / 2, 1) + EXPORT_SIZE(d, size, 1);

    if (len >= *ret_len && buf)
    {
        rsa_blob = (BCRYPT_RSAKEY_BLOB*)buf;
        rsa_blob->Magic = full ? BCRYPT_RSAFULLPRIVATE_MAGIC : BCRYPT_RSAPRIVATE_MAGIC;
        rsa_blob->BitLength = key->u.a.bitlen;

        dst = (UCHAR*)(rsa_blob + 1);
        rsa_blob->cbPublicExp = export_gnutls_datum(dst, size, &e, 0);

        dst += rsa_blob->cbPublicExp;
        rsa_blob->cbModulus = export_gnutls_datum(dst, size, &m, 1);

        dst += rsa_blob->cbModulus;
        rsa_blob->cbPrime1 = export_gnutls_datum(dst, size / 2, &p, 1);

        dst += rsa_blob->cbPrime1;
        rsa_blob->cbPrime2 = export_gnutls_datum(dst, size / 2, &q, 1);

        if (full)
        {
            dst += rsa_blob->cbPrime2;
            export_gnutls_datum(dst, size / 2, &e1, 1);

            dst += rsa_blob->cbPrime1;
            export_gnutls_datum(dst, size / 2, &e2, 1);

            dst += rsa_blob->cbPrime2;
            export_gnutls_datum(dst, size / 2, &u, 1);

            dst += rsa_blob->cbPrime1;
            export_gnutls_datum(dst, size, &d, 1);
        }
    }

    free(m.data); free(e.data); free(d.data); free(p.data); free(q.data); free(u.data);
    free(e1.data); free(e2.data);
    return STATUS_SUCCESS;
}

static NTSTATUS key_import_rsa(struct key* key, UCHAR* buf, ULONG len)
{
    BCRYPT_RSAKEY_BLOB* rsa_blob = (BCRYPT_RSAKEY_BLOB*)buf;
    gnutls_datum_t m, e, p, q;
    gnutls_privkey_t handle;
    int ret;

    if ((ret = gnutls_privkey_init(&handle)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    e.data = (unsigned char*)(rsa_blob + 1);
    e.size = rsa_blob->cbPublicExp;
    m.data = e.data + e.size;
    m.size = rsa_blob->cbModulus;
    p.data = m.data + m.size;
    p.size = rsa_blob->cbPrime1;
    q.data = p.data + p.size;
    q.size = rsa_blob->cbPrime2;

    if ((ret = gnutls_privkey_import_rsa_raw(handle, &m, &e, NULL, &p, &q, NULL, NULL, NULL)))
    {
        gnutls_perror(ret);
        gnutls_privkey_deinit(handle);
        return STATUS_INTERNAL_ERROR;
    }

    if (key_data(key)->a.privkey) gnutls_privkey_deinit(key_data(key)->a.privkey);
    key_data(key)->a.privkey = handle;
    return STATUS_SUCCESS;
}

static NTSTATUS key_export_dsa_capi(struct key* key, UCHAR* buf, ULONG len, ULONG* ret_len)
{
    BLOBHEADER* hdr;
    DSSPUBKEY* pubkey;
    gnutls_datum_t p, q, g, y, x;
    ULONG size = key->u.a.bitlen / 8;
    UCHAR* dst;
    int ret;

    if (!key_data(key)->a.privkey) return STATUS_INVALID_PARAMETER;

    if ((ret = gnutls_privkey_export_dsa_raw(key_data(key)->a.privkey, &p, &q, &g, &y, &x)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    if (q.size > 21 || x.size > 21)
    {
        free(p.data); free(q.data); free(g.data); free(y.data); free(x.data);
        return STATUS_NOT_SUPPORTED;
    }

    *ret_len = sizeof(*hdr) + sizeof(*pubkey) + sizeof(key->u.a.dss_seed) +
        EXPORT_SIZE(p, size, 1) + 20 + EXPORT_SIZE(g, size, 1) + 20;
    if (len >= *ret_len && buf)
    {
        hdr = (BLOBHEADER*)buf;
        hdr->bType = PRIVATEKEYBLOB;
        hdr->bVersion = 2;
        hdr->reserved = 0;
        hdr->aiKeyAlg = CALG_DSS_SIGN;

        pubkey = (DSSPUBKEY*)(hdr + 1);
        pubkey->magic = MAGIC_DSS2;
        pubkey->bitlen = key->u.a.bitlen;

        dst = (UCHAR*)(pubkey + 1);
        export_gnutls_datum(dst, size, &p, 1);
        reverse_bytes(dst, size);
        dst += size;

        export_gnutls_datum(dst, 20, &q, 1);
        reverse_bytes(dst, 20);
        dst += 20;

        export_gnutls_datum(dst, size, &g, 1);
        reverse_bytes(dst, size);
        dst += size;

        export_gnutls_datum(dst, 20, &x, 1);
        reverse_bytes(dst, 20);
        dst += 20;

        memcpy(dst, &key->u.a.dss_seed, sizeof(key->u.a.dss_seed));
    }

    free(p.data); free(q.data); free(g.data); free(y.data); free(x.data);
    return STATUS_SUCCESS;
}

static NTSTATUS key_import_dsa_capi(struct key* key, UCHAR* buf, ULONG len)
{
    BLOBHEADER* hdr = (BLOBHEADER*)buf;
    DSSPUBKEY* pubkey;
    gnutls_privkey_t handle;
    gnutls_datum_t p, q, g, x;
    unsigned char* data, p_data[128], q_data[20], g_data[128], x_data[20];
    int i, ret, size;

    if ((ret = gnutls_privkey_init(&handle)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    pubkey = (DSSPUBKEY*)(hdr + 1);
    if ((size = pubkey->bitlen / 8) > sizeof(p_data))
    {
        gnutls_privkey_deinit(handle);
        return STATUS_NOT_SUPPORTED;
    }
    data = (unsigned char*)(pubkey + 1);

    p.data = p_data;
    p.size = size;
    for (i = 0; i < p.size; i++) p.data[i] = data[p.size - i - 1];
    data += p.size;

    q.data = q_data;
    q.size = sizeof(q_data);
    for (i = 0; i < q.size; i++) q.data[i] = data[q.size - i - 1];
    data += q.size;

    g.data = g_data;
    g.size = size;
    for (i = 0; i < g.size; i++) g.data[i] = data[g.size - i - 1];
    data += g.size;

    x.data = x_data;
    x.size = sizeof(x_data);
    for (i = 0; i < x.size; i++) x.data[i] = data[x.size - i - 1];
    data += x.size;

    if ((ret = gnutls_privkey_import_dsa_raw(handle, &p, &q, &g, NULL, &x)))
    {
        gnutls_perror(ret);
        gnutls_privkey_deinit(handle);
        return STATUS_INTERNAL_ERROR;
    }

    memcpy(&key->u.a.dss_seed, data, sizeof(key->u.a.dss_seed));

    if (key_data(key)->a.privkey) gnutls_privkey_deinit(key_data(key)->a.privkey);
    key_data(key)->a.privkey = handle;
    return STATUS_SUCCESS;
}

static NTSTATUS key_import_ecc_public(struct key* key, UCHAR* buf, ULONG len)
{
    BCRYPT_ECCKEY_BLOB* ecc_blob;
    gnutls_ecc_curve_t curve;
    gnutls_datum_t x, y;
    gnutls_pubkey_t handle;
    int ret;

    switch (key->alg_id)
    {
    case ALG_ID_ECDH_P256:
    case ALG_ID_ECDSA_P256:
        curve = GNUTLS_ECC_CURVE_SECP256R1; break;

    case ALG_ID_ECDH_P384:
    case ALG_ID_ECDSA_P384:
        curve = GNUTLS_ECC_CURVE_SECP384R1; break;

    default:
        return STATUS_NOT_IMPLEMENTED;
    }

    if ((ret = gnutls_pubkey_init(&handle)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    ecc_blob = (BCRYPT_ECCKEY_BLOB*)buf;
    x.data = buf + sizeof(*ecc_blob);
    x.size = ecc_blob->cbKey;
    y.data = buf + sizeof(*ecc_blob) + ecc_blob->cbKey;
    y.size = ecc_blob->cbKey;

    if ((ret = gnutls_pubkey_import_ecc_raw(handle, curve, &x, &y)))
    {
        gnutls_perror(ret);
        gnutls_pubkey_deinit(handle);
        return STATUS_INTERNAL_ERROR;
    }

    if (key_data(key)->a.pubkey) gnutls_pubkey_deinit(key_data(key)->a.pubkey);
    key_data(key)->a.pubkey = handle;
    return STATUS_SUCCESS;
}

static NTSTATUS key_import_rsa_public(struct key* key, UCHAR* buf, ULONG len)
{
    BCRYPT_RSAKEY_BLOB* rsa_blob;
    gnutls_pubkey_t handle;
    gnutls_datum_t m, e;
    int ret;

    if ((ret = gnutls_pubkey_init(&handle)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    rsa_blob = (BCRYPT_RSAKEY_BLOB*)buf;
    e.data = buf + sizeof(*rsa_blob);
    e.size = rsa_blob->cbPublicExp;
    m.data = buf + sizeof(*rsa_blob) + rsa_blob->cbPublicExp;
    m.size = rsa_blob->cbModulus;

    if ((ret = gnutls_pubkey_import_rsa_raw(handle, &m, &e)))
    {
        gnutls_perror(ret);
        gnutls_pubkey_deinit(handle);
        return STATUS_INTERNAL_ERROR;
    }

    if (key_data(key)->a.pubkey) gnutls_pubkey_deinit(key_data(key)->a.pubkey);
    key_data(key)->a.pubkey = handle;
    return STATUS_SUCCESS;
}

static NTSTATUS key_import_dsa_public(struct key* key, UCHAR* buf, ULONG len)
{
    BCRYPT_DSA_KEY_BLOB* dsa_blob;
    gnutls_datum_t p, q, g, y;
    gnutls_pubkey_t handle;
    int ret;

    if ((ret = gnutls_pubkey_init(&handle)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    dsa_blob = (BCRYPT_DSA_KEY_BLOB*)buf;
    p.data = buf + sizeof(*dsa_blob);
    p.size = dsa_blob->cbKey;
    q.data = dsa_blob->q;
    q.size = sizeof(dsa_blob->q);
    g.data = buf + sizeof(*dsa_blob) + dsa_blob->cbKey;
    g.size = dsa_blob->cbKey;
    y.data = buf + sizeof(*dsa_blob) + dsa_blob->cbKey * 2;
    y.size = dsa_blob->cbKey;

    if ((ret = gnutls_pubkey_import_dsa_raw(handle, &p, &q, &g, &y)))
    {
        gnutls_perror(ret);
        gnutls_pubkey_deinit(handle);
        return STATUS_INTERNAL_ERROR;
    }

    if (key_data(key)->a.pubkey) gnutls_pubkey_deinit(key_data(key)->a.pubkey);
    key_data(key)->a.pubkey = handle;
    return STATUS_SUCCESS;
}

static NTSTATUS key_import_dsa_capi_public(struct key* key, UCHAR* buf, ULONG len)
{
    BLOBHEADER* hdr;
    DSSPUBKEY* pubkey;
    gnutls_datum_t p, q, g, y;
    gnutls_pubkey_t handle;
    unsigned char* data, p_data[128], q_data[20], g_data[128], y_data[128];
    int i, ret, size;

    if ((ret = gnutls_pubkey_init(&handle)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    hdr = (BLOBHEADER*)buf;
    pubkey = (DSSPUBKEY*)(hdr + 1);
    size = pubkey->bitlen / 8;
    data = (unsigned char*)(pubkey + 1);

    p.data = p_data;
    p.size = size;
    for (i = 0; i < p.size; i++) p.data[i] = data[p.size - i - 1];
    data += p.size;

    q.data = q_data;
    q.size = sizeof(q_data);
    for (i = 0; i < q.size; i++) q.data[i] = data[q.size - i - 1];
    data += q.size;

    g.data = g_data;
    g.size = size;
    for (i = 0; i < g.size; i++) g.data[i] = data[g.size - i - 1];
    data += g.size;

    y.data = y_data;
    y.size = sizeof(y_data);
    for (i = 0; i < y.size; i++) y.data[i] = data[y.size - i - 1];

    if ((ret = gnutls_pubkey_import_dsa_raw(handle, &p, &q, &g, &y)))
    {
        gnutls_perror(ret);
        gnutls_pubkey_deinit(handle);
        return STATUS_INTERNAL_ERROR;
    }

    if (key_data(key)->a.pubkey) gnutls_pubkey_deinit(key_data(key)->a.pubkey);
    key_data(key)->a.pubkey = handle;
    return STATUS_SUCCESS;
}

static NTSTATUS key_export_dh_public(struct key* key, UCHAR* buf, ULONG len, ULONG* ret_len)
{
    BCRYPT_DH_KEY_BLOB* dh_blob = (BCRYPT_DH_KEY_BLOB*)buf;
    ULONG size = key->u.a.bitlen / 8;
    gnutls_dh_params_t params;
    gnutls_datum_t p, g, y;
    UCHAR* dst;
    int ret = GNUTLS_E_INVALID_REQUEST;

    if ((ret = gnutls_dh_params_init(&params)) < 0)
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    if ((ret = gnutls_pubkey_export_dh_raw(key_data(key)->a.pubkey, params, &y, 0)))
    {
        gnutls_perror(ret);
        gnutls_dh_params_deinit(params);
        return STATUS_INTERNAL_ERROR;
    }

    if ((ret = gnutls_dh_params_export_raw(params, &p, &g, NULL)) < 0)
    {
        gnutls_perror(ret);
        free(y.data);
        gnutls_dh_params_deinit(params);
        return STATUS_INTERNAL_ERROR;
    }

    *ret_len = sizeof(*dh_blob) + EXPORT_SIZE(p, size, 1) + EXPORT_SIZE(g, size, 1) + EXPORT_SIZE(y, size, 1);
    if (len >= *ret_len && buf)
    {
        dst = (UCHAR*)(dh_blob + 1);
        dst += export_gnutls_datum(dst, size, &p, 1);
        dst += export_gnutls_datum(dst, size, &g, 1);
        dst += export_gnutls_datum(dst, size, &y, 1);

        dh_blob->dwMagic = BCRYPT_DH_PUBLIC_MAGIC;
        dh_blob->cbKey = size;
    }

    free(p.data); free(g.data); free(y.data);
    return STATUS_SUCCESS;
}

static NTSTATUS key_export_dh(struct key* key, UCHAR* buf, ULONG len, ULONG* ret_len)
{
    BCRYPT_DH_KEY_BLOB* dh_blob = (BCRYPT_DH_KEY_BLOB*)buf;
    gnutls_datum_t p, g, y, x;
    gnutls_dh_params_t params;
    ULONG size = key->u.a.bitlen / 8;
    UCHAR* dst;
    int ret;

    if (!key_data(key)->a.privkey) return STATUS_INVALID_PARAMETER;

    if ((ret = gnutls_dh_params_init(&params)) < 0)
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    if ((ret = gnutls_privkey_export_dh_raw(key_data(key)->a.privkey, params, &y, &x, 0)))
    {
        gnutls_perror(ret);
        gnutls_dh_params_deinit(params);
        return STATUS_INTERNAL_ERROR;
    }

    if ((ret = gnutls_dh_params_export_raw(params, &p, &g, NULL)) < 0)
    {
        gnutls_perror(ret);
        free(y.data); free(x.data);
        gnutls_dh_params_deinit(params);
        return STATUS_INTERNAL_ERROR;
    }

    *ret_len = sizeof(*dh_blob) + EXPORT_SIZE(p, size, 1) + EXPORT_SIZE(g, size, 1) +
        EXPORT_SIZE(y, size, 1) + EXPORT_SIZE(x, size, 1);
    if (len >= *ret_len && buf)
    {
        dst = (UCHAR*)(dh_blob + 1);
        dst += export_gnutls_datum(dst, size, &p, 1);
        dst += export_gnutls_datum(dst, size, &g, 1);
        dst += export_gnutls_datum(dst, size, &y, 1);
        dst += export_gnutls_datum(dst, size, &x, 1);

        dh_blob->dwMagic = BCRYPT_DH_PRIVATE_MAGIC;
        dh_blob->cbKey = size;
    }

    free(p.data); free(g.data); free(y.data); free(x.data);
    gnutls_dh_params_deinit(params);
    return STATUS_SUCCESS;
}

static NTSTATUS key_export_dh_params(struct key* key, UCHAR* buf, ULONG len, ULONG* ret_len)
{
    BCRYPT_DH_PARAMETER_HEADER* hdr = (BCRYPT_DH_PARAMETER_HEADER*)buf;
    unsigned int size = sizeof(*hdr) + key->u.a.bitlen / 8 * 2;
    gnutls_datum_t p, g;
    NTSTATUS status = STATUS_SUCCESS;
    UCHAR* dst;
    int ret;

    if (!key_data(key)->a.dh_params) return STATUS_INVALID_PARAMETER;

    if ((ret = gnutls_dh_params_export_raw(key_data(key)->a.dh_params, &p, &g, NULL)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    *ret_len = size;
    if (len < size) status = STATUS_BUFFER_TOO_SMALL;
    else if (buf)
    {
        hdr->cbLength = size;
        hdr->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;
        hdr->cbKeyLength = key->u.a.bitlen / 8;

        dst = (UCHAR*)(hdr + 1);
        dst += export_gnutls_datum(dst, hdr->cbKeyLength, &p, 1);
        dst += export_gnutls_datum(dst, hdr->cbKeyLength, &g, 1);
    }

    free(p.data); free(g.data);
    return status;
}

NTSTATUS key_asymmetric_export_gnu(struct key_asymmetric_export_params* args)
{
    const struct key_asymmetric_export_params* params = args;
    struct key* key = params->key;
    unsigned flags = params->flags;

    if (!(key->u.a.flags & KEY_FLAG_FINALIZED)) return STATUS_INVALID_HANDLE;

    switch (key->alg_id)
    {
    case ALG_ID_ECDH_P256:
    case ALG_ID_ECDH_P384:
    case ALG_ID_ECDSA_P256:
    case ALG_ID_ECDSA_P384:
        if (flags & KEY_EXPORT_FLAG_PUBLIC)
            return key_export_ecc_public(key, params->buf, params->len, params->ret_len);
        return key_export_ecc(key, params->buf, params->len, params->ret_len);

    case ALG_ID_RSA:
    case ALG_ID_RSA_SIGN:
        if (flags & KEY_EXPORT_FLAG_PUBLIC)
            return key_export_rsa_public(key, params->buf, params->len, params->ret_len);
        return key_export_rsa(key, flags, params->buf, params->len, params->ret_len);

    case ALG_ID_DSA:
        if (flags & KEY_EXPORT_FLAG_PUBLIC)
        {
            if (key->u.a.flags & KEY_FLAG_LEGACY_DSA_V2)
                return key_export_dsa_capi_public(key, params->buf, params->len, params->ret_len);
            return key_export_dsa_public(key, params->buf, params->len, params->ret_len);
        }
        if (key->u.a.flags & KEY_FLAG_LEGACY_DSA_V2)
            return key_export_dsa_capi(key, params->buf, params->len, params->ret_len);
        return STATUS_NOT_IMPLEMENTED;

    case ALG_ID_DH:
        if (flags & KEY_EXPORT_FLAG_DH_PARAMETERS)
            return key_export_dh_params(key, params->buf, params->len, params->ret_len);
        if (flags & KEY_EXPORT_FLAG_PUBLIC)
            return key_export_dh_public(key, params->buf, params->len, params->ret_len);
        return key_export_dh(key, params->buf, params->len, params->ret_len);

    default:
        return STATUS_NOT_IMPLEMENTED;
    }
}

static NTSTATUS key_import_dh_public(struct key* key, UCHAR* buf, ULONG len)
{
    BCRYPT_DH_KEY_BLOB* dh_blob;
    gnutls_dh_params_t params;
    gnutls_datum_t p, g, y;
    gnutls_pubkey_t handle;
    int ret;

    if ((ret = gnutls_pubkey_init(&handle)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    if ((ret = gnutls_dh_params_init(&params)) < 0)
    {
        gnutls_perror(ret);
        gnutls_pubkey_deinit(handle);
        return STATUS_INTERNAL_ERROR;
    }

    dh_blob = (BCRYPT_DH_KEY_BLOB*)buf;
    p.data = buf + sizeof(*dh_blob);
    p.size = dh_blob->cbKey;
    g.data = buf + sizeof(*dh_blob) + dh_blob->cbKey;
    g.size = dh_blob->cbKey;
    y.data = buf + sizeof(*dh_blob) + dh_blob->cbKey * 2;
    y.size = dh_blob->cbKey;

    if ((ret = gnutls_dh_params_import_raw(params, &p, &g)) < 0)
    {
        gnutls_perror(ret);
        gnutls_dh_params_deinit(params);
        gnutls_pubkey_deinit(handle);
        return STATUS_INTERNAL_ERROR;
    }

    if ((ret = gnutls_pubkey_import_dh_raw(handle, params, &y)))
    {
        gnutls_perror(ret);
        gnutls_dh_params_deinit(params);
        gnutls_pubkey_deinit(handle);
        return STATUS_INTERNAL_ERROR;
    }

    if (key_data(key)->a.pubkey) gnutls_pubkey_deinit(key_data(key)->a.pubkey);
    key_data(key)->a.pubkey = handle;

    if (key_data(key)->a.dh_params) gnutls_dh_params_deinit(key_data(key)->a.dh_params);
    key_data(key)->a.dh_params = params;
    return STATUS_SUCCESS;
}

static NTSTATUS key_import_dh(struct key* key, UCHAR* buf, ULONG len)
{
    BCRYPT_DH_KEY_BLOB* dh_blob;
    gnutls_dh_params_t params;
    gnutls_datum_t p, g, y, x;
    gnutls_privkey_t handle;
    int ret;

    if ((ret = gnutls_privkey_init(&handle)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    if ((ret = gnutls_dh_params_init(&params)) < 0)
    {
        gnutls_perror(ret);
        gnutls_privkey_deinit(handle);
        return STATUS_INTERNAL_ERROR;
    }

    dh_blob = (BCRYPT_DH_KEY_BLOB*)buf;
    p.data = buf + sizeof(*dh_blob);
    p.size = dh_blob->cbKey;
    g.data = buf + sizeof(*dh_blob) + dh_blob->cbKey;
    g.size = dh_blob->cbKey;
    y.data = buf + sizeof(*dh_blob) + dh_blob->cbKey * 2;
    y.size = dh_blob->cbKey;
    x.data = buf + sizeof(*dh_blob) + dh_blob->cbKey * 3;
    x.size = dh_blob->cbKey;

    if ((ret = gnutls_dh_params_import_raw(params, &p, &g)) < 0)
    {
        gnutls_perror(ret);
        gnutls_dh_params_deinit(params);
        gnutls_privkey_deinit(handle);
        return STATUS_INTERNAL_ERROR;
    }

    if ((ret = gnutls_privkey_import_dh_raw(handle, params, &y, &x)))
    {
        gnutls_perror(ret);
        gnutls_dh_params_deinit(params);
        gnutls_privkey_deinit(handle);
        return STATUS_INTERNAL_ERROR;
    }

    if (key_data(key)->a.privkey) gnutls_privkey_deinit(key_data(key)->a.privkey);
    key_data(key)->a.privkey = handle;

    if (key_data(key)->a.dh_params) gnutls_dh_params_deinit(key_data(key)->a.dh_params);
    key_data(key)->a.dh_params = params;
    return STATUS_SUCCESS;
}

static NTSTATUS key_import_dh_params(struct key* key, UCHAR* buf, ULONG len)
{
    BCRYPT_DH_PARAMETER_HEADER* dh_header = (BCRYPT_DH_PARAMETER_HEADER*)buf;
    gnutls_dh_params_t params;
    gnutls_datum_t p, g;
    int ret;

    if ((ret = gnutls_dh_params_init(&params)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    p.data = (unsigned char*)(dh_header + 1);
    p.size = dh_header->cbKeyLength;
    g.data = p.data + dh_header->cbKeyLength;
    g.size = dh_header->cbKeyLength;

    if ((ret = gnutls_dh_params_import_raw(params, &p, &g)))
    {
        gnutls_perror(ret);
        gnutls_dh_params_deinit(params);
        return STATUS_INTERNAL_ERROR;
    }

    if (key_data(key)->a.dh_params) gnutls_dh_params_deinit(key_data(key)->a.dh_params);
    key_data(key)->a.dh_params = params;
    return STATUS_SUCCESS;
}

NTSTATUS key_asymmetric_import_gnu(struct key_asymmetric_import_params* args)
{
    const struct key_asymmetric_import_params* params = args;
    struct key* key = params->key;
    unsigned flags = params->flags;
    gnutls_pubkey_t pubkey;
    NTSTATUS ret;

    switch (key->alg_id)
    {
    case ALG_ID_ECDH_P256:
    case ALG_ID_ECDH_P384:
    case ALG_ID_ECDSA_P256:
    case ALG_ID_ECDSA_P384:
        if (flags & KEY_IMPORT_FLAG_PUBLIC)
            return key_import_ecc_public(key, params->buf, params->len);
        ret = key_import_ecc(key, params->buf, params->len);
        break;

    case ALG_ID_RSA:
    case ALG_ID_RSA_SIGN:
        if (flags & KEY_IMPORT_FLAG_PUBLIC)
            return key_import_rsa_public(key, params->buf, params->len);
        ret = key_import_rsa(key, params->buf, params->len);
        break;

    case ALG_ID_DSA:
        if (flags & KEY_IMPORT_FLAG_PUBLIC)
        {
            if (key->u.a.flags & KEY_FLAG_LEGACY_DSA_V2)
                return key_import_dsa_capi_public(key, params->buf, params->len);
            return key_import_dsa_public(key, params->buf, params->len);
        }
        if (key->u.a.flags & KEY_FLAG_LEGACY_DSA_V2)
        {
            ret = key_import_dsa_capi(key, params->buf, params->len);
            break;
        }
        return STATUS_NOT_IMPLEMENTED;

    case ALG_ID_DH:
        if (flags & KEY_IMPORT_FLAG_DH_PARAMETERS)
            return key_import_dh_params(key, params->buf, params->len);
        if (flags & KEY_IMPORT_FLAG_PUBLIC)
            return key_import_dh_public(key, params->buf, params->len);
        ret = key_import_dh(key, params->buf, params->len);
        break;

    default:
        return STATUS_NOT_IMPLEMENTED;
    }

    if (ret) return ret;

    if ((ret = gnutls_pubkey_init(&pubkey)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    if (gnutls_pubkey_import_privkey(pubkey, key_data(params->key)->a.privkey, 0, 0))
    {
        /* Imported private key may be legitimately missing public key, so ignore the failure here. */
        gnutls_pubkey_deinit(pubkey);
    }
    else
    {
        if (key_data(key)->a.pubkey) gnutls_pubkey_deinit(key_data(key)->a.pubkey);
        key_data(key)->a.pubkey = pubkey;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS prepare_gnutls_signature_dsa(struct key* key, UCHAR* signature, ULONG signature_len,
    gnutls_datum_t* gnutls_signature)
{
    struct buffer buffer;
    DWORD r_len = signature_len / 2;
    DWORD s_len = r_len;
    BYTE* r = signature;
    BYTE* s = signature + r_len;

    buffer_init(&buffer);
    buffer_append_asn1_r_s(&buffer, r, r_len, s, s_len);
    if (buffer.error)
    {
        buffer_free(&buffer);
        return STATUS_NO_MEMORY;
    }

    gnutls_signature->data = buffer.buffer;
    gnutls_signature->size = buffer.pos;
    return STATUS_SUCCESS;
}

static NTSTATUS prepare_gnutls_signature_rsa(struct key* key, UCHAR* signature, ULONG signature_len,
    gnutls_datum_t* gnutls_signature)
{
    gnutls_signature->data = signature;
    gnutls_signature->size = signature_len;
    return STATUS_SUCCESS;
}

static NTSTATUS prepare_gnutls_signature(struct key* key, UCHAR* signature, ULONG signature_len,
    gnutls_datum_t* gnutls_signature)
{
    switch (key->alg_id)
    {
    case ALG_ID_ECDSA_P256:
    case ALG_ID_ECDSA_P384:
    case ALG_ID_DSA:
        return prepare_gnutls_signature_dsa(key, signature, signature_len, gnutls_signature);

    case ALG_ID_RSA:
    case ALG_ID_RSA_SIGN:
        return prepare_gnutls_signature_rsa(key, signature, signature_len, gnutls_signature);

    default:
        return STATUS_NOT_IMPLEMENTED;
    }
}

static gnutls_digest_algorithm_t get_digest_from_id(const WCHAR* alg_id)
{
    if (!wcscmp(alg_id, BCRYPT_SHA1_ALGORITHM))   return GNUTLS_DIG_SHA1;
    if (!wcscmp(alg_id, BCRYPT_SHA256_ALGORITHM)) return GNUTLS_DIG_SHA256;
    if (!wcscmp(alg_id, BCRYPT_SHA384_ALGORITHM)) return GNUTLS_DIG_SHA384;
    if (!wcscmp(alg_id, BCRYPT_SHA512_ALGORITHM)) return GNUTLS_DIG_SHA512;
    if (!wcscmp(alg_id, BCRYPT_MD2_ALGORITHM))    return GNUTLS_DIG_MD2;
    if (!wcscmp(alg_id, BCRYPT_MD5_ALGORITHM))    return GNUTLS_DIG_MD5;
    return GNUTLS_DIG_UNKNOWN;
}

static NTSTATUS pubkey_set_rsa_pss_params(gnutls_pubkey_t key, gnutls_digest_algorithm_t dig, unsigned int salt_size)
{
    gnutls_x509_spki_t spki;
    int ret;

    if (((ret = gnutls_x509_spki_init(&spki) < 0)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }
    gnutls_x509_spki_set_rsa_pss_params(spki, dig, salt_size);
    ret = gnutls_pubkey_set_spki(key, spki, 0);
    gnutls_x509_spki_deinit(spki);
    if (ret < 0)
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }
    return STATUS_SUCCESS;
}

NTSTATUS key_asymmetric_verify_gnu(struct key_asymmetric_verify_params* args)
{
#ifdef GNUTLS_VERIFY_ALLOW_BROKEN
    unsigned int verify_flags = GNUTLS_VERIFY_ALLOW_BROKEN;
#else
    unsigned int verify_flags = 0;
#endif
    const struct key_asymmetric_verify_params* params = args;
    struct key* key = params->key;
    unsigned flags = params->flags;
    gnutls_digest_algorithm_t hash_alg;
    gnutls_sign_algorithm_t sign_alg;
    gnutls_datum_t gnutls_hash, gnutls_signature;
    gnutls_pk_algorithm_t pk_alg;
    NTSTATUS status;
    int ret;

    switch (key->alg_id)
    {
    case ALG_ID_ECDSA_P256:
    case ALG_ID_ECDSA_P384:
    {
        
        /* only the hash size must match, not the actual hash function */
        switch (params->hash_len)
        {
        case 20: hash_alg = GNUTLS_DIG_SHA1; break;
        case 32: hash_alg = GNUTLS_DIG_SHA256; break;
        case 48: hash_alg = GNUTLS_DIG_SHA384; break;

        default:
            return STATUS_INVALID_SIGNATURE;
        }
        pk_alg = GNUTLS_PK_ECC;
        break;
    }
    case ALG_ID_RSA:
    case ALG_ID_RSA_SIGN:
    {
        if (flags & BCRYPT_PAD_PKCS1)
        {
            BCRYPT_PKCS1_PADDING_INFO* info = params->padding;

            if (!info) return STATUS_INVALID_PARAMETER;
            if (!info->pszAlgId)
            {
                hash_alg = GNUTLS_DIG_UNKNOWN;
                verify_flags |= GNUTLS_VERIFY_USE_TLS1_RSA;
            }
            else if ((hash_alg = get_digest_from_id(info->pszAlgId)) == GNUTLS_DIG_UNKNOWN)
            {
                return STATUS_NOT_SUPPORTED;
            }
            pk_alg = GNUTLS_PK_RSA;
        }
        else if (flags & BCRYPT_PAD_PSS)
        {
            BCRYPT_PSS_PADDING_INFO* info = params->padding;

            if (!info) return STATUS_INVALID_PARAMETER;
            if (!info->pszAlgId) return STATUS_INVALID_SIGNATURE;
            if ((hash_alg = get_digest_from_id(info->pszAlgId)) == GNUTLS_DIG_UNKNOWN)
            {
                return STATUS_NOT_SUPPORTED;
            }
            if ((status = pubkey_set_rsa_pss_params(key_data(key)->a.pubkey, hash_alg, info->cbSalt))) return status;
            pk_alg = GNUTLS_PK_RSA_PSS;
        }
        else return STATUS_INVALID_PARAMETER;
        break;
    }
    case ALG_ID_DSA:
    {
        if (params->hash_len != 20)
        {
            return STATUS_INVALID_PARAMETER;
        }
        hash_alg = GNUTLS_DIG_SHA1;
        pk_alg = GNUTLS_PK_DSA;
        break;
    }
    default:
        return STATUS_NOT_IMPLEMENTED;
    }

    if ((sign_alg = gnutls_pk_to_sign(pk_alg, hash_alg)) == GNUTLS_SIGN_UNKNOWN)
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    if ((status = prepare_gnutls_signature(key, params->signature, params->signature_len, &gnutls_signature)))
        return status;

    gnutls_hash.data = params->hash;
    gnutls_hash.size = params->hash_len;

    ret = gnutls_pubkey_verify_hash2(key_data(key)->a.pubkey, sign_alg, verify_flags, &gnutls_hash, &gnutls_signature);
    if (gnutls_signature.data != params->signature) free(gnutls_signature.data);
    return (ret < 0) ? STATUS_INVALID_SIGNATURE : STATUS_SUCCESS;
}

static unsigned int get_signature_length(enum alg_id id)
{
    switch (id)
    {
    case ALG_ID_ECDSA_P256: return 64;
    case ALG_ID_ECDSA_P384: return 96;
    case ALG_ID_DSA:        return 40;
    default:
        return 0;
    }
}

static NTSTATUS format_gnutls_signature(enum alg_id type, gnutls_datum_t signature,
    UCHAR* output, ULONG output_len, ULONG* ret_len)
{
    switch (type)
    {
    case ALG_ID_RSA:
    case ALG_ID_RSA_SIGN:
    {
        *ret_len = signature.size;
        if (output_len < signature.size) return STATUS_BUFFER_TOO_SMALL;
        if (output) memcpy(output, signature.data, signature.size);
        return STATUS_SUCCESS;
    }
    case ALG_ID_ECDSA_P256:
    case ALG_ID_ECDSA_P384:
    case ALG_ID_DSA:
    {
        int err;
        unsigned int sig_len = get_signature_length(type);
        gnutls_datum_t r, s; /* format as r||s */

        if ((err = gnutls_decode_rs_value(&signature, &r, &s)))
        {
            gnutls_perror(err);
            return STATUS_INTERNAL_ERROR;
        }

        *ret_len = sig_len;
        if (output_len < sig_len) return STATUS_BUFFER_TOO_SMALL;

        if (r.size > sig_len / 2 + 1 || s.size > sig_len / 2 + 1)
        {
            return STATUS_INTERNAL_ERROR;
        }

        if (output)
        {
            export_gnutls_datum(output, sig_len / 2, &r, 1);
            export_gnutls_datum(output + sig_len / 2, sig_len / 2, &s, 1);
        }

        free(r.data); free(s.data);
        return STATUS_SUCCESS;
    }
    default:
        return STATUS_INTERNAL_ERROR;
    }
}

static NTSTATUS privkey_set_rsa_pss_params(gnutls_privkey_t key, gnutls_digest_algorithm_t dig, unsigned int salt_size)
{
    gnutls_x509_spki_t spki;
    int ret;

    if (((ret = gnutls_x509_spki_init(&spki) < 0)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }
    gnutls_x509_spki_set_rsa_pss_params(spki, dig, salt_size);
    ret = gnutls_privkey_set_spki(key, spki, 0);
    gnutls_x509_spki_deinit(spki);
    if (ret < 0)
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }
    return STATUS_SUCCESS;
}

NTSTATUS key_asymmetric_sign_gnu(struct key_asymmetric_sign_params* args)
{
    const struct key_asymmetric_sign_params* params = args;
    struct key* key = params->key;
    unsigned int flags = params->flags, gnutls_flags = 0;
    gnutls_datum_t hash, signature;
    gnutls_digest_algorithm_t hash_alg;
    NTSTATUS status;
    int ret;

    if (key->alg_id == ALG_ID_ECDSA_P256 || key->alg_id == ALG_ID_ECDSA_P384)
    {
        /* With ECDSA, we find the digest algorithm from the hash length, and verify it */
        switch (params->input_len)
        {
        case 20: hash_alg = GNUTLS_DIG_SHA1; break;
        case 32: hash_alg = GNUTLS_DIG_SHA256; break;
        case 48: hash_alg = GNUTLS_DIG_SHA384; break;
        case 64: hash_alg = GNUTLS_DIG_SHA512; break;

        default:
            return STATUS_INVALID_PARAMETER;
        }

        if (flags == BCRYPT_PAD_PKCS1)
        {
            BCRYPT_PKCS1_PADDING_INFO* pad = params->padding;
            if (pad && pad->pszAlgId && get_digest_from_id(pad->pszAlgId) != hash_alg)
            {
                return STATUS_INVALID_PARAMETER;
            }
        }
    }
    else if (key->alg_id == ALG_ID_DSA)
    {
        if (params->input_len != 20)
        {
            return STATUS_INVALID_PARAMETER;
        }
        hash_alg = GNUTLS_DIG_SHA1;
    }
    else if (flags == BCRYPT_PAD_PKCS1)
    {
        BCRYPT_PKCS1_PADDING_INFO* pad = params->padding;

        if (!pad)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (!pad->pszAlgId) hash_alg = GNUTLS_DIG_UNKNOWN;
        else if ((hash_alg = get_digest_from_id(pad->pszAlgId)) == GNUTLS_DIG_UNKNOWN)
        {
            return STATUS_NOT_SUPPORTED;
        }
    }
    else if (flags == BCRYPT_PAD_PSS)
    {
        BCRYPT_PSS_PADDING_INFO* pad = params->padding;

        if (!pad || !pad->pszAlgId)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (key->alg_id != ALG_ID_RSA && key->alg_id != ALG_ID_RSA_SIGN)
        {
            return STATUS_NOT_SUPPORTED;
        }
        if ((hash_alg = get_digest_from_id(pad->pszAlgId)) == GNUTLS_DIG_UNKNOWN)
        {
            return STATUS_NOT_SUPPORTED;
        }

        if ((status = privkey_set_rsa_pss_params(key_data(key)->a.privkey, hash_alg, pad->cbSalt))) return status;
        gnutls_flags = GNUTLS_PRIVKEY_SIGN_FLAG_RSA_PSS;
    }
    else if (!flags)
    {
        return STATUS_INVALID_PARAMETER;
    }
    else
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    if (!params->output)
    {
        *params->ret_len = key->u.a.bitlen / 8;
        return STATUS_SUCCESS;
    }
    if (!key_data(key)->a.privkey) return STATUS_INVALID_PARAMETER;

    hash.data = params->input;
    hash.size = params->input_len;

    signature.data = NULL;
    signature.size = 0;

    if ((ret = gnutls_privkey_sign_hash(key_data(key)->a.privkey, hash_alg, gnutls_flags, &hash, &signature)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    status = format_gnutls_signature(key->alg_id, signature, params->output, params->output_len, params->ret_len);
    free(signature.data);
    return status;
}

NTSTATUS key_asymmetric_destroy_gnu(struct key* args)
{
    struct key* key = args;

    if (key_data(key)->a.privkey) gnutls_privkey_deinit(key_data(key)->a.privkey);
    if (key_data(key)->a.pubkey) gnutls_pubkey_deinit(key_data(key)->a.pubkey);
    if (key_data(key)->a.dh_params) gnutls_dh_params_deinit(key_data(key)->a.dh_params);
    return STATUS_SUCCESS;
}

static NTSTATUS dup_privkey(struct key* key_orig, struct key* key_copy)
{
    gnutls_privkey_t privkey;
    int ret;

    if ((ret = gnutls_privkey_init(&privkey)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    switch (key_orig->alg_id)
    {
    case ALG_ID_RSA:
    case ALG_ID_RSA_SIGN:
    {
        gnutls_datum_t m, e, d, p, q, u, e1, e2;

        if ((ret = gnutls_privkey_export_rsa_raw(key_data(key_orig)->a.privkey, &m, &e, &d, &p, &q, &u, &e1, &e2)))
            break;
        ret = gnutls_privkey_import_rsa_raw(privkey, &m, &e, &d, &p, &q, &u, &e1, &e2);
        free(m.data); free(e.data); free(d.data); free(p.data); free(q.data); free(u.data);
        free(e1.data); free(e2.data);
        break;
    }
    case ALG_ID_DSA:
    {
        gnutls_datum_t p, q, g, y, x;

        if ((ret = gnutls_privkey_export_dsa_raw(key_data(key_orig)->a.privkey, &p, &q, &g, &y, &x))) break;
        ret = gnutls_privkey_import_dsa_raw(privkey, &p, &q, &g, &y, &x);
        free(p.data); free(q.data); free(g.data); free(y.data); free(x.data);
        if (!ret) key_copy->u.a.dss_seed = key_orig->u.a.dss_seed;
        break;
    }
    case ALG_ID_ECDH_P256:
    case ALG_ID_ECDH_P384:
    case ALG_ID_ECDSA_P256:
    case ALG_ID_ECDSA_P384:
    {
        gnutls_ecc_curve_t curve;
        gnutls_datum_t x, y, k;

        if ((ret = gnutls_privkey_export_ecc_raw(key_data(key_orig)->a.privkey, &curve, &x, &y, &k))) break;
        ret = gnutls_privkey_import_ecc_raw(privkey, curve, &x, &y, &k);
        free(x.data); free(y.data); free(k.data);
        break;
    }
    case ALG_ID_DH:
    {
        gnutls_dh_params_t params;
        gnutls_datum_t y, x;

        if ((ret = gnutls_dh_params_init(&params)) < 0) break;
        if ((ret = gnutls_privkey_export_dh_raw(key_data(key_orig)->a.privkey, params, &y, &x, 0)) < 0)
        {
            gnutls_dh_params_deinit(params);
            break;
        }
        ret = gnutls_privkey_import_dh_raw(privkey, params, &y, &x);
        gnutls_dh_params_deinit(params);
        free(x.data); free(y.data);
        break;
    }
    default:
        gnutls_privkey_deinit(privkey);
        return STATUS_INTERNAL_ERROR;
    }

    if (ret < 0)
    {
        gnutls_perror(ret);
        gnutls_privkey_deinit(privkey);
        return STATUS_INTERNAL_ERROR;
    }

    key_data(key_copy)->a.privkey = privkey;
    return STATUS_SUCCESS;
}

static NTSTATUS dup_pubkey(struct key* key_orig, struct key* key_copy)
{
    gnutls_pubkey_t pubkey;
    int ret;

    if ((ret = gnutls_pubkey_init(&pubkey)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    switch (key_orig->alg_id)
    {
    case ALG_ID_RSA:
    case ALG_ID_RSA_SIGN:
    {
        gnutls_datum_t m, e;

        if ((ret = gnutls_pubkey_export_rsa_raw(key_data(key_orig)->a.pubkey, &m, &e))) break;
        ret = gnutls_pubkey_import_rsa_raw(pubkey, &m, &e);
        free(m.data); free(e.data);
        break;
    }
    case ALG_ID_DSA:
    {
        gnutls_datum_t p, q, g, y;

        if ((ret = gnutls_pubkey_export_dsa_raw(key_data(key_orig)->a.pubkey, &p, &q, &g, &y))) break;
        ret = gnutls_pubkey_import_dsa_raw(pubkey, &p, &q, &g, &y);
        free(p.data); free(q.data); free(g.data); free(y.data);
        if (!ret) key_copy->u.a.dss_seed = key_orig->u.a.dss_seed;
        break;
    }
    case ALG_ID_ECDH_P256:
    case ALG_ID_ECDH_P384:
    case ALG_ID_ECDSA_P256:
    case ALG_ID_ECDSA_P384:
    {
        gnutls_ecc_curve_t curve;
        gnutls_datum_t x, y;

        if ((ret = gnutls_pubkey_export_ecc_raw(key_data(key_orig)->a.pubkey, &curve, &x, &y))) break;
        ret = gnutls_pubkey_import_ecc_raw(pubkey, curve, &x, &y);
        free(x.data); free(y.data);
        break;
    }
    case ALG_ID_DH:
    {
        gnutls_dh_params_t params;
        gnutls_datum_t y;

        if ((ret = gnutls_dh_params_init(&params)) < 0) break;
        if ((ret = gnutls_pubkey_export_dh_raw(key_data(key_orig)->a.pubkey, params, &y, 0)) < 0)
        {
            gnutls_dh_params_deinit(params);
            break;
        }
        ret = gnutls_pubkey_import_dh_raw(pubkey, params, &y);
        gnutls_dh_params_deinit(params);
        free(y.data);
        break;
    }
    default:
        gnutls_pubkey_deinit(pubkey);
        return STATUS_INTERNAL_ERROR;
    }

    if (ret < 0)
    {
        gnutls_perror(ret);
        gnutls_pubkey_deinit(pubkey);
        return STATUS_INTERNAL_ERROR;
    }

    key_data(key_copy)->a.pubkey = pubkey;
    return STATUS_SUCCESS;
}

NTSTATUS key_asymmetric_duplicate_gnu(struct key_asymmetric_duplicate_params* args)
{
    const struct key_asymmetric_duplicate_params* params = args;
    NTSTATUS status;

    if (key_data(params->key_orig)->a.privkey && (status = dup_privkey(params->key_orig, params->key_copy)))
        return status;

    if (key_data(params->key_orig)->a.pubkey && (status = dup_pubkey(params->key_orig, params->key_copy)))
        return status;

    return STATUS_SUCCESS;
}

static NTSTATUS privkey_set_rsa_oaep_params(gnutls_privkey_t key, gnutls_digest_algorithm_t dig, gnutls_datum_t* label)
{
    gnutls_x509_spki_t spki;
    int ret;

    if (((ret = gnutls_x509_spki_init(&spki) < 0)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }
    gnutls_x509_spki_set_rsa_oaep_params(spki, dig, label);
    ret = gnutls_privkey_set_spki(key, spki, 0);
    gnutls_x509_spki_deinit(spki);
    if (ret < 0)
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }
    return STATUS_SUCCESS;
}

NTSTATUS key_asymmetric_decrypt_gnu(struct key_asymmetric_decrypt_params* args)
{
    const struct key_asymmetric_decrypt_params* params = args;
    gnutls_datum_t e, d = { 0 };
    NTSTATUS status = STATUS_SUCCESS;
    int ret;

    if (params->key->alg_id == ALG_ID_RSA && params->flags & BCRYPT_PAD_OAEP)
    {
        BCRYPT_OAEP_PADDING_INFO* pad = params->padding;
        gnutls_digest_algorithm_t dig;
        gnutls_datum_t label;

        if (!pad || !pad->pszAlgId)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if ((dig = get_digest_from_id(pad->pszAlgId)) == GNUTLS_DIG_UNKNOWN)
        {
            return STATUS_NOT_SUPPORTED;
        }

        label.data = pad->pbLabel;
        label.size = pad->cbLabel;
        if ((status = privkey_set_rsa_oaep_params(key_data(params->key)->a.privkey, dig, &label))) return status;
    }

    e.data = params->input;
    e.size = params->input_len;
    if ((ret = gnutls_privkey_decrypt_data(key_data(params->key)->a.privkey, 0, &e, &d)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    *params->ret_len = d.size;
    if (params->output_len >= d.size) memcpy(params->output, d.data, *params->ret_len);
    else if (params->output) status = STATUS_BUFFER_TOO_SMALL;

    free(d.data);
    return status;
}

static NTSTATUS pubkey_set_rsa_oaep_params(gnutls_pubkey_t key, gnutls_digest_algorithm_t dig, gnutls_datum_t* label)
{
    gnutls_x509_spki_t spki;
    int ret;

    if (((ret = gnutls_x509_spki_init(&spki) < 0)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }
    gnutls_x509_spki_set_rsa_oaep_params(spki, dig, label);
    ret = gnutls_pubkey_set_spki(key, spki, 0);
    gnutls_x509_spki_deinit(spki);
    if (ret < 0)
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }
    return STATUS_SUCCESS;
}

NTSTATUS key_asymmetric_encrypt_gnu(struct key_asymmetric_encrypt_params* args)
{
    const struct key_asymmetric_encrypt_params* params = args;
    gnutls_datum_t d, e = { 0 };
    NTSTATUS status = STATUS_SUCCESS;
    int ret;

    if (!key_data(params->key)->a.pubkey) return STATUS_INVALID_HANDLE;

    if (params->key->alg_id == ALG_ID_RSA && params->flags & BCRYPT_PAD_OAEP)
    {
        BCRYPT_OAEP_PADDING_INFO* pad = params->padding;
        gnutls_digest_algorithm_t dig;
        gnutls_datum_t label;

        if (!pad || !pad->pszAlgId || !pad->pbLabel)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if ((dig = get_digest_from_id(pad->pszAlgId)) == GNUTLS_DIG_UNKNOWN)
        {
            return STATUS_NOT_SUPPORTED;
        }

        label.data = pad->pbLabel;
        label.size = pad->cbLabel;
        if ((status = pubkey_set_rsa_oaep_params(key_data(params->key)->a.pubkey, dig, &label))) return status;
    }

    d.data = params->input;
    d.size = params->input_len;
    if ((ret = gnutls_pubkey_encrypt_data(key_data(params->key)->a.pubkey, 0, &d, &e)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    *params->ret_len = e.size;
    if (params->output_len >= e.size) memcpy(params->output, e.data, *params->ret_len);
    else if (params->output_len == 0) status = STATUS_SUCCESS;
    else status = STATUS_BUFFER_TOO_SMALL;

    free(e.data);
    return status;
}

NTSTATUS key_asymmetric_derive_key_gnu(struct key_asymmetric_derive_key_params* args)
{
    const struct key_asymmetric_derive_key_params* params = args;
    gnutls_datum_t s;
    NTSTATUS status = STATUS_SUCCESS;
    int ret;

    if ((ret = gnutls_privkey_derive_secret(key_data(params->privkey)->a.privkey,
        key_data(params->pubkey)->a.pubkey, NULL, &s, 0)))
    {
        gnutls_perror(ret);
        return STATUS_INTERNAL_ERROR;
    }

    *params->ret_len = EXPORT_SIZE(s, params->privkey->u.a.bitlen / 8, 1);
    if (params->output)
    {
        if (params->output_len < *params->ret_len) status = STATUS_BUFFER_TOO_SMALL;
        else export_gnutls_datum(params->output, *params->ret_len, &s, 1);
    }

    free(s.data);
    return status;
}
