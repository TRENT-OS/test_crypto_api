/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include "SeosCryptoCipher.h"
#include "SeosCryptoApi.h"

#include <string.h>

#define MAX_VECTOR_SIZE 128
typedef struct
{
    size_t len;
    unsigned char bytes[MAX_VECTOR_SIZE];
} vector_t;

typedef struct
{
    vector_t            iv;
    vector_t            ad;
    vector_t            pt;
    vector_t            ct;
    vector_t            tag;
    SeosCryptoKey_Data  key;
} cipherTestVector;

// -----------------------------------------------------------------------------

#define NUM_AES_ECB_TESTS 3
static const cipherTestVector aesEcbVectors[NUM_AES_ECB_TESTS] =
{
    {
        .key = {
            .type = SeosCryptoKey_Type_AES,
            .data.aes = {
                .len   = 16,
                .bytes = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
            },
        },
        .pt = {
            .len = 48,
            .bytes = {
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            }
        },
        .ct = {
            .len = 48,
            .bytes = {
                0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
                0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
                0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
            }
        },

    },
    {
        .key = {
            .type = SeosCryptoKey_Type_AES,
            .data.aes = {
                .len   = 24,
                .bytes = {
                    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
                },
            },
        },
        .pt = {
            .len = 16,
            .bytes = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a}
        },
        .ct = {
            .len = 16,
            .bytes = {0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f, 0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc},
        },
    },
    {
        .key = {
            .type = SeosCryptoKey_Type_AES,
            .data.aes = {
                .len   = 32,
                .bytes =
                {
                    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
                },
            },
        },
        .pt = {
            .len   = 16,
            .bytes = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a},
        },
        .ct = {
            .len = 16,
            .bytes = {0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8},
        },
    }
};

// -----------------------------------------------------------------------------

#define NUM_AES_CBC_TESTS 1
static const cipherTestVector aesCbcVectors[NUM_AES_CBC_TESTS] =
{
    {
        .key = {
            .type = SeosCryptoKey_Type_AES,
            .data.aes = {
                .len   = 16,
                .bytes = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
            },
        },
        .pt =
        {
            .len = 48,
            .bytes = {

                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            },
        },
        .ct =
        {
            .len = 48,
            .bytes = {
                0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D,
                0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76, 0x78, 0xB2,
                0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95, 0x16,
            },
        },
        .iv = {
            .len = 16,
            .bytes = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
        }
    }
};

// -----------------------------------------------------------------------------

#define NUM_AES_GCM_TESTS 2
static const cipherTestVector aesGcmVectors[NUM_AES_GCM_TESTS] =
{
    {
        .key = {
            .type = SeosCryptoKey_Type_AES,
            .data.aes = {
                .len   = 32,
                .bytes = {
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                },
            },
        },
        .iv = {
            .len = 12,
            .bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        },
        .pt =
        {
            .len = 16,
            .bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        },
        .ct =
        {
            .len = 16,
            .bytes = {0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18},
        },
        .tag =
        {
            .len = 16,
            .bytes = {0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19},
        },
    },
    {
        .key = {
            .type = SeosCryptoKey_Type_AES,
            .data.aes = {

                .len   = 32,
                .bytes = {
                    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
                    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f
                },
            },
        },
        .iv = {
            .len = 12,
            .bytes = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b},
        },
        .ad = {
            .len = 20,
            .bytes = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13},
        },
        .pt =
        {
            .len = 24,
            .bytes = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37},
        },
        .ct =
        {
            .len = 24,
            .bytes = {0x59, 0x1b, 0x1f, 0xf2, 0x72, 0xb4, 0x32, 0x04, 0x86, 0x8f, 0xfc, 0x7b, 0xc7, 0xd5, 0x21, 0x99, 0x35, 0x26, 0xb6, 0xfa, 0x32, 0x24, 0x7c, 0x3c},
        },
        .tag =
        {
            .len = 16,
            .bytes = {0x7d, 0xe1, 0x2a, 0x56, 0x70, 0xe5, 0x70, 0xd8, 0xca, 0xe6, 0x24, 0xa1, 0x6d, 0xf0, 0x9c, 0x08},
        },
    }
};

// -----------------------------------------------------------------------------

static const SeosCryptoKey_Spec aes128Spec =
{
    .type = SeosCryptoKey_SpecType_BITS,
    .key = {
        .type = SeosCryptoKey_Type_AES,
        .attribs.flags = SeosCryptoKey_Flags_EXPORTABLE_RAW,
        .params.bits = 128
    }
};
static const SeosCryptoKey_Spec dh64bSpec =
{
    .type = SeosCryptoKey_SpecType_BITS,
    .key = {
        .attribs.flags = SeosCryptoKey_Flags_EXPORTABLE_RAW,
        .type = SeosCryptoKey_Type_DH_PRV,
        .params.bits = 64
    }
};

// -----------------------------------------------------------------------------

static seos_err_t
do_AES_ECB(SeosCryptoCtx*       ctx,
           int                  algo,
           SeosCrypto_KeyHandle keyHandle,
           const vector_t*      din,
           const vector_t*      dout)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_CipherHandle cipherHandle;
    unsigned char buf[128];
    size_t n = sizeof(buf);

    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle, algo, keyHandle, NULL, 0);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle, din->bytes, din->len, buf,
                                      &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(n == dout->len);
    Debug_ASSERT(!memcmp(buf, dout->bytes, n));
    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    return SEOS_SUCCESS;
}

static void
testCipher_encrypt_AES_ECB(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_KeyHandle keyHandle = NULL;
    size_t i;

    for (i = 0; i < NUM_AES_ECB_TESTS; i++)
    {
        err = SeosCryptoApi_keyImport(ctx, &keyHandle, NULL, &aesEcbVectors[i].key);
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

        err = do_AES_ECB(ctx, SeosCryptoCipher_Algorithm_AES_ECB_ENC, keyHandle,
                         &aesEcbVectors[i].pt, &aesEcbVectors[i].ct);

        err = SeosCryptoApi_keyFree(ctx, keyHandle);
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    }

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testCipher_decrypt_AES_ECB(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_KeyHandle keyHandle = NULL;
    size_t i;

    for (i = 0; i < NUM_AES_ECB_TESTS; i++)
    {
        err = SeosCryptoApi_keyImport(ctx, &keyHandle, NULL, &aesEcbVectors[i].key);
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

        err = do_AES_ECB(ctx, SeosCryptoCipher_Algorithm_AES_ECB_DEC, keyHandle,
                         &aesEcbVectors[i].ct, &aesEcbVectors[i].pt);

        err = SeosCryptoApi_keyFree(ctx, keyHandle);
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    }

    Debug_PRINTF("->%s: OK\n", __func__);
}

static seos_err_t
do_AES_CBC(SeosCryptoCtx*       ctx,
           int                  algo,
           SeosCrypto_KeyHandle keyHandle,
           const vector_t*      iv,
           const vector_t*      din,
           const vector_t*      dout)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_CipherHandle cipherHandle;
    unsigned char buf[128];
    size_t n = sizeof(buf);

    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle, algo, keyHandle, iv->bytes,
                                   iv->len);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle, din->bytes, din->len, buf,
                                      &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(n == dout->len);
    Debug_ASSERT(!memcmp(buf, dout->bytes, n));
    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    return SEOS_SUCCESS;
}

static void
testCipher_encrypt_AES_CBC(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_KeyHandle keyHandle = NULL;
    size_t i;

    for (i = 0; i < NUM_AES_CBC_TESTS; i++)
    {
        err = SeosCryptoApi_keyImport(ctx, &keyHandle, NULL, &aesCbcVectors[i].key);
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

        err = do_AES_CBC(ctx, SeosCryptoCipher_Algorithm_AES_CBC_ENC, keyHandle,
                         &aesCbcVectors[i].iv, &aesCbcVectors[i].pt, &aesCbcVectors[i].ct);
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

        err = SeosCryptoApi_keyFree(ctx, keyHandle);
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    }

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testCipher_decrypt_AES_CBC(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_KeyHandle keyHandle = NULL;
    size_t i;

    for (i = 0; i < NUM_AES_CBC_TESTS; i++)
    {
        err = SeosCryptoApi_keyImport(ctx, &keyHandle, NULL, &aesCbcVectors[i].key);
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

        err = do_AES_CBC(ctx, SeosCryptoCipher_Algorithm_AES_CBC_DEC, keyHandle,
                         &aesCbcVectors[i].iv, &aesCbcVectors[i].ct, &aesCbcVectors[i].pt);
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

        err = SeosCryptoApi_keyFree(ctx, keyHandle);
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    }

    Debug_PRINTF("->%s: OK\n", __func__);
}

static seos_err_t
do_AES_GCM(SeosCryptoCtx*       ctx,
           int                  algo,
           SeosCrypto_KeyHandle keyHandle,
           const vector_t*      iv,
           const vector_t*      ad,
           const vector_t*      din,
           const vector_t*      dout,
           const vector_t*      tag)
{
    seos_err_t err = SEOS_ERROR_GENERIC, ret;
    SeosCrypto_CipherHandle cipherHandle = NULL;
    unsigned char buf[128];
    size_t n = sizeof(buf);

    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle, algo, keyHandle, iv->bytes,
                                   iv->len);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    if (ad->len > 0)
    {
        err = SeosCryptoApi_cipherStart(ctx, cipherHandle, ad->bytes, ad->len);
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    }
    else
    {
        err = SeosCryptoApi_cipherStart(ctx, cipherHandle, NULL, 0);
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    }

    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle, din->bytes, din->len, buf,
                                      &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(n == dout->len);
    Debug_ASSERT(!memcmp(buf, dout->bytes, n));

    if (algo == SeosCryptoCipher_Algorithm_AES_GCM_ENC)
    {
        // Here we create the tag
        n = sizeof(buf);
        err = SeosCryptoApi_cipherFinalize(ctx, cipherHandle, buf, &n);
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
        Debug_ASSERT(n == tag->len);
        Debug_ASSERT(!memcmp(buf, tag->bytes, n));
        ret = SEOS_SUCCESS;
    }
    else
    {
        // Here we check the tag
        n = tag->len;
        memcpy(buf, tag->bytes, tag->len);
        ret = SeosCryptoApi_cipherFinalize(ctx, cipherHandle, buf, &n);
    }

    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    return ret;
}

static void
testCipher_encrypt_AES_GCM(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_KeyHandle keyHandle = NULL;
    size_t i;

    for (i = 0; i < NUM_AES_GCM_TESTS; i++)
    {
        err = SeosCryptoApi_keyImport(ctx, &keyHandle, NULL, &aesGcmVectors[i].key);
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

        err = do_AES_GCM(ctx, SeosCryptoCipher_Algorithm_AES_GCM_ENC, keyHandle,
                         &aesGcmVectors[i].iv, &aesGcmVectors[i].ad, &aesGcmVectors[i].pt,
                         &aesGcmVectors[i].ct, &aesGcmVectors[i].tag);
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

        err = SeosCryptoApi_keyFree(ctx, keyHandle);
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    }

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testCipher_decrypt_AES_GCM_ok(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_KeyHandle keyHandle = NULL;
    size_t i;

    for (i = 0; i < NUM_AES_GCM_TESTS; i++)
    {
        err = SeosCryptoApi_keyImport(ctx, &keyHandle, NULL, &aesGcmVectors[i].key);
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

        err = do_AES_GCM(ctx, SeosCryptoCipher_Algorithm_AES_GCM_DEC, keyHandle,
                         &aesGcmVectors[i].iv, &aesGcmVectors[i].ad, &aesGcmVectors[i].ct,
                         &aesGcmVectors[i].pt, &aesGcmVectors[i].tag);
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

        err = SeosCryptoApi_keyFree(ctx, keyHandle);
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    }

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testCipher_decrypt_AES_GCM_fail(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_KeyHandle keyHandle = NULL;
    const cipherTestVector* vec;
    vector_t brokenTag;

    vec = &aesGcmVectors[0];

    memcpy(brokenTag.bytes, vec->tag.bytes, vec->tag.len);
    brokenTag.len = vec->tag.len;
    brokenTag.bytes[0] ^= 0xff;

    // Create GCM with manipulated tag
    err = SeosCryptoApi_keyImport(ctx, &keyHandle, NULL, &vec->key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = do_AES_GCM(ctx, SeosCryptoCipher_Algorithm_AES_GCM_DEC, keyHandle,
                     &vec->iv, &vec->ad, &vec->ct, &vec->pt, &brokenTag);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_ABORTED == err, "err %d", err);

    err = SeosCryptoApi_keyFree(ctx, keyHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testCipher_init_ok(SeosCryptoCtx*  ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_CipherHandle cipherHandle = NULL;
    SeosCrypto_KeyHandle keyHandle = NULL;
    const vector_t* vec;

    err = SeosCryptoApi_keyGenerate(ctx, &keyHandle, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Test GCM enc
    vec = &aesGcmVectors[0].iv;
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_GCM_ENC, keyHandle, vec->bytes, vec->len);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Test GCM dec
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_GCM_DEC, keyHandle, vec->bytes, vec->len);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Test CBC enc
    vec = &aesCbcVectors[0].iv;
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_CBC_ENC, keyHandle, vec->bytes, vec->len);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Test CBC dec
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_CBC_DEC, keyHandle, vec->bytes, vec->len);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Test ECB enc
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_ECB_ENC, keyHandle, NULL, 0);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Test ECB dec
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_ECB_DEC, keyHandle, NULL, 0);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_keyFree(ctx, keyHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testCipher_init_fail(SeosCryptoCtx*  ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_CipherHandle cipherHandle = NULL;
    SeosCrypto_KeyHandle keyHandle = NULL, tmpHandle = NULL;
    const vector_t* vec;

    err = SeosCryptoApi_keyGenerate(ctx, &keyHandle, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Test empty ctx
    vec = &aesGcmVectors[0].iv;
    err = SeosCryptoApi_cipherInit(NULL, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_GCM_ENC, keyHandle, vec->bytes, vec->len);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Test empty handle
    err = SeosCryptoApi_cipherInit(ctx, NULL,
                                   SeosCryptoCipher_Algorithm_AES_GCM_DEC, keyHandle, vec->bytes, vec->len);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Test invalid algorithm
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle, 666, keyHandle, vec->bytes,
                                   vec->len);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Test empty key handle
    tmpHandle = NULL;
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_CBC_DEC, tmpHandle, vec->bytes, vec->len);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);

    // Test GCM/CBC without IV buf
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_CBC_DEC, keyHandle, NULL, vec->len);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Test GCM/CBC without IV buf
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_GCM_DEC, keyHandle, vec->bytes, 0);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);
    // Test CBC with wrong sized IV
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_CBC_ENC, keyHandle, vec->bytes, vec->len);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Test GCM with wrong sized IV
    vec = &aesCbcVectors[0].iv;
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_GCM_ENC, keyHandle, vec->bytes, vec->len);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Test ECB with IV
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_ECB_ENC, keyHandle, vec->bytes, vec->len);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    err = SeosCryptoApi_keyFree(ctx, keyHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Test with wrong key type
    err = SeosCryptoApi_keyGenerate(ctx, &keyHandle, &dh64bSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyMakePublic(ctx, &tmpHandle, keyHandle,
                                      &dh64bSpec.key.attribs);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    vec = &aesGcmVectors[0].iv;
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_GCM_ENC, keyHandle, vec->bytes, vec->len);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);
    err = SeosCryptoApi_keyFree(ctx, tmpHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_keyFree(ctx, keyHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testCipher_free_ok(SeosCryptoCtx*  ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_CipherHandle cipherHandle = NULL;
    SeosCrypto_KeyHandle keyHandle = NULL;

    err = SeosCryptoApi_keyGenerate(ctx, &keyHandle, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_ECB_DEC, keyHandle, NULL, 0);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Simply free
    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_keyFree(ctx, keyHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testCipher_free_fail(SeosCryptoCtx*  ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_CipherHandle cipherHandle = NULL;
    SeosCrypto_KeyHandle keyHandle = NULL;

    err = SeosCryptoApi_keyGenerate(ctx, &keyHandle, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_ECB_DEC, keyHandle, NULL, 0);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Test without ctx
    err = SeosCryptoApi_cipherFree(NULL, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Test with empty handle
    err = SeosCryptoApi_cipherFree(ctx, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);

    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyFree(ctx, keyHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testCipher_start_fail(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_KeyHandle keyHandle = NULL;
    SeosCrypto_CipherHandle cipherHandle = NULL, emptyHandle = NULL;

    err = SeosCryptoApi_keyGenerate(ctx, &keyHandle, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_GCM_ENC, keyHandle, aesGcmVectors[0].iv.bytes,
                                   aesGcmVectors[0].iv.len);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Start without ctx
    err = SeosCryptoApi_cipherStart(NULL, cipherHandle, NULL, 0);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Start without invalid handle
    emptyHandle = NULL;
    err = SeosCryptoApi_cipherStart(ctx, emptyHandle, NULL, 0);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);

    // Start twice
    err = SeosCryptoApi_cipherStart(ctx, cipherHandle, NULL, 0);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherStart(ctx, cipherHandle, NULL, 0);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_ABORTED == err, "err %d", err);

    // Start for cipher in wrong mode
    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_ECB_ENC, keyHandle, NULL, 0);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherStart(ctx, cipherHandle, NULL, 0);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_ABORTED == err, "err %d", err);
    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_keyFree(ctx, keyHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testCipher_process_fail(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_KeyHandle keyHandle = NULL;
    SeosCrypto_CipherHandle cipherHandle = NULL, emptyHandle = NULL;
    unsigned char buf[128];
    size_t n = sizeof(buf);

    err = SeosCryptoApi_keyGenerate(ctx, &keyHandle, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_GCM_ENC, keyHandle, aesGcmVectors[0].iv.bytes,
                                   aesGcmVectors[0].iv.len);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Process without calling start for GCM
    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle, buf, 16, buf, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_ABORTED == err, "err %d", err);

    // Process without context
    err = SeosCryptoApi_cipherStart(ctx, cipherHandle, NULL, 0);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherProcess(NULL, cipherHandle, buf, 16, buf, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Process without context
    emptyHandle = NULL;
    err = SeosCryptoApi_cipherProcess(ctx, emptyHandle, buf, 16, buf, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);

    // Process with empty input buf
    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle, NULL, 16, buf, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Process with empty zero blocksize
    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle, buf, 0, buf, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Process without output buffer
    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle, buf, 16, NULL, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Process with too small output buffer
    n = 3;
    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle, buf, 16, buf, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);

    // Process without with non-aligned block (which is ok for last call to Process in GCM mode)
    // but then adding another block via Process
    n = sizeof(buf);
    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle, buf, 20, buf, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle, buf, 16, buf, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_ABORTED == err, "err %d", err);

    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Process with un-aligned block sizes for ECB
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_ECB_ENC, keyHandle, NULL, 0);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle, buf, 18, buf, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);
    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Process with un-aligned block sizes for CBC
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_CBC_ENC, keyHandle, aesCbcVectors[0].iv.bytes,
                                   aesCbcVectors[0].iv.len);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle, buf, 18, buf, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);
    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_keyFree(ctx, keyHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testCipher_finalize_fail(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_KeyHandle keyHandle = NULL;
    SeosCrypto_CipherHandle cipherHandle = NULL, emptyHandle = NULL;
    unsigned char buf[128];
    size_t n = sizeof(buf);

    err = SeosCryptoApi_keyGenerate(ctx, &keyHandle, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_GCM_ENC, keyHandle, aesGcmVectors[0].iv.bytes,
                                   aesGcmVectors[0].iv.len);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Finalize without calling start+Process
    err = SeosCryptoApi_cipherFinalize(ctx, cipherHandle, buf, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_ABORTED == err, "err %d", err);

    // Finalize without calling Process
    err = SeosCryptoApi_cipherStart(ctx, cipherHandle, NULL, 0);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherFinalize(ctx, cipherHandle, buf, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_ABORTED == err, "err %d", err);

    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle, buf, 16, buf, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Finalize without context
    err = SeosCryptoApi_cipherFinalize(NULL, cipherHandle, buf, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Finalize without handle
    emptyHandle = NULL;
    err = SeosCryptoApi_cipherFinalize(ctx, emptyHandle, buf, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);

    // Finalize without buffer in ENC mode (wants to write a tag)
    err = SeosCryptoApi_cipherFinalize(NULL, cipherHandle, NULL, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Finalize with zero length buffer
    err = SeosCryptoApi_cipherFinalize(NULL, cipherHandle, buf, 0);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Finalize without buffer in DEC mode (will just compare the tag)
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_GCM_DEC, keyHandle, aesGcmVectors[0].iv.bytes,
                                   aesGcmVectors[0].iv.len);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherStart(ctx, cipherHandle, NULL, 0);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle, buf, 16, buf, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherFinalize(ctx, cipherHandle, NULL, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Finalize without zero length in DEC mode (will just compare the tag)
    n = 0;
    err = SeosCryptoApi_cipherFinalize(ctx, cipherHandle, buf, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Finalize on wrong type of cipher
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_ECB_ENC, keyHandle, NULL, 0);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    n = sizeof(buf);
    err = SeosCryptoApi_cipherFinalize(ctx, cipherHandle, buf, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);
    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_keyFree(ctx, keyHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testCipher_init_buffer(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_KeyHandle keyHandle = NULL;
    SeosCrypto_CipherHandle cipherHandle = NULL;
    static unsigned char ivBuf[SeosCrypto_DATAPORT_SIZE + 1];
    size_t ivLen;

    err = SeosCryptoApi_keyGenerate(ctx, &keyHandle, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Should be OK
    ivLen = SeosCryptoCipher_AES_BLOCK_SIZE;
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_CBC_DEC, keyHandle, ivBuf, ivLen);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Should fail with SEOS_ERROR_INVALID_PARAMETER beacause it is way too large
    // for any cipher
    ivLen = SeosCrypto_DATAPORT_SIZE;
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_CBC_DEC, keyHandle, ivBuf, ivLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Should fail with SEOS_ERROR_INSUFFICIENT_SPACE because it is too large for
    // the internal dataports
    ivLen = SeosCrypto_DATAPORT_SIZE + 1;
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_CBC_DEC, keyHandle, ivBuf, ivLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INSUFFICIENT_SPACE == err, "err %d", err);

    err = SeosCryptoApi_keyFree(ctx, keyHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testCipher_start_buffer(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_KeyHandle keyHandle = NULL;
    SeosCrypto_CipherHandle cipherHandle;
    static unsigned char ivBuf[16], inputBuf[SeosCrypto_DATAPORT_SIZE + 1];
    size_t inLen;

    err = SeosCryptoApi_keyGenerate(ctx, &keyHandle, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_GCM_ENC, keyHandle, ivBuf, 12);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Should be OK
    inLen = SeosCrypto_DATAPORT_SIZE;
    err = SeosCryptoApi_cipherStart(ctx, cipherHandle, inputBuf, inLen);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Should fail because input is too big
    inLen = SeosCrypto_DATAPORT_SIZE + 1;
    err = SeosCryptoApi_cipherStart(ctx, cipherHandle, inputBuf, inLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INSUFFICIENT_SPACE == err, "err %d", err);

    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testCipher_process_buffer(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_KeyHandle keyHandle = NULL;
    SeosCrypto_CipherHandle cipherHandle = NULL;
    static unsigned char inBuf[SeosCrypto_DATAPORT_SIZE + 1],
           outBuf[SeosCrypto_DATAPORT_SIZE + 1];
    size_t inLen, outLen;

    err = SeosCryptoApi_keyGenerate(ctx, &keyHandle, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_ECB_DEC, keyHandle, NULL, 0);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // This should go OK
    inLen = outLen = SeosCrypto_DATAPORT_SIZE;
    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle, inBuf, inLen, outBuf,
                                      &outLen);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(inLen == outLen);

    // This should fail as input is too big
    inLen = SeosCrypto_DATAPORT_SIZE + 1;
    outLen = SeosCrypto_DATAPORT_SIZE;
    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle, inBuf, inLen, outBuf,
                                      &outLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INSUFFICIENT_SPACE == err, "err %d", err);

    // This should fail as output is too big
    inLen = SeosCrypto_DATAPORT_SIZE;
    outLen = SeosCrypto_DATAPORT_SIZE + 1;
    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle, inBuf, inLen, outBuf,
                                      &outLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INSUFFICIENT_SPACE == err, "err %d", err);

    // This should fail in the SeosCryptoCipher, but should give us the expected
    // (= minimum) output buffer size
    inLen = SeosCrypto_DATAPORT_SIZE;
    outLen = 10;
    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle, inBuf, inLen, outBuf,
                                      &outLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);
    Debug_ASSERT(inLen == outLen);

    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyFree(ctx, keyHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_keyImport(ctx, &keyHandle, NULL, &aesEcbVectors[0].key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_ECB_DEC, keyHandle, NULL, 0);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    // Compute with same buffer used for input and output
    memcpy(inBuf, aesEcbVectors[0].ct.bytes, aesEcbVectors[0].ct.len);
    outLen = aesEcbVectors[0].pt.len;
    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle,
                                      inBuf, aesEcbVectors[0].ct.len, 
                                      inBuf, &outLen);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(!memcmp(inBuf, aesEcbVectors[0].pt.bytes, aesEcbVectors[0].pt.len));
    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyFree(ctx, keyHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testCipher_finalize_buffer(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_CipherHandle cipherHandle = NULL;
    SeosCrypto_KeyHandle keyHandle = NULL;
    unsigned char inBuf[16], outBuf[16], iv[12];
    static unsigned char tagBuf[SeosCrypto_DATAPORT_SIZE + 1];
    size_t tagLen;

    err = SeosCryptoApi_keyGenerate(ctx, &keyHandle, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_GCM_ENC, keyHandle, iv, 12);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherStart(ctx, cipherHandle, NULL, 0);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    tagLen = sizeof(outBuf);
    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle, inBuf, 16, outBuf,
                                      &tagLen);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    // Should work fine and give the written size
    tagLen = SeosCrypto_DATAPORT_SIZE;
    err = SeosCryptoApi_cipherFinalize(ctx, cipherHandle, tagBuf, &tagLen);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(SeosCryptoCipher_AES_GCM_TAG_SIZE == tagLen);

    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_cipherInit(ctx, &cipherHandle,
                                   SeosCryptoCipher_Algorithm_AES_GCM_ENC, keyHandle, iv, 12);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_cipherStart(ctx, cipherHandle, NULL, 0);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    tagLen = sizeof(outBuf);
    err = SeosCryptoApi_cipherProcess(ctx, cipherHandle, inBuf, 16, outBuf,
                                      &tagLen);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    // Should fail due to limited internal buffers
    tagLen = SeosCrypto_DATAPORT_SIZE + 1;
    err = SeosCryptoApi_cipherFinalize(ctx, cipherHandle, tagBuf, &tagLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INSUFFICIENT_SPACE == err, "err %d", err);
    // Should fail (tags bust be at least 4 bytes) but give the minimum size
    tagLen = 3;
    err = SeosCryptoApi_cipherFinalize(ctx, cipherHandle, tagBuf, &tagLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);
    Debug_ASSERT(4 == tagLen);
    // Should work
    tagLen = 5;
    err = SeosCryptoApi_cipherFinalize(ctx, cipherHandle, tagBuf, &tagLen);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(5 == tagLen);

    err = SeosCryptoApi_cipherFree(ctx, cipherHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_keyFree(ctx, keyHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

void
testCipher(SeosCryptoCtx* ctx)
{
    testCipher_init_ok(ctx);
    testCipher_init_fail(ctx);

    testCipher_free_ok(ctx);
    testCipher_free_fail(ctx);

    testCipher_encrypt_AES_ECB(ctx);
    testCipher_decrypt_AES_ECB(ctx);

    testCipher_encrypt_AES_CBC(ctx);
    testCipher_decrypt_AES_CBC(ctx);

    testCipher_encrypt_AES_GCM(ctx);
    testCipher_decrypt_AES_GCM_ok(ctx);
    testCipher_decrypt_AES_GCM_fail(ctx);

    // Test only failures separately, as computing ref. values is sufficient
    // proof of correct funtioning
    testCipher_start_fail(ctx);
    testCipher_process_fail(ctx);
    testCipher_finalize_fail(ctx);

    testCipher_init_buffer(ctx);
    testCipher_start_buffer(ctx);
    testCipher_process_buffer(ctx);
    testCipher_finalize_buffer(ctx);
}