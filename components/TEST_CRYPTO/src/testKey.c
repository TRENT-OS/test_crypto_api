/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include "testKey.h"
#include "SeosCryptoApi.h"

#include <string.h>

static const SeosCryptoKey_DHPrv dhPrvData =
{
    .pBytes = {0x12, 0xdf, 0x4d, 0x76, 0x89, 0xdf, 0xf4, 0xc9, 0x9d, 0x9a, 0xe5, 0x7d, 0x07},
    .pLen   = 13,
    .gBytes = {0x00, 0x1e, 0x32, 0x15, 0x8a, 0x35, 0xe3, 0x4d, 0x7b, 0x61, 0x96, 0x57, 0xd6},
    .gLen   = 13,
    .xBytes = {0x11, 0x46, 0xbc, 0x69, 0xaf, 0x6c, 0x32, 0xca, 0xfa, 0xd1, 0x46, 0xbc, 0x69},
    .xLen   = 13,
};
static const SeosCryptoKey_DHPub dhPubData =
{
    .pBytes  = {0x12, 0xdf, 0x4d, 0x76, 0x89, 0xdf, 0xf4, 0xc9, 0x9d, 0x9a, 0xe5, 0x7d, 0x07},
    .pLen    = 13,
    .gBytes  = {0x00, 0x1e, 0x32, 0x15, 0x8a, 0x35, 0xe3, 0x4d, 0x7b, 0x61, 0x96, 0x57, 0xd6},
    .gLen    = 13,
    .gxBytes = {0x00, 0x41, 0x83, 0xa8, 0x6f, 0x35, 0x71, 0x0e, 0x4e, 0x69, 0xb1, 0x64, 0xa4},
    .gxLen   = 13,
};

// -----------------------------------------------------------------------------

static const SeosCryptoKey_RSAPrv rsaPrvData =
{
    .dBytes = {
        0x35, 0xe7, 0x4c, 0x80, 0x45, 0x9c, 0x4e, 0x69, 0x83, 0x2c, 0x62, 0xac, 0x26, 0x2d, 0x58, 0xac,
        0x0f, 0xd1, 0x53, 0x45, 0xd2, 0x0a, 0x94, 0x43, 0x0f, 0x29, 0x00, 0x0b, 0x50, 0x63, 0x05, 0x29,
        0x34, 0xa3, 0xaa, 0x1a, 0x1a, 0x4c, 0xea, 0x41, 0x27, 0xe4, 0x83, 0x4b, 0xc8, 0xd6, 0x48, 0x20,
        0xf5, 0xd0, 0x5c, 0x9f, 0x57, 0xad, 0xaf, 0xce, 0xc9, 0x75, 0xcf, 0x6d, 0xe9, 0x6e, 0xbf, 0xcc,
        0xd5, 0xb1, 0xc7, 0x90, 0x5a, 0xcb, 0xd5, 0xe8, 0xa0, 0x5b, 0x39, 0xaa, 0x9a, 0xa6, 0x3c, 0xe5,
        0xf5, 0xca, 0xe0, 0x49, 0x63, 0x90, 0xb5, 0x3b, 0xb0, 0x9c, 0x36, 0xda, 0x66, 0x59, 0x14, 0x97,
        0x76, 0xcb, 0x28, 0x0e, 0x0f, 0xa8, 0x3c, 0xa7, 0x62, 0x81, 0xdb, 0x1a, 0xcb, 0x8d, 0xd1, 0xb7,
        0xc7, 0xec, 0x25, 0xbb, 0x4b, 0xdb, 0x80, 0x07, 0xf7, 0x3c, 0xa5, 0xf1, 0x61, 0x1a, 0x74, 0x99
    },
    .dLen = 128,
    .eBytes = {
        0x01, 0x00, 0x01
    },
    .eLen = 3,
    .pBytes = {
        0xdd, 0x35, 0x19, 0x94, 0xcb, 0xe0, 0x45, 0x43, 0xb8, 0x1f, 0x32, 0xfb, 0xfe, 0xd1, 0x51, 0x2a,
        0xc0, 0xa2, 0xdb, 0x93, 0x80, 0xde, 0xc0, 0x54, 0x90, 0xd5, 0xe2, 0xbd, 0xd3, 0x17, 0xfb, 0x9a,
        0xa5, 0xeb, 0x11, 0x33, 0x49, 0x73, 0xc8, 0xa7, 0x12, 0x69, 0x80, 0x58, 0xb4, 0x01, 0x58, 0xab,
        0x87, 0x38, 0x21, 0x89, 0x0b, 0xc5, 0x0a, 0x06, 0x10, 0x54, 0x62, 0x20, 0xfa, 0xbd, 0x88, 0xa3
    },
    .pLen = 64,
    .qBytes = {
        0xa9, 0x1e, 0xc2, 0x6b, 0x18, 0x0b, 0x23, 0x2a, 0x51, 0x62, 0x12, 0x05, 0x51, 0xe8, 0xe7, 0x66,
        0xcf, 0x33, 0xd1, 0xdb, 0xb3, 0x50, 0x27, 0xde, 0x1c, 0xfe, 0xf1, 0xb8, 0x1c, 0xc8, 0x29, 0x4b,
        0x0d, 0xa5, 0x75, 0x2b, 0x2c, 0x83, 0x19, 0xf8, 0x74, 0xe8, 0xea, 0x37, 0x55, 0x48, 0xe5, 0xc6,
        0xbc, 0x78, 0x74, 0x9d, 0xbb, 0x17, 0x17, 0x76, 0x63, 0xb8, 0x29, 0xe1, 0x8c, 0xe3, 0xe1, 0xeb
    },
    .qLen = 64,
};
static const SeosCryptoKey_RSAPub rsaPubData =
{
    .nBytes = {
        0x92, 0x22, 0xa2, 0x1b, 0x01, 0x61, 0xff, 0xc3, 0xdd, 0xc0, 0x4f, 0x8e, 0x91, 0xf1, 0xcc, 0x1f,
        0xdc, 0x0d, 0x2a, 0x08, 0x66, 0xaf, 0x0d, 0xd9, 0x05, 0xe8, 0xe7, 0xd6, 0x52, 0xa0, 0x38, 0x62,
        0x0a, 0x01, 0x8d, 0xd1, 0x3d, 0x43, 0x40, 0x6d, 0xfc, 0xf7, 0xc0, 0xa2, 0x1c, 0x87, 0xa5, 0x41,
        0xfe, 0xde, 0xcb, 0x73, 0x28, 0x5b, 0xbe, 0xd0, 0x4b, 0x9e, 0x3e, 0x59, 0xaf, 0x2f, 0x59, 0x92,
        0x22, 0x88, 0xf3, 0x00, 0x92, 0x66, 0x8d, 0xfc, 0x89, 0x99, 0x44, 0x38, 0x3c, 0xe4, 0x11, 0x42,
        0xd2, 0xa0, 0x95, 0xcc, 0xf1, 0xa8, 0x97, 0xe3, 0x71, 0x9d, 0xc1, 0xbe, 0x88, 0x68, 0x26, 0x42,
        0x2f, 0xe0, 0x10, 0x5e, 0x3e, 0xf6, 0xb2, 0xab, 0x0a, 0xa0, 0xe7, 0x87, 0xbd, 0xa4, 0x70, 0xdf,
        0x04, 0xce, 0x67, 0x6c, 0x48, 0xd3, 0xd3, 0xc0, 0x2d, 0xb2, 0x3f, 0xb3, 0x0d, 0x9c, 0xb0, 0xa1
    },
    .nLen = 128,
    .eBytes = {
        0x01, 0x00, 0x01
    },
    .eLen = 3,
};

// -----------------------------------------------------------------------------

static const SeosCryptoKey_SECP256r1Prv ecPrvData =
{
    .dBytes = {
        0xc6, 0xef, 0x9c, 0x5d, 0x78, 0xae, 0x01, 0x2a, 0x01, 0x11, 0x64, 0xac, 0xb3, 0x97, 0xce, 0x20,
        0x88, 0x68, 0x5d, 0x8f, 0x06, 0xbf, 0x9b, 0xe0, 0xb2, 0x83, 0xab, 0x46, 0x47, 0x6b, 0xee, 0x53
    },
    .dLen   = 32,
};
static const SeosCryptoKey_SECP256r1Pub ecPubData =
{
    .qxBytes = {
        0xda, 0xd0, 0xb6, 0x53, 0x94, 0x22, 0x1c, 0xf9, 0xb0, 0x51, 0xe1, 0xfe, 0xca, 0x57, 0x87, 0xd0,
        0x98, 0xdf, 0xe6, 0x37, 0xfc, 0x90, 0xb9, 0xef, 0x94, 0x5d, 0x0c, 0x37, 0x72, 0x58, 0x11, 0x80
    },
    .qxLen   = 32,
    .qyBytes = {
        0x52, 0x71, 0xa0, 0x46, 0x1c, 0xdb, 0x82, 0x52, 0xd6, 0x1f, 0x1c, 0x45, 0x6f, 0xa3, 0xe5, 0x9a,
        0xb1, 0xf4, 0x5b, 0x33, 0xac, 0xcf, 0x5f, 0x58, 0x38, 0x9e, 0x05, 0x77, 0xb8, 0x99, 0x0b, 0xb3
    },
    .qyLen   = 32,
};

// -----------------------------------------------------------------------------

static const SeosCryptoKey_AES aes128 =
{
    "0123456789abcdef", 16
};
static const SeosCryptoKey_AES aes192 =
{
    "0123456789abcdef01234567", 24
};
static const SeosCryptoKey_AES aes256 =
{
    "0123456789abcdef0123456789abcdef", 32
};
static const SeosCryptoKey_AES aes120 =
{
    "0123456789abcde", 15
};

static void
testKey_export_ok(SeosCryptoCtx* ctx)
{
    seos_err_t err;
    SeosCrypto_KeyHandle key = NULL;
    size_t sz;
    SeosCryptoKey_AES aesKey;
    SeosCryptoKey_Flags flags;
    SeosCryptoKey_Type type;

    // Import key and export it again
    err = SeosCryptoApi_keyImport(ctx, &key, NULL, SeosCryptoKey_Type_AES,
                                  SeosCryptoKey_Flags_EXPORTABLE_RAW, &aes128, sizeof(aes128));
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    sz = sizeof(aesKey);
    err = SeosCryptoApi_keyExport(ctx, key, NULL, &type, &flags, &aesKey, &sz);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(flags == SeosCryptoKey_Flags_EXPORTABLE_RAW);
    Debug_ASSERT(type == SeosCryptoKey_Type_AES);
    Debug_ASSERT(sz == sizeof(aesKey));
    Debug_ASSERT(aesKey.len == 128 / 8);
    Debug_ASSERT(memcmp(aesKey.bytes, aes128.bytes, 16) == 0);

    SeosCryptoApi_keyFree(ctx, key);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testKey_export_fail(SeosCryptoCtx* ctx)
{
    seos_err_t err;
    SeosCrypto_KeyHandle key = NULL, wrapKey = NULL;
    size_t sz;
    SeosCryptoKey_AES aesKey;
    SeosCryptoKey_Flags flags;
    SeosCryptoKey_Type type;

    err = SeosCryptoApi_keyImport(ctx, &key, NULL, SeosCryptoKey_Type_AES,
                                  SeosCryptoKey_Flags_EXPORTABLE_RAW, &aes128, sizeof(aes128));
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Empty context
    sz = sizeof(aesKey);
    err = SeosCryptoApi_keyExport(NULL, key, NULL, &type, &flags, &aesKey, &sz);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // No key given
    err = SeosCryptoApi_keyExport(ctx, NULL, NULL, &type, &flags, &aesKey, &sz);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);

    // With non-null wrapping key
    err = SeosCryptoApi_keyGenerate(ctx, &wrapKey, SeosCryptoKey_Type_AES, 0, 128);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyExport(ctx, key, wrapKey, &type, &flags, &aesKey, &sz);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);
    err = SeosCryptoApi_keyFree(ctx, wrapKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // No type buffer
    err = SeosCryptoApi_keyExport(ctx, key, NULL, NULL, &flags, &aesKey, &sz);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // No flags buffer
    err = SeosCryptoApi_keyExport(ctx, key, NULL, &type, NULL, &aesKey, &sz);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // No key data buffer
    err = SeosCryptoApi_keyExport(ctx, key, NULL, &type, &flags, NULL, &sz);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Invalid key buffer size
    sz = 17;
    err = SeosCryptoApi_keyExport(ctx, key, NULL, &type, &flags, &aesKey, &sz);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);

    err = SeosCryptoApi_keyFree(ctx, key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Try non-exportable key
    err = SeosCryptoApi_keyGenerate(ctx, &key, SeosCryptoKey_Type_AES,
                                    SeosCryptoKey_Flags_NONE, 128);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    sz = sizeof(aesKey);
    err = SeosCryptoApi_keyExport(ctx, key, NULL, &type, &flags, &aesKey, &sz);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_ACCESS_DENIED == err, "err %d", err);
    SeosCryptoApi_keyFree(ctx, key);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testKey_import_ok(SeosCryptoCtx* ctx)
{
    seos_err_t err;
    SeosCrypto_KeyHandle key = NULL;

    // Try out 128 bit key
    err = SeosCryptoApi_keyImport(ctx, &key, NULL, SeosCryptoKey_Type_AES,
                                  SeosCryptoKey_Flags_NONE, &aes128, sizeof(aes128));
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    SeosCryptoApi_keyFree(ctx, key);

    // Try out 192 bit key
    err = SeosCryptoApi_keyImport(ctx, &key, NULL, SeosCryptoKey_Type_AES,
                                  SeosCryptoKey_Flags_NONE, &aes192, sizeof(aes192));
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    SeosCryptoApi_keyFree(ctx, key);

    // Try out 256 bit key
    err = SeosCryptoApi_keyImport(ctx, &key, NULL, SeosCryptoKey_Type_AES,
                                  SeosCryptoKey_Flags_NONE, &aes256, sizeof(aes256));
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    SeosCryptoApi_keyFree(ctx, key);

    // Import RSA public key
    err = SeosCryptoApi_keyImport(ctx, &key, NULL, SeosCryptoKey_Type_RSA_PUB,
                                  SeosCryptoKey_Flags_NONE, &rsaPubData, sizeof(rsaPubData));
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    SeosCryptoApi_keyFree(ctx, key);

    // Import RSA private key
    err = SeosCryptoApi_keyImport(ctx, &key, NULL, SeosCryptoKey_Type_RSA_PRV,
                                  SeosCryptoKey_Flags_NONE, &rsaPrvData, sizeof(rsaPrvData));
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    SeosCryptoApi_keyFree(ctx, key);

    // Import DH public key
    err = SeosCryptoApi_keyImport(ctx, &key, NULL, SeosCryptoKey_Type_DH_PUB,
                                  SeosCryptoKey_Flags_NONE, &dhPubData, sizeof(dhPubData));
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    SeosCryptoApi_keyFree(ctx, key);

    // Import DH private key
    err = SeosCryptoApi_keyImport(ctx, &key, NULL, SeosCryptoKey_Type_DH_PRV,
                                  SeosCryptoKey_Flags_NONE, &dhPrvData, sizeof(dhPrvData));
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    SeosCryptoApi_keyFree(ctx, key);

    // Import SECP256r1 public key
    err = SeosCryptoApi_keyImport(ctx, &key, NULL, SeosCryptoKey_Type_SECP256R1_PUB,
                                  SeosCryptoKey_Flags_NONE, &ecPubData, sizeof(ecPubData));
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    SeosCryptoApi_keyFree(ctx, key);

    // Import SECP256r1 private key
    err = SeosCryptoApi_keyImport(ctx, &key, NULL, SeosCryptoKey_Type_SECP256R1_PRV,
                                  SeosCryptoKey_Flags_NONE, &ecPrvData, sizeof(ecPrvData));
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    SeosCryptoApi_keyFree(ctx, key);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testKey_import_fail(SeosCryptoCtx* ctx)
{
    seos_err_t err;
    SeosCrypto_KeyHandle key = NULL, wrapKey = NULL;

    // No context
    err = SeosCryptoApi_keyImport(NULL, &key, NULL, SeosCryptoKey_Type_AES,
                                  SeosCryptoKey_Flags_NONE, &aes128, sizeof(aes128));
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // No key handle
    err = SeosCryptoApi_keyImport(ctx, NULL, NULL, SeosCryptoKey_Type_AES,
                                  SeosCryptoKey_Flags_NONE, &aes128, sizeof(aes128));
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // // Non-NULL wrapping key
    err = SeosCryptoApi_keyImport(ctx, &wrapKey, NULL, SeosCryptoKey_Type_AES,
                                  SeosCryptoKey_Flags_NONE, &aes128, sizeof(aes128));
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyImport(ctx, &key, wrapKey, SeosCryptoKey_Type_AES,
                                  SeosCryptoKey_Flags_NONE, &aes128, sizeof(aes128));
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);
    SeosCryptoApi_keyFree(ctx, wrapKey);

    // Invalid key type
    err = SeosCryptoApi_keyImport(ctx, &key, NULL, 666,
                                  SeosCryptoKey_Flags_NONE, &aes128, sizeof(aes128));
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Invalid flags
    err = SeosCryptoApi_keyImport(ctx, &key, NULL, SeosCryptoKey_Type_AES,
                                  666, &aes128, sizeof(aes128));
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty key buffer
    err = SeosCryptoApi_keyImport(ctx, &key, NULL, SeosCryptoKey_Type_AES,
                                  SeosCryptoKey_Flags_NONE, NULL, sizeof(aes128));
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Zero size
    err = SeosCryptoApi_keyImport(ctx, &key, NULL, SeosCryptoKey_Type_AES,
                                  SeosCryptoKey_Flags_NONE, &aes128, 17);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Import wrong keysize
    err = SeosCryptoApi_keyImport(ctx, &key, NULL, SeosCryptoKey_Type_AES,
                                  SeosCryptoKey_Flags_NONE, &aes120, sizeof(aes120));
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Try importing a key, twice
    err = SeosCryptoApi_keyImport(ctx, &key, NULL, SeosCryptoKey_Type_AES,
                                  SeosCryptoKey_Flags_NONE, &aes128, sizeof(aes128));
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyImport(ctx, &key, NULL, SeosCryptoKey_Type_AES,
                                  SeosCryptoKey_Flags_NONE, &aes128, sizeof(aes128));
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);
    SeosCryptoApi_keyFree(ctx, key);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testKey_generate_ok(SeosCryptoCtx* ctx)
{
    seos_err_t err;
    size_t sz;
    SeosCrypto_KeyHandle key = NULL;
    SeosCryptoKey_AES aesKey;
    SeosCryptoKey_Type type;
    SeosCryptoKey_Flags flags;

    err = SeosCryptoApi_keyGenerate(ctx, &key,  SeosCryptoKey_Type_AES,
                                    SeosCryptoKey_Flags_EXPORTABLE_RAW, 128);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    sz = sizeof(aesKey);
    err = SeosCryptoApi_keyExport(ctx, key, NULL, &type, &flags, &aesKey, &sz);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(flags == SeosCryptoKey_Flags_EXPORTABLE_RAW);
    Debug_ASSERT(type == SeosCryptoKey_Type_AES);
    Debug_ASSERT(sz == sizeof(aesKey));
    Debug_ASSERT(aesKey.len == 128 / 8);

    SeosCryptoApi_keyFree(ctx, key);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testKey_generate_fail(SeosCryptoCtx* ctx)
{
    seos_err_t err;
    SeosCrypto_KeyHandle key = NULL;

    // Dont pass ctx
    err = SeosCryptoApi_keyGenerate(NULL, &key,  SeosCryptoKey_Type_AES,
                                    SeosCryptoKey_Flags_EXPORTABLE_RAW, 128);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Pass empty key handle
    err = SeosCryptoApi_keyGenerate(ctx, NULL, SeosCryptoKey_Type_AES,
                                    SeosCryptoKey_Flags_EXPORTABLE_RAW, 128);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Pas invalid algorithm
    err = SeosCryptoApi_keyGenerate(ctx, &key, 666,
                                    SeosCryptoKey_Flags_EXPORTABLE_RAW, 128);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Pass invalid flag
    err = SeosCryptoApi_keyGenerate(ctx, &key,  SeosCryptoKey_Type_AES, 666, 128);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Pass invalid key size for AES
    err = SeosCryptoApi_keyGenerate(ctx, &key,  SeosCryptoKey_Type_AES,
                                    SeosCryptoKey_Flags_EXPORTABLE_RAW, 166);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testKey_generatePair_ok(SeosCryptoCtx* ctx)
{
    seos_err_t err;
    size_t sz;
    SeosCrypto_KeyHandle prvKey = NULL, pubKey = NULL;
    SeosCryptoKey_RSAPrv rsaPrv;
    SeosCryptoKey_RSAPub rsaPub;
    SeosCryptoKey_SECP256r1Prv ecPrv;
    SeosCryptoKey_SECP256r1Pub ecPub;
    SeosCryptoKey_DHPrv dhPrv;
    SeosCryptoKey_DHPub dhPub;
    SeosCryptoKey_Flags flags;
    SeosCryptoKey_Type type;

    // Generate RSA keypair
    err = SeosCryptoApi_keyGeneratePair(ctx, &prvKey, &pubKey,
                                        SeosCryptoKey_PairType_RSA, SeosCryptoKey_Flags_EXPORTABLE_RAW,
                                        SeosCryptoKey_Flags_EXPORTABLE_RAW, 128);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    sz = sizeof(rsaPrv);
    err = SeosCryptoApi_keyExport(ctx, prvKey, NULL, &type, &flags, &rsaPrv, &sz);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(type == SeosCryptoKey_Type_RSA_PRV);
    Debug_ASSERT(flags == SeosCryptoKey_Flags_EXPORTABLE_RAW);
    Debug_ASSERT(sz == sizeof(rsaPrv));
    sz = sizeof(rsaPub);
    err = SeosCryptoApi_keyExport(ctx, pubKey, NULL, &type, &flags, &rsaPub, &sz);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(type == SeosCryptoKey_Type_RSA_PUB);
    Debug_ASSERT(flags == SeosCryptoKey_Flags_EXPORTABLE_RAW);
    Debug_ASSERT(sz == sizeof(rsaPub));
    SeosCryptoApi_keyFree(ctx, prvKey);
    SeosCryptoApi_keyFree(ctx, pubKey);

    // Generate EC keypair
    err = SeosCryptoApi_keyGeneratePair(ctx, &prvKey, &pubKey,
                                        SeosCryptoKey_PairType_SECP256R1, SeosCryptoKey_Flags_EXPORTABLE_RAW,
                                        SeosCryptoKey_Flags_EXPORTABLE_RAW, 256);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    sz = sizeof(ecPrv);
    err = SeosCryptoApi_keyExport(ctx, prvKey, NULL, &type, &flags, &ecPrv, &sz);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(type == SeosCryptoKey_Type_SECP256R1_PRV);
    Debug_ASSERT(flags == SeosCryptoKey_Flags_EXPORTABLE_RAW);
    Debug_ASSERT(sz == sizeof(ecPrv));
    sz = sizeof(ecPub);
    err = SeosCryptoApi_keyExport(ctx, pubKey, NULL, &type, &flags, &ecPub, &sz);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(type == SeosCryptoKey_Type_SECP256R1_PUB);
    Debug_ASSERT(flags == SeosCryptoKey_Flags_EXPORTABLE_RAW);
    Debug_ASSERT(sz == sizeof(ecPub));
    SeosCryptoApi_keyFree(ctx, prvKey);
    SeosCryptoApi_keyFree(ctx, pubKey);

    // Generate DH keypair
    err = SeosCryptoApi_keyGeneratePair(ctx, &prvKey, &pubKey,
                                        SeosCryptoKey_PairType_DH, SeosCryptoKey_Flags_EXPORTABLE_RAW,
                                        SeosCryptoKey_Flags_EXPORTABLE_RAW, 128);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    sz = sizeof(dhPrv);
    err = SeosCryptoApi_keyExport(ctx, prvKey, NULL, &type, &flags, &dhPrv, &sz);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(type == SeosCryptoKey_Type_DH_PRV);
    Debug_ASSERT(flags == SeosCryptoKey_Flags_EXPORTABLE_RAW);
    Debug_ASSERT(sz == sizeof(dhPrv));
    sz = sizeof(dhPub);
    err = SeosCryptoApi_keyExport(ctx, pubKey, NULL, &type, &flags, &dhPub, &sz);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(type == SeosCryptoKey_Type_DH_PUB);
    Debug_ASSERT(flags == SeosCryptoKey_Flags_EXPORTABLE_RAW);
    Debug_ASSERT(sz == sizeof(dhPrv));
    SeosCryptoApi_keyFree(ctx, prvKey);
    SeosCryptoApi_keyFree(ctx, pubKey);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testKey_generatePair_fail(SeosCryptoCtx* ctx)
{
    seos_err_t err;
    SeosCrypto_KeyHandle prvKey, pubKey;

    // Empty ctx
    err = SeosCryptoApi_keyGeneratePair(NULL, &prvKey, &pubKey,
                                        SeosCryptoKey_PairType_RSA, SeosCryptoKey_Flags_EXPORTABLE_RAW,
                                        SeosCryptoKey_Flags_EXPORTABLE_RAW, 128);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty prvKey
    err = SeosCryptoApi_keyGeneratePair(ctx, NULL, &pubKey,
                                        SeosCryptoKey_PairType_RSA, SeosCryptoKey_Flags_EXPORTABLE_RAW,
                                        SeosCryptoKey_Flags_EXPORTABLE_RAW, 128);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty pubKey
    err = SeosCryptoApi_keyGeneratePair(ctx, &prvKey, NULL,
                                        SeosCryptoKey_PairType_RSA, SeosCryptoKey_Flags_EXPORTABLE_RAW,
                                        SeosCryptoKey_Flags_EXPORTABLE_RAW, 128);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Wrong pair type
    err = SeosCryptoApi_keyGeneratePair(ctx, &prvKey, &pubKey,
                                        666, SeosCryptoKey_Flags_EXPORTABLE_RAW,
                                        SeosCryptoKey_Flags_EXPORTABLE_RAW, 128);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Wrong prv key flags
    err = SeosCryptoApi_keyGeneratePair(ctx, &prvKey, &pubKey,
                                        SeosCryptoKey_PairType_RSA, 666,
                                        SeosCryptoKey_Flags_EXPORTABLE_RAW, 128);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Wrong pub key flags
    err = SeosCryptoApi_keyGeneratePair(ctx, &prvKey, &pubKey,
                                        SeosCryptoKey_PairType_RSA, SeosCryptoKey_Flags_EXPORTABLE_RAW,
                                        666, 128);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Too small RSA size
    err = SeosCryptoApi_keyGeneratePair(ctx, &prvKey, &pubKey,
                                        SeosCryptoKey_PairType_RSA, SeosCryptoKey_Flags_EXPORTABLE_RAW,
                                        SeosCryptoKey_Flags_EXPORTABLE_RAW, 127);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Too big RSA size
    err = SeosCryptoApi_keyGeneratePair(ctx, &prvKey, &pubKey,
                                        SeosCryptoKey_PairType_RSA, SeosCryptoKey_Flags_EXPORTABLE_RAW,
                                        SeosCryptoKey_Flags_EXPORTABLE_RAW, 4097);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Too big DH size
    err = SeosCryptoApi_keyGeneratePair(ctx, &prvKey, &pubKey,
                                        SeosCryptoKey_PairType_DH, SeosCryptoKey_Flags_EXPORTABLE_RAW,
                                        SeosCryptoKey_Flags_EXPORTABLE_RAW, 4097);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Too small DH size
    err = SeosCryptoApi_keyGeneratePair(ctx, &prvKey, &pubKey,
                                        SeosCryptoKey_PairType_DH, SeosCryptoKey_Flags_EXPORTABLE_RAW,
                                        SeosCryptoKey_Flags_EXPORTABLE_RAW, 63);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Incorrect EC size
    err = SeosCryptoApi_keyGeneratePair(ctx, &prvKey, &pubKey,
                                        SeosCryptoKey_PairType_SECP256R1, SeosCryptoKey_Flags_EXPORTABLE_RAW,
                                        SeosCryptoKey_Flags_EXPORTABLE_RAW, 255);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

void testKey(SeosCryptoCtx* ctx)
{
    testKey_export_ok(ctx);
    testKey_export_fail(ctx);

    testKey_import_ok(ctx);
    testKey_import_fail(ctx);

    testKey_generate_ok(ctx);
    testKey_generate_fail(ctx);

    testKey_generatePair_ok(ctx);
    testKey_generatePair_fail(ctx);
}