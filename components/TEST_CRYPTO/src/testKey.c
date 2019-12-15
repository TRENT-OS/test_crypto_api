/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include "SeosCryptoApi.h"

#include "LibDebug/Debug.h"

#include <string.h>

static const SeosCryptoApi_Key_Data dh101PrvData =
{
    .type = SeosCryptoApi_Key_TYPE_DH_PRV,
    .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
    .data.dh.prv = {
        .params = {
            .pBytes = {0x12, 0xdf, 0x4d, 0x76, 0x89, 0xdf, 0xf4, 0xc9, 0x9d, 0x9a, 0xe5, 0x7d, 0x07},
            .pLen   = 13,
            .gBytes = {0x00, 0x1e, 0x32, 0x15, 0x8a, 0x35, 0xe3, 0x4d, 0x7b, 0x61, 0x96, 0x57, 0xd6},
            .gLen   = 13,
        },
        .xBytes = {0x11, 0x46, 0xbc, 0x69, 0xaf, 0x6c, 0x32, 0xca, 0xfa, 0xd1, 0x46, 0xbc, 0x69},
        .xLen   = 13,
    }
};
static const SeosCryptoApi_Key_Data dh101PubData =
{
    .type = SeosCryptoApi_Key_TYPE_DH_PUB,
    .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
    .data.dh.pub = {
        .params = {
            .pBytes  = {0x12, 0xdf, 0x4d, 0x76, 0x89, 0xdf, 0xf4, 0xc9, 0x9d, 0x9a, 0xe5, 0x7d, 0x07},
            .pLen    = 13,
            .gBytes  = {0x00, 0x1e, 0x32, 0x15, 0x8a, 0x35, 0xe3, 0x4d, 0x7b, 0x61, 0x96, 0x57, 0xd6},
            .gLen    = 13,
        },
        .gxBytes = {0x00, 0x41, 0x83, 0xa8, 0x6f, 0x35, 0x71, 0x0e, 0x4e, 0x69, 0xb1, 0x64, 0xa4},
        .gxLen   = 13,
    }
};

// -----------------------------------------------------------------------------

static const SeosCryptoApi_Key_Data rsa1024PrvData =
{
    .type = SeosCryptoApi_Key_TYPE_RSA_PRV,
    .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
    .data.rsa.prv = {
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
    }
};
static const SeosCryptoApi_Key_Data rsa1024PubData =
{
    .type = SeosCryptoApi_Key_TYPE_RSA_PUB,
    .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
    .data.rsa.pub = {
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
    }
};
static const SeosCryptoApi_Key_Data rsaSmallData =
{
    .type = SeosCryptoApi_Key_TYPE_RSA_PRV,
    .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
    .data.rsa.prv = {
        .dBytes = {
            0xc7, 0xec, 0x25, 0xbb, 0x4b
        },
        .dLen = 5,
        .eBytes = {
            0x01, 0x00, 0x01
        },
        .eLen = 3,
        .pBytes = {
            0xdd, 0x35,
        },
        .pLen = 2,
        .qBytes = {
            0xa9, 0x1e, 0xc2
        },
        .qLen = 3,
    }
};
static const SeosCryptoApi_Key_Data rsaLargeData =
{
    .type = SeosCryptoApi_Key_TYPE_RSA_PRV,
    .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
    .data.rsa.prv = {
        .dBytes = {
            0xc7, 0xec, 0x25, 0xbb, 0x4b
        },
        .dLen = 1555,
        .eBytes = {
            0x01, 0x00, 0x01
        },
        .eLen = 1335,
        .pBytes = {
            0xdd, 0x35,
        },
        .pLen = 1111,
        .qBytes = {
            0xa9, 0x1e, 0xc2
        },
        .qLen = 7777,
    }
};

// -----------------------------------------------------------------------------

static const SeosCryptoApi_Key_Data secp256r1PrvData =
{
    .type = SeosCryptoApi_Key_TYPE_SECP256R1_PRV,
    .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
    .data.secp256r1.prv = {
        .dBytes = {
            0xc6, 0xef, 0x9c, 0x5d, 0x78, 0xae, 0x01, 0x2a, 0x01, 0x11, 0x64, 0xac, 0xb3, 0x97, 0xce, 0x20,
            0x88, 0x68, 0x5d, 0x8f, 0x06, 0xbf, 0x9b, 0xe0, 0xb2, 0x83, 0xab, 0x46, 0x47, 0x6b, 0xee, 0x53
        },
        .dLen   = 32,
    }
};
static const SeosCryptoApi_Key_Data secp256r1PubData =
{
    .type = SeosCryptoApi_Key_TYPE_SECP256R1_PUB,
    .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
    .data.secp256r1.pub = {
        .qxBytes = {
            0xda, 0xd0, 0xb6, 0x53, 0x94, 0x22, 0x1c, 0xf9, 0xb0, 0x51, 0xe1, 0xfe, 0xca, 0x57, 0x87, 0xd0,
            0x98, 0xdf, 0xe6, 0x37, 0xfc, 0x90, 0xb9, 0xef, 0x94, 0x5d, 0x0c, 0x37, 0x72, 0x58, 0x11, 0x80
        },
        .qxLen   = 32,
        .qyBytes = {
            0x52, 0x71, 0xa0, 0x46, 0x1c, 0xdb, 0x82, 0x52, 0xd6, 0x1f, 0x1c, 0x45, 0x6f, 0xa3, 0xe5, 0x9a,
            0xb1, 0xf4, 0x5b, 0x33, 0xac, 0xcf, 0x5f, 0x58, 0x38, 0x9e, 0x05, 0x77, 0xb8, 0x99, 0x0b, 0xb3
        },
        .qyLen   = 32
    }
};

// -----------------------------------------------------------------------------

static const SeosCryptoApi_Key_Data aes128Data =
{
    .type = SeosCryptoApi_Key_TYPE_AES,
    .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
    .data.aes = {
        .bytes = "0123456789abcdef",
        .len = 16
    }
};
static const SeosCryptoApi_Key_Data aes192Data =
{
    .type = SeosCryptoApi_Key_TYPE_AES,
    .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
    .data.aes = {
        .bytes = "0123456789abcdef01234567",
        .len = 24
    }
};
static const SeosCryptoApi_Key_Data aes256Data =
{
    .type = SeosCryptoApi_Key_TYPE_AES,
    .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
    .data.aes = {
        .bytes = "0123456789abcdef0123456789abcdef",
        .len = 32
    }
};
static const SeosCryptoApi_Key_Data aes120Data =
{
    .type = SeosCryptoApi_Key_TYPE_AES,
    .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
    .data.aes = {
        .bytes = "0123456789abcde",
        .len = 15
    }
};

// -----------------------------------------------------------------------------

static const SeosCryptoApi_Key_Spec aes128Spec =
{
    .type = SeosCryptoApi_Key_SPECTYPE_BITS,
    .key = {
        .type = SeosCryptoApi_Key_TYPE_AES,
        .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
        .params.bits = 128
    }
};
static const SeosCryptoApi_Key_Spec aes128noExpSpec =
{
    .type = SeosCryptoApi_Key_SPECTYPE_BITS,
    .key = {
        .type = SeosCryptoApi_Key_TYPE_AES,
        .attribs.flags = SeosCryptoApi_Key_FLAG_NONE,
        .params.bits = 128
    }
};
static const SeosCryptoApi_Key_Spec aes192Spec =
{
    .type = SeosCryptoApi_Key_SPECTYPE_BITS,
    .key = {
        .type = SeosCryptoApi_Key_TYPE_AES,
        .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
        .params.bits = 192
    }
};
static const SeosCryptoApi_Key_Spec aes256Spec =
{
    .type = SeosCryptoApi_Key_SPECTYPE_BITS,
    .key = {
        .type = SeosCryptoApi_Key_TYPE_AES,
        .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
        .params.bits = 256
    }
};
static const SeosCryptoApi_Key_Spec aes120Spec =
{
    .type = SeosCryptoApi_Key_SPECTYPE_BITS,
    .key = {
        .type = SeosCryptoApi_Key_TYPE_AES,
        .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
        .params.bits = 120
    }
};
static const SeosCryptoApi_Key_Spec dh64bSpec =
{
    .type = SeosCryptoApi_Key_SPECTYPE_BITS,
    .key = {
        .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
        .type = SeosCryptoApi_Key_TYPE_DH_PRV,
        .params.bits = 64
    }
};
static const SeosCryptoApi_Key_Spec dh101pSpec =
{
    .type = SeosCryptoApi_Key_SPECTYPE_PARAMS,
    .key = {
        .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
        .type = SeosCryptoApi_Key_TYPE_DH_PRV,
        .params.dh = {
            .pBytes = {0x12, 0xdf, 0x4d, 0x76, 0x89, 0xdf, 0xf4, 0xc9, 0x9d, 0x9a, 0xe5, 0x7d, 0x07},
            .pLen   = 13,
            .gBytes = {0x00, 0x1e, 0x32, 0x15, 0x8a, 0x35, 0xe3, 0x4d, 0x7b, 0x61, 0x96, 0x57, 0xd6},
            .gLen   = 13,
        }
    }
};
static const SeosCryptoApi_Key_Spec dh63bSpec =
{
    .type = SeosCryptoApi_Key_SPECTYPE_BITS,
    .key = {
        .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
        .type = SeosCryptoApi_Key_TYPE_DH_PRV,
        .params.bits = 63
    }
};
static const SeosCryptoApi_Key_Spec rsa128Spec =
{
    .type = SeosCryptoApi_Key_SPECTYPE_BITS,
    .key = {
        .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
        .type = SeosCryptoApi_Key_TYPE_RSA_PRV,
        .params.bits = 128
    }
};
static const SeosCryptoApi_Key_Spec secp256r1Spec =
{
    .type = SeosCryptoApi_Key_SPECTYPE_BITS,
    .key = {
        .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
        .type = SeosCryptoApi_Key_TYPE_SECP256R1_PRV,
    }
};
static const SeosCryptoApi_Key_Spec rsa127Spec =
{
    .type = SeosCryptoApi_Key_SPECTYPE_BITS,
    .key = {
        .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
        .type = SeosCryptoApi_Key_TYPE_RSA_PRV,
        .params.bits = 127
    }
};

// -----------------------------------------------------------------------------

static seos_err_t
do_import(SeosCryptoApi_Context*        ctx,
          const SeosCryptoApi_Key_Data* data)
{
    seos_err_t err;
    SeosCryptoApi_Key key;

    if ((err = SeosCryptoApi_Key_import(ctx, &key, NULL, data)) != SEOS_SUCCESS)
    {
        return err;
    }
    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    return SEOS_SUCCESS;
}

static void
testKey_import_ok(SeosCryptoApi_Context* ctx)
{
    seos_err_t err;

    // Import 128-bit AES key
    err = do_import(ctx, &aes128Data);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Import 192-bit AES key
    err = do_import(ctx, &aes192Data);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Import 256-bit AES key
    err = do_import(ctx, &aes256Data);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Import 1024-bit RSA pubkey
    err = do_import(ctx, &rsa1024PubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Import 1024-bit RSA prvkey
    err = do_import(ctx, &rsa1024PrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Import 101-bit DH pubkey
    err = do_import(ctx, &dh101PubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Import 101-bit DH RSA prvkey
    err = do_import(ctx, &dh101PrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Import SECP256r1 pubkey
    err = do_import(ctx, &secp256r1PubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Import SECP256r1 prvkey
    err = do_import(ctx, &secp256r1PrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testKey_import_fail(SeosCryptoApi_Context* ctx)
{
    seos_err_t err;
    SeosCryptoApi_Key key, wrapKey;

    err = SeosCryptoApi_Key_import(ctx, &wrapKey, NULL, &aes128Data);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Empty ctx
    err = SeosCryptoApi_Key_import(NULL, &key, NULL, &aes128Data);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty key
    err = SeosCryptoApi_Key_import(ctx, NULL, NULL, &aes128Data);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Non-empty wrapping key
    err = SeosCryptoApi_Key_import(ctx, &key, &wrapKey, &aes128Data);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Empty key data
    err = SeosCryptoApi_Key_import(ctx, &key, NULL, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Invalid AES key
    err = SeosCryptoApi_Key_import(ctx, &key, NULL, &aes120Data);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Invalid RSA key (too small)
    err = SeosCryptoApi_Key_import(ctx, &key, NULL, &rsaSmallData);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Invalid RSA key (too big)
    err = SeosCryptoApi_Key_import(ctx, &key, NULL, &rsaLargeData);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&wrapKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static seos_err_t
do_export(SeosCryptoApi_Context*        ctx,
          const SeosCryptoApi_Key_Data* data)
{
    seos_err_t err;
    SeosCryptoApi_Key key;
    SeosCryptoApi_Key_Data expData;

    err = SeosCryptoApi_Key_import(ctx, &key, NULL, data);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    memset(&expData, 0, sizeof(SeosCryptoApi_Key_Data));
    if ((err = SeosCryptoApi_Key_export(&key, NULL, &expData)) != SEOS_SUCCESS)
    {
        return err;
    }
    Debug_ASSERT(!memcmp(data, &expData, sizeof(SeosCryptoApi_Key_Data)));
    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    return SEOS_SUCCESS;
}

static void
testKey_export_ok(SeosCryptoApi_Context* ctx)
{
    seos_err_t err;

    // Export 128-bit AES key
    err = do_export(ctx, &aes128Data);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Export 192-bit AES key
    err = do_export(ctx, &aes192Data);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Export 256-bit AES key
    err = do_export(ctx, &aes256Data);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Export 1024-bit RSA pubkey
    err = do_export(ctx, &rsa1024PubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Export 1024-bit RSA prvkey
    err = do_export(ctx, &rsa1024PrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Export 101-bit DH pubkey
    err = do_export(ctx, &dh101PubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Export 101-bit DH prvkey
    err = do_export(ctx, &dh101PrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Export SECP256r1 pubkey
    err = do_export(ctx, &secp256r1PubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Export SECP256r1 prvkey
    err = do_export(ctx, &secp256r1PrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testKey_export_fail(SeosCryptoApi_Context* ctx)
{
    seos_err_t err;
    SeosCryptoApi_Key key, wrapKey;
    SeosCryptoApi_Key_Data expData;

    err = SeosCryptoApi_Key_import(ctx, &key, NULL, &aes128Data);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_generate(ctx, &wrapKey, &aes128noExpSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Empty key
    err = SeosCryptoApi_Key_export(NULL, NULL, &expData);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Non-empty wrapping key
    err = SeosCryptoApi_Key_export(&key, &wrapKey, &expData);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Empty export data buffer
    err = SeosCryptoApi_Key_export(&key, NULL, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Non-exportable key
    err = SeosCryptoApi_Key_export(&wrapKey, NULL, &expData);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_OPERATION_DENIED == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&wrapKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static seos_err_t
do_generate(SeosCryptoApi_Context*        ctx,
            const SeosCryptoApi_Key_Spec* spec)
{
    seos_err_t err;
    SeosCryptoApi_Key key;
    SeosCryptoApi_Key_Data expData;

    if ((err = SeosCryptoApi_Key_generate(ctx, &key, spec)) != SEOS_SUCCESS)
    {
        return err;
    }
    memset(&expData, 0, sizeof(SeosCryptoApi_Key_Data));
    err = SeosCryptoApi_Key_export(&key, NULL, &expData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(spec->key.type == expData.type);
    Debug_ASSERT(!memcmp(&spec->key.attribs, &expData.attribs,
                         sizeof(SeosCryptoApi_Key_Attribs)));
    if (spec->type == SeosCryptoApi_Key_SPECTYPE_PARAMS)
    {
        switch (spec->key.type)
        {
        case SeosCryptoApi_Key_TYPE_DH_PRV:
            Debug_ASSERT(!memcmp(&spec->key.params, &expData.data.dh.prv.params,
                                 sizeof(SeosCryptoApi_Key_DhParams)));
            break;
        default:
            Debug_ASSERT(1 == 0);
        }
    }
    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    return SEOS_SUCCESS;
}

static void
testKey_generate_ok(SeosCryptoApi_Context* ctx)
{
    seos_err_t err;

    // Generate 128-bit AES key
    err = do_generate(ctx, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Generate 192-bit AES key
    err = do_generate(ctx, &aes192Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Generate 256-bit AES key
    err = do_generate(ctx, &aes256Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Generate 64-bit DH privkey from bit spec
    err = do_generate(ctx, &dh64bSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Generate 101-bit DH privkey from param spec
    err = do_generate(ctx, &dh101pSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Generate 128-bit RSA privkey
    err = do_generate(ctx, &rsa128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Generate SECP256r1 privkey
    err = do_generate(ctx, &secp256r1Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testKey_generate_fail(SeosCryptoApi_Context* ctx)
{
    seos_err_t err;
    SeosCryptoApi_Key key;

    // Empty ctx
    err = SeosCryptoApi_Key_generate(NULL, &key, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty key
    err = SeosCryptoApi_Key_generate(ctx, NULL, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty spec
    err = SeosCryptoApi_Key_generate(ctx, &key, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Wrong key size: 120-bit AES key
    err = SeosCryptoApi_Key_generate(ctx, &key, &aes120Spec);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Wrong key size: 127-bit RSA key
    err = SeosCryptoApi_Key_generate(ctx, &key, &rsa127Spec);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Wrong key size: 63-bit DH key
    err = SeosCryptoApi_Key_generate(ctx, &key, &dh63bSpec);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static seos_err_t
do_makePublic(SeosCryptoApi_Context*        ctx,
              const SeosCryptoApi_Key_Spec* spec)
{
    seos_err_t err;
    SeosCryptoApi_Key key, pubKey;
    SeosCryptoApi_Key_Data expData;

    err = SeosCryptoApi_Key_generate(ctx, &key, spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    if ((err = SeosCryptoApi_Key_makePublic(&pubKey, &key,
                                            &spec->key.attribs)) != SEOS_SUCCESS)
    {
        return err;
    }
    err = SeosCryptoApi_Key_export(&pubKey, NULL, &expData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    switch (spec->key.type)
    {
    case SeosCryptoApi_Key_TYPE_RSA_PRV:
        Debug_ASSERT(expData.type == SeosCryptoApi_Key_TYPE_RSA_PUB);
        break;
    case SeosCryptoApi_Key_TYPE_DH_PRV:
        Debug_ASSERT(expData.type == SeosCryptoApi_Key_TYPE_DH_PUB);
        if (SeosCryptoApi_Key_SPECTYPE_PARAMS == spec->type)
        {
            Debug_ASSERT(!memcmp(&expData.data.dh.pub.params, &spec->key.params.dh,
                                 sizeof(SeosCryptoApi_Key_DhParams)));
        }
        break;
    case SeosCryptoApi_Key_TYPE_SECP256R1_PRV:
        Debug_ASSERT(expData.type == SeosCryptoApi_Key_TYPE_SECP256R1_PUB);
        break;
    default:
        Debug_ASSERT(1 == 0);
    }
    err = SeosCryptoApi_Key_free(&pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    return SEOS_SUCCESS;

}
static void
testKey_makePublic_ok(SeosCryptoApi_Context* ctx)
{
    seos_err_t err;

    // Make DH pubkey, with privkey from bit spec
    err = do_makePublic(ctx, &dh64bSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Make DH pubkey, with privkey from param spec
    err = do_makePublic(ctx, &dh101pSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Make RSA pubkey
    err = do_makePublic(ctx, &rsa128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Make SECP256r1 pubkey
    err = do_makePublic(ctx, &secp256r1Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testKey_makePublic_fail(SeosCryptoApi_Context* ctx)
{
    seos_err_t err;
    SeosCryptoApi_Key key, pubKey;

    err = SeosCryptoApi_Key_generate(ctx, &key, &dh64bSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Empty target handle
    err = SeosCryptoApi_Key_makePublic(NULL, &key, &dh64bSpec.key.attribs);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Invalid private handle
    err = SeosCryptoApi_Key_makePublic(&pubKey, NULL, &dh64bSpec.key.attribs);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty attribs
    err = SeosCryptoApi_Key_makePublic(&pubKey, &key, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Try making "public" from a symmetric key
    err = SeosCryptoApi_Key_generate(ctx, &key, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_makePublic(&pubKey, &key, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testKey_getParams_ok(SeosCryptoApi_Context* ctx)
{
    seos_err_t err;
    size_t n;
    SeosCryptoApi_Key key;
    SeosCryptoApi_Key_DhParams dhParams;
    SeosCryptoApi_Key_Data expData;

    // Generate params for DH
    err = SeosCryptoApi_Key_generate(ctx, &key, &dh101pSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    n = sizeof(dhParams);
    err = SeosCryptoApi_Key_getParams(&key, &dhParams, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(n == sizeof(dhParams));
    err = SeosCryptoApi_Key_export(&key, NULL, &expData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(!memcmp(&expData.data.dh.prv.params, &dhParams, n));
    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testKey_getParams_fail(SeosCryptoApi_Context* ctx)
{
    seos_err_t err;
    size_t n;
    SeosCryptoApi_Key key;
    SeosCryptoApi_Key_DhParams dhParams;

    err = SeosCryptoApi_Key_generate(ctx, &key, &dh64bSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Empty key handle
    n = sizeof(dhParams);
    err = SeosCryptoApi_Key_getParams(NULL, &dhParams, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty buffer
    err = SeosCryptoApi_Key_getParams(&key, NULL, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty buffer len
    err = SeosCryptoApi_Key_getParams(&key, &dhParams, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Too small buffer len
    n = 17;
    err = SeosCryptoApi_Key_getParams(&key, &dhParams, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testKey_loadParams_ok(SeosCryptoApi_Context* ctx)
{
    seos_err_t err;
    size_t n;
    SeosCryptoApi_Key_EccParams eccParams;

    // Load SECP192r1
    n = sizeof(eccParams);
    err = SeosCryptoApi_Key_loadParams(ctx, SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                       &eccParams, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(n == sizeof(eccParams));

    // Load SECP224r1
    err = SeosCryptoApi_Key_loadParams(ctx, SeosCryptoApi_Key_PARAM_ECC_SECP224R1,
                                       &eccParams, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(n == sizeof(eccParams));

    // Load SECP256r1
    err = SeosCryptoApi_Key_loadParams(ctx, SeosCryptoApi_Key_PARAM_ECC_SECP256R1,
                                       &eccParams, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(n == sizeof(eccParams));

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testKey_loadParams_fail(SeosCryptoApi_Context* ctx)
{
    seos_err_t err;
    size_t n;
    SeosCryptoApi_Key_EccParams eccParams;

    // Empty context
    n = sizeof(eccParams);
    err = SeosCryptoApi_Key_loadParams(NULL, SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                       &eccParams, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Wrong param name
    err = SeosCryptoApi_Key_loadParams(ctx, 666, &eccParams, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Empty buffer
    err = SeosCryptoApi_Key_loadParams(ctx, SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                       NULL, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty length
    err = SeosCryptoApi_Key_loadParams(ctx, SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                       &eccParams, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // To small buffer
    n = 17;
    err = SeosCryptoApi_Key_loadParams(ctx, SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                       &eccParams, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testKey_free_ok(SeosCryptoApi_Context* ctx)
{
    seos_err_t err;
    SeosCryptoApi_Key key;

    err = SeosCryptoApi_Key_generate(ctx, &key, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testKey_free_fail(SeosCryptoApi_Context* ctx)
{
    seos_err_t err;
    SeosCryptoApi_Key key;

    err = SeosCryptoApi_Key_generate(ctx, &key, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Empty key
    err = SeosCryptoApi_Key_free(NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testKey_getParams_buffer(SeosCryptoApi_Context* ctx)
{
    seos_err_t err;
    SeosCryptoApi_Key key;
    static unsigned char paramBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    size_t paramLen;

    err = SeosCryptoApi_Key_generate(ctx, &key, &dh101pSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Should be OK and give the correct length
    paramLen = SeosCryptoApi_SIZE_DATAPORT;
    err = SeosCryptoApi_Key_getParams(&key, paramBuf, &paramLen);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(paramLen == sizeof(SeosCryptoApi_Key_DhParams));

    // Should fail but give the correct length
    paramLen = 10;
    err = SeosCryptoApi_Key_getParams(&key, paramBuf, &paramLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);
    Debug_ASSERT(paramLen == sizeof(SeosCryptoApi_Key_DhParams));

    // Should fail due buffer being too big
    paramLen = SeosCryptoApi_SIZE_DATAPORT + 1;
    err = SeosCryptoApi_Key_getParams(&key, paramBuf, &paramLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INSUFFICIENT_SPACE == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testKey_loadParams_buffer(SeosCryptoApi_Context* ctx)
{
    seos_err_t err;
    static unsigned char paramBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    size_t paramLen;

    // Should be OK
    paramLen = SeosCryptoApi_SIZE_DATAPORT;
    err = SeosCryptoApi_Key_loadParams(ctx, SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                       paramBuf, &paramLen);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(paramLen == sizeof(SeosCryptoApi_Key_EccParams));

    // Should fail, but give the minimum size
    paramLen = 10;
    err = SeosCryptoApi_Key_loadParams(ctx, SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                       paramBuf, &paramLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);
    Debug_ASSERT(paramLen == sizeof(SeosCryptoApi_Key_EccParams));

    // Should fail because buffer is too big
    paramLen = SeosCryptoApi_SIZE_DATAPORT + 1;
    err = SeosCryptoApi_Key_loadParams(ctx, SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                       paramBuf, &paramLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INSUFFICIENT_SPACE == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

void testKey(SeosCryptoApi_Context* ctx)
{
    testKey_import_ok(ctx);
    testKey_import_fail(ctx);

    testKey_export_ok(ctx);
    testKey_export_fail(ctx);

    testKey_generate_ok(ctx);
    testKey_generate_fail(ctx);

    testKey_makePublic_ok(ctx);
    testKey_makePublic_fail(ctx);

    testKey_getParams_ok(ctx);
    testKey_getParams_fail(ctx);

    testKey_loadParams_ok(ctx);
    testKey_loadParams_fail(ctx);

    testKey_free_ok(ctx);
    testKey_free_fail(ctx);

    testKey_getParams_buffer(ctx);
    testKey_loadParams_buffer(ctx);
}