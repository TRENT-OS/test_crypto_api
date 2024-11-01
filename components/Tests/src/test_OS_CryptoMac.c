/**
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#include "OS_Crypto.h"

#include "ObjectLocation.h"
#include "SharedKeys.h"

#include "lib_macros/Test.h"

#include <string.h>

// -----------------------------------------------------------------------------

#define MAX_VECTOR_SIZE 256
typedef struct
{
    size_t len;
    uint8_t bytes[MAX_VECTOR_SIZE];
} ByteVector;

typedef struct
{
    OS_CryptoKey_Data_t key;
    ByteVector msg;
    ByteVector mac;
} macTestVector;

// -----------------------------------------------------------------------------

#define NUM_MD5_TESTS 3
static macTestVector md5Vectors[NUM_MD5_TESTS] =
{
    {
        .key = {
            .type = OS_CryptoKey_TYPE_MAC,
            .attribs.keepLocal = true,
            .data.mac = {
                .bytes = {0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61},
                .len = 16
            },
        },
        .msg = {
            .bytes = {0xb9, 0x1c, 0xe5, 0xac, 0x77, 0xd3, 0x3c, 0x23, 0x4e, 0x61, 0x00, 0x2e, 0xd6},
            .len = 13
        },
        .mac = {
            .bytes = {0x42, 0x55, 0x28, 0x82, 0xf0, 0x0b, 0xd4, 0x63, 0x3e, 0xa8, 0x11, 0x35, 0xa1, 0x84, 0xb2, 0x84},
            .len = 16
        },
    },
    {
        .key = {
            .type = OS_CryptoKey_TYPE_MAC,
            .attribs.keepLocal = true,
            .data.mac = {
                .bytes = {0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61},
                .len = 16
            },
        },
        .msg = {
            .bytes = {0x27, 0x0f, 0xcf, 0x11, 0xf2, 0x7c, 0x27, 0x44, 0x84, 0x57, 0xd7, 0x04, 0x9a, 0x7e, 0xdb, 0x08, 0x4a, 0x3e, 0x55, 0x4e, 0x0b, 0x2a, 0xcf, 0x58, 0x06, 0x98, 0x22, 0x13, 0xf0, 0xad, 0x51, 0x64, 0x02, 0xe4, 0xc8, 0x69, 0xc4, 0xff, 0x21, 0x71, 0xe1, 0x8e, 0x34, 0x89, 0xba, 0xa3, 0x12, 0x5d, 0x2c, 0x30, 0x56, 0xeb, 0xb6, 0x16, 0x29, 0x6f, 0x9b, 0x6a, 0xa9, 0x7e, 0xf6, 0x8e, 0xea, 0xbc, 0xdc, 0x0b, 0x6d, 0xde, 0x47, 0x77, 0x50, 0x04, 0x09, 0x6a, 0x24, 0x1e, 0xfc, 0xf0, 0xa9, 0x0d, 0x19, 0xb3, 0x4e, 0x89, 0x8c, 0xc7, 0x34, 0x0c, 0xdc, 0x94, 0x0f, 0x8b, 0xdd, 0x46, 0xe2, 0x3e, 0x35, 0x2f, 0x34, 0xbc, 0xa1, 0x31, 0xd4, 0xd6, 0x7a, 0x7c, 0x2d, 0xdb, 0x8d, 0x0d, 0x68, 0xb6, 0x7f, 0x06, 0x15, 0x2a, 0x12, 0x81, 0x68, 0xe1, 0xc3, 0x41, 0xc3, 0x7e, 0x0a, 0x66, 0xc5, 0x01, 0x89, 0x99, 0xb7, 0x05, 0x9b, 0xcc, 0x30, 0x0b, 0xee, 0xd2, 0xc1, 0x9d, 0xd1, 0x15, 0x2d, 0x2f, 0xe0, 0x62, 0x85, 0x32, 0x93, 0xb8, 0xf3, 0xc8, 0xb5},
            .len = 153
        },
        .mac = {
            .bytes = {0xa1, 0x6a, 0x84, 0x28, 0x91, 0x78, 0x6d, 0x01, 0xfe, 0x50, 0xba, 0x77, 0x31, 0xdb, 0x74, 0x64},
            .len = 16
        },
    },
    {
        .key = {
            .type = OS_CryptoKey_TYPE_MAC,
            .attribs.keepLocal = true,
            .data.mac = {
                .bytes = {0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61},
                .len = 70
            },
        },
        .msg = {
            .bytes = {0xb9, 0x1c, 0xe5, 0xac, 0x77, 0xd3, 0x3c, 0x23, 0x4e, 0x61, 0x00, 0x2e, 0xd6},
            .len = 13
        },
        .mac = {
            .bytes = {0xe9, 0x7f, 0x62, 0x39, 0x36, 0xf9, 0x8a, 0x7f, 0x74, 0x1c, 0x4b, 0xd0, 0x61, 0x2f, 0xec, 0xc2},
            .len = 16
        },
    },
};

// -----------------------------------------------------------------------------

#define NUM_SHA256_TESTS 3
static macTestVector sha256Vectors[NUM_SHA256_TESTS] =
{
    {
        .key = {
            .type = OS_CryptoKey_TYPE_MAC,
            .attribs.keepLocal = true,
            .data.mac = {
                .bytes = {0xcf, 0xd4, 0xa4, 0x49, 0x10, 0xc9, 0xe5, 0x67, 0x50, 0x7a, 0xbb, 0x6c, 0xed, 0xe4, 0xfe, 0x60, 0x1a, 0x7a, 0x27, 0x65, 0xc9, 0x75, 0x5a, 0xa2, 0xcf, 0x6b, 0xa4, 0x81, 0x42, 0x23, 0x81, 0x1a, 0x26, 0xa8, 0xa1, 0xef, 0x49, 0x9c, 0xeb, 0xd9},
                .len = 40
            },
        },
        .msg = {
            .bytes = {0x3f, 0xb3, 0x01, 0xcb, 0x40, 0x92, 0xf9, 0x62, 0x3a, 0xa5, 0xff, 0xd6, 0x90, 0xd2, 0x2d, 0x65, 0xd5, 0x6e, 0x5a, 0x1c, 0x33, 0x0b, 0x9c, 0x4a, 0x0d, 0x91, 0x0c, 0x34, 0xe3, 0x91, 0xc9, 0x0a, 0x76, 0xd5, 0x40, 0x1a, 0x2d, 0x3c, 0xaa, 0x44, 0xb8, 0xc5, 0xd5, 0xae, 0xf3, 0xe9, 0x28, 0xb9, 0x0d, 0x2e, 0xe2, 0x33, 0xe9, 0xf9, 0xa2, 0xce, 0xc4, 0xa3, 0x2c, 0xd0, 0x19, 0xd0, 0x6a, 0x0d, 0xc1, 0xfc, 0xb1, 0x12, 0x5f, 0x57, 0x46, 0xa4, 0xfb, 0xd3, 0x21, 0x69, 0xed, 0x7b, 0xf0, 0xe4, 0xfd, 0x06, 0x5f, 0xa7, 0xc8, 0xac, 0x97, 0xc3, 0x66, 0x38, 0x04, 0x84, 0x49, 0x5f, 0x5c, 0x5b, 0x68, 0x50, 0xdd, 0x1c, 0x9d, 0x8c, 0xd6, 0x69, 0x4c, 0xf8, 0x68, 0x6e, 0x46, 0x30, 0x8e, 0xd0, 0xed, 0x1f, 0x5b, 0xdf, 0x98, 0xcd, 0x83, 0x13, 0x39, 0x77, 0x1d, 0xb6, 0x3d, 0xe5, 0xa7, 0xde},
            .len = 128
        },
        .mac = {
            .bytes = {0x20, 0x15, 0x3b, 0xf8, 0xea, 0x29, 0x53, 0xc4, 0x82, 0x51, 0xeb, 0xcc, 0x41, 0x61, 0xf8, 0xb6, 0xe2, 0x84, 0x99, 0xe5, 0xc7, 0x6c, 0x24, 0x01, 0x4c, 0xff, 0x4a, 0x9e, 0x2f, 0x62, 0xd2, 0x5c},
            .len = 32
        },
    },
    {
        .key = {
            .type = OS_CryptoKey_TYPE_MAC,
            .attribs.keepLocal = true,
            .data.mac = {
                .bytes = {0x54, 0x48, 0x99, 0x8f, 0x9d, 0x8f, 0x98, 0x53, 0x4a, 0xdd, 0xf0, 0xc8, 0xba, 0x63, 0x1c, 0x49, 0x6b, 0xf8, 0xa8, 0x00, 0x6c, 0xbb, 0x46, 0xad, 0x15, 0xfa, 0x1f, 0xa2, 0xf5, 0x53, 0x67, 0x12, 0x0c, 0x19, 0x34, 0x8c, 0x3a, 0xfa, 0x90, 0xc3},
                .len = 40
            },
        },
        .msg = {
            .bytes = {0x1c, 0x43, 0x96, 0xf7, 0xb7, 0xf9, 0x22, 0x8e, 0x83, 0x2a, 0x13, 0x69, 0x20, 0x02, 0xba, 0x2a, 0xff, 0x43, 0x9d, 0xcb, 0x7f, 0xdd, 0xbf, 0xd4, 0x56, 0xc0, 0x22, 0xd1, 0x33, 0xee, 0x89, 0x03, 0xa2, 0xd4, 0x82, 0x56, 0x2f, 0xda, 0xa4, 0x93, 0xce, 0x39, 0x16, 0xd7, 0x7a, 0x0c, 0x51, 0x44, 0x1d, 0xab, 0x26, 0xf6, 0xb0, 0x34, 0x02, 0x38, 0xa3, 0x6a, 0x71, 0xf8, 0x7f, 0xc3, 0xe1, 0x79, 0xca, 0xbc, 0xa9, 0x48, 0x2b, 0x70, 0x49, 0x71, 0xce, 0x69, 0xf3, 0xf2, 0x0a, 0xb6, 0x4b, 0x70, 0x41, 0x3d, 0x6c, 0x29, 0x08, 0x53, 0x2b, 0x2a, 0x88, 0x8a, 0x9f, 0xc2, 0x24, 0xca, 0xe1, 0x36, 0x5d, 0xa4, 0x10, 0xb6, 0xf2, 0xe2, 0x98, 0x90, 0x4b, 0x63, 0xb4, 0xa4, 0x17, 0x26, 0x32, 0x18, 0x35, 0xa4, 0x77, 0x4d, 0xd0, 0x63, 0xc2, 0x11, 0xcf, 0xc8, 0xb5, 0x16, 0x6c, 0x2d, 0x11, 0xa2},
            .len = 128
        },
        .mac = {
            .bytes = {0x7e, 0x8c, 0xba, 0x9d, 0xd9, 0xf0, 0x6e, 0xbd, 0xd7, 0xf9, 0x2e, 0x0f, 0x1a, 0x67, 0xc7, 0xf4, 0xdf, 0x52, 0x69, 0x3c, 0x21, 0x2b, 0xdd, 0x84, 0xf6, 0x73, 0x70, 0xb3, 0x51, 0x53, 0x3c, 0x6c},
            .len = 32
        },
    },
    {
        .key = {
            .type = OS_CryptoKey_TYPE_MAC,
            .attribs.keepLocal = true,
            .data.mac = {
                .bytes = {0x9d, 0xa0, 0xc1, 0x14, 0x68, 0x2f, 0x82, 0xc1, 0xd1, 0xe9, 0xb5, 0x44, 0x30, 0x58, 0x0b, 0x9c, 0x56, 0x94, 0x89, 0xca, 0x16, 0xb9, 0x2e, 0xe1, 0x04, 0x98, 0xd5, 0x5d, 0x7c, 0xad, 0x5d, 0xb5, 0xe6, 0x52, 0x06, 0x34, 0x39, 0x31, 0x1e, 0x04},
                .len = 40
            },
        },
        .msg = {
            .bytes = {0x49, 0x53, 0x40, 0x8b, 0xe3, 0xdd, 0xde, 0x42, 0x52, 0x1e, 0xb6, 0x25, 0xa3, 0x7a, 0xf0, 0xd2, 0xcf, 0x9e, 0xd1, 0x84, 0xf5, 0xb6, 0x27, 0xe5, 0xe7, 0xe0, 0xe8, 0x24, 0xe8, 0xe1, 0x16, 0x48, 0xb4, 0x18, 0xe5, 0xc4, 0xc1, 0xb0, 0x20, 0x4b, 0xc5, 0x19, 0xc9, 0xe5, 0x78, 0xb8, 0x00, 0x43, 0x9b, 0xdd, 0x25, 0x4f, 0x39, 0xf6, 0x41, 0x08, 0x2d, 0x03, 0xa2, 0x8d, 0xe4, 0x4a, 0xc6, 0x77, 0x64, 0x4c, 0x7b, 0x6c, 0x8d, 0xf7, 0x43, 0xf2, 0x9f, 0x1d, 0xfd, 0x80, 0xfd, 0x25, 0xc2, 0xdb, 0x31, 0x01, 0x0e, 0xa0, 0x2f, 0x60, 0x20, 0x1c, 0xde, 0x24, 0xa3, 0x64, 0xd4, 0x16, 0x8d, 0xa2, 0x61, 0xd8, 0x48, 0xae, 0xd0, 0x1c, 0x10, 0xde, 0xe9, 0x14, 0x9c, 0x1e, 0xbb, 0x29, 0x00, 0x43, 0x98, 0xf0, 0xd2, 0x9c, 0x60, 0x5a, 0x8b, 0xca, 0x03, 0x2b, 0x31, 0xd2, 0x41, 0xad, 0x33, 0x71},
            .len = 128
        },
        .mac = {
            .bytes = {0xcd, 0xea, 0xcf, 0xce, 0xbf, 0x46, 0xcc, 0x9d, 0x7e, 0x4d, 0x41, 0x75, 0xe5, 0xd8, 0xd2, 0x67, 0xc2, 0x3a, 0x64, 0xcd, 0xe8, 0x3e, 0x86, 0x7e, 0x50, 0x01, 0xec, 0xf2, 0x6f, 0xbd, 0x30, 0xd2},
            .len = 32
        },
    },
};

// -----------------------------------------------------------------------------

static OS_CryptoKey_Data_t* testKeyDataList[] =
{
    &md5Vectors[0].key,
    &md5Vectors[1].key,
    &md5Vectors[2].key,
    &sha256Vectors[0].key,
    &sha256Vectors[1].key,
    &sha256Vectors[2].key,
    NULL
};

static OS_Error_t
do_mac(
    OS_CryptoMac_Handle_t hMac,
    const macTestVector*  vec)
{
    OS_Error_t err;
    char mac[64];
    size_t macSize;

    TEST_SUCCESS(OS_CryptoMac_process(hMac, vec->msg.bytes, vec->msg.len));

    macSize = sizeof(mac);
    if ((err = OS_CryptoMac_finalize(hMac, mac, &macSize)) != OS_SUCCESS)
    {
        return err;
    }

    TEST_TRUE(macSize == vec->mac.len);
    TEST_TRUE(!memcmp(mac, vec->mac.bytes, vec->mac.len));

    return OS_SUCCESS;
}

static void
test_OS_CryptoMac_do_HMAC_MD5(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoMac_Handle_t hMac;
    OS_CryptoKey_Handle_t hKey;
    size_t i;

    TEST_START("i", mode, "i", keepLocal);

    for (i = 0; i < NUM_MD5_TESTS; i++)
    {
        TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &md5Vectors[i].key));
        TEST_LOCACTION_FLAG(mode, keepLocal, hKey);
        TEST_SUCCESS(OS_CryptoMac_init(&hMac, hCrypto, hKey,
                                       OS_CryptoMac_ALG_HMAC_MD5));
        TEST_LOCACTION_FLAG(mode, keepLocal, hMac);

        TEST_SUCCESS(do_mac(hMac, &md5Vectors[i]));

        TEST_SUCCESS(OS_CryptoKey_free(hKey));
        TEST_SUCCESS(OS_CryptoMac_free(hMac));
    }

    TEST_FINISH();
}

static void
test_OS_CryptoMac_do_HMAC_SHA256(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoMac_Handle_t hMac;
    OS_CryptoKey_Handle_t hKey;
    size_t i;

    TEST_START("i", mode, "i", keepLocal);

    for (i = 0; i < NUM_SHA256_TESTS; i++)
    {
        TEST_SUCCESS(
            OS_CryptoKey_import(&hKey, hCrypto, &sha256Vectors[i].key));

        TEST_LOCACTION_FLAG(mode, keepLocal, hKey);
        TEST_SUCCESS(OS_CryptoMac_init(&hMac, hCrypto, hKey,
                                       OS_CryptoMac_ALG_HMAC_SHA256));
        TEST_LOCACTION_FLAG(mode, keepLocal, hMac);

        TEST_SUCCESS(do_mac(hMac, &sha256Vectors[i]));

        TEST_SUCCESS(OS_CryptoKey_free(hKey));
        TEST_SUCCESS(OS_CryptoMac_free(hMac));
    }

    TEST_FINISH();
}

static void
test_OS_CryptoMac_process_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoMac_Handle_t hMac;
    OS_CryptoKey_Handle_t hKey;
    const macTestVector* vec = &md5Vectors[0];

    TEST_START("i", mode, "i", keepLocal);

    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &vec->key));
    TEST_LOCACTION_FLAG(mode, keepLocal, hKey);
    TEST_SUCCESS(OS_CryptoMac_init(&hMac, hCrypto, hKey,
                                   OS_CryptoMac_ALG_HMAC_MD5));
    TEST_LOCACTION_FLAG(mode, keepLocal, hMac);

    // Test with empty handle
    TEST_INVAL_PARAM(OS_CryptoMac_process(NULL, vec->msg.bytes, vec->msg.len));

    // Test with empty input
    TEST_INVAL_PARAM(OS_CryptoMac_process(hMac, NULL, vec->msg.len));

    // Test with zero lenght input
    TEST_INVAL_PARAM(OS_CryptoMac_process(hMac, vec->msg.bytes, 0));

    TEST_SUCCESS(OS_CryptoMac_free(hMac));
    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoMac_finalize_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoMac_Handle_t hMac;
    OS_CryptoKey_Handle_t hKey;
    const macTestVector* vec = &md5Vectors[0];
    char mac[64];
    size_t macSize = sizeof(mac);

    TEST_START("i", mode, "i", keepLocal);

    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &vec->key));
    TEST_LOCACTION_FLAG(mode, keepLocal, hKey);
    TEST_SUCCESS(OS_CryptoMac_init(&hMac, hCrypto, hKey,
                                   OS_CryptoMac_ALG_HMAC_MD5));
    TEST_LOCACTION_FLAG(mode, keepLocal, hMac);

    // Finalize without updating
    TEST_ABORTED(OS_CryptoMac_finalize(hMac, mac, &macSize));

    TEST_SUCCESS(OS_CryptoMac_process(hMac, vec->msg.bytes, vec->msg.len));

    // Finalize without handle
    TEST_INVAL_PARAM(OS_CryptoMac_finalize(NULL, mac, &macSize));

    // Finalize without output buffer
    TEST_INVAL_PARAM(OS_CryptoMac_finalize(hMac, NULL, &macSize));

    // Finalize without sufficient space; but give us the right size
    macSize = 4;
    TEST_TOO_SMALL(OS_CryptoMac_finalize(hMac, mac, &macSize));
    TEST_TRUE(macSize == OS_CryptoMac_SIZE_HMAC_MD5);

    // Finalize twice
    macSize = sizeof(mac);
    TEST_SUCCESS(OS_CryptoMac_finalize(hMac, mac, &macSize));
    TEST_ABORTED(OS_CryptoMac_finalize(hMac, mac, &macSize));

    TEST_SUCCESS(OS_CryptoMac_free(hMac));
    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoMac_process_dataport(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoMac_Handle_t hMac;
    OS_CryptoKey_Handle_t hKey;
    const macTestVector* vec = &md5Vectors[0];
    static unsigned char inBuf[OS_DATAPORT_DEFAULT_SIZE + 1];
    size_t inLen;

    TEST_START("i", mode, "i", keepLocal);

    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &vec->key));
    TEST_LOCACTION_FLAG(mode, keepLocal, hKey);
    TEST_SUCCESS(OS_CryptoMac_init(&hMac, hCrypto, hKey,
                                   OS_CryptoMac_ALG_HMAC_MD5));
    TEST_LOCACTION_FLAG(mode, keepLocal, hMac);

    // Should go OK
    inLen = OS_DATAPORT_DEFAULT_SIZE;
    TEST_SUCCESS(OS_CryptoMac_process(hMac, inBuf, inLen));

    // Should fail due to internal buffers being limited
    inLen = OS_DATAPORT_DEFAULT_SIZE + 1;
    TEST_INVAL_PARAM(OS_CryptoMac_process(hMac, inBuf, inLen));

    TEST_SUCCESS(OS_CryptoMac_free(hMac));
    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoMac_finalize_dataport(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoMac_Handle_t hMac;
    OS_CryptoKey_Handle_t hKey;
    const macTestVector* vec = &md5Vectors[0];
    static unsigned char inBuf[OS_DATAPORT_DEFAULT_SIZE],
           outBuf[OS_DATAPORT_DEFAULT_SIZE + 1];
    size_t inLen, outLen;

    TEST_START("i", mode, "i", keepLocal);

    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &vec->key));
    TEST_LOCACTION_FLAG(mode, keepLocal, hKey);

    // Should be OK, as we are below the dataport limit
    inLen = OS_DATAPORT_DEFAULT_SIZE;
    outLen = OS_DATAPORT_DEFAULT_SIZE;
    TEST_SUCCESS(OS_CryptoMac_init(&hMac, hCrypto, hKey,
                                   OS_CryptoMac_ALG_HMAC_MD5));
    TEST_LOCACTION_FLAG(mode, keepLocal, hMac);
    TEST_SUCCESS(OS_CryptoMac_process(hMac, inBuf, inLen));
    TEST_SUCCESS(OS_CryptoMac_finalize(hMac, outBuf, &outLen));
    TEST_SUCCESS(OS_CryptoMac_free(hMac));

    // Should fail because out buffer is potentially too big
    inLen = OS_DATAPORT_DEFAULT_SIZE;
    outLen = OS_DATAPORT_DEFAULT_SIZE + 1;
    TEST_SUCCESS(OS_CryptoMac_init(&hMac, hCrypto, hKey,
                                   OS_CryptoMac_ALG_HMAC_MD5));
    TEST_LOCACTION_FLAG(mode, keepLocal, hMac);
    TEST_SUCCESS(OS_CryptoMac_process(hMac, inBuf, inLen));
    TEST_INVAL_PARAM(OS_CryptoMac_finalize(hMac, outBuf, &outLen));
    TEST_SUCCESS(OS_CryptoMac_free(hMac));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoMac_init_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoMac_Handle_t hMac;
    OS_CryptoKey_Handle_t hKey;
    const macTestVector* vec = &md5Vectors[0];

    TEST_START("i", mode, "i", keepLocal);

    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &vec->key));
    TEST_LOCACTION_FLAG(mode, keepLocal, hKey);

    // Test HMAC_MD5
    TEST_SUCCESS(OS_CryptoMac_init(&hMac, hCrypto, hKey,
                                   OS_CryptoMac_ALG_HMAC_MD5));
    TEST_LOCACTION_FLAG(mode, keepLocal, hMac);
    TEST_SUCCESS(OS_CryptoMac_free(hMac));

    // Test HMAC_SHA256
    TEST_SUCCESS(OS_CryptoMac_init(&hMac, hCrypto, hKey,
                                   OS_CryptoMac_ALG_HMAC_SHA256));
    TEST_SUCCESS(OS_CryptoMac_free(hMac));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoMac_init_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoMac_Handle_t hMac;
    OS_CryptoKey_Handle_t hKey;
    const macTestVector* vec = &md5Vectors[0];

    TEST_START("i", mode, "i", keepLocal);

    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &vec->key));
    TEST_LOCACTION_FLAG(mode, keepLocal, hKey);

    // Empty mac handle
    TEST_INVAL_PARAM(OS_CryptoMac_init(NULL, hCrypto, hKey,
                                       OS_CryptoMac_ALG_HMAC_MD5));

    // Empty crypto handle
    TEST_INVAL_PARAM(OS_CryptoMac_init(&hMac, NULL, hKey,
                                       OS_CryptoMac_ALG_HMAC_MD5));

    // Empty key handle
    TEST_INVAL_PARAM(OS_CryptoMac_init(&hMac, hCrypto, NULL,
                                       OS_CryptoMac_ALG_HMAC_MD5));

    // Incorrect algorithm
    TEST_NOT_SUPP(OS_CryptoMac_init(&hMac, hCrypto, hKey, 666));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoMac_free_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoMac_Handle_t hMac;
    OS_CryptoKey_Handle_t hKey;
    const macTestVector* vec = &md5Vectors[0];

    TEST_START("i", mode, "i", keepLocal);

    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &vec->key));
    TEST_LOCACTION_FLAG(mode, keepLocal, hKey);

    TEST_SUCCESS(OS_CryptoMac_init(&hMac, hCrypto, hKey,
                                   OS_CryptoMac_ALG_HMAC_MD5));
    TEST_LOCACTION_FLAG(mode, keepLocal, hMac);
    TEST_SUCCESS(OS_CryptoMac_free(hMac));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoMac_free_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    TEST_START("i", mode, "i", keepLocal);

    // Empty handle
    TEST_INVAL_PARAM(OS_CryptoMac_free(NULL));

    TEST_FINISH();
}

void
test_OS_CryptoMac(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode)
{
    keyData_setLocality(testKeyDataList, true);

    test_OS_CryptoMac_init_pos(hCrypto, mode, true);
    test_OS_CryptoMac_init_neg(hCrypto, mode, true);

    test_OS_CryptoMac_free_pos(hCrypto, mode, true);
    test_OS_CryptoMac_free_neg(hCrypto, mode, true);

    // Test only failures separately, as computing ref. values is sufficient
    // proof of correct funtioning
    test_OS_CryptoMac_process_neg(hCrypto, mode, true);
    test_OS_CryptoMac_finalize_neg(hCrypto, mode, true);

    // Test vectors
    test_OS_CryptoMac_do_HMAC_MD5(hCrypto, mode, true);
    test_OS_CryptoMac_do_HMAC_SHA256(hCrypto, mode, true);

    switch (mode)
    {
    case OS_Crypto_MODE_CLIENT:
        test_OS_CryptoMac_process_dataport(hCrypto, mode, true);
        test_OS_CryptoMac_finalize_dataport(hCrypto, mode, true);
        break;
    case OS_Crypto_MODE_KEY_SWITCH:
        keyData_setLocality(testKeyDataList, false);
        test_OS_CryptoMac_do_HMAC_MD5(hCrypto, mode, false);
        test_OS_CryptoMac_do_HMAC_SHA256(hCrypto, mode, false);
        break;
    default:
        break;
    }
}