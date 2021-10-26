/**
 * Copyright (C) 2019, HENSOLDT Cyber GmbH
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
    ByteVector iv;
    ByteVector ad;
    ByteVector pt;
    ByteVector ct;
    ByteVector tag;
    OS_CryptoKey_Data_t key;
} TestVector;

// -----------------------------------------------------------------------------

#define NUM_RAND_ITERATIONS 100

#define NUM_AES_ECB_TESTS 3
static TestVector aesEcbVectors[NUM_AES_ECB_TESTS] =
{
    {
        .key = {
            .type = OS_CryptoKey_TYPE_AES,
            .attribs.keepLocal = true,
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
            .type = OS_CryptoKey_TYPE_AES,
            .attribs.keepLocal = true,
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
            .type = OS_CryptoKey_TYPE_AES,
            .attribs.keepLocal = true,
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
static TestVector aesCbcVectors[NUM_AES_CBC_TESTS] =
{
    {
        .key = {
            .type = OS_CryptoKey_TYPE_AES,
            .attribs.keepLocal = true,
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

#define NUM_AES_CTR_TESTS 2
static TestVector aesCtrVectors[NUM_AES_CTR_TESTS] =
{
    {
        .key = {
            .type = OS_CryptoKey_TYPE_AES,
            .attribs.keepLocal = true,
            .data.aes = {
                .len   = 16,
                .bytes = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab,
                          0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
            },
        },
        .pt =
        {
            .len = 64,
            .bytes = {
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
            },
        },
        .ct =
        {
            .len = 64,
            .bytes = {
                0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
                0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
                0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
                0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee
            },
        },
        .iv = {
            .len = 16,
            .bytes = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff},
        }
    },
    {
        .key = {
            .type = OS_CryptoKey_TYPE_AES,
            .attribs.keepLocal = true,
            .data.aes = {
                .len   = 32,
                .bytes = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b,
                          0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 
                          0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10,
                          0xa3, 0x09, 0x14, 0xdf, 0xf4},
            },
        },
        .pt =
        {
            .len = 64,
            .bytes = {
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
            },
        },
        .ct =
        {
            .len = 64,
            .bytes = {
                0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
                0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
                0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
                0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6
            },
        },
        .iv = {
            .len = 16,
            .bytes = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff},
        }
    }
};

// -----------------------------------------------------------------------------

#define NUM_AES_GCM_TESTS 2
static TestVector aesGcmVectors[NUM_AES_GCM_TESTS] =
{
    {
        .key = {
            .type = OS_CryptoKey_TYPE_AES,
            .attribs.keepLocal = true,
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
            .type = OS_CryptoKey_TYPE_AES,
            .attribs.keepLocal = true,
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

static OS_CryptoKey_Data_t* testKeyDataList[] =
{
    &aesEcbVectors[0].key,
    &aesEcbVectors[1].key,
    &aesEcbVectors[2].key,
    &aesCbcVectors[0].key,
    &aesCtrVectors[0].key,
    &aesCtrVectors[1].key,
    &aesGcmVectors[0].key,
    &aesGcmVectors[1].key,
    NULL
};

// -----------------------------------------------------------------------------

static OS_Error_t
do_AES_ECB(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal,
    OS_CryptoKey_Handle_t  hKey,
    int                    algo,
    const ByteVector*      din,
    const ByteVector*      dout)
{
    OS_CryptoCipher_Handle_t hCipher;
    unsigned char buf[128];
    size_t n = sizeof(buf);

    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey, algo, NULL, 0));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
    TEST_SUCCESS(OS_CryptoCipher_process(hCipher, din->bytes, din->len, buf,
                                         &n));
    TEST_TRUE(n == dout->len);
    TEST_TRUE(!memcmp(buf, dout->bytes, n));
    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    return OS_SUCCESS;
}

static void
test_OS_CryptoCipher_do_AES_ECB_enc(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;
    size_t i;

    TEST_START("i", mode, "i", keepLocal);

    for (i = 0; i < NUM_AES_ECB_TESTS; i++)
    {
        TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &aesEcbVectors[i].key));
        TEST_SUCCESS(do_AES_ECB(hCrypto, mode, keepLocal, hKey,
                                OS_CryptoCipher_ALG_AES_ECB_ENC,
                                &aesEcbVectors[i].pt,
                                &aesEcbVectors[i].ct));
        TEST_SUCCESS(OS_CryptoKey_free(hKey));
    }

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_do_AES_ECB_dec(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;
    size_t i;

    TEST_START("i", mode, "i", keepLocal);

    for (i = 0; i < NUM_AES_ECB_TESTS; i++)
    {
        TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &aesEcbVectors[i].key));
        TEST_SUCCESS(do_AES_ECB(hCrypto, mode, keepLocal, hKey,
                                OS_CryptoCipher_ALG_AES_ECB_DEC,
                                &aesEcbVectors[i].ct,
                                &aesEcbVectors[i].pt));
        TEST_SUCCESS(OS_CryptoKey_free(hKey));
    }

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_do_AES_ECB_rnd(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoCipher_Handle_t hCipher;
    OS_CryptoKey_Handle_t hKey;
    uint8_t pt[16], ct[16], tmp[16];
    size_t len;

    TEST_START("i", mode, "i", keepLocal);

    for (size_t i = 0; i < NUM_RAND_ITERATIONS; i++)
    {
        // Generate random key, PT
        TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec));
        TEST_SUCCESS(OS_CryptoRng_getBytes(hCrypto, 0, pt, sizeof(pt)));

        // Encrypt
        len = sizeof(ct);
        TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                          OS_CryptoCipher_ALG_AES_ECB_ENC,
                                          NULL, 0));
        TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
        TEST_SUCCESS(OS_CryptoCipher_process(hCipher, pt, sizeof(pt), ct, &len));
        TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

        // Decrypt
        len = sizeof(tmp);
        TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                          OS_CryptoCipher_ALG_AES_ECB_DEC,
                                          NULL, 0));
        TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
        TEST_SUCCESS(OS_CryptoCipher_process(hCipher, ct, sizeof(ct), tmp, &len));
        TEST_SUCCESS(OS_CryptoCipher_free(hCipher));
        // Check decryption result
        ASSERT_EQ_INT(0, memcmp(tmp, pt, len));

        TEST_SUCCESS(OS_CryptoKey_free(hKey));
    }

    TEST_FINISH();
}

static OS_Error_t
do_AES_CBC(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal,
    OS_CryptoKey_Handle_t  hKey,
    int                    algo,
    const ByteVector*      iv,
    const ByteVector*      din,
    const ByteVector*      dout)
{
    OS_CryptoCipher_Handle_t hCipher;
    unsigned char buf[128];
    size_t n = sizeof(buf);

    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey, algo, iv->bytes,
                                      iv->len));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
    TEST_SUCCESS(OS_CryptoCipher_process(hCipher, din->bytes, din->len, buf,
                                         &n));
    TEST_TRUE(n == dout->len);
    TEST_TRUE(!memcmp(buf, dout->bytes, n));
    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    return OS_SUCCESS;
}

static void
test_OS_CryptoCipher_do_AES_CBC_enc(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;
    size_t i;

    TEST_START("i", mode, "i", keepLocal);

    for (i = 0; i < NUM_AES_CBC_TESTS; i++)
    {
        TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &aesCbcVectors[i].key));
        TEST_SUCCESS(do_AES_CBC(hCrypto, mode, keepLocal, hKey,
                                OS_CryptoCipher_ALG_AES_CBC_ENC,
                                &aesCbcVectors[i].iv,
                                &aesCbcVectors[i].pt,
                                &aesCbcVectors[i].ct));
        TEST_SUCCESS(OS_CryptoKey_free(hKey));
    }

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_do_AES_CBC_dec(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;
    size_t i;

    TEST_START("i", mode, "i", keepLocal);

    for (i = 0; i < NUM_AES_CBC_TESTS; i++)
    {
        TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &aesCbcVectors[i].key));
        TEST_SUCCESS(do_AES_CBC(hCrypto, mode, keepLocal, hKey,
                                OS_CryptoCipher_ALG_AES_CBC_DEC,
                                &aesCbcVectors[i].iv,
                                &aesCbcVectors[i].ct,
                                &aesCbcVectors[i].pt));
        TEST_SUCCESS(OS_CryptoKey_free(hKey));
    }

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_do_AES_CBC_rnd(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoCipher_Handle_t hCipher;
    OS_CryptoKey_Handle_t hKey;
    uint8_t pt[16], ct[16], tmp[16], iv[16];
    size_t len;

    TEST_START("i", mode, "i", keepLocal);

    for (size_t i = 0; i < NUM_RAND_ITERATIONS; i++)
    {
        // Generate random key, IV, PT
        TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec));
        TEST_SUCCESS(OS_CryptoRng_getBytes(hCrypto, 0, pt, sizeof(pt)));
        TEST_SUCCESS(OS_CryptoRng_getBytes(hCrypto, 0, iv, sizeof(iv)));

        // Encrypt
        len = sizeof(ct);
        TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                          OS_CryptoCipher_ALG_AES_CBC_ENC,
                                          iv, sizeof(iv)));
        TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
        TEST_SUCCESS(OS_CryptoCipher_process(hCipher, pt, sizeof(pt), ct, &len));
        TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

        // Decrypt
        len = sizeof(tmp);
        TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                          OS_CryptoCipher_ALG_AES_CBC_DEC,
                                          iv, sizeof(iv)));
        TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
        TEST_SUCCESS(OS_CryptoCipher_process(hCipher, ct, sizeof(ct), tmp, &len));
        TEST_SUCCESS(OS_CryptoCipher_free(hCipher));
        // Check decryption result
        ASSERT_EQ_INT(0, memcmp(tmp, pt, len));

        TEST_SUCCESS(OS_CryptoKey_free(hKey));
    }

    TEST_FINISH();
}

static OS_Error_t
do_AES_CTR(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal,
    OS_CryptoKey_Handle_t  hKey,
    int                    algo,
    const ByteVector*      iv,
    const ByteVector*      din,
    const ByteVector*      dout)
{
    OS_CryptoCipher_Handle_t hCipher;
    unsigned char buf[128];
    size_t n = sizeof(buf);

    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey, algo, iv->bytes,
                                      iv->len));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
    TEST_SUCCESS(OS_CryptoCipher_process(hCipher, din->bytes, din->len, buf,
                                         &n));
    TEST_TRUE(n == dout->len);
    TEST_TRUE(!memcmp(buf, dout->bytes, n));
    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    return OS_SUCCESS;
}

static void
test_OS_CryptoCipher_do_AES_CTR_enc(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;
    size_t i;

    TEST_START("i", mode, "i", keepLocal);

    for (i = 0; i < NUM_AES_CTR_TESTS; i++)
    {
        TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &aesCtrVectors[i].key));
        TEST_SUCCESS(do_AES_CTR(hCrypto, mode, keepLocal, hKey,
                                OS_CryptoCipher_ALG_AES_CTR_ENC,
                                &aesCtrVectors[i].iv,
                                &aesCtrVectors[i].pt,
                                &aesCtrVectors[i].ct));
        TEST_SUCCESS(OS_CryptoKey_free(hKey));
    }

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_do_AES_CTR_dec(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;
    size_t i;

    TEST_START("i", mode, "i", keepLocal);

    for (i = 0; i < NUM_AES_CTR_TESTS; i++)
    {
        TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &aesCtrVectors[i].key));
        TEST_SUCCESS(do_AES_CTR(hCrypto, mode, keepLocal, hKey,
                                OS_CryptoCipher_ALG_AES_CTR_DEC,
                                &aesCtrVectors[i].iv,
                                &aesCtrVectors[i].ct,
                                &aesCtrVectors[i].pt));
        TEST_SUCCESS(OS_CryptoKey_free(hKey));
    }

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_do_AES_CTR_rnd(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoCipher_Handle_t hCipher;
    OS_CryptoKey_Handle_t hKey;
    uint8_t pt[32], ct[32], tmp[32], iv[16];
    size_t len;

    TEST_START("i", mode, "i", keepLocal);

    for (size_t i = 0; i < NUM_RAND_ITERATIONS; i++)
    {
        // Generate random key, IV, PT
        TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec));
        TEST_SUCCESS(OS_CryptoRng_getBytes(hCrypto, 0, pt, sizeof(pt)));
        TEST_SUCCESS(OS_CryptoRng_getBytes(hCrypto, 0, iv, sizeof(iv)));

        // Encrypt
        len = sizeof(ct);
        TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                          OS_CryptoCipher_ALG_AES_CTR_ENC,
                                          iv, sizeof(iv)));
        TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
        TEST_SUCCESS(OS_CryptoCipher_process(hCipher, pt, sizeof(pt), ct, &len));
        TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

        // Decrypt
        len = sizeof(tmp);
        TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                          OS_CryptoCipher_ALG_AES_CTR_DEC,
                                          iv, sizeof(iv)));
        TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
        TEST_SUCCESS(OS_CryptoCipher_process(hCipher, ct, sizeof(ct), tmp, &len));
        TEST_SUCCESS(OS_CryptoCipher_free(hCipher));
        // Check decryption result
        Debug_ASSERT(!memcmp(tmp, pt, len));

        TEST_SUCCESS(OS_CryptoKey_free(hKey));
    }

    TEST_FINISH();
}

static OS_Error_t
do_AES_GCM(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal,
    OS_CryptoKey_Handle_t  hKey,
    int                    algo,
    const ByteVector*      iv,
    const ByteVector*      ad,
    const ByteVector*      din,
    const ByteVector*      dout,
    const ByteVector*      tag)
{
    OS_Error_t ret;
    OS_CryptoCipher_Handle_t hCipher;
    unsigned char buf[128];
    size_t n = sizeof(buf);

    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey, algo, iv->bytes,
                                      iv->len));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);

    if (ad->len > 0)
    {
        TEST_SUCCESS(OS_CryptoCipher_start(hCipher, ad->bytes, ad->len));
    }
    else
    {
        TEST_SUCCESS(OS_CryptoCipher_start(hCipher, NULL, 0));
    }

    TEST_SUCCESS(OS_CryptoCipher_process(hCipher, din->bytes, din->len, buf,
                                         &n));
    TEST_TRUE(n == dout->len);
    TEST_TRUE(!memcmp(buf, dout->bytes, n));

    if (algo == OS_CryptoCipher_ALG_AES_GCM_ENC)
    {
        // Here we create the tag
        n = sizeof(buf);
        TEST_SUCCESS(OS_CryptoCipher_finalize(hCipher, buf, &n));
        TEST_TRUE(n == tag->len);
        TEST_TRUE(!memcmp(buf, tag->bytes, n));
        ret = OS_SUCCESS;
    }
    else
    {
        // Here we check the tag
        n = tag->len;
        memcpy(buf, tag->bytes, tag->len);
        ret = OS_CryptoCipher_finalize(hCipher, buf, &n);
    }

    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    return ret;
}

static void
test_OS_CryptoCipher_do_AES_GCM_enc(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;
    size_t i;

    TEST_START("i", mode, "i", keepLocal);

    for (i = 0; i < NUM_AES_GCM_TESTS; i++)
    {
        TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &aesGcmVectors[i].key));
        TEST_SUCCESS(do_AES_GCM(hCrypto, mode, keepLocal, hKey,
                                OS_CryptoCipher_ALG_AES_GCM_ENC,
                                &aesGcmVectors[i].iv,
                                &aesGcmVectors[i].ad,
                                &aesGcmVectors[i].pt,
                                &aesGcmVectors[i].ct,
                                &aesGcmVectors[i].tag));
        TEST_SUCCESS(OS_CryptoKey_free(hKey));
    }

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_do_AES_GCM_dec_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;
    size_t i;

    TEST_START("i", mode, "i", keepLocal);

    for (i = 0; i < NUM_AES_GCM_TESTS; i++)
    {
        TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &aesGcmVectors[i].key));
        TEST_SUCCESS(do_AES_GCM(hCrypto, mode, keepLocal, hKey,
                                OS_CryptoCipher_ALG_AES_GCM_DEC,
                                &aesGcmVectors[i].iv,
                                &aesGcmVectors[i].ad,
                                &aesGcmVectors[i].ct,
                                &aesGcmVectors[i].pt,
                                &aesGcmVectors[i].tag));
        TEST_SUCCESS(OS_CryptoKey_free(hKey));
    }

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_do_AES_GCM_dec_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;
    const TestVector* vec = &aesGcmVectors[0];
    ByteVector brokenTag;

    TEST_START("i", mode, "i", keepLocal);

    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &vec->key));

    // Create GCM with manipulated tag
    memcpy(brokenTag.bytes, vec->tag.bytes, vec->tag.len);
    brokenTag.len = vec->tag.len;
    brokenTag.bytes[0] ^= 0xff;

    // Check manipulated TAG is detected
    TEST_ABORTED(do_AES_GCM(hCrypto, mode, keepLocal, hKey,
                            OS_CryptoCipher_ALG_AES_GCM_DEC,
                            &vec->iv, &vec->ad, &vec->ct, &vec->pt, &brokenTag));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_do_AES_GCM_rnd(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoCipher_Handle_t hCipher;
    OS_CryptoKey_Handle_t hKey;
    uint8_t pt[16], ct[16], tmp[16], iv[12], tag[16], ad[16];
    size_t len;

    TEST_START("i", mode, "i", keepLocal);

    for (size_t i = 0; i < NUM_RAND_ITERATIONS; i++)
    {
        // Generate random key, PT, IV, AD
        TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec));
        TEST_SUCCESS(OS_CryptoRng_getBytes(hCrypto, 0, pt, sizeof(pt)));
        TEST_SUCCESS(OS_CryptoRng_getBytes(hCrypto, 0, iv, sizeof(iv)));
        TEST_SUCCESS(OS_CryptoRng_getBytes(hCrypto, 0, ad, sizeof(ad)));

        // Encrypt
        len = sizeof(ct);
        TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                          OS_CryptoCipher_ALG_AES_GCM_ENC,
                                          iv, sizeof(iv)));
        TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
        TEST_SUCCESS(OS_CryptoCipher_start(hCipher, ad, sizeof(ad)));
        TEST_SUCCESS(OS_CryptoCipher_process(hCipher, pt, sizeof(pt), ct, &len));
        len = sizeof(tag);
        TEST_SUCCESS(OS_CryptoCipher_finalize(hCipher, tag, &len));
        TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

        // Decrypt
        len = sizeof(tmp);
        TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                          OS_CryptoCipher_ALG_AES_GCM_DEC,
                                          iv, sizeof(iv)));
        TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
        TEST_SUCCESS(OS_CryptoCipher_start(hCipher, ad, sizeof(ad)));
        len = sizeof(tmp);
        TEST_SUCCESS(OS_CryptoCipher_process(hCipher, ct, sizeof(ct), tmp, &len));
        TEST_SUCCESS(OS_CryptoCipher_finalize(hCipher, tag, &len));
        TEST_SUCCESS(OS_CryptoCipher_free(hCipher));
        // Check decryption result
        ASSERT_EQ_INT(0, memcmp(tmp, pt, len));

        TEST_SUCCESS(OS_CryptoKey_free(hKey));
    }

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_init_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoCipher_Handle_t hCipher;
    OS_CryptoKey_Handle_t hKey;
    const ByteVector* iv;

    TEST_START("i", mode, "i", keepLocal);

    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec));

    // Test GCM enc
    iv = &aesGcmVectors[0].iv;
    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_GCM_ENC,
                                      iv->bytes, iv->len));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    // Test GCM dec
    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_GCM_DEC,
                                      iv->bytes, iv->len));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    // Test CBC enc
    iv = &aesCbcVectors[0].iv;
    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_CBC_ENC,
                                      iv->bytes, iv->len));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    // Test CBC dec
    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_CBC_DEC,
                                      iv->bytes, iv->len));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    // Test CTR enc
    iv = &aesCtrVectors[0].iv;
    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_CTR_ENC,
                                      iv->bytes, iv->len));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    // Test CTR dec
    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_CTR_DEC,
                                      iv->bytes, iv->len));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    // Test ECB enc
    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_ECB_ENC,
                                      NULL, 0));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    // Test ECB dec
    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_ECB_DEC,
                                      NULL, 0));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_init_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoCipher_Handle_t hCipher;
    OS_CryptoKey_Handle_t hKey, hPubKey;
    const ByteVector* iv;

    TEST_START("i", mode, "i", keepLocal);

    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec));
    TEST_SUCCESS(OS_CryptoKey_import(&hPubKey, hCrypto, &secp256r1PubData));

    // Test empty cipher handle
    iv = &aesGcmVectors[0].iv;
    TEST_INVAL_PARAM(OS_CryptoCipher_init(NULL, hCrypto, hKey,
                                          OS_CryptoCipher_ALG_AES_GCM_ENC,
                                          iv->bytes, iv->len));

    // Test empty crypto handle
    TEST_INVAL_PARAM(OS_CryptoCipher_init(&hCipher, NULL, hKey,
                                          OS_CryptoCipher_ALG_AES_GCM_ENC,
                                          iv->bytes, iv->len));

    // Test empty key handle
    TEST_INVAL_PARAM(OS_CryptoCipher_init(&hCipher, hCrypto, NULL,
                                          OS_CryptoCipher_ALG_AES_GCM_ENC,
                                          iv->bytes, iv->len));

    // Test with wrong key type (EC pub key)
    TEST_INVAL_PARAM(OS_CryptoCipher_init(&hCipher, hCrypto, hPubKey,
                                          OS_CryptoCipher_ALG_AES_GCM_ENC,
                                          iv->bytes, iv->len));

    // Test invalid algorithm
    TEST_NOT_SUPP(OS_CryptoCipher_init(&hCipher, hCrypto, hKey, 666,
                                       iv->bytes, iv->len));

    // Test without zero sized buf
    TEST_INVAL_PARAM(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                          OS_CryptoCipher_ALG_AES_GCM_DEC,
                                          iv->bytes, 0));

    // Test CBC with wrong sized IV
    TEST_INVAL_PARAM(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                          OS_CryptoCipher_ALG_AES_CBC_ENC,
                                          iv->bytes, iv->len));

    // Test GCM with wrong sized IV
    iv = &aesCbcVectors[0].iv;
    TEST_NOT_SUPP(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                       OS_CryptoCipher_ALG_AES_GCM_ENC,
                                       iv->bytes, iv->len));

    // Test ECB with IV
    TEST_INVAL_PARAM(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                          OS_CryptoCipher_ALG_AES_ECB_ENC,
                                          iv->bytes, iv->len));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));
    TEST_SUCCESS(OS_CryptoKey_free(hPubKey));

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_free_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoCipher_Handle_t hCipher;
    OS_CryptoKey_Handle_t hKey;

    TEST_START("i", mode, "i", keepLocal);

    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec));
    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_ECB_DEC,
                                      NULL, 0));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);

    // Simply free
    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_free_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoCipher_Handle_t hCipher;
    OS_CryptoKey_Handle_t hKey;

    TEST_START("i", mode, "i", keepLocal);

    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec));
    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_ECB_DEC,
                                      NULL, 0));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);

    // Test with empty handle
    TEST_INVAL_PARAM(OS_CryptoCipher_free(NULL));

    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));
    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_start_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoCipher_Handle_t hCipher;

    TEST_START("i", mode, "i", keepLocal);

    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec));

    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_GCM_ENC,
                                      aesGcmVectors[0].iv.bytes,
                                      aesGcmVectors[0].iv.len));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);

    // Start without crypto handle
    TEST_INVAL_PARAM(OS_CryptoCipher_start(NULL, NULL, 0));

    // Start twice
    TEST_SUCCESS(OS_CryptoCipher_start(hCipher, NULL, 0));
    TEST_ABORTED(OS_CryptoCipher_start(hCipher, NULL, 0));

    // Start for hCipher in wrong mode
    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));
    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_ECB_ENC,
                                      NULL, 0));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
    TEST_ABORTED(OS_CryptoCipher_start(hCipher, NULL, 0));
    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_process_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoCipher_Handle_t hCipher;
    unsigned char buf[128];
    size_t n = sizeof(buf);

    TEST_START("i", mode, "i", keepLocal);

    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec));

    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_GCM_ENC,
                                      aesGcmVectors[0].iv.bytes,
                                      aesGcmVectors[0].iv.len));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);

    // Process without calling start for GCM
    TEST_ABORTED(OS_CryptoCipher_process(hCipher, buf, 16, buf, &n));

    // Process without handle
    TEST_SUCCESS(OS_CryptoCipher_start(hCipher, NULL, 0));
    TEST_INVAL_PARAM(OS_CryptoCipher_process(NULL, buf, 16, buf, &n));

    // Process with empty input buf
    TEST_INVAL_PARAM(OS_CryptoCipher_process(hCipher, NULL, 16, buf, &n));

    // Process with empty zero blocksize
    TEST_INVAL_PARAM(OS_CryptoCipher_process(hCipher, buf, 0, buf, &n));

    // Process without output buffer
    TEST_INVAL_PARAM(OS_CryptoCipher_process(hCipher, buf, 16, NULL, &n));

    // Process with too small output buffer; should give right size though
    n = 3;
    TEST_TOO_SMALL(OS_CryptoCipher_process(hCipher, buf, 16, buf, &n));
    TEST_TRUE(n == 16);

    // Process without with non-aligned block (which is ok for last call to Process in GCM mode)
    // but then adding another block via Process
    n = sizeof(buf);
    TEST_SUCCESS(OS_CryptoCipher_process(hCipher, buf, 20, buf, &n));
    TEST_ABORTED(OS_CryptoCipher_process(hCipher, buf, 16, buf, &n));

    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    // Process with un-aligned block sizes for ECB
    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_ECB_ENC,
                                      NULL, 0));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
    TEST_INVAL_PARAM(OS_CryptoCipher_process(hCipher, buf, 18, buf, &n));
    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    // Process with un-aligned block sizes for CBC
    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_CBC_ENC,
                                      aesCbcVectors[0].iv.bytes,
                                      aesCbcVectors[0].iv.len));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
    TEST_INVAL_PARAM(OS_CryptoCipher_process(hCipher, buf, 18, buf, &n));
    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_finalize_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoCipher_Handle_t hCipher;
    unsigned char buf[128];
    size_t n = sizeof(buf);

    TEST_START("i", mode, "i", keepLocal);

    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec));

    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_GCM_ENC,
                                      aesGcmVectors[0].iv.bytes,
                                      aesGcmVectors[0].iv.len));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);

    // Finalize without calling start+Process
    TEST_ABORTED(OS_CryptoCipher_finalize(hCipher, buf, &n));

    // Finalize without calling Process
    TEST_SUCCESS(OS_CryptoCipher_start(hCipher, NULL, 0));
    TEST_ABORTED(OS_CryptoCipher_finalize(hCipher, buf, &n));

    TEST_SUCCESS(OS_CryptoCipher_process(hCipher, buf, 16, buf, &n));

    // Finalize without handle
    TEST_INVAL_PARAM(OS_CryptoCipher_finalize(NULL, buf, &n));

    // Finalize without buffer in ENC mode (wants to write a tag)
    TEST_INVAL_PARAM(OS_CryptoCipher_finalize(hCipher, NULL, &n));

    // Finalize with zero length buffer
    TEST_INVAL_PARAM(OS_CryptoCipher_finalize(hCipher, buf, 0));

    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    // Finalize without buffer in DEC mode (will just compare the tag)
    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_GCM_DEC,
                                      aesGcmVectors[0].iv.bytes,
                                      aesGcmVectors[0].iv.len));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
    TEST_SUCCESS(OS_CryptoCipher_start(hCipher, NULL, 0));
    TEST_SUCCESS(OS_CryptoCipher_process(hCipher, buf, 16, buf, &n));
    TEST_INVAL_PARAM(OS_CryptoCipher_finalize(hCipher, NULL, &n));

    // Finalize without zero length in DEC mode (will just compare the tag)
    n = 0;
    TEST_INVAL_PARAM(OS_CryptoCipher_finalize(hCipher, buf, &n));

    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    // Finalize on wrong type of hCipher
    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_ECB_ENC,
                                      NULL, 0));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
    n = sizeof(buf);
    TEST_NOT_SUPP(OS_CryptoCipher_finalize(hCipher, buf, &n));
    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_init_dataport(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoCipher_Handle_t hCipher;
    static unsigned char ivBuf[OS_DATAPORT_DEFAULT_SIZE + 1];
    size_t ivLen;

    TEST_START("i", mode, "i", keepLocal);

    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec));

    // Should be OK
    ivLen = OS_CryptoCipher_SIZE_AES_BLOCK;
    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_CBC_DEC,
                                      ivBuf, ivLen));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    // Should fail with OS_ERROR_INVALID_PARAMETER beacause it is way too large
    // for any hCipher
    ivLen = OS_DATAPORT_DEFAULT_SIZE;
    TEST_INVAL_PARAM(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                          OS_CryptoCipher_ALG_AES_CBC_DEC,
                                          ivBuf, ivLen));

    // Should fail with OS_ERROR_INSUFFICIENT_SPACE because it is too large for
    // the internal dataports
    ivLen = OS_DATAPORT_DEFAULT_SIZE + 1;
    TEST_INVAL_PARAM(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                          OS_CryptoCipher_ALG_AES_CBC_DEC,
                                          ivBuf, ivLen));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_start_dataport(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoCipher_Handle_t hCipher;
    static unsigned char ivBuf[16], inputBuf[OS_DATAPORT_DEFAULT_SIZE + 1];
    size_t inLen;

    TEST_START("i", mode, "i", keepLocal);

    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec));
    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_GCM_ENC,
                                      ivBuf, 12));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);

    // Should be OK
    inLen = OS_DATAPORT_DEFAULT_SIZE;
    TEST_SUCCESS(OS_CryptoCipher_start(hCipher, inputBuf, inLen));

    // Should fail because input is too big
    inLen = OS_DATAPORT_DEFAULT_SIZE + 1;
    TEST_INVAL_PARAM(OS_CryptoCipher_start(hCipher, inputBuf, inLen));

    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_process_buffer(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoCipher_Handle_t hCipher;
    static unsigned char inBuf[OS_DATAPORT_DEFAULT_SIZE + 1];
    size_t inLen, outLen;

    TEST_START("i", mode, "i", keepLocal);

    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &aesEcbVectors[0].key));
    TEST_LOCACTION_FLAG(mode, keepLocal, hKey);
    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_ECB_DEC,
                                      NULL, 0));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);

    // Let input/output buffer be the same; this should work, as long as we
    // are below the DATAPORT size (which is the size internally used to
    // have a buffer where a copy of the input is kept).
    memcpy(inBuf, aesEcbVectors[0].ct.bytes, aesEcbVectors[0].ct.len);
    inLen = aesEcbVectors[0].pt.len;
    outLen = OS_DATAPORT_DEFAULT_SIZE;
    TEST_SUCCESS(OS_CryptoCipher_process(hCipher,
                                         inBuf, inLen,
                                         inBuf, &outLen));
    TEST_TRUE(outLen == aesEcbVectors[0].pt.len);
    TEST_TRUE(!memcmp(inBuf, aesEcbVectors[0].pt.bytes,
                      aesEcbVectors[0].pt.len));

    // This should fail as input is too big for internal buffer; which is set
    // to the size of the dataport.
    inLen = OS_DATAPORT_DEFAULT_SIZE + 1;
    outLen = OS_DATAPORT_DEFAULT_SIZE;
    TEST_INVAL_PARAM(OS_CryptoCipher_process(hCipher, inBuf, inLen, inBuf,
                                             &outLen));

    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));
    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_process_dataport(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoCipher_Handle_t hCipher;
    static unsigned char inBuf[OS_DATAPORT_DEFAULT_SIZE + 1],
           outBuf[OS_DATAPORT_DEFAULT_SIZE + 1];
    size_t inLen, outLen;

    TEST_START("i", mode, "i", keepLocal);

    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec));
    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_ECB_DEC,
                                      NULL, 0));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);

    // This should go OK
    inLen = outLen = OS_DATAPORT_DEFAULT_SIZE;
    TEST_SUCCESS(OS_CryptoCipher_process(hCipher, inBuf, inLen, outBuf,
                                         &outLen));
    TEST_TRUE(inLen == outLen);

    // This should fail as input is too big
    inLen = OS_DATAPORT_DEFAULT_SIZE + 1;
    outLen = OS_DATAPORT_DEFAULT_SIZE;
    TEST_INVAL_PARAM(OS_CryptoCipher_process(hCipher, inBuf, inLen, outBuf,
                                             &outLen));

    // This should fail as output is too big
    inLen = OS_DATAPORT_DEFAULT_SIZE;
    outLen = OS_DATAPORT_DEFAULT_SIZE + 1;
    TEST_INVAL_PARAM(OS_CryptoCipher_process(hCipher, inBuf, inLen, outBuf,
                                             &outLen));

    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));
    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoCipher_finalize_dataport(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoCipher_Handle_t hCipher;
    OS_CryptoKey_Handle_t hKey;
    unsigned char inBuf[16], outBuf[16], iv[12];
    static unsigned char tagBuf[OS_DATAPORT_DEFAULT_SIZE + 1];
    size_t tagLen;

    TEST_START("i", mode, "i", keepLocal);

    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec));

    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_GCM_ENC,
                                      iv, 12));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
    TEST_SUCCESS(OS_CryptoCipher_start(hCipher, NULL, 0));
    tagLen = sizeof(outBuf);
    TEST_SUCCESS(OS_CryptoCipher_process(hCipher, inBuf, 16, outBuf, &tagLen));

    // Should work fine and give the written size
    tagLen = OS_DATAPORT_DEFAULT_SIZE;
    TEST_SUCCESS(OS_CryptoCipher_finalize(hCipher, tagBuf, &tagLen));
    TEST_TRUE(OS_CryptoCipher_SIZE_AES_GCM_TAG_MAX == tagLen);

    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));

    TEST_SUCCESS(OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                                      OS_CryptoCipher_ALG_AES_GCM_ENC,
                                      iv, 12));
    TEST_LOCACTION_FLAG(mode, keepLocal, hCipher);
    TEST_SUCCESS(OS_CryptoCipher_start(hCipher, NULL, 0));
    tagLen = sizeof(outBuf);
    TEST_SUCCESS(OS_CryptoCipher_process(hCipher, inBuf, 16, outBuf, &tagLen));

    // Should fail due to limited internal buffers
    tagLen = OS_DATAPORT_DEFAULT_SIZE + 1;
    TEST_INVAL_PARAM(OS_CryptoCipher_finalize(hCipher, tagBuf, &tagLen));

    // Should fail (tags bust be at least 4 bytes) but give the minimum size
    tagLen = 3;
    TEST_TOO_SMALL(OS_CryptoCipher_finalize(hCipher, tagBuf, &tagLen));
    TEST_TRUE(4 == tagLen);

    // Should work
    tagLen = 5;
    TEST_SUCCESS(OS_CryptoCipher_finalize(hCipher, tagBuf, &tagLen));
    TEST_TRUE(5 == tagLen);

    TEST_SUCCESS(OS_CryptoCipher_free(hCipher));
    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

void
test_OS_CryptoCipher(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode)
{
    keyData_setLocality(keyDataList, true);
    keyData_setLocality(testKeyDataList, true);
    keySpec_setLocality(keySpecList, true);

    test_OS_CryptoCipher_init_pos(hCrypto, mode, true);
    test_OS_CryptoCipher_init_neg(hCrypto, mode, true);

    test_OS_CryptoCipher_free_pos(hCrypto, mode, true);
    test_OS_CryptoCipher_free_neg(hCrypto, mode, true);

    // Test only failures separately, as computing ref. values is sufficient
    // proof of correct funtioning
    test_OS_CryptoCipher_start_neg(hCrypto, mode, true);
    test_OS_CryptoCipher_process_neg(hCrypto, mode, true);
    test_OS_CryptoCipher_finalize_neg(hCrypto, mode, true);

    // Test vectors
    test_OS_CryptoCipher_do_AES_ECB_enc(hCrypto, mode, true);
    test_OS_CryptoCipher_do_AES_ECB_dec(hCrypto, mode, true);
    test_OS_CryptoCipher_do_AES_CBC_enc(hCrypto, mode, true);
    test_OS_CryptoCipher_do_AES_CBC_dec(hCrypto, mode, true);
    test_OS_CryptoCipher_do_AES_GCM_enc(hCrypto, mode, true);
    test_OS_CryptoCipher_do_AES_CTR_enc(hCrypto, mode, true);
    test_OS_CryptoCipher_do_AES_CTR_dec(hCrypto, mode, true);
    test_OS_CryptoCipher_do_AES_GCM_dec_pos(hCrypto, mode, true);
    test_OS_CryptoCipher_do_AES_GCM_dec_neg(hCrypto, mode, true);

    // Random values
    test_OS_CryptoCipher_do_AES_ECB_rnd(hCrypto, mode, true);
    test_OS_CryptoCipher_do_AES_CBC_rnd(hCrypto, mode, true);
    test_OS_CryptoCipher_do_AES_CTR_rnd(hCrypto, mode, true);
    test_OS_CryptoCipher_do_AES_GCM_rnd(hCrypto, mode, true);

    switch (mode)
    {
    case OS_Crypto_MODE_LIBRARY:
        test_OS_CryptoCipher_process_buffer(hCrypto, mode, true);
        break;
    case OS_Crypto_MODE_CLIENT:
        test_OS_CryptoCipher_init_dataport(hCrypto, mode, true);
        test_OS_CryptoCipher_start_dataport(hCrypto, mode, true);
        test_OS_CryptoCipher_process_dataport(hCrypto, mode, true);
        test_OS_CryptoCipher_finalize_dataport(hCrypto, mode, true);
        break;
    case OS_Crypto_MODE_KEY_SWITCH:
        keyData_setLocality(keyDataList, false);
        keyData_setLocality(testKeyDataList, false);
        keySpec_setLocality(keySpecList, false);
        test_OS_CryptoCipher_do_AES_ECB_enc(hCrypto, mode, false);
        test_OS_CryptoCipher_do_AES_ECB_dec(hCrypto, mode, false);
        test_OS_CryptoCipher_do_AES_CBC_enc(hCrypto, mode, false);
        test_OS_CryptoCipher_do_AES_CBC_dec(hCrypto, mode, false);
        test_OS_CryptoCipher_do_AES_CTR_enc(hCrypto, mode, false);
        test_OS_CryptoCipher_do_AES_CTR_dec(hCrypto, mode, false);
        test_OS_CryptoCipher_do_AES_GCM_enc(hCrypto, mode, false);
        test_OS_CryptoCipher_do_AES_GCM_dec_pos(hCrypto, mode, false);
        test_OS_CryptoCipher_do_AES_ECB_rnd(hCrypto, mode, false);
        test_OS_CryptoCipher_do_AES_CBC_rnd(hCrypto, mode, false);
        test_OS_CryptoCipher_do_AES_CTR_rnd(hCrypto, mode, false);
        test_OS_CryptoCipher_do_AES_GCM_rnd(hCrypto, mode, false);
        break;
    default:
        break;
    }
}