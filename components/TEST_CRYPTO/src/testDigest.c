/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include "SeosCryptoDigest.h"
#include "SeosCryptoApi.h"

#include <string.h>

#define MAX_VECTOR_SIZE 2048
typedef struct
{
    size_t len;
    unsigned char bytes[MAX_VECTOR_SIZE];
} vector_t;

typedef struct
{
    vector_t msg;
    vector_t digest;
} digestTestVector;

// -----------------------------------------------------------------------------

#define NUM_MD5_TESTS 5
static const digestTestVector md5Vectors[NUM_MD5_TESTS] =
{
    {
        .msg    = {
            .bytes = "a",
            .len   = 1,
        },
        .digest = {
            .bytes = {0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8, 0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61},
            .len = 16
        }
    },
    {
        .msg    = {
            .bytes = "abc",
            .len = 3
        },
        .digest = {
            .bytes = {0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72},
            .len = 16
        }
    },
    {
        .msg    = {
            .bytes = "message digest",
            .len = 14
        },
        .digest = {
            .bytes = {0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d, 0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0},
            .len = 16
        }
    },
    {
        .msg = {
            .bytes = "abcdefghijklmnopqrstuvwxyz",
            .len = 26
        },
        .digest = {
            .bytes = {0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00, 0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67, 0xe1, 0x3b},
            .len = 16
        }
    },
    {
        .msg = {
            .bytes = "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            .len = 80
        },
        .digest = {
            .bytes = {0x57, 0xed, 0xf4, 0xa2, 0x2b, 0xe3, 0xc9, 0x55, 0xac, 0x49, 0xda, 0x2e, 0x21, 0x07, 0xb6, 0x7a},
            .len = 16
        }
    },
};

// -----------------------------------------------------------------------------

#define NUM_SHA256_TESTS 4
static const digestTestVector sha256Vectors[NUM_SHA256_TESTS] =
{
    {
        .msg    = {
            .bytes = {0xbd},
            .len = 1,
        },
        .digest = {
            .bytes = {0x68, 0x32, 0x57, 0x20, 0xaa, 0xbd, 0x7c, 0x82, 0xf3, 0x0f, 0x55, 0x4b, 0x31, 0x3d, 0x05, 0x70, 0xc9, 0x5a, 0xcc, 0xbb, 0x7d, 0xc4, 0xb5, 0xaa, 0xe1, 0x12, 0x04, 0xc0, 0x8f, 0xfe, 0x73, 0x2b},
            .len    = 32
        }
    },
    {
        .msg    = {
            .bytes = {0x5f, 0xd4},
            .len = 2
        },
        .digest = {
            .bytes = {0x7c, 0x4f, 0xbf, 0x48, 0x44, 0x98, 0xd2, 0x1b, 0x48, 0x7b, 0x9d, 0x61, 0xde, 0x89, 0x14, 0xb2, 0xea, 0xda, 0xf2, 0x69, 0x87, 0x12, 0x93, 0x6d, 0x47, 0xc3, 0xad, 0xa2, 0x55, 0x8f, 0x67, 0x88},
            .len = 32
        }
    },
    {
        .msg    = {
            .bytes = {0x81, 0xa7, 0x23, 0xd9, 0x66},
            .len = 5
        },
        .digest = {
            .bytes = {0x75, 0x16, 0xfb, 0x8b, 0xb1, 0x13, 0x50, 0xdf, 0x2b, 0xf3, 0x86, 0xbc, 0x3c, 0x33, 0xbd, 0x0f, 0x52, 0xcb, 0x4c, 0x67, 0xc6, 0xe4, 0x74, 0x5e, 0x04, 0x88, 0xe6, 0x2c, 0x2a, 0xea, 0x26, 0x05},
            .len = 32
        }
    },
    {
        .msg    = {
            .bytes = {0x83, 0x90, 0xcf, 0x0b, 0xe0, 0x76, 0x61, 0xcc, 0x76, 0x69, 0xaa, 0xc5, 0x4c, 0xe0, 0x9a, 0x37, 0x73, 0x3a, 0x62, 0x9d, 0x45, 0xf5, 0xd9, 0x83, 0xef, 0x20, 0x1f, 0x9b, 0x2d, 0x13, 0x80, 0x0e, 0x55, 0x5d, 0x9b, 0x10, 0x97, 0xfe, 0xc3, 0xb7, 0x83, 0xd7, 0xa5, 0x0d, 0xcb, 0x5e, 0x2b, 0x64, 0x4b, 0x96, 0xa1, 0xe9, 0x46, 0x3f, 0x17, 0x7c, 0xf3, 0x49, 0x06, 0xbf, 0x38, 0x8f, 0x36, 0x6d, 0xb5, 0xc2, 0xde, 0xee, 0x04, 0xa3, 0x0e, 0x28, 0x3f, 0x76, 0x4a, 0x97, 0xc3, 0xb3, 0x77, 0xa0, 0x34, 0xfe, 0xfc, 0x22, 0xc2, 0x59, 0x21, 0x4f, 0xaa, 0x99, 0xba, 0xba, 0xff, 0x16, 0x0a, 0xb0, 0xaa, 0xa7, 0xe2, 0xcc, 0xb0, 0xce, 0x09, 0xc6, 0xb3, 0x2f, 0xe0, 0x8c, 0xbc, 0x47, 0x46, 0x94, 0x37, 0x5a, 0xba, 0x70, 0x3f, 0xad, 0xbf, 0xa3, 0x1c, 0xf6, 0x85, 0xb3, 0x0a, 0x11, 0xc5, 0x7f, 0x3c, 0xf4, 0xed, 0xd3, 0x21, 0xe5, 0x7d, 0x3a, 0xe6, 0xeb, 0xb1, 0x13, 0x3c, 0x82, 0x60, 0xe7, 0x5b, 0x92, 0x24, 0xfa, 0x47, 0xa2, 0xbb, 0x20, 0x52, 0x49, 0xad, 0xd2, 0xe2, 0xe6, 0x2f, 0x81, 0x74, 0x91, 0x48, 0x2a, 0xe1, 0x52, 0x32, 0x2b, 0xe0, 0x90, 0x03, 0x55, 0xcd, 0xcc, 0x8d, 0x42, 0xa9, 0x8f, 0x82, 0xe9, 0x61, 0xa0, 0xdc, 0x6f, 0x53, 0x7b, 0x7b, 0x41, 0x0e, 0xff, 0x10, 0x5f, 0x59, 0x67, 0x3b, 0xfb, 0x78, 0x7b, 0xf0, 0x42, 0xaa, 0x07, 0x1f, 0x7a, 0xf6, 0x8d, 0x94, 0x4d, 0x27, 0x37, 0x1c, 0x64, 0x16, 0x0f, 0xe9, 0x38, 0x27, 0x72, 0x37, 0x25, 0x16, 0xc2, 0x30, 0xc1, 0xf4, 0x5c, 0x0d, 0x6b, 0x6c, 0xca, 0x7f, 0x27, 0x4b, 0x39, 0x4d, 0xa9, 0x40, 0x2d, 0x3e, 0xaf, 0xdf, 0x73, 0x39, 0x94, 0xec, 0x58, 0xab, 0x22, 0xd7, 0x18, 0x29, 0xa9, 0x83, 0x99, 0x57, 0x4d, 0x4b, 0x59, 0x08, 0xa4, 0x47, 0xa5, 0xa6, 0x81, 0xcb, 0x0d, 0xd5, 0x0a, 0x31, 0x14, 0x53, 0x11, 0xd9, 0x2c, 0x22, 0xa1, 0x6d, 0xe1, 0xea, 0xd6, 0x6a, 0x54, 0x99, 0xf2, 0xdc, 0xeb, 0x4c, 0xae, 0x69, 0x47, 0x72, 0xce, 0x90, 0x76, 0x2e, 0xf8, 0x33, 0x6a, 0xfe, 0xc6, 0x53, 0xaa, 0x9b, 0x1a, 0x1c, 0x48, 0x20, 0xb2, 0x21, 0x13, 0x6d, 0xfc, 0xe8, 0x0d, 0xce, 0x2b, 0xa9, 0x20, 0xd8, 0x8a, 0x53, 0x0c, 0x94, 0x10, 0xd0, 0xa4, 0xe0, 0x35, 0x8a, 0x3a, 0x11, 0x05, 0x2e, 0x58, 0xdd, 0x73, 0xb0, 0xb1, 0x79, 0xef, 0x8f, 0x56, 0xfe, 0x3b, 0x5a, 0x2d, 0x11, 0x7a, 0x73, 0xa0, 0xc3, 0x8a, 0x13, 0x92, 0xb6, 0x93, 0x8e, 0x97, 0x82, 0xe0, 0xd8, 0x64, 0x56, 0xee, 0x48, 0x84, 0xe3, 0xc3, 0x9d, 0x4d, 0x75, 0x81, 0x3f, 0x13, 0x63, 0x3b, 0xc7, 0x9b, 0xaa, 0x07, 0xc0, 0xd2, 0xd5, 0x55, 0xaf, 0xbf, 0x20, 0x7f, 0x52, 0xb7, 0xdc, 0xa1, 0x26, 0xd0, 0x15, 0xaa, 0x2b, 0x98, 0x73, 0xb3, 0xeb, 0x06, 0x5e, 0x90, 0xb9, 0xb0, 0x65, 0xa5, 0x37, 0x3f, 0xe1, 0xfb, 0x1b, 0x20, 0xd5, 0x94, 0x32, 0x7d, 0x19, 0xfb, 0xa5, 0x6c, 0xb8, 0x1e, 0x7b, 0x66, 0x96, 0x60, 0x5f, 0xfa, 0x56, 0xeb, 0xa3, 0xc2, 0x7a, 0x43, 0x86, 0x97, 0xcc, 0x21, 0xb2, 0x01, 0xfd, 0x7e, 0x09, 0xf1, 0x8d, 0xee, 0xa1, 0xb3, 0xea, 0x2f, 0x0d, 0x1e, 0xdc, 0x02, 0xdf, 0x0e, 0x20, 0x39, 0x6a, 0x14, 0x54, 0x12, 0xcd, 0x6b, 0x13, 0xc3, 0x2d, 0x2e, 0x60, 0x56, 0x41, 0xc9, 0x48, 0xb7, 0x14, 0xae, 0xc3, 0x0c, 0x06, 0x49, 0xdc, 0x44, 0x14, 0x35, 0x11, 0xf3, 0x5a, 0xb0, 0xfd, 0x5d, 0xd6, 0x4c, 0x34, 0xd0, 0x6f, 0xe8, 0x6f, 0x38, 0x36, 0xdf, 0xe9, 0xed, 0xeb, 0x7f, 0x08, 0xcf, 0xc3, 0xbd, 0x40, 0x95, 0x68, 0x26, 0x35, 0x62, 0x42, 0x19, 0x1f, 0x99, 0xf5, 0x34, 0x73, 0xf3, 0x2b, 0x0c, 0xc0, 0xcf, 0x93, 0x21, 0xd6, 0xc9, 0x2a, 0x11, 0x2e, 0x8d, 0xb9, 0x0b, 0x86, 0xee, 0x9e, 0x87, 0xcc, 0x32, 0xd0, 0x34, 0x3d, 0xb0, 0x1e, 0x32, 0xce, 0x9e, 0xb7, 0x82, 0xcb, 0x24, 0xef, 0xbb, 0xbe, 0xb4, 0x40, 0xfe, 0x92, 0x9e, 0x8f, 0x2b, 0xf8, 0xdf, 0xb1, 0x55, 0x0a, 0x3a, 0x2e, 0x74, 0x2e, 0x8b, 0x45, 0x5a, 0x3e, 0x57, 0x30, 0xe9, 0xe6, 0xa7, 0xa9, 0x82, 0x4d, 0x17, 0xac, 0xc0, 0xf7, 0x2a, 0x7f, 0x67, 0xea, 0xe0, 0xf0, 0x97, 0x0f, 0x8b, 0xde, 0x46, 0xdc, 0xde, 0xfa, 0xed, 0x30, 0x47, 0xcf, 0x80, 0x7e, 0x7f, 0x00, 0xa4, 0x2e, 0x5f, 0xd1, 0x1d, 0x40, 0xf5, 0xe9, 0x85, 0x33, 0xd7, 0x57, 0x44, 0x25, 0xb7, 0xd2, 0xbc, 0x3b, 0x38, 0x45, 0xc4, 0x43, 0x00, 0x8b, 0x58, 0x98, 0x0e, 0x76, 0x8e, 0x46, 0x4e, 0x17, 0xcc, 0x6f, 0x6b, 0x39, 0x39, 0xee, 0xe5, 0x2f, 0x71, 0x39, 0x63, 0xd0, 0x7d, 0x8c, 0x4a, 0xbf, 0x02, 0x44, 0x8e, 0xf0, 0xb8, 0x89, 0xc9, 0x67, 0x1e, 0x2f, 0x8a, 0x43, 0x6d, 0xde, 0xef, 0xfc, 0xca, 0x71, 0x76, 0xe9, 0xbf, 0x9d, 0x10, 0x05, 0xec, 0xd3, 0x77, 0xf2, 0xfa, 0x67, 0xc2, 0x3e, 0xd1, 0xf1, 0x37, 0xe6, 0x0b, 0xf4, 0x60, 0x18, 0xa8, 0xbd, 0x61, 0x3d, 0x03, 0x8e, 0x88, 0x37, 0x04, 0xfc, 0x26, 0xe7, 0x98, 0x96, 0x9d, 0xf3, 0x5e, 0xc7, 0xbb, 0xc6, 0xa4, 0xfe, 0x46, 0xd8, 0x91, 0x0b, 0xd8, 0x2f, 0xa3, 0xcd, 0xed, 0x26, 0x5d, 0x0a, 0x3b, 0x6d, 0x39, 0x9e, 0x42, 0x51, 0xe4, 0xd8, 0x23, 0x3d, 0xaa, 0x21, 0xb5, 0x81, 0x2f, 0xde, 0xd6, 0x53, 0x61, 0x98, 0xff, 0x13, 0xaa, 0x5a, 0x1c, 0xd4, 0x6a, 0x5b, 0x9a, 0x17, 0xa4, 0xdd, 0xc1, 0xd9, 0xf8, 0x55, 0x44, 0xd1, 0xd1, 0xcc, 0x16, 0xf3, 0xdf, 0x85, 0x80, 0x38, 0xc8, 0xe0, 0x71, 0xa1, 0x1a, 0x7e, 0x15, 0x7a, 0x85, 0xa6, 0xa8, 0xdc, 0x47, 0xe8, 0x8d, 0x75, 0xe7, 0x00, 0x9a, 0x8b, 0x26, 0xfd, 0xb7, 0x3f, 0x33, 0xa2, 0xa7, 0x0f, 0x1e, 0x0c, 0x25, 0x9f, 0x8f, 0x95, 0x33, 0xb9, 0xb8, 0xf9, 0xaf, 0x92, 0x88, 0xb7, 0x27, 0x4f, 0x21, 0xba, 0xee, 0xc7, 0x8d, 0x39, 0x6f, 0x8b, 0xac, 0xdc, 0xc2, 0x24, 0x71, 0x20, 0x7d, 0x9b, 0x4e, 0xfc, 0xcd, 0x3f, 0xed, 0xc5, 0xc5, 0xa2, 0x21, 0x4f, 0xf5, 0xe5, 0x1c, 0x55, 0x3f, 0x35, 0xe2, 0x1a, 0xe6, 0x96, 0xfe, 0x51, 0xe8, 0xdf, 0x73, 0x3a, 0x8e, 0x06, 0xf5, 0x0f, 0x41, 0x9e, 0x59, 0x9e, 0x9f, 0x9e, 0x4b, 0x37, 0xce, 0x64, 0x3f, 0xc8, 0x10, 0xfa, 0xaa, 0x47, 0x98, 0x97, 0x71, 0x50, 0x9d, 0x69, 0xa1, 0x10, 0xac, 0x91, 0x62, 0x61, 0x42, 0x70, 0x26, 0x36, 0x9a, 0x21, 0x26, 0x3a, 0xc4, 0x46, 0x0f, 0xb4, 0xf7, 0x08, 0xf8, 0xae, 0x28, 0x59, 0x98, 0x56, 0xdb, 0x7c, 0xb6, 0xa4, 0x3a, 0xc8, 0xe0, 0x3d, 0x64, 0xa9, 0x60, 0x98, 0x07, 0xe7, 0x6c, 0x5f, 0x31, 0x2b, 0x9d, 0x18, 0x63, 0xbf, 0xa3, 0x04, 0xe8, 0x95, 0x36, 0x47, 0x64, 0x8b, 0x4f, 0x4a, 0xb0, 0xed, 0x99, 0x5e},
            .len = 955
        },
        .digest = {
            .bytes = {0x41, 0x09, 0xcd, 0xbe, 0xc3, 0x24, 0x0a, 0xd7, 0x4c, 0xc6, 0xc3, 0x7f, 0x39, 0x30, 0x0f, 0x70, 0xfe, 0xde, 0x16, 0xe2, 0x1e, 0xfc, 0x77, 0xf7, 0x86, 0x59, 0x98, 0x71, 0x4a, 0xad, 0x0b, 0x5e},
            .len = 32
        }
    }
};

// -----------------------------------------------------------------------------

static void
do_hash(SeosCryptoCtx*              ctx,
        SeosCrypto_DigestHandle     digHandle,
        const digestTestVector*     vec)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    char digest[64];
    size_t digestSize;

    err = SeosCryptoApi_digestProcess(ctx, digHandle, vec->msg.bytes, vec->msg.len);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    digestSize = sizeof(digest);
    err = SeosCryptoApi_digestFinalize(ctx, digHandle, digest, &digestSize);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(digestSize == vec->digest.len);
    Debug_ASSERT(!memcmp(digest, vec->digest.bytes, vec->digest.len));
}

static void
testDigest_hash_MD5(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_DigestHandle digHandle;
    size_t i;

    err = SeosCryptoApi_digestInit(ctx, &digHandle, SeosCryptoDigest_Algorithm_MD5);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    for (i = 0; i < NUM_MD5_TESTS; i++)
    {
        do_hash(ctx, digHandle, &md5Vectors[i]);
    }

    err = SeosCryptoApi_digestFree(ctx, digHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testDigest_hash_SHA256(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_DigestHandle digHandle;
    size_t i;

    err = SeosCryptoApi_digestInit(ctx, &digHandle,
                                   SeosCryptoDigest_Algorithm_SHA256);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    for (i = 0; i < NUM_SHA256_TESTS; i++)
    {
        do_hash(ctx, digHandle, &sha256Vectors[i]);
    }

    err = SeosCryptoApi_digestFree(ctx, digHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
do_clone(SeosCryptoCtx*                     ctx,
         const SeosCryptoDigest_Algorithm   algo,
         const digestTestVector*            vec)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_DigestHandle dstDigHandle, srcDigHandle;
    char srcDigest[64], dstDigest[64];
    size_t digestSize;

    // Create digest object and process something
    err = SeosCryptoApi_digestInit(ctx, &srcDigHandle, algo);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_digestProcess(ctx, srcDigHandle, vec->msg.bytes,
                                      vec->msg.len);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Create new digest and clone the state of the other one
    err = SeosCryptoApi_digestInit(ctx, &dstDigHandle, algo);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_digestClone(ctx, dstDigHandle, srcDigHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Finalize both objects and check if they match
    digestSize = sizeof(srcDigest);
    err = SeosCryptoApi_digestFinalize(ctx, srcDigHandle, srcDigest, &digestSize);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(digestSize == vec->digest.len);
    digestSize = sizeof(dstDigest);
    err = SeosCryptoApi_digestFinalize(ctx, dstDigHandle, dstDigest, &digestSize);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(digestSize == vec->digest.len);
    Debug_ASSERT(!memcmp(srcDigest, dstDigest, digestSize));

    err = SeosCryptoApi_digestFree(ctx, dstDigHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_digestFree(ctx, srcDigHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
}

static void
testDigest_clone_ok(SeosCryptoCtx* ctx)
{
    do_clone(ctx, SeosCryptoDigest_Algorithm_MD5, &md5Vectors[0]);
    do_clone(ctx, SeosCryptoDigest_Algorithm_SHA256, &sha256Vectors[0]);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testDigest_clone_fail(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    const digestTestVector* vec = &md5Vectors[0];
    SeosCrypto_DigestHandle dstDigHandle, srcDigHandle;

    // Create digest object and process something
    err = SeosCryptoApi_digestInit(ctx, &srcDigHandle, SeosCryptoDigest_Algorithm_MD5);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_digestProcess(ctx, srcDigHandle, vec->msg.bytes,
                                      vec->msg.len);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_digestInit(ctx, &dstDigHandle, SeosCryptoDigest_Algorithm_MD5);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Empty ctx
    err = SeosCryptoApi_digestClone(NULL, dstDigHandle, srcDigHandle);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty dst handle
    err = SeosCryptoApi_digestClone(ctx, NULL, srcDigHandle);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);

    // Empty src handle
    err = SeosCryptoApi_digestClone(ctx, dstDigHandle, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);

    // Clone into wrong type of digest
    err = SeosCryptoApi_digestFree(ctx, dstDigHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_digestInit(ctx, &dstDigHandle, SeosCryptoDigest_Algorithm_SHA256);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_digestClone(ctx, dstDigHandle, srcDigHandle);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    err = SeosCryptoApi_digestFree(ctx, dstDigHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_digestFree(ctx, srcDigHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testDigest_init_ok(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_DigestHandle digHandle;

    // Test MD5
    err = SeosCryptoApi_digestInit(ctx, &digHandle, SeosCryptoDigest_Algorithm_MD5);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_digestFree(ctx, digHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Test SHA256
    err = SeosCryptoApi_digestInit(ctx, &digHandle,
                                   SeosCryptoDigest_Algorithm_SHA256);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_digestFree(ctx, digHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testDigest_init_fail(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_DigestHandle digHandle;

    // Test with emtpy ctx
    err = SeosCryptoApi_digestInit(NULL, &digHandle,
                                   SeosCryptoDigest_Algorithm_MD5);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Test with emtpy handle
    err = SeosCryptoApi_digestInit(ctx, NULL, SeosCryptoDigest_Algorithm_MD5);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Test with invalid algo id
    err = SeosCryptoApi_digestInit(ctx, &digHandle, 666);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testDigest_free_ok(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_DigestHandle digHandle;

    err = SeosCryptoApi_digestInit(ctx, &digHandle, SeosCryptoDigest_Algorithm_MD5);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_digestFree(ctx, digHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testDigest_free_fail(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_DigestHandle digHandle, emptyHandle;

    err = SeosCryptoApi_digestInit(ctx, &digHandle, SeosCryptoDigest_Algorithm_MD5);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Test empty ctx
    err = SeosCryptoApi_digestFree(NULL, digHandle);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Test empty handle
    emptyHandle = NULL;
    err = SeosCryptoApi_digestFree(ctx, emptyHandle);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);

    err = SeosCryptoApi_digestFree(ctx, digHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testDigest_process_fail(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_DigestHandle digHandle;
    const digestTestVector* vec = &md5Vectors[0];

    err = SeosCryptoApi_digestInit(ctx, &digHandle, SeosCryptoDigest_Algorithm_MD5);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Test with empty ctx
    err = SeosCryptoApi_digestProcess(NULL, digHandle, vec->msg.bytes,
                                      vec->msg.len);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Test with empty handle
    err = SeosCryptoApi_digestProcess(ctx, NULL, vec->msg.bytes, vec->msg.len);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);

    // Test with empty input
    err = SeosCryptoApi_digestProcess(ctx, digHandle, NULL, vec->msg.len);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Test with zero lenght input
    err = SeosCryptoApi_digestProcess(ctx, digHandle, vec->msg.bytes, 0);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    err = SeosCryptoApi_digestFree(ctx, digHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testDigest_finalize_fail(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_DigestHandle digHandle;
    const digestTestVector* vec = &md5Vectors[0];
    char digest[64];
    size_t digestSize = sizeof(digest);

    err = SeosCryptoApi_digestInit(ctx, &digHandle, SeosCryptoDigest_Algorithm_MD5);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Finalize without updating
    err = SeosCryptoApi_digestFinalize(ctx, digHandle, digest, &digestSize);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_ABORTED == err, "err %d", err);

    err = SeosCryptoApi_digestProcess(ctx, digHandle, vec->msg.bytes, vec->msg.len);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Finalize without context
    err = SeosCryptoApi_digestFinalize(NULL, digHandle, digest, &digestSize);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Finalize without handle
    err = SeosCryptoApi_digestFinalize(ctx, NULL, digest, &digestSize);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);

    // Finalize without output buffer
    err = SeosCryptoApi_digestFinalize(ctx, digHandle, NULL, &digestSize);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Finalize without sufficient space
    digestSize = 4;
    err = SeosCryptoApi_digestFinalize(ctx, digHandle, digest, &digestSize);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);

    // Finalize twice
    digestSize = sizeof(digest);
    err = SeosCryptoApi_digestFinalize(ctx, digHandle, digest, &digestSize);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_digestFinalize(ctx, digHandle, digest, &digestSize);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_ABORTED == err, "err %d", err);

    err = SeosCryptoApi_digestFree(ctx, digHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testDigest_process_buffer(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_DigestHandle digHandle;
    static unsigned char inBuf[SeosCrypto_Size_DATAPORT + 1];
    size_t inLen;

    err = SeosCryptoApi_digestInit(ctx, &digHandle, SeosCryptoDigest_Algorithm_MD5);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Should go OK
    inLen = SeosCrypto_Size_DATAPORT;
    err = SeosCryptoApi_digestProcess(ctx, digHandle, inBuf, inLen);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Should fail due to internal buffers being limited
    inLen = SeosCrypto_Size_DATAPORT + 1;
    err = SeosCryptoApi_digestProcess(ctx, digHandle, inBuf, inLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INSUFFICIENT_SPACE == err, "err %d", err);

    err = SeosCryptoApi_digestFree(ctx, digHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testDigest_finalize_buffer(SeosCryptoCtx* ctx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_DigestHandle digHandle;
    static unsigned char inBuf[SeosCrypto_Size_DATAPORT],
           outBuf[SeosCrypto_Size_DATAPORT + 1];
    size_t inLen, outLen;

    err = SeosCryptoApi_digestInit(ctx, &digHandle, SeosCryptoDigest_Algorithm_MD5);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    inLen = SeosCrypto_Size_DATAPORT;
    err = SeosCryptoApi_digestProcess(ctx, digHandle, inBuf, inLen);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    // Should be OK, as we are below the dataport limit
    outLen = SeosCrypto_Size_DATAPORT;
    err = SeosCryptoApi_digestFinalize(ctx, digHandle, outBuf, &outLen);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_digestFree(ctx, digHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_digestInit(ctx, &digHandle, SeosCryptoDigest_Algorithm_MD5);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    inLen = SeosCrypto_Size_DATAPORT;
    err = SeosCryptoApi_digestProcess(ctx, digHandle, inBuf, inLen);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    // Should fail because out buffer is potentially too big
    outLen = SeosCrypto_Size_DATAPORT + 1;
    err = SeosCryptoApi_digestFinalize(ctx, digHandle, outBuf, &outLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INSUFFICIENT_SPACE == err, "err %d", err);
    err = SeosCryptoApi_digestFree(ctx, digHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_digestInit(ctx, &digHandle, SeosCryptoDigest_Algorithm_MD5);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    inLen = SeosCrypto_Size_DATAPORT;
    err = SeosCryptoApi_digestProcess(ctx, digHandle, inBuf, inLen);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    // This should fail but give us the expected buffer size
    outLen = 10;
    err = SeosCryptoApi_digestFinalize(ctx, digHandle, outBuf, &outLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);
    Debug_ASSERT(outLen == SeosCryptoDigest_Size_MD5);
    err = SeosCryptoApi_digestFree(ctx, digHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

void
testDigest(SeosCryptoCtx* ctx)
{
    testDigest_init_ok(ctx);
    testDigest_init_fail(ctx);

    testDigest_free_ok(ctx);
    testDigest_free_fail(ctx);

    testDigest_hash_SHA256(ctx);
    testDigest_hash_MD5(ctx);

    testDigest_clone_ok(ctx);
    testDigest_clone_fail(ctx);

    // Test only failures separately, as computing ref. values is sufficient
    // proof of correct funtioning
    testDigest_process_fail(ctx);
    testDigest_finalize_fail(ctx);

    testDigest_process_buffer(ctx);
    testDigest_finalize_buffer(ctx);
}