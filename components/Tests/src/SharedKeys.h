/**
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#pragma once

#include "OS_Crypto.h"
#include "lib_compiler/compiler.h"

/*
 * This header defines all the key data/spec we use for the tests in one place.
 * However, not all tests use all keys, so the compiler will complain. In order
 * to avoid this, temporarily ignore the relevant warning parameter..
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"

static OS_CryptoKey_Data_t dh101PrvData =
{
    .type = OS_CryptoKey_TYPE_DH_PRV,
    .attribs.keepLocal = true,
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
static OS_CryptoKey_Data_t dh101PubData =
{
    .type = OS_CryptoKey_TYPE_DH_PUB,
    .attribs.keepLocal = true,
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
static OS_CryptoKey_Data_t rsa1024PrvData =
{
    .type = OS_CryptoKey_TYPE_RSA_PRV,
    .attribs.keepLocal = true,
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
static OS_CryptoKey_Data_t rsa1024PubData =
{
    .type = OS_CryptoKey_TYPE_RSA_PUB,
    .attribs.keepLocal = true,
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
static OS_CryptoKey_Data_t rsaSmallData =
{
    .type = OS_CryptoKey_TYPE_RSA_PRV,
    .attribs.keepLocal = true,
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
static OS_CryptoKey_Data_t rsaLargeData =
{
    .type = OS_CryptoKey_TYPE_RSA_PRV,
    .attribs.keepLocal = true,
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
static OS_CryptoKey_Data_t secp256r1PrvData =
{
    .type = OS_CryptoKey_TYPE_SECP256R1_PRV,
    .attribs.keepLocal = true,
    .data.secp256r1.prv = {
        .dBytes = {
            0xc6, 0xef, 0x9c, 0x5d, 0x78, 0xae, 0x01, 0x2a, 0x01, 0x11, 0x64, 0xac, 0xb3, 0x97, 0xce, 0x20,
            0x88, 0x68, 0x5d, 0x8f, 0x06, 0xbf, 0x9b, 0xe0, 0xb2, 0x83, 0xab, 0x46, 0x47, 0x6b, 0xee, 0x53
        },
        .dLen   = 32,
    }
};
static OS_CryptoKey_Data_t secp256r1PubData =
{
    .type = OS_CryptoKey_TYPE_SECP256R1_PUB,
    .attribs.keepLocal = true,
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
static OS_CryptoKey_Data_t aes128Data =
{
    .type = OS_CryptoKey_TYPE_AES,
    .attribs.keepLocal = true,
    .data.aes = {
        .bytes = "0123456789abcdef",
        .len = 16
    }
};
static OS_CryptoKey_Data_t aes192Data =
{
    .type = OS_CryptoKey_TYPE_AES,
    .attribs.keepLocal = true,
    .data.aes = {
        .bytes = "0123456789abcdef01234567",
        .len = 24
    }
};
static OS_CryptoKey_Data_t aes256Data =
{
    .type = OS_CryptoKey_TYPE_AES,
    .attribs.keepLocal = true,
    .data.aes = {
        .bytes = "0123456789abcdef0123456789abcdef",
        .len = 32
    }
};
static OS_CryptoKey_Data_t aes120Data =
{
    .type = OS_CryptoKey_TYPE_AES,
    .attribs.keepLocal = true,
    .data.aes = {
        .bytes = "0123456789abcde",
        .len = 15
    }
};
static OS_CryptoKey_Data_t macData =
{
    .type = OS_CryptoKey_TYPE_MAC,
    .attribs.keepLocal = true,
    .data.mac = {
        .bytes = "0123456789abcde",
        .len = 15
    }
};

static OS_CryptoKey_Data_t* keyDataList[] =
{
    &macData,
    &aes120Data,
    &aes256Data,
    &aes192Data,
    &aes128Data,
    &secp256r1PubData,
    &secp256r1PrvData,
    &rsaLargeData,
    &rsaSmallData,
    &rsa1024PubData,
    &rsa1024PrvData,
    &dh101PubData,
    &dh101PrvData,
    NULL
};

// -----------------------------------------------------------------------------

static OS_CryptoKey_Spec_t aes128Spec =
{
    .type = OS_CryptoKey_SPECTYPE_BITS,
    .key = {
        .type = OS_CryptoKey_TYPE_AES,
        .attribs.keepLocal = true,
        .params.bits = 128
    }
};
static OS_CryptoKey_Spec_t aes192Spec =
{
    .type = OS_CryptoKey_SPECTYPE_BITS,
    .key = {
        .type = OS_CryptoKey_TYPE_AES,
        .attribs.keepLocal = true,
        .params.bits = 192
    }
};
static OS_CryptoKey_Spec_t aes256Spec =
{
    .type = OS_CryptoKey_SPECTYPE_BITS,
    .key = {
        .type = OS_CryptoKey_TYPE_AES,
        .attribs.keepLocal = true,
        .params.bits = 256
    }
};
static OS_CryptoKey_Spec_t aes120Spec =
{
    .type = OS_CryptoKey_SPECTYPE_BITS,
    .key = {
        .type = OS_CryptoKey_TYPE_AES,
        .attribs.keepLocal = true,
        .params.bits = 120
    }
};
static OS_CryptoKey_Spec_t macSpec =
{
    .type = OS_CryptoKey_SPECTYPE_BITS,
    .key = {
        .type = OS_CryptoKey_TYPE_MAC,
        .attribs.keepLocal = true,
        .params.bits = 4096
    }
};
static OS_CryptoKey_Spec_t dh64bSpec =
{
    .type = OS_CryptoKey_SPECTYPE_BITS,
    .key = {
        .type = OS_CryptoKey_TYPE_DH_PRV,
        .attribs.keepLocal = true,
        .params.bits = 64
    }
};
static OS_CryptoKey_Spec_t dh101pSpec =
{
    .type = OS_CryptoKey_SPECTYPE_PARAMS,
    .key = {
        .type = OS_CryptoKey_TYPE_DH_PRV,
        .attribs.keepLocal = true,
        .params.dh = {
            .pBytes = {0x12, 0xdf, 0x4d, 0x76, 0x89, 0xdf, 0xf4, 0xc9, 0x9d, 0x9a, 0xe5, 0x7d, 0x07},
            .pLen   = 13,
            .gBytes = {0x00, 0x1e, 0x32, 0x15, 0x8a, 0x35, 0xe3, 0x4d, 0x7b, 0x61, 0x96, 0x57, 0xd6},
            .gLen   = 13,
        }
    }
};
static OS_CryptoKey_Spec_t dh63bSpec =
{
    .type = OS_CryptoKey_SPECTYPE_BITS,
    .key = {
        .type = OS_CryptoKey_TYPE_DH_PRV,
        .attribs.keepLocal = true,
        .params.bits = 63
    }
};
static OS_CryptoKey_Spec_t dh64pSpec =
{
    .type = OS_CryptoKey_SPECTYPE_PARAMS,
    .key = {
        .attribs.keepLocal = true,
        .type = OS_CryptoKey_TYPE_DH_PRV,
    }
};
static OS_CryptoKey_Spec_t rsa128Spec =
{
    .type = OS_CryptoKey_SPECTYPE_BITS,
    .key = {
        .type = OS_CryptoKey_TYPE_RSA_PRV,
        .attribs.keepLocal = true,
        .params.bits = 128
    }
};
static OS_CryptoKey_Spec_t secp256r1Spec =
{
    .type = OS_CryptoKey_SPECTYPE_BITS,
    .key = {
        .type = OS_CryptoKey_TYPE_SECP256R1_PRV,
        .attribs.keepLocal = true,
    }
};
static OS_CryptoKey_Spec_t rsa127Spec =
{
    .type = OS_CryptoKey_SPECTYPE_BITS,
    .key = {
        .type = OS_CryptoKey_TYPE_RSA_PRV,
        .attribs.keepLocal = true,
        .params.bits = 127
    }
};

static OS_CryptoKey_Spec_t* keySpecList[] =
{
    &aes128Spec,
    &aes192Spec,
    &aes256Spec,
    &aes120Spec,
    &macSpec,
    &dh64bSpec,
    &dh64pSpec,
    &dh101pSpec,
    &dh63bSpec,
    &rsa128Spec,
    &secp256r1Spec,
    &rsa127Spec,
    NULL
};

#pragma GCC diagnostic pop

INLINE void
keyData_setLocality(
    OS_CryptoKey_Data_t* dataList[],
    bool                 keepLocal)
{
    OS_CryptoKey_Data_t* pData;
    size_t i;

    i = 0;
    while ((pData = dataList[i++]) != NULL)
    {
        pData->attribs.keepLocal = keepLocal;
    }
}

INLINE void
keySpec_setLocality(
    OS_CryptoKey_Spec_t* specList[],
    bool                 keepLocal)
{
    OS_CryptoKey_Spec_t* pSpec;
    size_t i;

    i = 0;
    while ((pSpec = specList[i++]) != NULL)
    {
        pSpec->key.attribs.keepLocal = keepLocal;
    }
}