/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include "SeosCryptoApi.h"

#include "LibDebug/Debug.h"

#include <string.h>

/*
 * https://8gwifi.org/RSAFunctionality?rsasignverifyfunctions=rsasignverifyfunctions&keysize=512
 * https://superdry.apphb.com/tools/online-rsa-key-converter
 * https://cryptii.com/pipes/base64-to-hex
 *

   -----BEGIN PUBLIC KEY-----
   MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCSIqIbAWH/w93AT46R8cwf3A0q
   CGavDdkF6OfWUqA4YgoBjdE9Q0Bt/PfAohyHpUH+3stzKFu+0EuePlmvL1mSIojz
   AJJmjfyJmUQ4POQRQtKglczxqJfjcZ3BvohoJkIv4BBePvayqwqg54e9pHDfBM5n
   bEjT08Atsj+zDZywoQIDAQAB
   -----END PUBLIC KEY-----

   -----BEGIN RSA PRIVATE KEY-----
   MIICXAIBAAKBgQCSIqIbAWH/w93AT46R8cwf3A0qCGavDdkF6OfWUqA4YgoBjdE9
   Q0Bt/PfAohyHpUH+3stzKFu+0EuePlmvL1mSIojzAJJmjfyJmUQ4POQRQtKglczx
   qJfjcZ3BvohoJkIv4BBePvayqwqg54e9pHDfBM5nbEjT08Atsj+zDZywoQIDAQAB
   AoGANedMgEWcTmmDLGKsJi1YrA/RU0XSCpRDDykAC1BjBSk0o6oaGkzqQSfkg0vI
   1kgg9dBcn1etr87Jdc9t6W6/zNWxx5Bay9XooFs5qpqmPOX1yuBJY5C1O7CcNtpm
   WRSXdssoDg+oPKdigdsay43Rt8fsJbtL24AH9zyl8WEadJkCQQDdNRmUy+BFQ7gf
   Mvv+0VEqwKLbk4DewFSQ1eK90xf7mqXrETNJc8inEmmAWLQBWKuHOCGJC8UKBhBU
   YiD6vYijAkEAqR7CaxgLIypRYhIFUejnZs8z0duzUCfeHP7xuBzIKUsNpXUrLIMZ
 +HTo6jdVSOXGvHh0nbsXF3ZjuCnhjOPh6wJAK4ZKLUPcMeS8Mq9Wc/H9lXrn0Gp6
   fdm8Ce97uLvzSRdJtDHjNH2qqmzuA0nwyR8ISQfbWVrOf0VoKyJPuOZYHwJAC8Js
   yF+Snq5ZnFUec5SbSoXL16LMNB2hjyiXDDNMI7rpRwD/sIepLaKLc4XHc1su13oU
   uccBkwsTYgHfghlyYwJBALcysjB7G/LuNoGu7f/ZBB4aHHahhRROuURsowTUWoED
   O0cDVO8QxyqxkriQmgn84zfk1dSLhn6zLoVkOnyvY/k=
   -----END RSA PRIVATE KEY-----

 */

static const SeosCryptoApi_Key_Data rsaPrvData =
{
    .type = SeosCryptoApi_Key_TYPE_RSA_PRV,
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

static const SeosCryptoApi_Key_Data rsaPubData =
{
    .type = SeosCryptoApi_Key_TYPE_RSA_PUB,
    .data.rsa.pub =
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
    }
};
static const SeosCryptoApi_Key_Spec aes128Spec =
{
    .type = SeosCryptoApi_Key_SPECTYPE_BITS,
    .key = {
        .type = SeosCryptoApi_Key_TYPE_AES,
        .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
        .params.bits = 128
    }
};

// The following signature has been verified online and it is the one that we expect
// to be produced according to the current implementation of therandom number
// generator
static const char msgData[] = "test";
static const char expectedRsaSignature[] =
{
    0x89, 0x72, 0x26, 0x64, 0x53, 0x8b, 0x1e, 0xf1, 0xe3, 0x26, 0x47, 0xaa, 0xcb, 0xe0, 0x9d, 0x43,
    0xd7, 0x3a, 0xeb, 0xfb, 0x88, 0x04, 0x00, 0xa3, 0xd4, 0x39, 0xd8, 0xa6, 0xea, 0x53, 0xd3, 0x25,
    0xab, 0xc2, 0x9a, 0x02, 0x43, 0x47, 0x80, 0x7a, 0xcc, 0x15, 0x22, 0x0d, 0x25, 0x8b, 0x93, 0x33,
    0x82, 0x1d, 0x36, 0x55, 0xf1, 0xc1, 0xe6, 0x96, 0x69, 0x2a, 0xb2, 0x18, 0x1b, 0x84, 0x07, 0x9b,
    0x67, 0x69, 0x0a, 0x6b, 0x75, 0x5f, 0x24, 0x75, 0x12, 0x56, 0x03, 0x94, 0x9d, 0xd5, 0x09, 0x69,
    0x02, 0xe7, 0xd4, 0x76, 0xce, 0xe9, 0x31, 0xbd, 0x0b, 0x33, 0xda, 0x74, 0x2b, 0x17, 0xd2, 0x66,
    0x5c, 0xff, 0x05, 0x65, 0xd2, 0xf0, 0x78, 0xe8, 0xc3, 0x9b, 0x9c, 0xb5, 0x2e, 0x69, 0xaf, 0x3f,
    0x6c, 0x6a, 0x03, 0x4d, 0xca, 0x5c, 0x58, 0x54, 0x08, 0x42, 0x6b, 0xa2, 0x76, 0x3d, 0x44, 0x54
};

static void
testSignature_sign_RSA_ok(SeosCryptoApi_Context* ctx)
{
    SeosCryptoApi_Key prvKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;
    char signature[256];
    size_t signatureSize = sizeof(signature);

    err = SeosCryptoApi_Key_import(ctx, &prvKey, NULL, &rsaPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // For signing we only need a private key
    err = SeosCryptoApi_Signature_init(ctx, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &prvKey, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_Signature_sign(&obj, msgData, strlen(msgData),
                                       signature, &signatureSize);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(!memcmp(expectedRsaSignature, signature,
                         sizeof(expectedRsaSignature)));

    err = SeosCryptoApi_Signature_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testSignature_sign_fail(SeosCryptoApi_Context* ctx)
{
    SeosCryptoApi_Key prvKey, pubKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;
    char signature[256];
    size_t signatureSize = sizeof(signature);

    err = SeosCryptoApi_Key_import(ctx, &prvKey, NULL, &rsaPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_import(ctx, &pubKey, NULL, &rsaPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_Signature_init(ctx, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &prvKey, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Use empty context
    err = SeosCryptoApi_Signature_sign(NULL, msgData, strlen(msgData),
                                       signature, &signatureSize);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Use empty data
    err = SeosCryptoApi_Signature_sign(&obj, NULL, strlen(msgData), signature,
                                       &signatureSize);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Use zero length data
    err = SeosCryptoApi_Signature_sign(&obj, msgData, 0, signature, &signatureSize);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Use NULL output buffer
    err = SeosCryptoApi_Signature_sign(&obj, msgData, strlen(msgData), NULL,
                                       &signatureSize);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Use NULL output size buffer
    err = SeosCryptoApi_Signature_sign(&obj, msgData, strlen(msgData), signature,
                                       NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Use too small output buffer
    signatureSize = 10;
    err = SeosCryptoApi_Signature_sign(&obj, msgData, strlen(msgData), signature,
                                       &signatureSize);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);

    err = SeosCryptoApi_Signature_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Try signing with only a public key
    err = SeosCryptoApi_Signature_init(ctx, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       NULL, &pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Signature_sign(&obj, msgData, strlen(msgData),
                                       signature, &signatureSize);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_ABORTED == err, "err %d", err);
    err = SeosCryptoApi_Signature_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testSignature_verify_RSA_ok(SeosCryptoApi_Context* ctx)
{
    SeosCryptoApi_Key pubKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;

    err = SeosCryptoApi_Key_import(ctx, &pubKey, NULL, &rsaPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // For signing we only need a public key
    err = SeosCryptoApi_Signature_init(ctx, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       NULL, &pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_Signature_verify(&obj, msgData, strlen(msgData),
                                         expectedRsaSignature, sizeof(expectedRsaSignature));
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_Signature_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testSignature_verify_fail(SeosCryptoApi_Context* ctx)
{
    SeosCryptoApi_Key pubKey, prvKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;

    err = SeosCryptoApi_Key_import(ctx, &prvKey, NULL, &rsaPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_import(ctx, &pubKey, NULL, &rsaPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Signature_init(ctx, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       NULL, &pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Use empty context
    err = SeosCryptoApi_Signature_verify(NULL, msgData, strlen(msgData),
                                         expectedRsaSignature, sizeof(expectedRsaSignature));
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Use empty msg buffer
    err = SeosCryptoApi_Signature_verify(&obj, NULL, strlen(msgData),
                                         expectedRsaSignature, sizeof(expectedRsaSignature));
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Use zero lenght input
    err = SeosCryptoApi_Signature_verify(&obj, msgData, 0,
                                         expectedRsaSignature, sizeof(expectedRsaSignature));
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Use empty signature buffer
    err = SeosCryptoApi_Signature_verify(&obj, msgData, strlen(msgData),
                                         NULL, sizeof(expectedRsaSignature));
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Use zero length signature
    err = SeosCryptoApi_Signature_verify(&obj, msgData, strlen(msgData),
                                         expectedRsaSignature, 0);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    err = SeosCryptoApi_Signature_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Try verification if we have only private key
    err = SeosCryptoApi_Signature_init(ctx, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &prvKey, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Signature_verify(&obj, msgData, strlen(msgData),
                                         expectedRsaSignature, sizeof(expectedRsaSignature));
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_ABORTED == err, "err %d", err);
    err = SeosCryptoApi_Signature_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testSignature_init_ok(SeosCryptoApi_Context* ctx)
{
    SeosCryptoApi_Key pubKey, prvKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;

    err = SeosCryptoApi_Key_import(ctx, &prvKey, NULL, &rsaPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_import(ctx, &pubKey, NULL, &rsaPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Init just with prv key
    err = SeosCryptoApi_Signature_init(ctx, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &prvKey, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Signature_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Init just with prv key
    err = SeosCryptoApi_Signature_init(ctx, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       NULL, &pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Signature_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Use both keys
    err = SeosCryptoApi_Signature_init(ctx, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &prvKey, &pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Signature_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testSignature_init_fail(SeosCryptoApi_Context* ctx)
{
    SeosCryptoApi_Key key, prvKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;

    err = SeosCryptoApi_Key_generate(ctx, &key, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_import(ctx, &prvKey, NULL, &rsaPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Use empty context
    err = SeosCryptoApi_Signature_init(NULL, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &prvKey, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Use empty sig handle
    err = SeosCryptoApi_Signature_init(ctx, NULL,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &prvKey, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Use wrong algorithm
    err = SeosCryptoApi_Signature_init(ctx, &obj, 666,
                                       SeosCryptoApi_Digest_ALG_NONE, &prvKey, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Use wrong digest algorithm
    err = SeosCryptoApi_Signature_init(ctx, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15, 666, &prvKey, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Use wrong type of key for prv
    err = SeosCryptoApi_Signature_init(ctx, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &key, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Use wrong type of key for prv
    err = SeosCryptoApi_Signature_init(ctx, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       NULL, &key);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Use no keys
    err = SeosCryptoApi_Signature_init(ctx, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       NULL, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testSignature_free_ok(SeosCryptoApi_Context* ctx)
{
    SeosCryptoApi_Key pubKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;

    err = SeosCryptoApi_Key_import(ctx, &pubKey, NULL, &rsaPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_Signature_init(ctx, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       NULL, &pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Signature_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testSignature_free_fail(SeosCryptoApi_Context* ctx)
{
    SeosCryptoApi_Key pubKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;

    err = SeosCryptoApi_Key_import(ctx, &pubKey, NULL, &rsaPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Signature_init(ctx, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       NULL, &pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Empty context
    err = SeosCryptoApi_Signature_free(NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    err = SeosCryptoApi_Signature_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testSignature_sign_buffer(SeosCryptoApi_Context* ctx)
{
    SeosCryptoApi_Key prvKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;
    static unsigned int hashBuf[SeosCryptoApi_SIZE_DATAPORT + 1],
           sigBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    size_t hashLen, sigLen;

    err = SeosCryptoApi_Key_import(ctx, &prvKey, NULL, &rsaPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Signature_init(ctx, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &prvKey, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Should go through but then return ABORTED because crypto fails
    hashLen = SeosCryptoApi_SIZE_DATAPORT;
    sigLen = SeosCryptoApi_SIZE_DATAPORT;
    err = SeosCryptoApi_Signature_sign(&obj, hashBuf, hashLen, sigBuf,
                                       &sigLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_ABORTED == err, "err %d", err);

    // Should fail because input is too long
    hashLen = SeosCryptoApi_SIZE_DATAPORT + 1;
    sigLen = SeosCryptoApi_SIZE_DATAPORT;
    err = SeosCryptoApi_Signature_sign(&obj, hashBuf, hashLen, sigBuf,
                                       &sigLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INSUFFICIENT_SPACE == err, "err %d", err);

    // Should fail because output is too long
    hashLen = SeosCryptoApi_SIZE_DATAPORT;
    sigLen = SeosCryptoApi_SIZE_DATAPORT + 1;
    err = SeosCryptoApi_Signature_sign(&obj, hashBuf, hashLen, sigBuf,
                                       &sigLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INSUFFICIENT_SPACE == err, "err %d", err);

    // Should fail but give us the required output size which is the size of the
    // modulus of the private key, e.g., |N| = |P| + |Q|
    hashLen = SeosCryptoApi_Digest_SIZE_MD5;
    sigLen = 10;
    err = SeosCryptoApi_Signature_sign(&obj, hashBuf, hashLen, sigBuf,
                                       &sigLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);
    Debug_ASSERT(sigLen == (rsaPrvData.data.rsa.prv.pLen +
                            rsaPrvData.data.rsa.prv.qLen));

    err = SeosCryptoApi_Signature_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_Key_import(ctx, &prvKey, NULL, &rsaPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Signature_init(ctx, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &prvKey, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    // Sign with input/output buffer being the same
    memcpy(hashBuf, msgData, strlen(msgData));
    hashLen = strlen(msgData);
    sigLen = SeosCryptoApi_SIZE_DATAPORT;
    err = SeosCryptoApi_Signature_sign(&obj,
                                       hashBuf, hashLen,
                                       hashBuf, &sigLen);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(sigLen == sizeof(expectedRsaSignature));
    Debug_ASSERT(!memcmp(expectedRsaSignature, hashBuf, sigLen));
    err = SeosCryptoApi_Signature_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testSignature_verify_buffer(SeosCryptoApi_Context* ctx)
{
    SeosCryptoApi_Key pubKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;
    static unsigned int hashBuf[SeosCryptoApi_SIZE_DATAPORT + 1],
           sigBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    size_t hashLen, sigLen;

    err = SeosCryptoApi_Key_import(ctx, &pubKey, NULL, &rsaPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Signature_init(ctx, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       NULL, &pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Should go through but fail with ABORTED because crypto fails
    sigLen = (rsaPrvData.data.rsa.prv.pLen + rsaPrvData.data.rsa.prv.qLen);
    hashLen = SeosCryptoApi_SIZE_DATAPORT - sigLen;
    err = SeosCryptoApi_Signature_verify(&obj, hashBuf, hashLen, sigBuf,
                                         sigLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_ABORTED == err, "err %d", err);

    // Should fail because the total of both is too big for internal buffer
    hashLen = 16;
    sigLen = SeosCryptoApi_SIZE_DATAPORT;
    err = SeosCryptoApi_Signature_verify(&obj, hashBuf, hashLen, sigBuf,
                                         sigLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INSUFFICIENT_SPACE == err, "err %d", err);

    err = SeosCryptoApi_Signature_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

void
testSignature(SeosCryptoApi_Context* ctx)
{
    testSignature_init_ok(ctx);
    testSignature_init_fail(ctx);

    testSignature_free_ok(ctx);
    testSignature_free_fail(ctx);

    testSignature_sign_RSA_ok(ctx);
    testSignature_sign_fail(ctx);

    testSignature_verify_RSA_ok(ctx);
    testSignature_verify_fail(ctx);

    testSignature_sign_buffer(ctx);
    testSignature_verify_buffer(ctx);
}
