/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoApi.h"

#include "SharedKeys.h"
#include "ObjectLocation.h"

#include "LibDebug/Debug.h"

#include <string.h>

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

static bool allowExport;
#define Debug_ASSERT_LOCATION(api, o) \
    Debug_ASSERT_OBJ_LOCATION(api, allowExport, o.signature)

static void
TestSignature_sign_RSA_ok(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key prvKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;
    char signature[256];
    size_t signatureSize = sizeof(signature);

    err = SeosCryptoApi_Key_import(api, &prvKey, &rsa1024PrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // For signing we only need a private key
    err = SeosCryptoApi_Signature_init(api, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &prvKey, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_LOCATION(api, obj);

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
TestSignature_sign_fail(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key prvKey, pubKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;
    char signature[256];
    size_t signatureSize = sizeof(signature);

    err = SeosCryptoApi_Key_import(api, &prvKey, &rsa1024PrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_import(api, &pubKey, &rsa1024PubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_Signature_init(api, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &prvKey, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_LOCATION(api, obj);

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
    err = SeosCryptoApi_Signature_init(api, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       NULL, &pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_LOCATION(api, obj);
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
TestSignature_verify_RSA_ok(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;

    err = SeosCryptoApi_Key_import(api, &pubKey, &rsa1024PubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // For signing we only need a public key
    err = SeosCryptoApi_Signature_init(api, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       NULL, &pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_LOCATION(api, obj);

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
TestSignature_verify_fail(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey, prvKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;

    err = SeosCryptoApi_Key_import(api, &prvKey, &rsa1024PrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_import(api, &pubKey, &rsa1024PubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Signature_init(api, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       NULL, &pubKey);
    Debug_ASSERT_LOCATION(api, obj);
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
    err = SeosCryptoApi_Signature_init(api, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &prvKey, NULL);
    Debug_ASSERT_LOCATION(api, obj);
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
TestSignature_init_ok(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey, prvKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;

    err = SeosCryptoApi_Key_import(api, &prvKey, &rsa1024PrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_import(api, &pubKey, &rsa1024PubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Init just with prv key
    err = SeosCryptoApi_Signature_init(api, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &prvKey, NULL);
    Debug_ASSERT_LOCATION(api, obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Signature_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Init just with prv key
    err = SeosCryptoApi_Signature_init(api, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       NULL, &pubKey);
    Debug_ASSERT_LOCATION(api, obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Signature_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Use both keys
    err = SeosCryptoApi_Signature_init(api, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &prvKey, &pubKey);
    Debug_ASSERT_LOCATION(api, obj);
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
TestSignature_init_fail(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key key, prvKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;

    err = SeosCryptoApi_Key_generate(api, &key, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_import(api, &prvKey, &rsa1024PrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Use empty context
    err = SeosCryptoApi_Signature_init(NULL, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &prvKey, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Use empty sig handle
    err = SeosCryptoApi_Signature_init(api, NULL,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &prvKey, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Use wrong algorithm
    err = SeosCryptoApi_Signature_init(api, &obj, 666,
                                       SeosCryptoApi_Digest_ALG_NONE, &prvKey, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Use wrong digest algorithm
    err = SeosCryptoApi_Signature_init(api, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15, 666, &prvKey, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Use wrong type of key for prv
    err = SeosCryptoApi_Signature_init(api, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &key, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Use wrong type of key for prv
    err = SeosCryptoApi_Signature_init(api, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       NULL, &key);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Use no keys
    err = SeosCryptoApi_Signature_init(api, &obj,
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
TestSignature_free_ok(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;

    err = SeosCryptoApi_Key_import(api, &pubKey, &rsa1024PubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_Signature_init(api, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       NULL, &pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_LOCATION(api, obj);
    err = SeosCryptoApi_Signature_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
TestSignature_free_fail(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;

    err = SeosCryptoApi_Key_import(api, &pubKey, &rsa1024PubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Signature_init(api, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       NULL, &pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_LOCATION(api, obj);

    // Empty context
    err = SeosCryptoApi_Signature_free(NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    err = SeosCryptoApi_Signature_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
TestSignature_sign_buffer(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key prvKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;
    static unsigned int hashBuf[SeosCryptoApi_SIZE_DATAPORT + 1],
           sigBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    size_t hashLen, sigLen;

    err = SeosCryptoApi_Key_import(api, &prvKey, &rsa1024PrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Signature_init(api, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &prvKey, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_LOCATION(api, obj);

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
    Debug_ASSERT(sigLen == (rsa1024PrvData.data.rsa.prv.pLen +
                            rsa1024PrvData.data.rsa.prv.qLen));

    err = SeosCryptoApi_Signature_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_Key_import(api, &prvKey, &rsa1024PrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Signature_init(api, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &prvKey, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_LOCATION(api, obj);
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
TestSignature_verify_buffer(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;
    static unsigned int hashBuf[SeosCryptoApi_SIZE_DATAPORT + 1],
           sigBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    size_t hashLen, sigLen;

    err = SeosCryptoApi_Key_import(api, &pubKey, &rsa1024PubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Signature_init(api, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       NULL, &pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_LOCATION(api, obj);

    // Should go through but fail with ABORTED because crypto fails
    sigLen = (rsa1024PrvData.data.rsa.prv.pLen + rsa1024PrvData.data.rsa.prv.qLen);
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

static void
TestSignature_key_fail(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey, prvKey;
    SeosCryptoApi_Signature obj;
    seos_err_t err = SEOS_ERROR_GENERIC;

    // Test with both keys having different exportable attributes
    rsa1024PrvData.attribs.exportable = false;
    rsa1024PubData.attribs.exportable = true;

    err = SeosCryptoApi_Key_import(api, &prvKey, &rsa1024PrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_import(api, &pubKey, &rsa1024PubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Should fail due to different key localities
    err = SeosCryptoApi_Signature_init(api, &obj,
                                       SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                       SeosCryptoApi_Digest_ALG_NONE,
                                       &prvKey, &pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

void
TestSignature_testAll(
    SeosCryptoApi* api)
{
    allowExport = true;
    keyData_setExportable(keyDataList, allowExport);
    keySpec_setExportable(keySpecList, allowExport);

    TestSignature_init_ok(api);
    TestSignature_init_fail(api);

    TestSignature_free_ok(api);
    TestSignature_free_fail(api);

    TestSignature_sign_RSA_ok(api);
    TestSignature_sign_fail(api);

    TestSignature_verify_RSA_ok(api);
    TestSignature_verify_fail(api);

    TestSignature_sign_buffer(api);
    TestSignature_verify_buffer(api);

    // Make all used keys NON-EXPORTABLE and re-run parts of the tests
    if (api->mode == SeosCryptoApi_Mode_ROUTER)
    {
        allowExport = false;
        keyData_setExportable(keyDataList, allowExport);
        keySpec_setExportable(keySpecList, allowExport);

        TestSignature_sign_RSA_ok(api);
        TestSignature_verify_RSA_ok(api);

        TestSignature_key_fail(api);
    }
}