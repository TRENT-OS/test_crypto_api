/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoApi.h"

#include "SharedKeys.h"
#include "ObjectLocation.h"
#include "TestMacros.h"

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
#define TEST_LOCATION(api, o) \
    Debug_ASSERT_OBJ_LOCATION(api, allowExport, o.signature)

static void
test_SeosCryptoApi_Signature_do_RSA_PKCS1_V15_sign(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key prvKey;
    SeosCryptoApi_Signature obj;
    char signature[256];
    size_t signatureSize = sizeof(signature);

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &prvKey, &rsa1024PrvData));

    // For signing we only need a private key
    TEST_SUCCESS(SeosCryptoApi_Signature_init(api, &obj,
                                              SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                              SeosCryptoApi_Digest_ALG_NONE,
                                              &prvKey, NULL));
    TEST_LOCATION(api, obj);

    TEST_SUCCESS(SeosCryptoApi_Signature_sign(&obj, msgData, strlen(msgData),
                                              signature, &signatureSize));
    TEST_TRUE(!memcmp(expectedRsaSignature, signature,
                         sizeof(expectedRsaSignature)));

    TEST_SUCCESS(SeosCryptoApi_Signature_free(&obj));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&prvKey));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Signature_sign_neg(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key prvKey, pubKey;
    SeosCryptoApi_Signature obj;
    char signature[256];
    size_t signatureSize = sizeof(signature);

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &prvKey, &rsa1024PrvData));
    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &pubKey, &rsa1024PubData));

    TEST_SUCCESS(SeosCryptoApi_Signature_init(api, &obj,
                                              SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                              SeosCryptoApi_Digest_ALG_NONE,
                                              &prvKey, NULL));
    TEST_LOCATION(api, obj);

    // Use empty context
    TEST_INVAL_PARAM(SeosCryptoApi_Signature_sign(NULL, msgData, strlen(msgData),
                                                  signature, &signatureSize));

    // Use empty data
    TEST_INVAL_PARAM(SeosCryptoApi_Signature_sign(&obj, NULL, strlen(msgData),
                                                  signature, &signatureSize));

    // Use zero length data
    TEST_INVAL_PARAM(SeosCryptoApi_Signature_sign(&obj, msgData, 0, signature,
                                                  &signatureSize));

    // Use NULL output buffer
    TEST_INVAL_PARAM(SeosCryptoApi_Signature_sign(&obj, msgData, strlen(msgData),
                                                  NULL, &signatureSize));

    // Use NULL output size buffer
    TEST_INVAL_PARAM(SeosCryptoApi_Signature_sign(&obj, msgData, strlen(msgData),
                                                  signature, NULL));

    // Use too small output buffer
    signatureSize = 10;
    TEST_TOO_SMALL(SeosCryptoApi_Signature_sign(&obj, msgData, strlen(msgData),
                                                signature, &signatureSize));

    TEST_SUCCESS(SeosCryptoApi_Signature_free(&obj));

    // Try signing with only a public key
    TEST_SUCCESS(SeosCryptoApi_Signature_init(api, &obj,
                                              SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                              SeosCryptoApi_Digest_ALG_NONE, NULL,
                                              &pubKey));
    TEST_LOCATION(api, obj);
    TEST_ABORTED(SeosCryptoApi_Signature_sign(&obj, msgData, strlen(msgData),
                                              signature, &signatureSize));

    TEST_SUCCESS(SeosCryptoApi_Signature_free(&obj));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&prvKey));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&pubKey));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Signature_do_RSA_PKCS1_V15_verify(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey;
    SeosCryptoApi_Signature obj;

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &pubKey, &rsa1024PubData));

    // For signing we only need a public key
    TEST_SUCCESS(SeosCryptoApi_Signature_init(api, &obj,
                                              SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                              SeosCryptoApi_Digest_ALG_NONE, NULL,
                                              &pubKey));
    TEST_LOCATION(api, obj);
    TEST_SUCCESS(SeosCryptoApi_Signature_verify(&obj, msgData, strlen(msgData),
                                                expectedRsaSignature, sizeof(expectedRsaSignature)));

    TEST_SUCCESS(SeosCryptoApi_Signature_free(&obj));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&pubKey));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Signature_verify_neg(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey, prvKey;
    SeosCryptoApi_Signature obj;

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &prvKey, &rsa1024PrvData));
    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &pubKey, &rsa1024PubData));
    TEST_SUCCESS(SeosCryptoApi_Signature_init(api, &obj,
                                              SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                              SeosCryptoApi_Digest_ALG_NONE, NULL,
                                              &pubKey));
    TEST_LOCATION(api, obj)

    // Use empty context
    TEST_INVAL_PARAM(SeosCryptoApi_Signature_verify(NULL, msgData, strlen(msgData),
                                                    expectedRsaSignature, sizeof(expectedRsaSignature)));

    // Use empty msg buffer
    TEST_INVAL_PARAM(SeosCryptoApi_Signature_verify(&obj, NULL, strlen(msgData),
                                                    expectedRsaSignature, sizeof(expectedRsaSignature)));

    // Use zero lenght input
    TEST_INVAL_PARAM(SeosCryptoApi_Signature_verify(&obj, msgData, 0,
                                                    expectedRsaSignature, sizeof(expectedRsaSignature)));

    // Use empty signature buffer
    TEST_INVAL_PARAM(SeosCryptoApi_Signature_verify(&obj, msgData, strlen(msgData),
                                                    NULL, sizeof(expectedRsaSignature)));

    // Use zero length signature
    TEST_INVAL_PARAM(SeosCryptoApi_Signature_verify(&obj, msgData, strlen(msgData),
                                                    expectedRsaSignature, 0));

    TEST_SUCCESS(SeosCryptoApi_Signature_free(&obj));

    // Try verification if we have only private key
    TEST_SUCCESS(SeosCryptoApi_Signature_init(api, &obj,
                                              SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                              SeosCryptoApi_Digest_ALG_NONE,
                                              &prvKey, NULL));
    TEST_LOCATION(api, obj)
    TEST_ABORTED(SeosCryptoApi_Signature_verify(&obj, msgData, strlen(msgData),
                                                expectedRsaSignature, sizeof(expectedRsaSignature)));
    TEST_SUCCESS(SeosCryptoApi_Signature_free(&obj));

    TEST_SUCCESS(SeosCryptoApi_Key_free(&pubKey));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&prvKey));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Signature_init_pos(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey, prvKey;
    SeosCryptoApi_Signature obj;

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &prvKey, &rsa1024PrvData));
    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &pubKey, &rsa1024PubData));

    // Init just with prv key
    TEST_SUCCESS(SeosCryptoApi_Signature_init(api, &obj,
                                              SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                              SeosCryptoApi_Digest_ALG_NONE,
                                              &prvKey, NULL));
    TEST_LOCATION(api, obj)
    TEST_SUCCESS(SeosCryptoApi_Signature_free(&obj));

    // Init just with prv key
    TEST_SUCCESS(SeosCryptoApi_Signature_init(api, &obj,
                                              SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                              SeosCryptoApi_Digest_ALG_NONE, NULL,
                                              &pubKey));
    TEST_LOCATION(api, obj)
    TEST_SUCCESS(SeosCryptoApi_Signature_free(&obj));

    // Use both keys
    TEST_SUCCESS(SeosCryptoApi_Signature_init(api, &obj,
                                              SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                              SeosCryptoApi_Digest_ALG_NONE,
                                              &prvKey, &pubKey));
    TEST_LOCATION(api, obj)
    TEST_SUCCESS(SeosCryptoApi_Signature_free(&obj));

    TEST_SUCCESS(SeosCryptoApi_Key_free(&pubKey));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&prvKey));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Signature_init_neg(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key key, prvKey;
    SeosCryptoApi_Signature obj;

    TEST_SUCCESS(SeosCryptoApi_Key_generate(api, &key, &aes128Spec));
    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &prvKey, &rsa1024PrvData));

    // Use empty context
    TEST_INVAL_PARAM(SeosCryptoApi_Signature_init(NULL, &obj,
                                                  SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                                  SeosCryptoApi_Digest_ALG_NONE,
                                                  &prvKey, NULL));

    // Use empty sig handle
    TEST_INVAL_PARAM(SeosCryptoApi_Signature_init(api, NULL,
                                                  SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                                  SeosCryptoApi_Digest_ALG_NONE,
                                                  &prvKey, NULL));

    // Use wrong algorithm
    TEST_NOT_SUPP(SeosCryptoApi_Signature_init(api, &obj, 666,
                                               SeosCryptoApi_Digest_ALG_NONE, &prvKey, NULL));

    // Use wrong digest algorithm
    TEST_NOT_SUPP(SeosCryptoApi_Signature_init(api, &obj,
                                               SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                               666, &prvKey, NULL));

    // Use wrong type of key for prv
    TEST_INVAL_PARAM(SeosCryptoApi_Signature_init(api, &obj,
                                                  SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                                  SeosCryptoApi_Digest_ALG_NONE, &key,
                                                  NULL));

    // Use wrong type of key for prv
    TEST_INVAL_PARAM(SeosCryptoApi_Signature_init(api, &obj,
                                                  SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                                  SeosCryptoApi_Digest_ALG_NONE, NULL,
                                                  &key));

    // Use no keys
    TEST_INVAL_PARAM(SeosCryptoApi_Signature_init(api, &obj,
                                                  SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                                  SeosCryptoApi_Digest_ALG_NONE, NULL,
                                                  NULL));

    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&prvKey));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Signature_free_pos(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey;
    SeosCryptoApi_Signature obj;

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &pubKey, &rsa1024PubData));

    TEST_SUCCESS(SeosCryptoApi_Signature_init(api, &obj,
                                              SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                              SeosCryptoApi_Digest_ALG_NONE, NULL,
                                              &pubKey));
    TEST_LOCATION(api, obj);
    TEST_SUCCESS(SeosCryptoApi_Signature_free(&obj));

    TEST_SUCCESS(SeosCryptoApi_Key_free(&pubKey));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Signature_free_neg(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey;
    SeosCryptoApi_Signature obj;

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &pubKey, &rsa1024PubData));
    TEST_SUCCESS(SeosCryptoApi_Signature_init(api, &obj,
                                              SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                              SeosCryptoApi_Digest_ALG_NONE, NULL,
                                              &pubKey));
    TEST_LOCATION(api, obj);

    // Empty context
    TEST_INVAL_PARAM(SeosCryptoApi_Signature_free(NULL));

    TEST_SUCCESS(SeosCryptoApi_Signature_free(&obj));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Signature_sign_buffer(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key prvKey;
    SeosCryptoApi_Signature obj;
    static unsigned int hashBuf[SeosCryptoApi_SIZE_DATAPORT + 1],
           sigBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    size_t hashLen, sigLen;

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &prvKey, &rsa1024PrvData));
    TEST_SUCCESS(SeosCryptoApi_Signature_init(api, &obj,
                                              SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                              SeosCryptoApi_Digest_ALG_NONE,
                                              &prvKey, NULL));
    TEST_LOCATION(api, obj);

    // Should go through but then return ABORTED because crypto fails
    hashLen = SeosCryptoApi_SIZE_DATAPORT;
    sigLen = SeosCryptoApi_SIZE_DATAPORT;
    TEST_ABORTED(SeosCryptoApi_Signature_sign(&obj, hashBuf, hashLen, sigBuf,
                                              &sigLen));

    // Should fail because input is too long
    hashLen = SeosCryptoApi_SIZE_DATAPORT + 1;
    sigLen = SeosCryptoApi_SIZE_DATAPORT;
    TEST_INSUFF_SPACE(SeosCryptoApi_Signature_sign(&obj, hashBuf, hashLen, sigBuf,
                                                   &sigLen));

    // Should fail because output is too long
    hashLen = SeosCryptoApi_SIZE_DATAPORT;
    sigLen = SeosCryptoApi_SIZE_DATAPORT + 1;
    TEST_INSUFF_SPACE(SeosCryptoApi_Signature_sign(&obj, hashBuf, hashLen, sigBuf,
                                                   &sigLen));

    // Should fail but give us the required output size which is the size of the
    // modulus of the private key, e.g., |N| = |P| + |Q|
    hashLen = SeosCryptoApi_Digest_SIZE_MD5;
    sigLen = 10;
    TEST_TOO_SMALL(SeosCryptoApi_Signature_sign(&obj, hashBuf, hashLen, sigBuf,
                                                &sigLen));
    TEST_TRUE(sigLen == (rsa1024PrvData.data.rsa.prv.pLen +
                            rsa1024PrvData.data.rsa.prv.qLen));

    TEST_SUCCESS(SeosCryptoApi_Signature_free(&obj));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&prvKey));

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &prvKey, &rsa1024PrvData));
    TEST_SUCCESS(SeosCryptoApi_Signature_init(api, &obj,
                                              SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                              SeosCryptoApi_Digest_ALG_NONE,
                                              &prvKey, NULL));
    TEST_LOCATION(api, obj);
    // Sign with input/output buffer being the same
    memcpy(hashBuf, msgData, strlen(msgData));
    hashLen = strlen(msgData);
    sigLen = SeosCryptoApi_SIZE_DATAPORT;
    TEST_SUCCESS(SeosCryptoApi_Signature_sign(&obj, hashBuf, hashLen, hashBuf,
                                              &sigLen));
    TEST_TRUE(sigLen == sizeof(expectedRsaSignature));
    TEST_TRUE(!memcmp(expectedRsaSignature, hashBuf, sigLen));
    TEST_SUCCESS(SeosCryptoApi_Signature_free(&obj));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&prvKey));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Signature_verify_buffer(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey;
    SeosCryptoApi_Signature obj;
    static unsigned int hashBuf[SeosCryptoApi_SIZE_DATAPORT + 1],
           sigBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    size_t hashLen, sigLen;

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &pubKey, &rsa1024PubData));
    TEST_SUCCESS(SeosCryptoApi_Signature_init(api, &obj,
                                              SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                              SeosCryptoApi_Digest_ALG_NONE, NULL,
                                              &pubKey));
    TEST_LOCATION(api, obj);

    // Should go through but fail with ABORTED because crypto fails
    sigLen = (rsa1024PrvData.data.rsa.prv.pLen + rsa1024PrvData.data.rsa.prv.qLen);
    hashLen = SeosCryptoApi_SIZE_DATAPORT - sigLen;
    TEST_ABORTED(SeosCryptoApi_Signature_verify(&obj, hashBuf, hashLen, sigBuf,
                                                sigLen));

    // Should fail because the total of both is too big for internal buffer
    hashLen = 16;
    sigLen = SeosCryptoApi_SIZE_DATAPORT;
    TEST_INSUFF_SPACE(SeosCryptoApi_Signature_verify(&obj, hashBuf, hashLen, sigBuf,
                                                     sigLen));

    TEST_SUCCESS(SeosCryptoApi_Signature_free(&obj));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&pubKey));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Signature_key_neg(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey, prvKey;
    SeosCryptoApi_Signature obj;

    // Test with both keys having different exportable attributes
    rsa1024PrvData.attribs.exportable = false;
    rsa1024PubData.attribs.exportable = true;

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &prvKey, &rsa1024PrvData));
    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &pubKey, &rsa1024PubData));

    // Should fail due to different key localities
    TEST_INVAL_HANDLE(SeosCryptoApi_Signature_init(api, &obj,
                                                   SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15,
                                                   SeosCryptoApi_Digest_ALG_NONE,
                                                   &prvKey, &pubKey));

    TEST_SUCCESS(SeosCryptoApi_Key_free(&pubKey));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&prvKey));

    TEST_OK(api->mode, allowExport);
}

void
test_SeosCryptoApi_Signature(
    SeosCryptoApi* api)
{
    allowExport = true;
    keyData_setExportable(keyDataList, allowExport);
    keySpec_setExportable(keySpecList, allowExport);

    test_SeosCryptoApi_Signature_init_pos(api);
    test_SeosCryptoApi_Signature_init_neg(api);

    test_SeosCryptoApi_Signature_free_pos(api);
    test_SeosCryptoApi_Signature_free_neg(api);

    // Test only failures separately, as computing ref. values is sufficient
    // proof of correct funtioning
    test_SeosCryptoApi_Signature_sign_neg(api);
    test_SeosCryptoApi_Signature_verify_neg(api);

    test_SeosCryptoApi_Signature_sign_buffer(api);
    test_SeosCryptoApi_Signature_verify_buffer(api);

    // Test vectors
    test_SeosCryptoApi_Signature_do_RSA_PKCS1_V15_sign(api);
    test_SeosCryptoApi_Signature_do_RSA_PKCS1_V15_verify(api);

    // Make all used keys NON-EXPORTABLE and re-run parts of the tests
    if (api->mode == SeosCryptoApi_Mode_ROUTER)
    {
        allowExport = false;
        keyData_setExportable(keyDataList, allowExport);
        keySpec_setExportable(keySpecList, allowExport);

        test_SeosCryptoApi_Signature_do_RSA_PKCS1_V15_sign(api);
        test_SeosCryptoApi_Signature_do_RSA_PKCS1_V15_verify(api);

        test_SeosCryptoApi_Signature_key_neg(api);
    }
}