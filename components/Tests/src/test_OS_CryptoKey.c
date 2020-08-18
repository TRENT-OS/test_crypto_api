/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"

#include "ObjectLocation.h"
#include "SharedKeys.h"
#include "TestMacros.h"

#include <string.h>

// -----------------------------------------------------------------------------

static OS_Error_t
do_import(
    OS_Crypto_Handle_t         hCrypto,
    const OS_Crypto_Mode_t     mode,
    const bool                 keepLocal,
    const OS_CryptoKey_Data_t* data)
{
    OS_Error_t err;
    OS_CryptoKey_Handle_t hKey;

    if ((err = OS_CryptoKey_import(&hKey, hCrypto, data)) != OS_SUCCESS)
    {
        return err;
    }
    TEST_LOCACTION_FLAG(mode, keepLocal, hKey);

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    return OS_SUCCESS;
}

static void
test_OS_CryptoKey_import_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    TEST_START(mode, keepLocal);

    // Import 128-bit AES key
    TEST_SUCCESS(do_import(hCrypto, mode, keepLocal, &aes128Data));

    // Import 192-bit AES key
    TEST_SUCCESS(do_import(hCrypto, mode, keepLocal, &aes192Data));

    // Import 256-bit AES key
    TEST_SUCCESS(do_import(hCrypto, mode, keepLocal, &aes256Data));

    // Import MAC key
    TEST_SUCCESS(do_import(hCrypto, mode, keepLocal, &macData));

    // Import 1024-bit RSA pubkey
    TEST_SUCCESS(do_import(hCrypto, mode, keepLocal, &rsa1024PubData));

    // Import 1024-bit RSA prvkey
    TEST_SUCCESS(do_import(hCrypto, mode, keepLocal, &rsa1024PrvData));

    // Import 101-bit DH pubkey
    TEST_SUCCESS(do_import(hCrypto, mode, keepLocal, &dh101PubData));

    // Import 101-bit DH RSA prvkey
    TEST_SUCCESS(do_import(hCrypto, mode, keepLocal, &dh101PrvData));

    // Import SECP256r1 pubkey
    TEST_SUCCESS(do_import(hCrypto, mode, keepLocal, &secp256r1PubData));

    // Import SECP256r1 prvkey
    TEST_SUCCESS(do_import(hCrypto, mode, keepLocal, &secp256r1PrvData));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_import_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;

    TEST_START(mode, keepLocal);

    // Empty key handle
    TEST_INVAL_HANDLE(OS_CryptoKey_import(NULL, hCrypto, &aes128Data));

    // Empty crypto handle
    TEST_INVAL_HANDLE(OS_CryptoKey_import(&hKey, NULL, &aes128Data));

    // Empty key data
    TEST_INVAL_PARAM(OS_CryptoKey_import(&hKey, hCrypto, NULL));

    // Invalid AES key
    TEST_INVAL_PARAM(OS_CryptoKey_import(&hKey, hCrypto, &aes120Data));

    // Invalid RSA key (too small)
    TEST_NOT_SUPP(OS_CryptoKey_import(&hKey, hCrypto, &rsaSmallData));

    // Invalid RSA key (too big)
    TEST_INVAL_PARAM(OS_CryptoKey_import(&hKey, hCrypto, &rsaLargeData));

    TEST_FINISH();
}

static OS_Error_t
do_export(
    OS_Crypto_Handle_t         hCrypto,
    const OS_Crypto_Mode_t     mode,
    const bool                 keepLocal,
    const OS_CryptoKey_Data_t* data)
{
    OS_Error_t err;
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoKey_Data_t expData;

    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, data));
    TEST_LOCACTION_FLAG(mode, keepLocal, hKey);

    memset(&expData, 0, sizeof(OS_CryptoKey_Data_t));
    if ((err = OS_CryptoKey_export(hKey, &expData)) != OS_SUCCESS)
    {
        return err;
    }

    TEST_TRUE(!memcmp(data, &expData, sizeof(OS_CryptoKey_Data_t)));
    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    return OS_SUCCESS;
}

static void
test_OS_CryptoKey_export_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    TEST_START(mode, keepLocal);

    // Export 128-bit AES key
    TEST_SUCCESS(do_export(hCrypto, mode, keepLocal, &aes128Data));

    // Export 192-bit AES key
    TEST_SUCCESS(do_export(hCrypto, mode, keepLocal, &aes192Data));

    // Export 256-bit AES key
    TEST_SUCCESS(do_export(hCrypto, mode, keepLocal, &aes256Data));

    // Export 256-bit AES key
    TEST_SUCCESS(do_export(hCrypto, mode, keepLocal, &macData));

    // Export 1024-bit RSA pubkey
    TEST_SUCCESS(do_export(hCrypto, mode, keepLocal, &rsa1024PubData));

    // Export 1024-bit RSA prvkey
    TEST_SUCCESS(do_export(hCrypto, mode, keepLocal, &rsa1024PrvData));

    // Export 101-bit DH pubkey
    TEST_SUCCESS(do_export(hCrypto, mode, keepLocal, &dh101PubData));

    // Export 101-bit DH prvkey
    TEST_SUCCESS(do_export(hCrypto, mode, keepLocal, &dh101PrvData));

    // Export SECP256r1 pubkey
    TEST_SUCCESS(do_export(hCrypto, mode, keepLocal, &secp256r1PubData));

    // Export SECP256r1 prvkey
    TEST_SUCCESS(do_export(hCrypto, mode, keepLocal, &secp256r1PrvData));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_export_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoKey_Data_t expData;
    OS_CryptoKey_Spec_t aes128noExpSpec =
    {
        .type = OS_CryptoKey_SPECTYPE_BITS,
        .key = {
            .type = OS_CryptoKey_TYPE_AES,
            .attribs.keepLocal = false,
            .params.bits = 128
        }
    };

    TEST_START(mode, keepLocal);

    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &aes128Data));

    // Empty key handle
    TEST_INVAL_HANDLE(OS_CryptoKey_export(NULL, &expData));

    // Empty export data buffer
    TEST_INVAL_PARAM(OS_CryptoKey_export(hKey, NULL));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    // Remote key
    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128noExpSpec));

    if (mode == OS_Crypto_MODE_LIBRARY_ONLY)
    {
        /*
         * A library instance will store all keys in memory which is shared with the
         * host component. Therefore, if the API runs in library mode, it will ALWAYS
         * allow exports, even if the key is marked as "non exportable".
         */
        TEST_SUCCESS(OS_CryptoKey_export(hKey, &expData));
    }
    else
    {
        /*
         * It is assumed that all other modes of the Crypto API respect the
         * exportable flag and thus deny the operation.
         */
        TEST_OP_DENIED(OS_CryptoKey_export(hKey, &expData));
    }

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static OS_Error_t
do_generate(
    OS_Crypto_Handle_t         hCrypto,
    const OS_Crypto_Mode_t     mode,
    const bool                 keepLocal,
    const OS_CryptoKey_Spec_t* spec)
{
    OS_Error_t err;
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoKey_Data_t expData;

    if ((err = OS_CryptoKey_generate(&hKey, hCrypto, spec)) != OS_SUCCESS)
    {
        return err;
    }
    TEST_LOCACTION_FLAG(mode, keepLocal, hKey);

    memset(&expData, 0, sizeof(OS_CryptoKey_Data_t));
    if (keepLocal)
    {
        TEST_SUCCESS(OS_CryptoKey_export(hKey, &expData));
        TEST_TRUE(spec->key.type == expData.type);
        TEST_TRUE(!memcmp(&spec->key.attribs, &expData.attribs,
                          sizeof(OS_CryptoKey_Attrib_t)));
        if (spec->type == OS_CryptoKey_SPECTYPE_PARAMS)
        {
            switch (spec->key.type)
            {
            case OS_CryptoKey_TYPE_DH_PRV:
                TEST_TRUE(!memcmp(&spec->key.params, &expData.data.dh.prv.params,
                                  sizeof(OS_CryptoKey_DhParams_t)));
                break;
            default:
                TEST_TRUE(1 == 0);
            }
        }
    }
    else
    {
        TEST_OP_DENIED(OS_CryptoKey_export(hKey, &expData));
    }

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    return OS_SUCCESS;
}

static void
test_OS_CryptoKey_generate_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    TEST_START(mode, keepLocal);

    // Generate 128-bit AES key
    TEST_SUCCESS(do_generate(hCrypto, mode, keepLocal, &aes128Spec));

    // Generate 192-bit AES key
    TEST_SUCCESS(do_generate(hCrypto, mode, keepLocal, &aes192Spec));

    // Generate 256-bit AES key
    TEST_SUCCESS(do_generate(hCrypto, mode, keepLocal, &aes256Spec));

    // Generate 256-bit AES key
    TEST_SUCCESS(do_generate(hCrypto, mode, keepLocal, &macSpec));

    // Generate 64-bit DH privkey from bit spec
    TEST_SUCCESS(do_generate(hCrypto, mode, keepLocal, &dh64bSpec));

    // Generate 101-bit DH privkey from param spec
    TEST_SUCCESS(do_generate(hCrypto, mode, keepLocal, &dh101pSpec));

    // Generate 128-bit RSA privkey
    TEST_SUCCESS(do_generate(hCrypto, mode, keepLocal, &rsa128Spec));

    // Generate SECP256r1 privkey
    TEST_SUCCESS(do_generate(hCrypto, mode, keepLocal, &secp256r1Spec));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_generate_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;

    TEST_START(mode, keepLocal);

    // Empty crypto handle
    TEST_INVAL_HANDLE(OS_CryptoKey_generate(NULL, hCrypto, &aes128Spec));

    // Empty key handle
    TEST_INVAL_HANDLE(OS_CryptoKey_generate(&hKey, NULL, &aes128Spec));

    // Empty key spec
    TEST_INVAL_PARAM(OS_CryptoKey_generate(&hKey, hCrypto, NULL));

    // Wrong key size: 120-bit AES key
    TEST_INVAL_PARAM(OS_CryptoKey_generate(&hKey, hCrypto, &aes120Spec));

    // Wrong key size: 127-bit RSA key
    TEST_NOT_SUPP(OS_CryptoKey_generate(&hKey, hCrypto, &rsa127Spec));

    // Wrong key size: 63-bit DH key
    TEST_NOT_SUPP(OS_CryptoKey_generate(&hKey, hCrypto, &dh63bSpec));

    TEST_FINISH();
}

static OS_Error_t
do_makePublic(
    OS_Crypto_Handle_t         hCrypto,
    const OS_Crypto_Mode_t     mode,
    const bool                 keepLocal,
    const OS_CryptoKey_Spec_t* spec)
{
    OS_Error_t err;
    OS_CryptoKey_Handle_t hPrvKey, hPubKey;
    OS_CryptoKey_Data_t expData;

    TEST_SUCCESS(OS_CryptoKey_generate(&hPrvKey, hCrypto, spec));
    TEST_LOCACTION_FLAG(mode, keepLocal, hPrvKey);
    if ((err = OS_CryptoKey_makePublic(&hPubKey, hCrypto, hPrvKey,
                                       &spec->key.attribs)) != OS_SUCCESS)
    {
        return err;
    }

    if (keepLocal)
    {
        TEST_SUCCESS(OS_CryptoKey_export(hPubKey, &expData));
        TEST_LOCACTION_FLAG(mode, keepLocal, hPubKey);
        switch (spec->key.type)
        {
        case OS_CryptoKey_TYPE_RSA_PRV:
            TEST_TRUE(expData.type == OS_CryptoKey_TYPE_RSA_PUB);
            break;
        case OS_CryptoKey_TYPE_DH_PRV:
            TEST_TRUE(expData.type == OS_CryptoKey_TYPE_DH_PUB);
            if (OS_CryptoKey_SPECTYPE_PARAMS == spec->type)
            {
                TEST_TRUE(!memcmp(&expData.data.dh.pub.params, &spec->key.params.dh,
                                  sizeof(OS_CryptoKey_DhParams_t)));
            }
            break;
        case OS_CryptoKey_TYPE_SECP256R1_PRV:
            TEST_TRUE(expData.type == OS_CryptoKey_TYPE_SECP256R1_PUB);
            break;
        default:
            TEST_TRUE(1 == 0);
        }
    }
    else
    {
        TEST_OP_DENIED(OS_CryptoKey_export(hPubKey, &expData));
    }

    TEST_SUCCESS(OS_CryptoKey_free(hPubKey));
    TEST_SUCCESS(OS_CryptoKey_free(hPrvKey));

    return OS_SUCCESS;

}
static void
test_OS_CryptoKey_makePublic_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    TEST_START(mode, keepLocal);

    // Make DH pubkey, with privkey from bit spec
    TEST_SUCCESS(do_makePublic(hCrypto, mode, keepLocal, &dh64bSpec));

    // Make DH pubkey, with privkey from param spec
    TEST_SUCCESS(do_makePublic(hCrypto, mode, keepLocal, &dh101pSpec));

    // Make RSA pubkey
    TEST_SUCCESS(do_makePublic(hCrypto, mode, keepLocal, &rsa128Spec));

    // Make SECP256r1 pubkey
    TEST_SUCCESS(do_makePublic(hCrypto, mode, keepLocal, &secp256r1Spec));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_makePublic_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hPrvKey, hPubKey;

    TEST_START(mode, keepLocal);

    TEST_SUCCESS(OS_CryptoKey_generate(&hPrvKey, hCrypto, &dh64bSpec));

    // Empty target handle
    TEST_INVAL_HANDLE(OS_CryptoKey_makePublic(NULL, hCrypto, hPrvKey,
                                              &dh64bSpec.key.attribs));

    // Empty crypto handle
    TEST_INVAL_HANDLE(OS_CryptoKey_makePublic(&hPubKey, NULL, hPrvKey,
                                              &dh64bSpec.key.attribs));

    // Empty private handle
    TEST_INVAL_HANDLE(OS_CryptoKey_makePublic(&hPubKey, hCrypto, NULL,
                                              &dh64bSpec.key.attribs));

    // Empty attribs
    TEST_INVAL_PARAM(OS_CryptoKey_makePublic(&hPubKey, hCrypto, hPrvKey,
                                             NULL));

    TEST_SUCCESS(OS_CryptoKey_free(hPrvKey));

    // Try making "public" from a symmetric key
    TEST_SUCCESS(OS_CryptoKey_generate(&hPrvKey, hCrypto, &aes128Spec));
    TEST_LOCACTION_FLAG(mode, keepLocal, hPrvKey);
    TEST_INVAL_PARAM(OS_CryptoKey_makePublic(&hPubKey, hCrypto, hPrvKey,
                                             NULL));
    TEST_SUCCESS(OS_CryptoKey_free(hPrvKey));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_getParams_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    size_t n;
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoKey_DhParams_t dhParams;
    OS_CryptoKey_Data_t expData;

    TEST_START(mode, keepLocal);

    // Generate params for DH
    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &dh101pSpec));
    TEST_LOCACTION_FLAG(mode, keepLocal, hKey);
    n = sizeof(dhParams);
    TEST_SUCCESS(OS_CryptoKey_getParams(hKey, &dhParams, &n));
    TEST_TRUE(n == sizeof(dhParams));
    if (keepLocal)
    {
        TEST_SUCCESS(OS_CryptoKey_export(hKey, &expData));
        TEST_TRUE(!memcmp(&expData.data.dh.prv.params, &dhParams, n));
    }
    else
    {
        TEST_OP_DENIED(OS_CryptoKey_export(hKey, &expData));
    }
    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_getParams_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    size_t n;
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoKey_DhParams_t dhParams;

    TEST_START(mode, keepLocal);

    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &dh64bSpec));
    TEST_LOCACTION_FLAG(mode, keepLocal, hKey);

    // Empty key handle
    n = sizeof(dhParams);
    TEST_INVAL_HANDLE(OS_CryptoKey_getParams(NULL, &dhParams, &n));

    // Empty buffer
    TEST_INVAL_PARAM(OS_CryptoKey_getParams(hKey, NULL, &n));

    // Empty buffer len
    TEST_INVAL_PARAM(OS_CryptoKey_getParams(hKey, &dhParams, NULL));

    // Too small buffer len
    n = 17;
    TEST_TOO_SMALL(OS_CryptoKey_getParams(hKey, &dhParams, &n));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_loadParams_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    size_t n;
    OS_CryptoKey_EccParams_t eccParams;

    TEST_START(mode, keepLocal);

    // Load SECP192r1
    n = sizeof(eccParams);
    TEST_SUCCESS(OS_CryptoKey_loadParams(hCrypto,
                                         OS_CryptoKey_PARAM_ECC_SECP192R1,
                                         &eccParams, &n));
    TEST_TRUE(n == sizeof(eccParams));

    // Load SECP224r1
    TEST_SUCCESS(OS_CryptoKey_loadParams(hCrypto,
                                         OS_CryptoKey_PARAM_ECC_SECP224R1,
                                         &eccParams, &n));
    TEST_TRUE(n == sizeof(eccParams));

    // Load SECP256r1
    TEST_SUCCESS(OS_CryptoKey_loadParams(hCrypto,
                                         OS_CryptoKey_PARAM_ECC_SECP256R1,
                                         &eccParams, &n));
    TEST_TRUE(n == sizeof(eccParams));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_loadParams_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    size_t n;
    OS_CryptoKey_EccParams_t eccParams;

    TEST_START(mode, keepLocal);

    // Empty handle
    n = sizeof(eccParams);
    TEST_INVAL_HANDLE(OS_CryptoKey_loadParams(NULL,
                                              OS_CryptoKey_PARAM_ECC_SECP192R1,
                                              &eccParams, &n));

    // Wrong param name
    TEST_NOT_SUPP(OS_CryptoKey_loadParams(hCrypto, 666, &eccParams, &n));

    // Empty buffer
    TEST_INVAL_PARAM(OS_CryptoKey_loadParams(hCrypto,
                                             OS_CryptoKey_PARAM_ECC_SECP192R1,
                                             NULL, &n));

    // Empty length
    TEST_INVAL_PARAM(OS_CryptoKey_loadParams(hCrypto,
                                             OS_CryptoKey_PARAM_ECC_SECP192R1,
                                             &eccParams, NULL));

    // To small buffer
    n = 17;
    TEST_TOO_SMALL(OS_CryptoKey_loadParams(hCrypto,
                                           OS_CryptoKey_PARAM_ECC_SECP192R1,
                                           &eccParams, &n));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_getAttribs_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoKey_Attrib_t attribs;

    TEST_START(mode, keepLocal);

    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &aes128Data));

    // Get attribs of key and make sure it matches the imported data
    memset(&attribs, 0, sizeof(OS_CryptoKey_Attrib_t));
    TEST_SUCCESS(OS_CryptoKey_getAttribs(hKey, &attribs));
    TEST_TRUE(!memcmp(&attribs, &aes128Data.attribs,
                      sizeof(OS_CryptoKey_Attrib_t)));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_getAttribs_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoKey_Attrib_t attribs;

    TEST_START(mode, keepLocal);

    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &aes128Data));

    // Empty key handle
    TEST_INVAL_HANDLE(OS_CryptoKey_getAttribs(NULL, &attribs));

    // Empty attrib buffer
    TEST_INVAL_PARAM(OS_CryptoKey_getAttribs(hKey, NULL));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_free_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;

    TEST_START(mode, keepLocal);

    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec));
    TEST_LOCACTION_FLAG(mode, keepLocal, hKey);
    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_free_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;

    TEST_START(mode, keepLocal);

    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec));
    TEST_LOCACTION_FLAG(mode, keepLocal, hKey);

    // Empty key handle
    TEST_INVAL_HANDLE(OS_CryptoKey_free(NULL));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_getParams_buffer(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    OS_CryptoKey_Handle_t hKey;
    static unsigned char paramBuf[OS_DATAPORT_DEFAULT_SIZE + 1];
    size_t paramLen;

    TEST_START(mode, keepLocal);

    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &dh101pSpec));
    TEST_LOCACTION_FLAG(mode, keepLocal, hKey);

    // Should be OK and give the correct length
    paramLen = OS_DATAPORT_DEFAULT_SIZE;
    TEST_SUCCESS(OS_CryptoKey_getParams(hKey, paramBuf, &paramLen));
    TEST_TRUE(paramLen == sizeof(OS_CryptoKey_DhParams_t));

    // Should fail but give the correct length
    paramLen = 10;
    TEST_TOO_SMALL(OS_CryptoKey_getParams(hKey, paramBuf, &paramLen));
    TEST_TRUE(paramLen == sizeof(OS_CryptoKey_DhParams_t));

    // Should fail due buffer being too big
    paramLen = OS_DATAPORT_DEFAULT_SIZE + 1;
    TEST_INSUFF_SPACE(OS_CryptoKey_getParams(hKey, paramBuf, &paramLen));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_loadParams_buffer(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             keepLocal)
{
    static unsigned char paramBuf[OS_DATAPORT_DEFAULT_SIZE + 1];
    size_t paramLen;

    TEST_START(mode, keepLocal);

    // Should be OK
    paramLen = OS_DATAPORT_DEFAULT_SIZE;
    TEST_SUCCESS(OS_CryptoKey_loadParams(hCrypto,
                                         OS_CryptoKey_PARAM_ECC_SECP192R1,
                                         paramBuf, &paramLen));
    TEST_TRUE(paramLen == sizeof(OS_CryptoKey_EccParams_t));

    // Should fail, but give the minimum size
    paramLen = 10;
    TEST_TOO_SMALL(OS_CryptoKey_loadParams(hCrypto,
                                           OS_CryptoKey_PARAM_ECC_SECP192R1,
                                           paramBuf, &paramLen));
    TEST_TRUE(paramLen == sizeof(OS_CryptoKey_EccParams_t));

    // Should fail because buffer is too big
    paramLen = OS_DATAPORT_DEFAULT_SIZE + 1;
    TEST_INSUFF_SPACE(OS_CryptoKey_loadParams(hCrypto,
                                              OS_CryptoKey_PARAM_ECC_SECP192R1,
                                              paramBuf, &paramLen));

    TEST_FINISH();
}

void test_OS_CryptoKey(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode)
{
    bool keepLocal = true;

    keyData_setLocality(keyDataList, keepLocal);
    keySpec_setLocality(keySpecList, keepLocal);

    test_OS_CryptoKey_import_pos(hCrypto, mode, keepLocal);
    test_OS_CryptoKey_import_neg(hCrypto, mode, keepLocal);

    test_OS_CryptoKey_export_pos(hCrypto, mode, keepLocal);
    test_OS_CryptoKey_export_neg(hCrypto, mode, keepLocal);

    test_OS_CryptoKey_generate_pos(hCrypto, mode, keepLocal);
    test_OS_CryptoKey_generate_neg(hCrypto, mode, keepLocal);

    test_OS_CryptoKey_makePublic_pos(hCrypto, mode, keepLocal);
    test_OS_CryptoKey_makePublic_neg(hCrypto, mode, keepLocal);

    test_OS_CryptoKey_getParams_pos(hCrypto, mode, keepLocal);
    test_OS_CryptoKey_getParams_neg(hCrypto, mode, keepLocal);

    test_OS_CryptoKey_loadParams_pos(hCrypto, mode, keepLocal);
    test_OS_CryptoKey_loadParams_neg(hCrypto, mode, keepLocal);

    test_OS_CryptoKey_getAttribs_pos(hCrypto, mode, keepLocal);
    test_OS_CryptoKey_getAttribs_neg(hCrypto, mode, keepLocal);

    test_OS_CryptoKey_free_pos(hCrypto, mode, keepLocal);
    test_OS_CryptoKey_free_neg(hCrypto, mode, keepLocal);

    test_OS_CryptoKey_getParams_buffer(hCrypto, mode, keepLocal);
    test_OS_CryptoKey_loadParams_buffer(hCrypto, mode, keepLocal);

    // Make all used keys remote and re-run parts of the tests
    if (mode == OS_Crypto_MODE_CLIENT)
    {
        keepLocal = false;
        keyData_setLocality(keyDataList, keepLocal);
        keySpec_setLocality(keySpecList, keepLocal);

        test_OS_CryptoKey_import_pos(hCrypto, mode, keepLocal);
        test_OS_CryptoKey_generate_pos(hCrypto, mode, keepLocal);
        test_OS_CryptoKey_makePublic_pos(hCrypto, mode, keepLocal);
        test_OS_CryptoKey_getParams_pos(hCrypto, mode, keepLocal);
        test_OS_CryptoKey_loadParams_pos(hCrypto, mode, keepLocal);
    }
}