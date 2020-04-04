/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"

#include "ObjectLocation.h"
#include "SharedKeys.h"
#include "TestMacros.h"

#include <string.h>

// -----------------------------------------------------------------------------

static seos_err_t
do_import(
    OS_Crypto_Handle_t         hCrypto,
    const OS_Crypto_Mode_t     mode,
    const bool                 expo,
    const OS_CryptoKey_Data_t* data)
{
    seos_err_t err;
    OS_CryptoKey_Handle_t hKey;

    if ((err = OS_CryptoKey_import(&hKey, hCrypto, data)) != SEOS_SUCCESS)
    {
        return err;
    }
    TEST_LOCACTION_EXP(mode, expo, hKey);

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    return SEOS_SUCCESS;
}

static void
test_OS_CryptoKey_import_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    TEST_START(mode, expo);

    // Import 128-bit AES key
    TEST_SUCCESS(do_import(hCrypto, mode, expo, &aes128Data));

    // Import 192-bit AES key
    TEST_SUCCESS(do_import(hCrypto, mode, expo, &aes192Data));

    // Import 256-bit AES key
    TEST_SUCCESS(do_import(hCrypto, mode, expo, &aes256Data));

    // Import 1024-bit RSA pubkey
    TEST_SUCCESS(do_import(hCrypto, mode, expo, &rsa1024PubData));

    // Import 1024-bit RSA prvkey
    TEST_SUCCESS(do_import(hCrypto, mode, expo, &rsa1024PrvData));

    // Import 101-bit DH pubkey
    TEST_SUCCESS(do_import(hCrypto, mode, expo, &dh101PubData));

    // Import 101-bit DH RSA prvkey
    TEST_SUCCESS(do_import(hCrypto, mode, expo, &dh101PrvData));

    // Import SECP256r1 pubkey
    TEST_SUCCESS(do_import(hCrypto, mode, expo, &secp256r1PubData));

    // Import SECP256r1 prvkey
    TEST_SUCCESS(do_import(hCrypto, mode, expo, &secp256r1PrvData));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_import_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    OS_CryptoKey_Handle_t hKey;

    TEST_START(mode, expo);

    // Empty key
    TEST_INVAL_PARAM(OS_CryptoKey_import(NULL, hCrypto, &aes128Data));

    // Empty crypto context
    TEST_INVAL_PARAM(OS_CryptoKey_import(&hKey, NULL, &aes128Data));

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

static seos_err_t
do_export(
    OS_Crypto_Handle_t         hCrypto,
    const OS_Crypto_Mode_t     mode,
    const bool                 expo,
    const OS_CryptoKey_Data_t* data)
{
    seos_err_t err;
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoKey_Data_t expData;

    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, data));
    TEST_LOCACTION_EXP(mode, expo, hKey);

    memset(&expData, 0, sizeof(OS_CryptoKey_Data_t));
    if ((err = OS_CryptoKey_export(hKey, &expData)) != SEOS_SUCCESS)
    {
        return err;
    }

    TEST_TRUE(!memcmp(data, &expData, sizeof(OS_CryptoKey_Data_t)));
    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    return SEOS_SUCCESS;
}

static void
test_OS_CryptoKey_export_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    TEST_START(mode, expo);

    // Export 128-bit AES key
    TEST_SUCCESS(do_export(hCrypto, mode, expo, &aes128Data));

    // Export 192-bit AES key
    TEST_SUCCESS(do_export(hCrypto, mode, expo, &aes192Data));

    // Export 256-bit AES key
    TEST_SUCCESS(do_export(hCrypto, mode, expo, &aes256Data));

    // Export 1024-bit RSA pubkey
    TEST_SUCCESS(do_export(hCrypto, mode, expo, &rsa1024PubData));

    // Export 1024-bit RSA prvkey
    TEST_SUCCESS(do_export(hCrypto, mode, expo, &rsa1024PrvData));

    // Export 101-bit DH pubkey
    TEST_SUCCESS(do_export(hCrypto, mode, expo, &dh101PubData));

    // Export 101-bit DH prvkey
    TEST_SUCCESS(do_export(hCrypto, mode, expo, &dh101PrvData));

    // Export SECP256r1 pubkey
    TEST_SUCCESS(do_export(hCrypto, mode, expo, &secp256r1PubData));

    // Export SECP256r1 prvkey
    TEST_SUCCESS(do_export(hCrypto, mode, expo, &secp256r1PrvData));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_export_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoKey_Data_t expData;
    OS_CryptoKey_Spec_t aes128noExpSpec =
    {
        .type = OS_CryptoKey_SPECTYPE_BITS,
        .key = {
            .type = OS_CryptoKey_TYPE_AES,
            .attribs.exportable = false,
            .params.bits = 128
        }
    };

    TEST_START(mode, expo);

    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &aes128Data));

    // Empty key
    TEST_INVAL_PARAM(OS_CryptoKey_export(NULL, &expData));

    // Empty export data buffer
    TEST_INVAL_PARAM(OS_CryptoKey_export(hKey, NULL));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    // Non-exportable key
    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128noExpSpec));

    if (mode == OS_Crypto_MODE_LIBRARY)
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

static seos_err_t
do_generate(
    OS_Crypto_Handle_t         hCrypto,
    const OS_Crypto_Mode_t     mode,
    const bool                 expo,
    const OS_CryptoKey_Spec_t* spec)
{
    seos_err_t err;
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoKey_Data_t expData;

    if ((err = OS_CryptoKey_generate(&hKey, hCrypto, spec)) != SEOS_SUCCESS)
    {
        return err;
    }
    TEST_LOCACTION_EXP(mode, expo, hKey);

    memset(&expData, 0, sizeof(OS_CryptoKey_Data_t));
    if (expo)
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

    return SEOS_SUCCESS;
}

static void
test_OS_CryptoKey_generate_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    TEST_START(mode, expo);

    // Generate 128-bit AES key
    TEST_SUCCESS(do_generate(hCrypto, mode, expo, &aes128Spec));

    // Generate 192-bit AES key
    TEST_SUCCESS(do_generate(hCrypto, mode, expo, &aes192Spec));

    // Generate 256-bit AES key
    TEST_SUCCESS(do_generate(hCrypto, mode, expo, &aes256Spec));

    // Generate 64-bit DH privkey from bit spec
    TEST_SUCCESS(do_generate(hCrypto, mode, expo, &dh64bSpec));

    // Generate 101-bit DH privkey from param spec
    TEST_SUCCESS(do_generate(hCrypto, mode, expo, &dh101pSpec));

    // Generate 128-bit RSA privkey
    TEST_SUCCESS(do_generate(hCrypto, mode, expo, &rsa128Spec));

    // Generate SECP256r1 privkey
    TEST_SUCCESS(do_generate(hCrypto, mode, expo, &secp256r1Spec));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_generate_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    OS_CryptoKey_Handle_t hKey;

    TEST_START(mode, expo);

    // Empty crypto handle
    TEST_INVAL_PARAM(OS_CryptoKey_generate(NULL, hCrypto, &aes128Spec));

    // Empty key handle
    TEST_INVAL_PARAM(OS_CryptoKey_generate(&hKey, NULL, &aes128Spec));

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

static seos_err_t
do_makePublic(
    OS_Crypto_Handle_t         hCrypto,
    const OS_Crypto_Mode_t     mode,
    const bool                 expo,
    const OS_CryptoKey_Spec_t* spec)
{
    seos_err_t err;
    OS_CryptoKey_Handle_t hPrvKey, hPubKey;
    OS_CryptoKey_Data_t expData;

    TEST_SUCCESS(OS_CryptoKey_generate(&hPrvKey, hCrypto, spec));
    TEST_LOCACTION_EXP(mode, expo, hPrvKey);
    if ((err = OS_CryptoKey_makePublic(&hPubKey, hCrypto, hPrvKey,
                                       &spec->key.attribs)) != SEOS_SUCCESS)
    {
        return err;
    }

    if (expo)
    {
        TEST_SUCCESS(OS_CryptoKey_export(hPubKey, &expData));
        TEST_LOCACTION_EXP(mode, expo, hPubKey);
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

    return SEOS_SUCCESS;

}
static void
test_OS_CryptoKey_makePublic_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    TEST_START(mode, expo);

    // Make DH pubkey, with privkey from bit spec
    TEST_SUCCESS(do_makePublic(hCrypto, mode, expo, &dh64bSpec));

    // Make DH pubkey, with privkey from param spec
    TEST_SUCCESS(do_makePublic(hCrypto, mode, expo, &dh101pSpec));

    // Make RSA pubkey
    TEST_SUCCESS(do_makePublic(hCrypto, mode, expo, &rsa128Spec));

    // Make SECP256r1 pubkey
    TEST_SUCCESS(do_makePublic(hCrypto, mode, expo, &secp256r1Spec));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_makePublic_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    OS_CryptoKey_Handle_t hPrvKey, hPubKey;

    TEST_START(mode, expo);

    TEST_SUCCESS(OS_CryptoKey_generate(&hPrvKey, hCrypto, &dh64bSpec));

    // Empty target handle
    TEST_INVAL_PARAM(OS_CryptoKey_makePublic(NULL, hCrypto, hPrvKey,
                                             &dh64bSpec.key.attribs));

    // Empty crypto handle
    TEST_INVAL_PARAM(OS_CryptoKey_makePublic(&hPubKey, NULL, hPrvKey,
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
    TEST_LOCACTION_EXP(mode, expo, hPrvKey);
    TEST_INVAL_PARAM(OS_CryptoKey_makePublic(&hPubKey, hCrypto, hPrvKey,
                                             NULL));
    TEST_SUCCESS(OS_CryptoKey_free(hPrvKey));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_getParams_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    size_t n;
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoKey_DhParams_t dhParams;
    OS_CryptoKey_Data_t expData;

    TEST_START(mode, expo);

    // Generate params for DH
    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &dh101pSpec));
    TEST_LOCACTION_EXP(mode, expo, hKey);
    n = sizeof(dhParams);
    TEST_SUCCESS(OS_CryptoKey_getParams(hKey, &dhParams, &n));
    TEST_TRUE(n == sizeof(dhParams));
    if (expo)
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
    const bool             expo)
{
    size_t n;
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoKey_DhParams_t dhParams;

    TEST_START(mode, expo);

    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &dh64bSpec));
    TEST_LOCACTION_EXP(mode, expo, hKey);

    // Empty key handle
    n = sizeof(dhParams);
    TEST_INVAL_PARAM(OS_CryptoKey_getParams(NULL, &dhParams, &n));

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
    const bool             expo)
{
    size_t n;
    OS_CryptoKey_EccParams_t eccParams;

    TEST_START(mode, expo);

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
    const bool             expo)
{
    size_t n;
    OS_CryptoKey_EccParams_t eccParams;

    TEST_START(mode, expo);

    // Empty context
    n = sizeof(eccParams);
    TEST_INVAL_PARAM(OS_CryptoKey_loadParams(NULL,
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
    const bool             expo)
{
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoKey_Attrib_t attribs;

    TEST_START(mode, expo);

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
    const bool             expo)
{
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoKey_Attrib_t attribs;

    TEST_START(mode, expo);

    TEST_SUCCESS(OS_CryptoKey_import(&hKey, hCrypto, &aes128Data));

    // Empty key object
    TEST_INVAL_PARAM(OS_CryptoKey_getAttribs(NULL, &attribs));

    // Empty attrib buffer
    TEST_INVAL_PARAM(OS_CryptoKey_getAttribs(hKey, NULL));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_free_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    OS_CryptoKey_Handle_t hKey;

    TEST_START(mode, expo);

    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec));
    TEST_LOCACTION_EXP(mode, expo, hKey);
    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_free_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    OS_CryptoKey_Handle_t hKey;

    TEST_START(mode, expo);

    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec));
    TEST_LOCACTION_EXP(mode, expo, hKey);

    // Empty key
    TEST_INVAL_PARAM(OS_CryptoKey_free(NULL));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_getParams_buffer(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    OS_CryptoKey_Handle_t hKey;
    static unsigned char paramBuf[OS_Crypto_SIZE_DATAPORT + 1];
    size_t paramLen;

    TEST_START(mode, expo);

    TEST_SUCCESS(OS_CryptoKey_generate(&hKey, hCrypto, &dh101pSpec));
    TEST_LOCACTION_EXP(mode, expo, hKey);

    // Should be OK and give the correct length
    paramLen = OS_Crypto_SIZE_DATAPORT;
    TEST_SUCCESS(OS_CryptoKey_getParams(hKey, paramBuf, &paramLen));
    TEST_TRUE(paramLen == sizeof(OS_CryptoKey_DhParams_t));

    // Should fail but give the correct length
    paramLen = 10;
    TEST_TOO_SMALL(OS_CryptoKey_getParams(hKey, paramBuf, &paramLen));
    TEST_TRUE(paramLen == sizeof(OS_CryptoKey_DhParams_t));

    // Should fail due buffer being too big
    paramLen = OS_Crypto_SIZE_DATAPORT + 1;
    TEST_INSUFF_SPACE(OS_CryptoKey_getParams(hKey, paramBuf, &paramLen));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_loadParams_buffer(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    static unsigned char paramBuf[OS_Crypto_SIZE_DATAPORT + 1];
    size_t paramLen;

    TEST_START(mode, expo);

    // Should be OK
    paramLen = OS_Crypto_SIZE_DATAPORT;
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
    paramLen = OS_Crypto_SIZE_DATAPORT + 1;
    TEST_INSUFF_SPACE(OS_CryptoKey_loadParams(hCrypto,
                                              OS_CryptoKey_PARAM_ECC_SECP192R1,
                                              paramBuf, &paramLen));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_migrate_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoLib_Object_ptr ptr;

    TEST_START(mode, expo);

    // Let the remote side load a key into its address space, then migrate
    // it so it can be used through our API instance
    TEST_SUCCESS(CryptoRpcServer_loadKey(&ptr));
    TEST_SUCCESS(OS_Crypto_migrateObject(&hKey, hCrypto, ptr));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_CryptoKey_migrate_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoLib_Object_ptr ptr;

    TEST_START(mode, expo);

    TEST_SUCCESS(CryptoRpcServer_loadKey(&ptr));

    // Empty key
    TEST_INVAL_PARAM(OS_Crypto_migrateObject(NULL, hCrypto, ptr));

    // Empty ctx
    TEST_INVAL_PARAM(OS_Crypto_migrateObject(&hKey, NULL, ptr));

    // Invalid remote pointer
    TEST_INVAL_HANDLE(OS_Crypto_migrateObject(&hKey, hCrypto, NULL));

    TEST_FINISH();
}

void test_OS_CryptoKey(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode)
{
    bool expo = true;

    keyData_setExportable(keyDataList, expo);
    keySpec_setExportable(keySpecList, expo);

    test_OS_CryptoKey_import_pos(hCrypto, mode, expo);
    test_OS_CryptoKey_import_neg(hCrypto, mode, expo);

    test_OS_CryptoKey_export_pos(hCrypto, mode, expo);
    test_OS_CryptoKey_export_neg(hCrypto, mode, expo);

    test_OS_CryptoKey_generate_pos(hCrypto, mode, expo);
    test_OS_CryptoKey_generate_neg(hCrypto, mode, expo);

    test_OS_CryptoKey_makePublic_pos(hCrypto, mode, expo);
    test_OS_CryptoKey_makePublic_neg(hCrypto, mode, expo);

    test_OS_CryptoKey_getParams_pos(hCrypto, mode, expo);
    test_OS_CryptoKey_getParams_neg(hCrypto, mode, expo);

    test_OS_CryptoKey_loadParams_pos(hCrypto, mode, expo);
    test_OS_CryptoKey_loadParams_neg(hCrypto, mode, expo);

    test_OS_CryptoKey_getAttribs_pos(hCrypto, mode, expo);
    test_OS_CryptoKey_getAttribs_neg(hCrypto, mode, expo);

    test_OS_CryptoKey_free_pos(hCrypto, mode, expo);
    test_OS_CryptoKey_free_neg(hCrypto, mode, expo);

    test_OS_CryptoKey_getParams_buffer(hCrypto, mode, expo);
    test_OS_CryptoKey_loadParams_buffer(hCrypto, mode, expo);

    // Make all used keys NON-EXPORTABLE and re-run parts of the tests
    if (mode == OS_Crypto_MODE_ROUTER)
    {
        expo = false;
        keyData_setExportable(keyDataList, expo);
        keySpec_setExportable(keySpecList, expo);

        test_OS_CryptoKey_import_pos(hCrypto, mode, expo);
        test_OS_CryptoKey_generate_pos(hCrypto, mode, expo);
        test_OS_CryptoKey_makePublic_pos(hCrypto, mode, expo);
        test_OS_CryptoKey_getParams_pos(hCrypto, mode, expo);
        test_OS_CryptoKey_loadParams_pos(hCrypto, mode, expo);
    }

    // Migration is only useful when done not locally, as we need to migrate
    // a key created on the remote side to use it with the local API instance.
    // NOTE: These test require the remote instance to be initialized.
    if (mode == OS_Crypto_MODE_ROUTER ||
        mode == OS_Crypto_MODE_RPC_CLIENT)
    {
        test_OS_CryptoKey_migrate_pos(hCrypto, mode, expo);
        test_OS_CryptoKey_migrate_neg(hCrypto, mode, expo);
    }
}