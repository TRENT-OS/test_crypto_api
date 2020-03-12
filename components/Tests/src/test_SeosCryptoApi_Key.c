/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoApi.h"

#include "ObjectLocation.h"
#include "SharedKeys.h"
#include "TestMacros.h"

#include <string.h>

// -----------------------------------------------------------------------------

static seos_err_t
do_import(
    SeosCryptoApiH                hCrypto,
    const SeosCryptoApi_Mode      mode,
    const bool                    expo,
    const SeosCryptoApi_Key_Data* data)
{
    seos_err_t err;
    SeosCryptoApi_KeyH hKey;

    if ((err = SeosCryptoApi_Key_import(&hKey, hCrypto, data)) != SEOS_SUCCESS)
    {
        return err;
    }
    TEST_LOCACTION_EXP(mode, expo, hKey);

    TEST_SUCCESS(SeosCryptoApi_Key_free(hKey));

    return SEOS_SUCCESS;
}

static void
test_SeosCryptoApi_Key_import_pos(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode,
    const bool               expo)
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
test_SeosCryptoApi_Key_import_neg(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode,
    const bool               expo)
{
    SeosCryptoApi_KeyH hKey;

    TEST_START(mode, expo);

    // Empty key
    TEST_INVAL_PARAM(SeosCryptoApi_Key_import(NULL, hCrypto, &aes128Data));

    // Empty crypto context
    TEST_INVAL_PARAM(SeosCryptoApi_Key_import(&hKey, NULL, &aes128Data));

    // Empty key data
    TEST_INVAL_PARAM(SeosCryptoApi_Key_import(&hKey, hCrypto, NULL));

    // Invalid AES key
    TEST_INVAL_PARAM(SeosCryptoApi_Key_import(&hKey, hCrypto, &aes120Data));

    // Invalid RSA key (too small)
    TEST_NOT_SUPP(SeosCryptoApi_Key_import(&hKey, hCrypto, &rsaSmallData));

    // Invalid RSA key (too big)
    TEST_INVAL_PARAM(SeosCryptoApi_Key_import(&hKey, hCrypto, &rsaLargeData));

    TEST_FINISH();
}

static seos_err_t
do_export(
    SeosCryptoApiH                hCrypto,
    const SeosCryptoApi_Mode      mode,
    const bool                    expo,
    const SeosCryptoApi_Key_Data* data)
{
    seos_err_t err;
    SeosCryptoApi_KeyH hKey;
    SeosCryptoApi_Key_Data expData;

    TEST_SUCCESS(SeosCryptoApi_Key_import(&hKey, hCrypto, data));
    TEST_LOCACTION_EXP(mode, expo, hKey);

    memset(&expData, 0, sizeof(SeosCryptoApi_Key_Data));
    if ((err = SeosCryptoApi_Key_export(hKey, &expData)) != SEOS_SUCCESS)
    {
        return err;
    }

    TEST_TRUE(!memcmp(data, &expData, sizeof(SeosCryptoApi_Key_Data)));
    TEST_SUCCESS(SeosCryptoApi_Key_free(hKey));

    return SEOS_SUCCESS;
}

static void
test_SeosCryptoApi_Key_export_pos(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode,
    const bool               expo)
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
test_SeosCryptoApi_Key_export_neg(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode,
    const bool               expo)
{
    SeosCryptoApi_KeyH hKey;
    SeosCryptoApi_Key_Data expData;
    SeosCryptoApi_Key_Spec aes128noExpSpec =
    {
        .type = SeosCryptoApi_Key_SPECTYPE_BITS,
        .key = {
            .type = SeosCryptoApi_Key_TYPE_AES,
            .attribs.exportable = false,
            .params.bits = 128
        }
    };

    TEST_START(mode, expo);

    TEST_SUCCESS(SeosCryptoApi_Key_import(&hKey, hCrypto, &aes128Data));

    // Empty key
    TEST_INVAL_PARAM(SeosCryptoApi_Key_export(NULL, &expData));

    // Empty export data buffer
    TEST_INVAL_PARAM(SeosCryptoApi_Key_export(hKey, NULL));

    TEST_SUCCESS(SeosCryptoApi_Key_free(hKey));

    // Non-exportable key
    TEST_SUCCESS(SeosCryptoApi_Key_generate(&hKey, hCrypto, &aes128noExpSpec));

    if (mode == SeosCryptoApi_Mode_LIBRARY)
    {
        /*
         * A library instance will store all keys in memory which is shared with the
         * host component. Therefore, if the API runs in library mode, it will ALWAYS
         * allow exports, even if the key is marked as "non exportable".
         */
        TEST_SUCCESS(SeosCryptoApi_Key_export(hKey, &expData));
    }
    else
    {
        /*
         * It is assumed that all other modes of the Crypto API respect the
         * exportable flag and thus deny the operation.
         */
        TEST_OP_DENIED(SeosCryptoApi_Key_export(hKey, &expData));
    }

    TEST_SUCCESS(SeosCryptoApi_Key_free(hKey));

    TEST_FINISH();
}

static seos_err_t
do_generate(
    SeosCryptoApiH                hCrypto,
    const SeosCryptoApi_Mode      mode,
    const bool                    expo,
    const SeosCryptoApi_Key_Spec* spec)
{
    seos_err_t err;
    SeosCryptoApi_KeyH hKey;
    SeosCryptoApi_Key_Data expData;

    if ((err = SeosCryptoApi_Key_generate(&hKey, hCrypto, spec)) != SEOS_SUCCESS)
    {
        return err;
    }
    TEST_LOCACTION_EXP(mode, expo, hKey);

    memset(&expData, 0, sizeof(SeosCryptoApi_Key_Data));
    if (expo)
    {
        TEST_SUCCESS(SeosCryptoApi_Key_export(hKey, &expData));
        TEST_TRUE(spec->key.type == expData.type);
        TEST_TRUE(!memcmp(&spec->key.attribs, &expData.attribs,
                          sizeof(SeosCryptoApi_Key_Attribs)));
        if (spec->type == SeosCryptoApi_Key_SPECTYPE_PARAMS)
        {
            switch (spec->key.type)
            {
            case SeosCryptoApi_Key_TYPE_DH_PRV:
                TEST_TRUE(!memcmp(&spec->key.params, &expData.data.dh.prv.params,
                                  sizeof(SeosCryptoApi_Key_DhParams)));
                break;
            default:
                TEST_TRUE(1 == 0);
            }
        }
    }
    else
    {
        TEST_OP_DENIED(SeosCryptoApi_Key_export(hKey, &expData));
    }

    TEST_SUCCESS(SeosCryptoApi_Key_free(hKey));

    return SEOS_SUCCESS;
}

static void
test_SeosCryptoApi_Key_generate_pos(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode,
    const bool               expo)
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
test_SeosCryptoApi_Key_generate_neg(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode,
    const bool               expo)
{
    SeosCryptoApi_KeyH hKey;

    TEST_START(mode, expo);

    // Empty crypto handle
    TEST_INVAL_PARAM(SeosCryptoApi_Key_generate(NULL, hCrypto, &aes128Spec));

    // Empty key handle
    TEST_INVAL_PARAM(SeosCryptoApi_Key_generate(&hKey, NULL, &aes128Spec));

    // Empty key spec
    TEST_INVAL_PARAM(SeosCryptoApi_Key_generate(&hKey, hCrypto, NULL));

    // Wrong key size: 120-bit AES key
    TEST_INVAL_PARAM(SeosCryptoApi_Key_generate(&hKey, hCrypto, &aes120Spec));

    // Wrong key size: 127-bit RSA key
    TEST_NOT_SUPP(SeosCryptoApi_Key_generate(&hKey, hCrypto, &rsa127Spec));

    // Wrong key size: 63-bit DH key
    TEST_NOT_SUPP(SeosCryptoApi_Key_generate(&hKey, hCrypto, &dh63bSpec));

    TEST_FINISH();
}

static seos_err_t
do_makePublic(
    SeosCryptoApiH                hCrypto,
    const SeosCryptoApi_Mode      mode,
    const bool                    expo,
    const SeosCryptoApi_Key_Spec* spec)
{
    seos_err_t err;
    SeosCryptoApi_KeyH hPrvKey, hPubKey;
    SeosCryptoApi_Key_Data expData;

    TEST_SUCCESS(SeosCryptoApi_Key_generate(&hPrvKey, hCrypto, spec));
    TEST_LOCACTION_EXP(mode, expo, hPrvKey);
    if ((err = SeosCryptoApi_Key_makePublic(&hPubKey, hCrypto, hPrvKey,
                                            &spec->key.attribs)) != SEOS_SUCCESS)
    {
        return err;
    }

    if (expo)
    {
        TEST_SUCCESS(SeosCryptoApi_Key_export(hPubKey, &expData));
        TEST_LOCACTION_EXP(mode, expo, hPubKey);
        switch (spec->key.type)
        {
        case SeosCryptoApi_Key_TYPE_RSA_PRV:
            TEST_TRUE(expData.type == SeosCryptoApi_Key_TYPE_RSA_PUB);
            break;
        case SeosCryptoApi_Key_TYPE_DH_PRV:
            TEST_TRUE(expData.type == SeosCryptoApi_Key_TYPE_DH_PUB);
            if (SeosCryptoApi_Key_SPECTYPE_PARAMS == spec->type)
            {
                TEST_TRUE(!memcmp(&expData.data.dh.pub.params, &spec->key.params.dh,
                                  sizeof(SeosCryptoApi_Key_DhParams)));
            }
            break;
        case SeosCryptoApi_Key_TYPE_SECP256R1_PRV:
            TEST_TRUE(expData.type == SeosCryptoApi_Key_TYPE_SECP256R1_PUB);
            break;
        default:
            TEST_TRUE(1 == 0);
        }
    }
    else
    {
        TEST_OP_DENIED(SeosCryptoApi_Key_export(hPubKey, &expData));
    }

    TEST_SUCCESS(SeosCryptoApi_Key_free(hPubKey));
    TEST_SUCCESS(SeosCryptoApi_Key_free(hPrvKey));

    return SEOS_SUCCESS;

}
static void
test_SeosCryptoApi_Key_makePublic_pos(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode,
    const bool               expo)
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
test_SeosCryptoApi_Key_makePublic_neg(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode,
    const bool               expo)
{
    SeosCryptoApi_KeyH hPrvKey, hPubKey;

    TEST_START(mode, expo);

    TEST_SUCCESS(SeosCryptoApi_Key_generate(&hPrvKey, hCrypto, &dh64bSpec));

    // Empty target handle
    TEST_INVAL_PARAM(SeosCryptoApi_Key_makePublic(NULL, hCrypto, hPrvKey,
                                                  &dh64bSpec.key.attribs));

    // Empty crypto handle
    TEST_INVAL_PARAM(SeosCryptoApi_Key_makePublic(&hPubKey, NULL, hPrvKey,
                                                  &dh64bSpec.key.attribs));

    // Empty private handle
    TEST_INVAL_HANDLE(SeosCryptoApi_Key_makePublic(&hPubKey, hCrypto, NULL,
                                                   &dh64bSpec.key.attribs));

    // Empty attribs
    TEST_INVAL_PARAM(SeosCryptoApi_Key_makePublic(&hPubKey, hCrypto, hPrvKey,
                                                  NULL));

    TEST_SUCCESS(SeosCryptoApi_Key_free(hPrvKey));

    // Try making "public" from a symmetric key
    TEST_SUCCESS(SeosCryptoApi_Key_generate(&hPrvKey, hCrypto, &aes128Spec));
    TEST_LOCACTION_EXP(mode, expo, hPrvKey);
    TEST_INVAL_PARAM(SeosCryptoApi_Key_makePublic(&hPubKey, hCrypto, hPrvKey,
                                                  NULL));
    TEST_SUCCESS(SeosCryptoApi_Key_free(hPrvKey));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Key_getParams_pos(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode,
    const bool               expo)
{
    size_t n;
    SeosCryptoApi_KeyH hKey;
    SeosCryptoApi_Key_DhParams dhParams;
    SeosCryptoApi_Key_Data expData;

    TEST_START(mode, expo);

    // Generate params for DH
    TEST_SUCCESS(SeosCryptoApi_Key_generate(&hKey, hCrypto, &dh101pSpec));
    TEST_LOCACTION_EXP(mode, expo, hKey);
    n = sizeof(dhParams);
    TEST_SUCCESS(SeosCryptoApi_Key_getParams(hKey, &dhParams, &n));
    TEST_TRUE(n == sizeof(dhParams));
    if (expo)
    {
        TEST_SUCCESS(SeosCryptoApi_Key_export(hKey, &expData));
        TEST_TRUE(!memcmp(&expData.data.dh.prv.params, &dhParams, n));
    }
    else
    {
        TEST_OP_DENIED(SeosCryptoApi_Key_export(hKey, &expData));
    }
    TEST_SUCCESS(SeosCryptoApi_Key_free(hKey));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Key_getParams_neg(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode,
    const bool               expo)
{
    size_t n;
    SeosCryptoApi_KeyH hKey;
    SeosCryptoApi_Key_DhParams dhParams;

    TEST_START(mode, expo);

    TEST_SUCCESS(SeosCryptoApi_Key_generate(&hKey, hCrypto, &dh64bSpec));
    TEST_LOCACTION_EXP(mode, expo, hKey);

    // Empty key handle
    n = sizeof(dhParams);
    TEST_INVAL_PARAM(SeosCryptoApi_Key_getParams(NULL, &dhParams, &n));

    // Empty buffer
    TEST_INVAL_PARAM(SeosCryptoApi_Key_getParams(hKey, NULL, &n));

    // Empty buffer len
    TEST_INVAL_PARAM(SeosCryptoApi_Key_getParams(hKey, &dhParams, NULL));

    // Too small buffer len
    n = 17;
    TEST_TOO_SMALL(SeosCryptoApi_Key_getParams(hKey, &dhParams, &n));

    TEST_SUCCESS(SeosCryptoApi_Key_free(hKey));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Key_loadParams_pos(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode,
    const bool               expo)
{
    size_t n;
    SeosCryptoApi_Key_EccParams eccParams;

    TEST_START(mode, expo);

    // Load SECP192r1
    n = sizeof(eccParams);
    TEST_SUCCESS(SeosCryptoApi_Key_loadParams(hCrypto,
                                              SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                              &eccParams, &n));
    TEST_TRUE(n == sizeof(eccParams));

    // Load SECP224r1
    TEST_SUCCESS(SeosCryptoApi_Key_loadParams(hCrypto,
                                              SeosCryptoApi_Key_PARAM_ECC_SECP224R1,
                                              &eccParams, &n));
    TEST_TRUE(n == sizeof(eccParams));

    // Load SECP256r1
    TEST_SUCCESS(SeosCryptoApi_Key_loadParams(hCrypto,
                                              SeosCryptoApi_Key_PARAM_ECC_SECP256R1,
                                              &eccParams, &n));
    TEST_TRUE(n == sizeof(eccParams));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Key_loadParams_neg(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode,
    const bool               expo)
{
    size_t n;
    SeosCryptoApi_Key_EccParams eccParams;

    TEST_START(mode, expo);

    // Empty context
    n = sizeof(eccParams);
    TEST_INVAL_PARAM(SeosCryptoApi_Key_loadParams(NULL,
                                                  SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                                  &eccParams, &n));

    // Wrong param name
    TEST_NOT_SUPP(SeosCryptoApi_Key_loadParams(hCrypto, 666, &eccParams, &n));

    // Empty buffer
    TEST_INVAL_PARAM(SeosCryptoApi_Key_loadParams(hCrypto,
                                                  SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                                  NULL, &n));

    // Empty length
    TEST_INVAL_PARAM(SeosCryptoApi_Key_loadParams(hCrypto,
                                                  SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                                  &eccParams, NULL));

    // To small buffer
    n = 17;
    TEST_TOO_SMALL(SeosCryptoApi_Key_loadParams(hCrypto,
                                                SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                                &eccParams, &n));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Key_getAttribs_pos(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode,
    const bool               expo)
{
    SeosCryptoApi_KeyH hKey;
    SeosCryptoApi_Key_Attribs attribs;

    TEST_START(mode, expo);

    TEST_SUCCESS(SeosCryptoApi_Key_import(&hKey, hCrypto, &aes128Data));

    // Get attribs of key and make sure it matches the imported data
    memset(&attribs, 0, sizeof(SeosCryptoApi_Key_Attribs));
    TEST_SUCCESS(SeosCryptoApi_Key_getAttribs(hKey, &attribs));
    TEST_TRUE(!memcmp(&attribs, &aes128Data.attribs,
                      sizeof(SeosCryptoApi_Key_Attribs)));

    TEST_SUCCESS(SeosCryptoApi_Key_free(hKey));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Key_getAttribs_neg(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode,
    const bool               expo)
{
    SeosCryptoApi_KeyH hKey;
    SeosCryptoApi_Key_Attribs attribs;

    TEST_START(mode, expo);

    TEST_SUCCESS(SeosCryptoApi_Key_import(&hKey, hCrypto, &aes128Data));

    // Empty key object
    TEST_INVAL_PARAM(SeosCryptoApi_Key_getAttribs(NULL, &attribs));

    // Empty attrib buffer
    TEST_INVAL_PARAM(SeosCryptoApi_Key_getAttribs(hKey, NULL));

    TEST_SUCCESS(SeosCryptoApi_Key_free(hKey));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Key_free_pos(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode,
    const bool               expo)
{
    SeosCryptoApi_KeyH hKey;

    TEST_START(mode, expo);

    TEST_SUCCESS(SeosCryptoApi_Key_generate(&hKey, hCrypto, &aes128Spec));
    TEST_LOCACTION_EXP(mode, expo, hKey);
    TEST_SUCCESS(SeosCryptoApi_Key_free(hKey));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Key_free_neg(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode,
    const bool               expo)
{
    SeosCryptoApi_KeyH hKey;

    TEST_START(mode, expo);

    TEST_SUCCESS(SeosCryptoApi_Key_generate(&hKey, hCrypto, &aes128Spec));
    TEST_LOCACTION_EXP(mode, expo, hKey);

    // Empty key
    TEST_INVAL_PARAM(SeosCryptoApi_Key_free(NULL));

    TEST_SUCCESS(SeosCryptoApi_Key_free(hKey));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Key_getParams_buffer(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode,
    const bool               expo)
{
    SeosCryptoApi_KeyH hKey;
    static unsigned char paramBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    size_t paramLen;

    TEST_START(mode, expo);

    TEST_SUCCESS(SeosCryptoApi_Key_generate(&hKey, hCrypto, &dh101pSpec));
    TEST_LOCACTION_EXP(mode, expo, hKey);

    // Should be OK and give the correct length
    paramLen = SeosCryptoApi_SIZE_DATAPORT;
    TEST_SUCCESS(SeosCryptoApi_Key_getParams(hKey, paramBuf, &paramLen));
    TEST_TRUE(paramLen == sizeof(SeosCryptoApi_Key_DhParams));

    // Should fail but give the correct length
    paramLen = 10;
    TEST_TOO_SMALL(SeosCryptoApi_Key_getParams(hKey, paramBuf, &paramLen));
    TEST_TRUE(paramLen == sizeof(SeosCryptoApi_Key_DhParams));

    // Should fail due buffer being too big
    paramLen = SeosCryptoApi_SIZE_DATAPORT + 1;
    TEST_INSUFF_SPACE(SeosCryptoApi_Key_getParams(hKey, paramBuf, &paramLen));

    TEST_SUCCESS(SeosCryptoApi_Key_free(hKey));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Key_loadParams_buffer(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode,
    const bool               expo)
{
    static unsigned char paramBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    size_t paramLen;

    TEST_START(mode, expo);

    // Should be OK
    paramLen = SeosCryptoApi_SIZE_DATAPORT;
    TEST_SUCCESS(SeosCryptoApi_Key_loadParams(hCrypto,
                                              SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                              paramBuf, &paramLen));
    TEST_TRUE(paramLen == sizeof(SeosCryptoApi_Key_EccParams));

    // Should fail, but give the minimum size
    paramLen = 10;
    TEST_TOO_SMALL(SeosCryptoApi_Key_loadParams(hCrypto,
                                                SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                                paramBuf, &paramLen));
    TEST_TRUE(paramLen == sizeof(SeosCryptoApi_Key_EccParams));

    // Should fail because buffer is too big
    paramLen = SeosCryptoApi_SIZE_DATAPORT + 1;
    TEST_INSUFF_SPACE(SeosCryptoApi_Key_loadParams(hCrypto,
                                                   SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                                   paramBuf, &paramLen));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Key_migrate_pos(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode,
    const bool               expo)
{
    SeosCryptoApi_KeyH hKey;
    SeosCryptoLib_Object ptr;

    TEST_START(mode, expo);

    // Let the remote side load a key into its address space, then migrate
    // it so it can be used through our API instance
    TEST_SUCCESS(CryptoRpcServer_loadKey(&ptr));
    TEST_SUCCESS(SeosCryptoApi_migrateObject(&hKey, hCrypto, ptr));

    TEST_SUCCESS(SeosCryptoApi_Key_free(hKey));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Key_migrate_neg(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode,
    const bool               expo)
{
    SeosCryptoApi_KeyH hKey;
    SeosCryptoLib_Object ptr;

    TEST_START(mode, expo);

    TEST_SUCCESS(CryptoRpcServer_loadKey(&ptr));

    // Empty key
    TEST_INVAL_PARAM(SeosCryptoApi_migrateObject(NULL, hCrypto, ptr));

    // Empty ctx
    TEST_INVAL_PARAM(SeosCryptoApi_migrateObject(&hKey, NULL, ptr));

    // Invalid remote pointer
    TEST_INVAL_HANDLE(SeosCryptoApi_migrateObject(&hKey, hCrypto, NULL));

    TEST_FINISH();
}

void test_SeosCryptoApi_Key(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode)
{
    bool expo = true;

    keyData_setExportable(keyDataList, expo);
    keySpec_setExportable(keySpecList, expo);

    test_SeosCryptoApi_Key_import_pos(hCrypto, mode, expo);
    test_SeosCryptoApi_Key_import_neg(hCrypto, mode, expo);

    test_SeosCryptoApi_Key_export_pos(hCrypto, mode, expo);
    test_SeosCryptoApi_Key_export_neg(hCrypto, mode, expo);

    test_SeosCryptoApi_Key_generate_pos(hCrypto, mode, expo);
    test_SeosCryptoApi_Key_generate_neg(hCrypto, mode, expo);

    test_SeosCryptoApi_Key_makePublic_pos(hCrypto, mode, expo);
    test_SeosCryptoApi_Key_makePublic_neg(hCrypto, mode, expo);

    test_SeosCryptoApi_Key_getParams_pos(hCrypto, mode, expo);
    test_SeosCryptoApi_Key_getParams_neg(hCrypto, mode, expo);

    test_SeosCryptoApi_Key_loadParams_pos(hCrypto, mode, expo);
    test_SeosCryptoApi_Key_loadParams_neg(hCrypto, mode, expo);

    test_SeosCryptoApi_Key_getAttribs_pos(hCrypto, mode, expo);
    test_SeosCryptoApi_Key_getAttribs_neg(hCrypto, mode, expo);

    test_SeosCryptoApi_Key_free_pos(hCrypto, mode, expo);
    test_SeosCryptoApi_Key_free_neg(hCrypto, mode, expo);

    test_SeosCryptoApi_Key_getParams_buffer(hCrypto, mode, expo);
    test_SeosCryptoApi_Key_loadParams_buffer(hCrypto, mode, expo);

    // Make all used keys NON-EXPORTABLE and re-run parts of the tests
    if (mode == SeosCryptoApi_Mode_ROUTER)
    {
        expo = false;
        keyData_setExportable(keyDataList, expo);
        keySpec_setExportable(keySpecList, expo);

        test_SeosCryptoApi_Key_import_pos(hCrypto, mode, expo);
        test_SeosCryptoApi_Key_generate_pos(hCrypto, mode, expo);
        test_SeosCryptoApi_Key_makePublic_pos(hCrypto, mode, expo);
        test_SeosCryptoApi_Key_getParams_pos(hCrypto, mode, expo);
        test_SeosCryptoApi_Key_loadParams_pos(hCrypto, mode, expo);
    }

    // Migration is only useful when done not locally, as we need to migrate
    // a key created on the remote side to use it with the local API instance.
    // NOTE: These test require the remote instance to be initialized.
    if (mode == SeosCryptoApi_Mode_ROUTER ||
        mode == SeosCryptoApi_Mode_RPC_CLIENT)
    {
        test_SeosCryptoApi_Key_migrate_pos(hCrypto, mode, expo);
        test_SeosCryptoApi_Key_migrate_neg(hCrypto, mode, expo);
    }
}