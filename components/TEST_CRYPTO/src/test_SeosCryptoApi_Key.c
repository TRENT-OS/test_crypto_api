/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoApi.h"

#include "ObjectLocation.h"
#include "SharedKeys.h"
#include "TestMacros.h"

#include <string.h>

static bool allowExport;
#define TEST_LOCATION(api, o) \
    Debug_ASSERT_OBJ_LOCATION(api, allowExport, o.key)

// -----------------------------------------------------------------------------

static seos_err_t
do_import(
    SeosCryptoApi*                api,
    const SeosCryptoApi_Key_Data* data)
{
    seos_err_t err;
    SeosCryptoApi_Key key;

    if ((err = SeosCryptoApi_Key_import(api, &key, data)) != SEOS_SUCCESS)
    {
        return err;
    }

    TEST_LOCATION(api, key);
    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));

    return SEOS_SUCCESS;
}

static void
test_SeosCryptoApi_Key_import_pos(
    SeosCryptoApi* api)
{
    // Import 128-bit AES key
    TEST_SUCCESS(do_import(api, &aes128Data));

    // Import 192-bit AES key
    TEST_SUCCESS(do_import(api, &aes192Data));

    // Import 256-bit AES key
    TEST_SUCCESS(do_import(api, &aes256Data));

    // Import 1024-bit RSA pubkey
    TEST_SUCCESS(do_import(api, &rsa1024PubData));

    // Import 1024-bit RSA prvkey
    TEST_SUCCESS(do_import(api, &rsa1024PrvData));

    // Import 101-bit DH pubkey
    TEST_SUCCESS(do_import(api, &dh101PubData));

    // Import 101-bit DH RSA prvkey
    TEST_SUCCESS(do_import(api, &dh101PrvData));

    // Import SECP256r1 pubkey
    TEST_SUCCESS(do_import(api, &secp256r1PubData));

    // Import SECP256r1 prvkey
    TEST_SUCCESS(do_import(api, &secp256r1PrvData));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_import_neg(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key key;

    // Empty api
    TEST_INVAL_PARAM(SeosCryptoApi_Key_import(NULL, &key, &aes128Data));

    // Empty key
    TEST_INVAL_PARAM(SeosCryptoApi_Key_import(api, NULL, &aes128Data));

    // Empty key data
    TEST_INVAL_PARAM(SeosCryptoApi_Key_import(api, &key, NULL));

    // Invalid AES key
    TEST_INVAL_PARAM(SeosCryptoApi_Key_import(api, &key, &aes120Data));

    // Invalid RSA key (too small)
    TEST_NOT_SUPP(SeosCryptoApi_Key_import(api, &key, &rsaSmallData));

    // Invalid RSA key (too big)
    TEST_INVAL_PARAM(SeosCryptoApi_Key_import(api, &key, &rsaLargeData));

    TEST_OK(api->mode, allowExport);
}

static seos_err_t
do_export(
    SeosCryptoApi*                api,
    const SeosCryptoApi_Key_Data* data)
{
    seos_err_t err;
    SeosCryptoApi_Key key;
    SeosCryptoApi_Key_Data expData;

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &key, data));
    TEST_LOCATION(api, key);

    memset(&expData, 0, sizeof(SeosCryptoApi_Key_Data));
    if ((err = SeosCryptoApi_Key_export(&key, &expData)) != SEOS_SUCCESS)
    {
        return err;
    }

    TEST_TRUE(!memcmp(data, &expData, sizeof(SeosCryptoApi_Key_Data)));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));

    return SEOS_SUCCESS;
}

static void
test_SeosCryptoApi_Key_export_pos(
    SeosCryptoApi* api)
{
    // Export 128-bit AES key
    TEST_SUCCESS(do_export(api, &aes128Data));

    // Export 192-bit AES key
    TEST_SUCCESS(do_export(api, &aes192Data));

    // Export 256-bit AES key
    TEST_SUCCESS(do_export(api, &aes256Data));

    // Export 1024-bit RSA pubkey
    TEST_SUCCESS(do_export(api, &rsa1024PubData));

    // Export 1024-bit RSA prvkey
    TEST_SUCCESS(do_export(api, &rsa1024PrvData));

    // Export 101-bit DH pubkey
    TEST_SUCCESS(do_export(api, &dh101PubData));

    // Export 101-bit DH prvkey
    TEST_SUCCESS(do_export(api, &dh101PrvData));

    // Export SECP256r1 pubkey
    TEST_SUCCESS(do_export(api, &secp256r1PubData));

    // Export SECP256r1 prvkey
    TEST_SUCCESS(do_export(api, &secp256r1PrvData));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_export_neg(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key key;
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

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &key, &aes128Data));

    // Empty key
    TEST_INVAL_PARAM(SeosCryptoApi_Key_export(NULL, &expData));

    // Empty export data buffer
    TEST_INVAL_PARAM(SeosCryptoApi_Key_export(&key, NULL));

    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));

    // Non-exportable key
    TEST_SUCCESS(SeosCryptoApi_Key_generate(api, &key, &aes128noExpSpec));

    if (api->mode == SeosCryptoApi_Mode_LIBRARY)
    {
        /*
         * A library instance will store all keys in memory which is shared with the
         * host component. Therefore, if the API runs in library mode, it will ALWAYS
         * allow exports, even if the key is marked as "non exportable".
         */
        TEST_SUCCESS(SeosCryptoApi_Key_export(&key, &expData));
    }
    else
    {
        /*
         * It is assumed that all other modes of the Crypto API respect the
         * exportable flag and thus deny the operation.
         */
        TEST_OP_DENIED(SeosCryptoApi_Key_export(&key, &expData));
    }

    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));

    TEST_OK(api->mode, allowExport);
}

static seos_err_t
do_generate(
    SeosCryptoApi*                api,
    const SeosCryptoApi_Key_Spec* spec)
{
    seos_err_t err;
    SeosCryptoApi_Key key;
    SeosCryptoApi_Key_Data expData;

    if ((err = SeosCryptoApi_Key_generate(api, &key, spec)) != SEOS_SUCCESS)
    {
        return err;
    }
    TEST_LOCATION(api, key);

    memset(&expData, 0, sizeof(SeosCryptoApi_Key_Data));
    if (allowExport)
    {
        TEST_SUCCESS(SeosCryptoApi_Key_export(&key, &expData));
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
        TEST_OP_DENIED(SeosCryptoApi_Key_export(&key, &expData));
    }

    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));

    return SEOS_SUCCESS;
}

static void
test_SeosCryptoApi_Key_generate_pos(
    SeosCryptoApi* api)
{
    // Generate 128-bit AES key
    TEST_SUCCESS(do_generate(api, &aes128Spec));

    // Generate 192-bit AES key
    TEST_SUCCESS(do_generate(api, &aes192Spec));

    // Generate 256-bit AES key
    TEST_SUCCESS(do_generate(api, &aes256Spec));

    // Generate 64-bit DH privkey from bit spec
    TEST_SUCCESS(do_generate(api, &dh64bSpec));

    // Generate 101-bit DH privkey from param spec
    TEST_SUCCESS(do_generate(api, &dh101pSpec));

    // Generate 128-bit RSA privkey
    TEST_SUCCESS(do_generate(api, &rsa128Spec));

    // Generate SECP256r1 privkey
    TEST_SUCCESS(do_generate(api, &secp256r1Spec));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_generate_neg(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key key;

    // Empty api
    TEST_INVAL_PARAM(SeosCryptoApi_Key_generate(NULL, &key, &aes128Spec));

    // Empty key
    TEST_INVAL_PARAM(SeosCryptoApi_Key_generate(api, NULL, &aes128Spec));

    // Empty spec
    TEST_INVAL_PARAM(SeosCryptoApi_Key_generate(api, &key, NULL));

    // Wrong key size: 120-bit AES key
    TEST_INVAL_PARAM(SeosCryptoApi_Key_generate(api, &key, &aes120Spec));

    // Wrong key size: 127-bit RSA key
    TEST_NOT_SUPP(SeosCryptoApi_Key_generate(api, &key, &rsa127Spec));

    // Wrong key size: 63-bit DH key
    TEST_NOT_SUPP(SeosCryptoApi_Key_generate(api, &key, &dh63bSpec));

    TEST_OK(api->mode, allowExport);
}

static seos_err_t
do_makePublic(
    SeosCryptoApi*                api,
    const SeosCryptoApi_Key_Spec* spec)
{
    seos_err_t err;
    SeosCryptoApi_Key key, pubKey;
    SeosCryptoApi_Key_Data expData;

    TEST_SUCCESS(SeosCryptoApi_Key_generate(api, &key, spec));
    TEST_LOCATION(api, key);
    if ((err = SeosCryptoApi_Key_makePublic(&pubKey, &key,
                                            &spec->key.attribs)) != SEOS_SUCCESS)
    {
        return err;
    }

    if (allowExport)
    {
        TEST_SUCCESS(SeosCryptoApi_Key_export(&pubKey, &expData));
        TEST_LOCATION(api, pubKey);
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
        TEST_OP_DENIED(SeosCryptoApi_Key_export(&pubKey, &expData));
    }

    TEST_SUCCESS(SeosCryptoApi_Key_free(&pubKey));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));

    return SEOS_SUCCESS;

}
static void
test_SeosCryptoApi_Key_makePublic_pos(
    SeosCryptoApi* api)
{
    // Make DH pubkey, with privkey from bit spec
    TEST_SUCCESS(do_makePublic(api, &dh64bSpec));

    // Make DH pubkey, with privkey from param spec
    TEST_SUCCESS(do_makePublic(api, &dh101pSpec));

    // Make RSA pubkey
    TEST_SUCCESS(do_makePublic(api, &rsa128Spec));

    // Make SECP256r1 pubkey
    TEST_SUCCESS(do_makePublic(api, &secp256r1Spec));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_makePublic_neg(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key key, pubKey;

    TEST_SUCCESS(SeosCryptoApi_Key_generate(api, &key, &dh64bSpec));

    // Empty target handle
    TEST_INVAL_PARAM(SeosCryptoApi_Key_makePublic(NULL, &key,
                                                  &dh64bSpec.key.attribs));

    // Invalid private handle
    TEST_INVAL_PARAM(SeosCryptoApi_Key_makePublic(&pubKey, NULL,
                                                  &dh64bSpec.key.attribs));

    // Empty attribs
    TEST_INVAL_PARAM(SeosCryptoApi_Key_makePublic(&pubKey, &key, NULL));

    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));

    // Try making "public" from a symmetric key
    TEST_SUCCESS(SeosCryptoApi_Key_generate(api, &key, &aes128Spec));
    TEST_LOCATION(api, key);
    TEST_INVAL_PARAM(SeosCryptoApi_Key_makePublic(&pubKey, &key, NULL));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_getParams_pos(
    SeosCryptoApi* api)
{
    size_t n;
    SeosCryptoApi_Key key;
    SeosCryptoApi_Key_DhParams dhParams;
    SeosCryptoApi_Key_Data expData;

    // Generate params for DH
    TEST_SUCCESS(SeosCryptoApi_Key_generate(api, &key, &dh101pSpec));
    TEST_LOCATION(api, key);
    n = sizeof(dhParams);
    TEST_SUCCESS(SeosCryptoApi_Key_getParams(&key, &dhParams, &n));
    TEST_TRUE(n == sizeof(dhParams));
    if (allowExport)
    {
        TEST_SUCCESS(SeosCryptoApi_Key_export(&key, &expData));
        TEST_TRUE(!memcmp(&expData.data.dh.prv.params, &dhParams, n));
    }
    else
    {
        TEST_OP_DENIED(SeosCryptoApi_Key_export(&key, &expData));
    }
    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_getParams_neg(
    SeosCryptoApi* api)
{
    size_t n;
    SeosCryptoApi_Key key;
    SeosCryptoApi_Key_DhParams dhParams;

    TEST_SUCCESS(SeosCryptoApi_Key_generate(api, &key, &dh64bSpec));
    TEST_LOCATION(api, key);

    // Empty key handle
    n = sizeof(dhParams);
    TEST_INVAL_PARAM(SeosCryptoApi_Key_getParams(NULL, &dhParams, &n));

    // Empty buffer
    TEST_INVAL_PARAM(SeosCryptoApi_Key_getParams(&key, NULL, &n));

    // Empty buffer len
    TEST_INVAL_PARAM(SeosCryptoApi_Key_getParams(&key, &dhParams, NULL));

    // Too small buffer len
    n = 17;
    TEST_TOO_SMALL(SeosCryptoApi_Key_getParams(&key, &dhParams, &n));

    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_loadParams_pos(
    SeosCryptoApi* api)
{
    size_t n;
    SeosCryptoApi_Key_EccParams eccParams;

    // Load SECP192r1
    n = sizeof(eccParams);
    TEST_SUCCESS(SeosCryptoApi_Key_loadParams(api,
                                              SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                              &eccParams, &n));
    TEST_TRUE(n == sizeof(eccParams));

    // Load SECP224r1
    TEST_SUCCESS(SeosCryptoApi_Key_loadParams(api,
                                              SeosCryptoApi_Key_PARAM_ECC_SECP224R1,
                                              &eccParams, &n));
    TEST_TRUE(n == sizeof(eccParams));

    // Load SECP256r1
    TEST_SUCCESS(SeosCryptoApi_Key_loadParams(api,
                                              SeosCryptoApi_Key_PARAM_ECC_SECP256R1,
                                              &eccParams, &n));
    TEST_TRUE(n == sizeof(eccParams));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_loadParams_neg(
    SeosCryptoApi* api)
{
    size_t n;
    SeosCryptoApi_Key_EccParams eccParams;

    // Empty context
    n = sizeof(eccParams);
    TEST_INVAL_PARAM(SeosCryptoApi_Key_loadParams(NULL,
                                                  SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                                  &eccParams, &n));

    // Wrong param name
    TEST_NOT_SUPP(SeosCryptoApi_Key_loadParams(api, 666, &eccParams, &n));

    // Empty buffer
    TEST_INVAL_PARAM(SeosCryptoApi_Key_loadParams(api,
                                                  SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                                  NULL, &n));

    // Empty length
    TEST_INVAL_PARAM(SeosCryptoApi_Key_loadParams(api,
                                                  SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                                  &eccParams, NULL));

    // To small buffer
    n = 17;
    TEST_TOO_SMALL(SeosCryptoApi_Key_loadParams(api,
                                                SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                                &eccParams, &n));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_free_pos(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key key;

    TEST_SUCCESS(SeosCryptoApi_Key_generate(api, &key, &aes128Spec));
    TEST_LOCATION(api, key);
    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_free_neg(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key key;

    TEST_SUCCESS(SeosCryptoApi_Key_generate(api, &key, &aes128Spec));
    TEST_LOCATION(api, key);

    // Empty key
    TEST_INVAL_PARAM(SeosCryptoApi_Key_free(NULL));

    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_getParams_buffer(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key key;
    static unsigned char paramBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    size_t paramLen;

    TEST_SUCCESS(SeosCryptoApi_Key_generate(api, &key, &dh101pSpec));
    TEST_LOCATION(api, key);

    // Should be OK and give the correct length
    paramLen = SeosCryptoApi_SIZE_DATAPORT;
    TEST_SUCCESS(SeosCryptoApi_Key_getParams(&key, paramBuf, &paramLen));
    TEST_TRUE(paramLen == sizeof(SeosCryptoApi_Key_DhParams));

    // Should fail but give the correct length
    paramLen = 10;
    TEST_TOO_SMALL(SeosCryptoApi_Key_getParams(&key, paramBuf, &paramLen));
    TEST_TRUE(paramLen == sizeof(SeosCryptoApi_Key_DhParams));

    // Should fail due buffer being too big
    paramLen = SeosCryptoApi_SIZE_DATAPORT + 1;
    TEST_INSUFF_SPACE(SeosCryptoApi_Key_getParams(&key, paramBuf, &paramLen));

    TEST_SUCCESS(SeosCryptoApi_Key_free(&key));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_loadParams_buffer(
    SeosCryptoApi* api)
{
    static unsigned char paramBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    size_t paramLen;

    // Should be OK
    paramLen = SeosCryptoApi_SIZE_DATAPORT;
    TEST_SUCCESS(SeosCryptoApi_Key_loadParams(api,
                                              SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                              paramBuf, &paramLen));
    TEST_TRUE(paramLen == sizeof(SeosCryptoApi_Key_EccParams));

    // Should fail, but give the minimum size
    paramLen = 10;
    TEST_TOO_SMALL(SeosCryptoApi_Key_loadParams(api,
                                                SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                                paramBuf, &paramLen));
    TEST_TRUE(paramLen == sizeof(SeosCryptoApi_Key_EccParams));

    // Should fail because buffer is too big
    paramLen = SeosCryptoApi_SIZE_DATAPORT + 1;
    TEST_INSUFF_SPACE(SeosCryptoApi_Key_loadParams(api,
                                                   SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                                   paramBuf, &paramLen));

    TEST_OK(api->mode, allowExport);
}

void test_SeosCryptoApi_Key(
    SeosCryptoApi* api)
{
    allowExport = true;
    keyData_setExportable(keyDataList, allowExport);
    keySpec_setExportable(keySpecList, allowExport);

    test_SeosCryptoApi_Key_import_pos(api);
    test_SeosCryptoApi_Key_import_neg(api);

    test_SeosCryptoApi_Key_export_pos(api);
    test_SeosCryptoApi_Key_export_neg(api);

    test_SeosCryptoApi_Key_generate_pos(api);
    test_SeosCryptoApi_Key_generate_neg(api);

    test_SeosCryptoApi_Key_makePublic_pos(api);
    test_SeosCryptoApi_Key_makePublic_neg(api);

    test_SeosCryptoApi_Key_getParams_pos(api);
    test_SeosCryptoApi_Key_getParams_neg(api);

    test_SeosCryptoApi_Key_loadParams_pos(api);
    test_SeosCryptoApi_Key_loadParams_neg(api);

    test_SeosCryptoApi_Key_free_pos(api);
    test_SeosCryptoApi_Key_free_neg(api);

    test_SeosCryptoApi_Key_getParams_buffer(api);
    test_SeosCryptoApi_Key_loadParams_buffer(api);

    // Make all used keys NON-EXPORTABLE and re-run parts of the tests
    if (api->mode == SeosCryptoApi_Mode_ROUTER)
    {
        allowExport = false;
        keyData_setExportable(keyDataList, allowExport);
        keySpec_setExportable(keySpecList, allowExport);

        test_SeosCryptoApi_Key_import_pos(api);
        test_SeosCryptoApi_Key_generate_pos(api);
        test_SeosCryptoApi_Key_makePublic_pos(api);
        test_SeosCryptoApi_Key_getParams_pos(api);
        test_SeosCryptoApi_Key_loadParams_pos(api);
    }
}