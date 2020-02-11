/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoApi.h"

#include "ObjectLocation.h"
#include "SharedKeys.h"
#include "TestMacros.h"

#include <string.h>

static bool allowExport;
#define Debug_ASSERT_LOCATION(api, o) \
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
    Debug_ASSERT_LOCATION(api, key);
    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    return SEOS_SUCCESS;
}

static void
test_SeosCryptoApi_Key_import_pos(
    SeosCryptoApi* api)
{
    seos_err_t err;

    // Import 128-bit AES key
    err = do_import(api, &aes128Data);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Import 192-bit AES key
    err = do_import(api, &aes192Data);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Import 256-bit AES key
    err = do_import(api, &aes256Data);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Import 1024-bit RSA pubkey
    err = do_import(api, &rsa1024PubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Import 1024-bit RSA prvkey
    err = do_import(api, &rsa1024PrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Import 101-bit DH pubkey
    err = do_import(api, &dh101PubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Import 101-bit DH RSA prvkey
    err = do_import(api, &dh101PrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Import SECP256r1 pubkey
    err = do_import(api, &secp256r1PubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Import SECP256r1 prvkey
    err = do_import(api, &secp256r1PrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_import_neg(
    SeosCryptoApi* api)
{
    seos_err_t err;
    SeosCryptoApi_Key key;

    // Empty api
    err = SeosCryptoApi_Key_import(NULL, &key, &aes128Data);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty key
    err = SeosCryptoApi_Key_import(api, NULL, &aes128Data);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty key data
    err = SeosCryptoApi_Key_import(api, &key, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Invalid AES key
    err = SeosCryptoApi_Key_import(api, &key, &aes120Data);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Invalid RSA key (too small)
    err = SeosCryptoApi_Key_import(api, &key, &rsaSmallData);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Invalid RSA key (too big)
    err = SeosCryptoApi_Key_import(api, &key, &rsaLargeData);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

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

    err = SeosCryptoApi_Key_import(api, &key, data);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_LOCATION(api, key);
    memset(&expData, 0, sizeof(SeosCryptoApi_Key_Data));
    if ((err = SeosCryptoApi_Key_export(&key, &expData)) != SEOS_SUCCESS)
    {
        return err;
    }
    Debug_ASSERT(!memcmp(data, &expData, sizeof(SeosCryptoApi_Key_Data)));
    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    return SEOS_SUCCESS;
}

static void
test_SeosCryptoApi_Key_export_pos(
    SeosCryptoApi* api)
{
    seos_err_t err;

    // Export 128-bit AES key
    err = do_export(api, &aes128Data);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Export 192-bit AES key
    err = do_export(api, &aes192Data);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Export 256-bit AES key
    err = do_export(api, &aes256Data);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Export 1024-bit RSA pubkey
    err = do_export(api, &rsa1024PubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Export 1024-bit RSA prvkey
    err = do_export(api, &rsa1024PrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Export 101-bit DH pubkey
    err = do_export(api, &dh101PubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Export 101-bit DH prvkey
    err = do_export(api, &dh101PrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Export SECP256r1 pubkey
    err = do_export(api, &secp256r1PubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Export SECP256r1 prvkey
    err = do_export(api, &secp256r1PrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_export_neg(
    SeosCryptoApi* api)
{
    seos_err_t err;
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

    err = SeosCryptoApi_Key_import(api, &key, &aes128Data);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Empty key
    err = SeosCryptoApi_Key_export(NULL, &expData);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty export data buffer
    err = SeosCryptoApi_Key_export(&key, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Non-exportable key
    err = SeosCryptoApi_Key_generate(api, &key, &aes128noExpSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_export(&key, &expData);
    if (api->mode == SeosCryptoApi_Mode_LIBRARY)
    {
        /*
         * A library instance will store all keys in memory which is shared with the
         * host component. Therefore, if the API runs in library mode, it will ALWAYS
         * allow exports, even if the key is marked as "non exportable".
         */
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    }
    else
    {
        /*
         * It is assumed that all other modes of the Crypto API respect the
         * exportable flag and thus deny the operation.
         */
        Debug_ASSERT_PRINTFLN(SEOS_ERROR_OPERATION_DENIED == err, "err %d", err);
    }
    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

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
    Debug_ASSERT_LOCATION(api, key);
    memset(&expData, 0, sizeof(SeosCryptoApi_Key_Data));
    err = SeosCryptoApi_Key_export(&key, &expData);
    if (allowExport)
    {
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
        Debug_ASSERT(spec->key.type == expData.type);
        Debug_ASSERT(!memcmp(&spec->key.attribs, &expData.attribs,
                             sizeof(SeosCryptoApi_Key_Attribs)));
        if (spec->type == SeosCryptoApi_Key_SPECTYPE_PARAMS)
        {
            switch (spec->key.type)
            {
            case SeosCryptoApi_Key_TYPE_DH_PRV:
                Debug_ASSERT(!memcmp(&spec->key.params, &expData.data.dh.prv.params,
                                     sizeof(SeosCryptoApi_Key_DhParams)));
                break;
            default:
                Debug_ASSERT(1 == 0);
            }
        }
    }
    else
    {
        Debug_ASSERT_PRINTFLN(SEOS_ERROR_OPERATION_DENIED == err, "err %d", err);
    }
    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    return SEOS_SUCCESS;
}

static void
test_SeosCryptoApi_Key_generate_pos(
    SeosCryptoApi* api)
{
    seos_err_t err;

    // Generate 128-bit AES key
    err = do_generate(api, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Generate 192-bit AES key
    err = do_generate(api, &aes192Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Generate 256-bit AES key
    err = do_generate(api, &aes256Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Generate 64-bit DH privkey from bit spec
    err = do_generate(api, &dh64bSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Generate 101-bit DH privkey from param spec
    err = do_generate(api, &dh101pSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Generate 128-bit RSA privkey
    err = do_generate(api, &rsa128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Generate SECP256r1 privkey
    err = do_generate(api, &secp256r1Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_generate_neg(
    SeosCryptoApi* api)
{
    seos_err_t err;
    SeosCryptoApi_Key key;

    // Empty api
    err = SeosCryptoApi_Key_generate(NULL, &key, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty key
    err = SeosCryptoApi_Key_generate(api, NULL, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty spec
    err = SeosCryptoApi_Key_generate(api, &key, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Wrong key size: 120-bit AES key
    err = SeosCryptoApi_Key_generate(api, &key, &aes120Spec);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Wrong key size: 127-bit RSA key
    err = SeosCryptoApi_Key_generate(api, &key, &rsa127Spec);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Wrong key size: 63-bit DH key
    err = SeosCryptoApi_Key_generate(api, &key, &dh63bSpec);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

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

    err = SeosCryptoApi_Key_generate(api, &key, spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_LOCATION(api, key);
    if ((err = SeosCryptoApi_Key_makePublic(&pubKey, &key,
                                            &spec->key.attribs)) != SEOS_SUCCESS)
    {
        return err;
    }
    err = SeosCryptoApi_Key_export(&pubKey, &expData);
    Debug_ASSERT_LOCATION(api, pubKey);
    if (allowExport)
    {
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
        switch (spec->key.type)
        {
        case SeosCryptoApi_Key_TYPE_RSA_PRV:
            Debug_ASSERT(expData.type == SeosCryptoApi_Key_TYPE_RSA_PUB);
            break;
        case SeosCryptoApi_Key_TYPE_DH_PRV:
            Debug_ASSERT(expData.type == SeosCryptoApi_Key_TYPE_DH_PUB);
            if (SeosCryptoApi_Key_SPECTYPE_PARAMS == spec->type)
            {
                Debug_ASSERT(!memcmp(&expData.data.dh.pub.params, &spec->key.params.dh,
                                     sizeof(SeosCryptoApi_Key_DhParams)));
            }
            break;
        case SeosCryptoApi_Key_TYPE_SECP256R1_PRV:
            Debug_ASSERT(expData.type == SeosCryptoApi_Key_TYPE_SECP256R1_PUB);
            break;
        default:
            Debug_ASSERT(1 == 0);
        }
    }
    else
    {
        Debug_ASSERT_PRINTFLN(SEOS_ERROR_OPERATION_DENIED == err, "err %d", err);
    }

    err = SeosCryptoApi_Key_free(&pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    return SEOS_SUCCESS;

}
static void
test_SeosCryptoApi_Key_makePublic_pos(
    SeosCryptoApi* api)
{
    seos_err_t err;

    // Make DH pubkey, with privkey from bit spec
    err = do_makePublic(api, &dh64bSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Make DH pubkey, with privkey from param spec
    err = do_makePublic(api, &dh101pSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Make RSA pubkey
    err = do_makePublic(api, &rsa128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Make SECP256r1 pubkey
    err = do_makePublic(api, &secp256r1Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_makePublic_neg(
    SeosCryptoApi* api)
{
    seos_err_t err;
    SeosCryptoApi_Key key, pubKey;

    err = SeosCryptoApi_Key_generate(api, &key, &dh64bSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Empty target handle
    err = SeosCryptoApi_Key_makePublic(NULL, &key, &dh64bSpec.key.attribs);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Invalid private handle
    err = SeosCryptoApi_Key_makePublic(&pubKey, NULL, &dh64bSpec.key.attribs);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty attribs
    err = SeosCryptoApi_Key_makePublic(&pubKey, &key, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Try making "public" from a symmetric key
    err = SeosCryptoApi_Key_generate(api, &key, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_LOCATION(api, key);
    err = SeosCryptoApi_Key_makePublic(&pubKey, &key, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_getParams_pos(
    SeosCryptoApi* api)
{
    seos_err_t err;
    size_t n;
    SeosCryptoApi_Key key;
    SeosCryptoApi_Key_DhParams dhParams;
    SeosCryptoApi_Key_Data expData;

    // Generate params for DH
    err = SeosCryptoApi_Key_generate(api, &key, &dh101pSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_LOCATION(api, key);
    n = sizeof(dhParams);
    err = SeosCryptoApi_Key_getParams(&key, &dhParams, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(n == sizeof(dhParams));
    err = SeosCryptoApi_Key_export(&key, &expData);
    if (allowExport)
    {
        Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
        Debug_ASSERT(!memcmp(&expData.data.dh.prv.params, &dhParams, n));
    }
    else
    {
        Debug_ASSERT_PRINTFLN(SEOS_ERROR_OPERATION_DENIED == err, "err %d", err);
    }
    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_getParams_neg(
    SeosCryptoApi* api)
{
    seos_err_t err;
    size_t n;
    SeosCryptoApi_Key key;
    SeosCryptoApi_Key_DhParams dhParams;

    err = SeosCryptoApi_Key_generate(api, &key, &dh64bSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_LOCATION(api, key);

    // Empty key handle
    n = sizeof(dhParams);
    err = SeosCryptoApi_Key_getParams(NULL, &dhParams, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty buffer
    err = SeosCryptoApi_Key_getParams(&key, NULL, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty buffer len
    err = SeosCryptoApi_Key_getParams(&key, &dhParams, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Too small buffer len
    n = 17;
    err = SeosCryptoApi_Key_getParams(&key, &dhParams, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_loadParams_pos(
    SeosCryptoApi* api)
{
    seos_err_t err;
    size_t n;
    SeosCryptoApi_Key_EccParams eccParams;

    // Load SECP192r1
    n = sizeof(eccParams);
    err = SeosCryptoApi_Key_loadParams(api, SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                       &eccParams, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(n == sizeof(eccParams));

    // Load SECP224r1
    err = SeosCryptoApi_Key_loadParams(api, SeosCryptoApi_Key_PARAM_ECC_SECP224R1,
                                       &eccParams, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(n == sizeof(eccParams));

    // Load SECP256r1
    err = SeosCryptoApi_Key_loadParams(api, SeosCryptoApi_Key_PARAM_ECC_SECP256R1,
                                       &eccParams, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(n == sizeof(eccParams));

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_loadParams_neg(
    SeosCryptoApi* api)
{
    seos_err_t err;
    size_t n;
    SeosCryptoApi_Key_EccParams eccParams;

    // Empty context
    n = sizeof(eccParams);
    err = SeosCryptoApi_Key_loadParams(NULL, SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                       &eccParams, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Wrong param name
    err = SeosCryptoApi_Key_loadParams(api, 666, &eccParams, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Empty buffer
    err = SeosCryptoApi_Key_loadParams(api, SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                       NULL, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty length
    err = SeosCryptoApi_Key_loadParams(api, SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                       &eccParams, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // To small buffer
    n = 17;
    err = SeosCryptoApi_Key_loadParams(api, SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                       &eccParams, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_free_pos(
    SeosCryptoApi* api)
{
    seos_err_t err;
    SeosCryptoApi_Key key;

    err = SeosCryptoApi_Key_generate(api, &key, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_LOCATION(api, key);
    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_free_neg(
    SeosCryptoApi* api)
{
    seos_err_t err;
    SeosCryptoApi_Key key;

    err = SeosCryptoApi_Key_generate(api, &key, &aes128Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_LOCATION(api, key);

    // Empty key
    err = SeosCryptoApi_Key_free(NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_getParams_buffer(
    SeosCryptoApi* api)
{
    seos_err_t err;
    SeosCryptoApi_Key key;
    static unsigned char paramBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    size_t paramLen;

    err = SeosCryptoApi_Key_generate(api, &key, &dh101pSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_LOCATION(api, key);

    // Should be OK and give the correct length
    paramLen = SeosCryptoApi_SIZE_DATAPORT;
    err = SeosCryptoApi_Key_getParams(&key, paramBuf, &paramLen);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(paramLen == sizeof(SeosCryptoApi_Key_DhParams));

    // Should fail but give the correct length
    paramLen = 10;
    err = SeosCryptoApi_Key_getParams(&key, paramBuf, &paramLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);
    Debug_ASSERT(paramLen == sizeof(SeosCryptoApi_Key_DhParams));

    // Should fail due buffer being too big
    paramLen = SeosCryptoApi_SIZE_DATAPORT + 1;
    err = SeosCryptoApi_Key_getParams(&key, paramBuf, &paramLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INSUFFICIENT_SPACE == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&key);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    TEST_OK(api->mode, allowExport);
}

static void
test_SeosCryptoApi_Key_loadParams_buffer(
    SeosCryptoApi* api)
{
    seos_err_t err;
    static unsigned char paramBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    size_t paramLen;

    // Should be OK
    paramLen = SeosCryptoApi_SIZE_DATAPORT;
    err = SeosCryptoApi_Key_loadParams(api, SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                       paramBuf, &paramLen);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(paramLen == sizeof(SeosCryptoApi_Key_EccParams));

    // Should fail, but give the minimum size
    paramLen = 10;
    err = SeosCryptoApi_Key_loadParams(api, SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                       paramBuf, &paramLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);
    Debug_ASSERT(paramLen == sizeof(SeosCryptoApi_Key_EccParams));

    // Should fail because buffer is too big
    paramLen = SeosCryptoApi_SIZE_DATAPORT + 1;
    err = SeosCryptoApi_Key_loadParams(api, SeosCryptoApi_Key_PARAM_ECC_SECP192R1,
                                       paramBuf, &paramLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INSUFFICIENT_SPACE == err, "err %d", err);

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