/**
 * @addtogroup CryptoApi_Tests
 * @{
 *
 * @file testRunner.c
 *
 * @brief top level test for the crypto API and the key store API
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "LibDebug/Debug.h"

#include "SeosCrypto.h"

#include "testSignature.h"
#include "testAgreement.h"
#include "testCipher.h"
#include "testRng.h"
#include "testDigest.h"
#include "testKey.h"

#include <camkes.h>
#include <string.h>

/* Defines -------------------------------------------------------------------*/

int entropyFunc(void*           ctx,
                unsigned char*  buf,
                size_t          len)
{
    // This would be the platform specific function to obtain entropy
    memset(buf, 0, len);
    return 0;
}

int run()
{
    const SeosCrypto_Callbacks cb = {
        .malloc     = malloc,
        .free       = free,
        .entropy    = entropyFunc
    };   
    SeosCrypto cryptoCtx;
    SeosCryptoClient client;
    SeosCryptoCtx* apiLocal;
    SeosCryptoCtx* apiRpc;
    SeosCryptoRpc_Handle rpcHandle = NULL;
    seos_err_t err = SEOS_ERROR_GENERIC;

    err = Crypto_getRpcHandle(&rpcHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);
    Debug_LOG_INFO("%s: got rpc object %p from server", __func__, rpcHandle);

    err = SeosCryptoClient_init(&client, rpcHandle, cryptoClientDataport);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    err = SeosCrypto_init(&cryptoCtx, &cb, NULL);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    apiLocal    = SeosCrypto_TO_SEOS_CRYPTO_CTX(&cryptoCtx);
    apiRpc      = SeosCryptoClient_TO_SEOS_CRYPTO_CTX(&client);

    Debug_PRINTF("Starting tests of SeosCryptoApi:\n");

    testKey(apiLocal);
    testKey(apiRpc);
    
    testAgreement(apiLocal);
    testAgreement(apiRpc);

    testCipher(apiLocal);
    testCipher(apiRpc);

    testDigest(apiLocal);
    testDigest(apiRpc);

    testRng(apiLocal);
    testRng(apiRpc);

    testSignature(apiLocal);
    testSignature(apiRpc);

    Debug_PRINTF("All tests completed.\n");

    return 0;
}

///@}
