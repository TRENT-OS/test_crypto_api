/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoApi.h"

#include "LibDebug/Debug.h"

#include <string.h>
#include <camkes.h>

int entropy(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    // This would be the platform specific function to obtain entropy
    memset(buf, 0, len);
    return 0;
}

seos_err_t
Crypto_openSession(
    SeosCryptoApi_Ptr* api)
{
    seos_err_t err;
    SeosCryptoApi* inst;
    SeosCryptoApi_Config cfg =
    {
        .mode = SeosCryptoApi_Mode_RPC_SERVER_WITH_LIBRARY,
        .mem = {
            .malloc = malloc,
            .free   = free,
        },
        .impl.lib.rng = {
            .entropy = entropy,
            .context = NULL
        },
        .server.dataPort = cryptoServerDataport
    };

    if ((inst = malloc(sizeof(SeosCryptoApi))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    err = SeosCryptoApi_init(inst, &cfg);
    Debug_LOG_TRACE("SeosCryptoApi_init failed with %d", err);

    *api = inst;

    return err;
}

seos_err_t
Crypto_closeSession(
    SeosCryptoApi_Ptr api)
{
    seos_err_t err;

    // Attention:
    // We are allowing the user to free an arbitrary memory pointer, so we
    // better trust the user or we do not implement something like this in
    // production!
    if ((err = SeosCryptoApi_free(api)) != SEOS_SUCCESS)
    {
        Debug_LOG_TRACE("SeosCryptoApi_free failed with %d", err);
    }

    free(api);

    return err;
}