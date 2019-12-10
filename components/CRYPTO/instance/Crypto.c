/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include "SeosCryptoApi.h"
#include "SeosCryptoRpcServer.h"
#include "SeosCryptoLib.h"

#include "LibDebug/Debug.h"

#include <string.h>
#include <camkes.h>

static SeosCryptoLib    cryptoCore;

int entropyFunc(void*           ctx,
                unsigned char*  buf,
                size_t          len)
{
    // This would be the platform specific function to obtain entropy
    memset(buf, 0, len);
    return 0;
}

seos_err_t
Crypto_getRpcHandle(SeosCryptoApi_RpcServer* instance)
{
    static SeosCryptoRpcServer the_one;
    const SeosCryptoApi_Callbacks cb = {
        .malloc     = malloc,
        .free       = free,
        .entropy    = entropyFunc
    };

    seos_err_t retval = SeosCryptoLib_init(&cryptoCore, &cb, NULL);
    if (SEOS_SUCCESS == retval)
    {
        retval = SeosCryptoRpcServer_init(&the_one, &cryptoCore, cryptoServerDataport);
        *instance = &the_one;

        if (SEOS_SUCCESS == retval)
        {
            Debug_LOG_TRACE("%s: created rpc object %p", __func__, *instance);
        }
    }
    return retval;
}

void
Crypto_closeRpcHandle(SeosCryptoApi_RpcServer instance)
{
    /// TODO
}

