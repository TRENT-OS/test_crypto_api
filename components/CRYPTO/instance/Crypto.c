/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoApi.h"
#include "Crypto.h"

#include "LibDebug/Debug.h"
#include "LibUtil/PointerVector.h"

#include <string.h>
#include <camkes.h>

static PointerVector myObjects;
static SeosCryptoApi myCrypto;

// Private static functions ----------------------------------------------------

static size_t
findObject(
    const void* ptr)
{
    size_t i;

    for (i = 0; i < PointerVector_getSize(&myObjects); i++)
    {
        if (ptr == PointerVector_getElementAt(&myObjects, i))
        {
            return i;
        }
    }

    return -1;
}

static int
my_entropy(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    // This would be the platform specific function to obtain entropy
    memset(buf, 0, len);
    return 0;
}

static void*
my_malloc(
    size_t size)
{
    void* ptr;

    if ((ptr = malloc(size)) != NULL)
    {
        if (!PointerVector_pushBack(&myObjects, ptr))
        {
            Debug_LOG_TRACE("Could not add object to list.");
            free(ptr);
            ptr = NULL;
        }
    }

    return ptr;
}

static void
my_free(
    void* ptr)
{
    size_t pos;

    if ((pos = findObject(ptr)) != -1)
    {
        PointerVector_replaceElementAt(&myObjects, pos,
                                       PointerVector_getBack(&myObjects));
        PointerVector_popBack(&myObjects);
        free(ptr);
    }
    else
    {
        Debug_LOG_TRACE("Tried free'ing object that was not in list.");
    }
}

SeosCryptoApi*
SeosCryptoRpcServer_getSeosCryptoApi(
    void)
{
    // We have only a single instance
    return &myCrypto;
}

// Public Functions -----------------------------------------------------------

seos_err_t
Crypto_openSession()
{
    seos_err_t err;
    SeosCryptoApi_Config cfg =
    {
        .mode = SeosCryptoApi_Mode_RPC_SERVER_WITH_LIBRARY,
        .mem = {
            .malloc = my_malloc,
            .free   = my_free,
        },
        .impl.lib.rng = {
            .entropy = my_entropy,
        },
        .server.dataPort = SeosCryptoDataport
    };

    if (!PointerVector_ctor(&myObjects, 1))
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    if ((err = SeosCryptoApi_init(&myCrypto, &cfg)) != SEOS_SUCCESS)
    {
        Debug_LOG_TRACE("SeosCryptoApi_init failed with %d", err);
        goto err;
    }

    return SEOS_SUCCESS;

err:
    PointerVector_dtor(&myObjects);
    return err;
}

int
Crypto_hasObject(
    Object_Ptr ptr)
{
    return (findObject(ptr) != -1) ? 1 : 0;
}

seos_err_t
Crypto_closeSession()
{
    seos_err_t err;

    // Attention:
    // We are allowing the user to free an arbitrary memory pointer, so we
    // better trust the user or we do not implement something like this in
    // production!
    if ((err = SeosCryptoApi_free(&myCrypto)) != SEOS_SUCCESS)
    {
        Debug_LOG_TRACE("SeosCryptoApi_free failed with %d", err);
    }

    PointerVector_dtor(&myObjects);

    return err;
}