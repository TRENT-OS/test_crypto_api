/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"

#include "LibDebug/Debug.h"
#include "LibUtil/PointerVector.h"

#include <string.h>
#include <camkes.h>

static PointerVector myObjects;
static OS_Crypto_Handle_t hCrypto;

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

static void*
my_calloc(
    size_t n,
    size_t size)
{
    void* ptr;

    if ((ptr = calloc(n, size)) != NULL)
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

OS_Crypto_Handle_t
crypto_rpc_getCrypto(
    void)
{
    // We have only a single instance
    return hCrypto;
}

// Public Functions -----------------------------------------------------------

static OS_Crypto_Config_t cfg =
{
    .mode = OS_Crypto_MODE_SERVER,
    .memory = {
        .calloc = my_calloc,
        .free   = my_free,
    },
    .dataport = OS_DATAPORT_ASSIGN(crypto_port),
    .entropy = IF_OS_ENTROPY_ASSIGN(
        entropy_rpc,
        entropy_port),
};

OS_Error_t
testServer_rpc_openSession()
{
    OS_Error_t err;

    if (!PointerVector_ctor(&myObjects, 1))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }
    if ((err = OS_Crypto_init(&hCrypto, &cfg)) != OS_SUCCESS)
    {
        Debug_LOG_TRACE("OS_Crypto_init failed with %d", err);
        goto err;
    }

    return OS_SUCCESS;

err:
    PointerVector_dtor(&myObjects);
    return err;
}

int
testServer_rpc_hasObject(
    CryptoLib_Object_ptr ptr)
{
    return (findObject(ptr) != -1) ? 1 : 0;
}

OS_Error_t
testServer_rpc_loadKey(
    CryptoLib_Object_ptr* ptr)
{
    OS_Error_t err;
    OS_CryptoKey_Handle_t hKey;
    static OS_CryptoKey_Data_t aesKey =
    {
        .type = OS_CryptoKey_TYPE_AES,
        .attribs.exportable = true,
        .data.aes = {
            .len   = 24,
            .bytes = {
                0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
            },
        },
    };

    // Import key data into the Crypto API
    if ((err = OS_CryptoKey_import(&hKey, hCrypto, &aesKey)) != OS_SUCCESS)
    {
        return err;
    }

    // Send back only the pointer to the LIB Key object
    *ptr = OS_Crypto_getLibObject(hKey);

    return OS_SUCCESS;
}

OS_Error_t
testServer_rpc_closeSession()
{
    OS_Error_t err;

    if ((err = OS_Crypto_free(hCrypto)) != OS_SUCCESS)
    {
        Debug_LOG_TRACE("OS_Crypto_free failed with %d", err);
    }

    PointerVector_dtor(&myObjects);

    return err;
}