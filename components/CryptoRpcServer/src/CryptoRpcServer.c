/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"

#include "CryptoRpcServer.h"

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

OS_Crypto_Handle_t
CryptoLibServer_getCrypto(
    void)
{
    // We have only a single instance
    return hCrypto;
}

// Public Functions -----------------------------------------------------------

seos_err_t
CryptoRpcServer_openSession()
{
    seos_err_t err;
    OS_Crypto_Config_t cfg =
    {
        .mode = OS_Crypto_MODE_SERVER,
        .mem = {
            .malloc = my_malloc,
            .free   = my_free,
        },
        .library.rng.entropy = my_entropy,
        .rpc.server.dataPort = CryptoLibDataport
    };

    if (!PointerVector_ctor(&myObjects, 1))
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    if ((err = OS_Crypto_init(&hCrypto, &cfg)) != SEOS_SUCCESS)
    {
        Debug_LOG_TRACE("OS_Crypto_init failed with %d", err);
        goto err;
    }

    return SEOS_SUCCESS;

err:
    PointerVector_dtor(&myObjects);
    return err;
}

int
CryptoRpcServer_hasObject(
    CryptoLib_Object_ptr ptr)
{
    return (findObject(ptr) != -1) ? 1 : 0;
}

seos_err_t
CryptoRpcServer_loadKey(
    CryptoLib_Object_ptr* ptr)
{
    seos_err_t err;
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
    if ((err = OS_CryptoKey_import(&hKey, hCrypto, &aesKey)) != SEOS_SUCCESS)
    {
        return err;
    }

    // Send back only the pointer to the LIB Key object
    *ptr = OS_Crypto_getLibObject(hKey);

    return SEOS_SUCCESS;
}

seos_err_t
CryptoRpcServer_closeSession()
{
    seos_err_t err;

    if ((err = OS_Crypto_free(hCrypto)) != SEOS_SUCCESS)
    {
        Debug_LOG_TRACE("OS_Crypto_free failed with %d", err);
    }

    PointerVector_dtor(&myObjects);

    return err;
}