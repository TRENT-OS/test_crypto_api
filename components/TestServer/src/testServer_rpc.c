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
static OS_Dataport_t port = OS_DATAPORT_ASSIGN(testServer_port);

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

// Public Functions -----------------------------------------------------------

static OS_Crypto_Config_t cfg =
{
    .mode = OS_Crypto_MODE_LIBRARY,
    .memory = {
        .calloc = my_calloc,
        .free   = my_free,
    },
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
    intptr_t ptr)
{
    return (findObject((void*)ptr) != -1) ? 1 : 0;
}

OS_Error_t
testServer_rpc_loadKey(
    OS_CryptoKey_Handle_t* hKey)
{
    OS_Error_t err;
    static OS_CryptoKey_Data_t aesKey =
    {
        .type = OS_CryptoKey_TYPE_AES,
        .attribs.keepLocal = true,
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
    if ((err = OS_CryptoKey_import(
             hKey,
             hCrypto,
             &aesKey)) != OS_SUCCESS)
    {
        return err;
    }

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

// if_OS_Crypto interface functions --------------------------------------------

OS_Error_t
testServer_rpc_Rng_getBytes(
    unsigned int flags,
    size_t       bufSize)
{
    return OS_CryptoRng_getBytes(
        hCrypto,
        flags,
        OS_Dataport_getBuf(port),
        bufSize);
}

OS_Error_t
testServer_rpc_Rng_reseed(
    size_t seedSize)
{
    return OS_CryptoRng_reseed(
        hCrypto,
        OS_Dataport_getBuf(port),
        seedSize);
}

OS_Error_t
testServer_rpc_Mac_init(
    OS_CryptoMac_Handle_t* pMacHandle,
    OS_CryptoMac_Handle_t  keyHandle,
    unsigned int           algorithm)
{
    return OS_CryptoMac_init(
        pMacHandle,
        hCrypto,
        keyHandle,
        algorithm);
}

OS_Error_t
testServer_rpc_Mac_free(
    OS_CryptoMac_Handle_t macHandle)
{
    return OS_CryptoMac_free(macHandle);
}

OS_Error_t
testServer_rpc_Mac_process(
    OS_CryptoMac_Handle_t macHandle,
    size_t                dataSize)
{
    return OS_CryptoMac_process(
        macHandle,
        OS_Dataport_getBuf(port),
        dataSize);
}

OS_Error_t
testServer_rpc_Mac_finalize(
    OS_CryptoMac_Handle_t macHandle,
    size_t*               macSize)
{
    *macSize = (*macSize <= OS_Dataport_getSize(port)) ?
               *macSize : OS_Dataport_getSize(port);

    return OS_CryptoMac_finalize(
        macHandle,
        OS_Dataport_getBuf(port),
        macSize);
}

OS_Error_t
testServer_rpc_Digest_init(
    OS_CryptoDigest_Handle_t* pDigestHandle,
    unsigned int              algorithm)
{
    return OS_CryptoDigest_init(
        pDigestHandle,
        hCrypto,
        algorithm);
}

OS_Error_t
testServer_rpc_Digest_free(
    OS_CryptoDigest_Handle_t digestHandle)
{
    return OS_CryptoDigest_free(digestHandle);
}

OS_Error_t
testServer_rpc_Digest_clone(
    OS_CryptoDigest_Handle_t* pDigestHandle,
    OS_CryptoDigest_Handle_t  srcDigestHandle)
{
    return OS_CryptoDigest_clone(
        pDigestHandle,
        hCrypto,
        srcDigestHandle);
}

OS_Error_t
testServer_rpc_Digest_process(
    OS_CryptoDigest_Handle_t digestHandle,
    size_t                   inSize)
{
    return OS_CryptoDigest_process(
        digestHandle,
        OS_Dataport_getBuf(port),
        inSize);
}

OS_Error_t
testServer_rpc_Digest_finalize(
    OS_CryptoDigest_Handle_t digestHandle,
    size_t*                  digestSize)
{
    *digestSize = (*digestSize <= OS_Dataport_getSize(port)) ?
                  *digestSize : OS_Dataport_getSize(port);

    return OS_CryptoDigest_finalize(
        digestHandle,
        OS_Dataport_getBuf(port),
        digestSize);
}

OS_Error_t
testServer_rpc_Key_generate(
    OS_CryptoKey_Handle_t* pKeyHandle)
{
    return OS_CryptoKey_generate(
        pKeyHandle,
        hCrypto,
        OS_Dataport_getBuf(port));
}

OS_Error_t
testServer_rpc_Key_makePublic(
    OS_CryptoKey_Handle_t* pPubKeyHandle,
    OS_CryptoKey_Handle_t  prvKeyHandle)
{
    return OS_CryptoKey_makePublic(
        pPubKeyHandle,
        hCrypto,
        prvKeyHandle,
        OS_Dataport_getBuf(port));
}

OS_Error_t
testServer_rpc_Key_import(
    OS_CryptoKey_Handle_t* pKeyHandle)
{
    return OS_CryptoKey_import(
        pKeyHandle,
        hCrypto,
        OS_Dataport_getBuf(port));
}

OS_Error_t
testServer_rpc_Key_export(
    OS_CryptoKey_Handle_t keyHandle)
{
    return OS_CryptoKey_export(
        keyHandle,
        OS_Dataport_getBuf(port));
}

OS_Error_t
testServer_rpc_Key_getParams(
    OS_CryptoKey_Handle_t keyHandle,
    size_t*               paramSize)
{
    *paramSize = (*paramSize <= OS_Dataport_getSize(port)) ?
                 *paramSize : OS_Dataport_getSize(port);

    return OS_CryptoKey_getParams(
        keyHandle,
        OS_Dataport_getBuf(port),
        paramSize);
}

OS_Error_t
testServer_rpc_Key_getAttribs(
    OS_CryptoKey_Handle_t keyHandle)
{
    return OS_CryptoKey_getAttribs(
        keyHandle,
        OS_Dataport_getBuf(port));
}

OS_Error_t
testServer_rpc_Key_loadParams(
    OS_CryptoKey_Param_t param,
    size_t*              paramSize)
{
    *paramSize = (*paramSize <= OS_Dataport_getSize(port)) ?
                 *paramSize : OS_Dataport_getSize(port);

    return OS_CryptoKey_loadParams(
        hCrypto,
        param,
        OS_Dataport_getBuf(port),
        paramSize);
}

OS_Error_t
testServer_rpc_Key_free(
    OS_CryptoKey_Handle_t keyHandle)
{
    return OS_CryptoKey_free(
        keyHandle);
}

OS_Error_t
testServer_rpc_Agreement_init(
    OS_CryptoAgreement_Handle_t* pAgrHandle,
    OS_CryptoKey_Handle_t        prvKeyHandle,
    OS_CryptoAgreement_Alg_t     algorithm)
{
    return OS_CryptoAgreement_init(
        pAgrHandle,
        hCrypto,
        prvKeyHandle,
        algorithm);
}

OS_Error_t
testServer_rpc_Agreement_agree(
    OS_CryptoAgreement_Handle_t agrHandle,
    OS_CryptoKey_Handle_t       pubKeyHandle,
    size_t*                     sharedSize)
{
    *sharedSize = (*sharedSize <= OS_Dataport_getSize(port)) ?
                  *sharedSize : OS_Dataport_getSize(port);

    return OS_CryptoAgreement_agree(
        agrHandle,
        pubKeyHandle,
        OS_Dataport_getBuf(port),
        sharedSize);
}

OS_Error_t
testServer_rpc_Agreement_free(
    OS_CryptoAgreement_Handle_t agrHandle)
{
    return OS_CryptoAgreement_free(
        agrHandle);
}

OS_Error_t
testServer_rpc_Signature_init(
    OS_CryptoSignature_Handle_t* pSigHandle,
    OS_CryptoKey_Handle_t        prvKeyHandle,
    OS_CryptoKey_Handle_t        pubKeyHandle,
    unsigned int                 algorithm,
    unsigned int                 digest)
{
    return OS_CryptoSignature_init(
        pSigHandle,
        hCrypto,
        prvKeyHandle,
        pubKeyHandle,
        algorithm,
        digest);
}

OS_Error_t
testServer_rpc_Signature_verify(
    OS_CryptoSignature_Handle_t sigHandle,
    size_t                      hashSize,
    size_t                      signatureSize)
{
    return OS_CryptoSignature_verify(
        sigHandle,
        OS_Dataport_getBuf(port),
        hashSize,
        OS_Dataport_getBuf(port) + hashSize,
        signatureSize);
}

OS_Error_t
testServer_rpc_Signature_sign(
    OS_CryptoSignature_Handle_t sigHandle,
    size_t                      hashSize,
    size_t*                     signatureSize)
{
    *signatureSize = (*signatureSize <= OS_Dataport_getSize(port)) ?
                     *signatureSize : OS_Dataport_getSize(port);

    return OS_CryptoSignature_sign(
        sigHandle,
        OS_Dataport_getBuf(port),
        hashSize,
        OS_Dataport_getBuf(port),
        signatureSize);
}

OS_Error_t
testServer_rpc_Signature_free(
    OS_CryptoSignature_Handle_t sigHandle)
{
    return OS_CryptoSignature_free(sigHandle);
}

OS_Error_t
testServer_rpc_Cipher_init(
    OS_CryptoCipher_Handle_t* pCipherHandle,
    OS_CryptoKey_Handle_t     keyHandle,
    unsigned int              algorithm,
    size_t                    ivSize)
{
    return OS_CryptoCipher_init(
        pCipherHandle,
        hCrypto,
        keyHandle,
        algorithm,
        OS_Dataport_getBuf(port),
        ivSize);
}

OS_Error_t
testServer_rpc_Cipher_free(
    OS_CryptoCipher_Handle_t cipherHandle)
{
    return OS_CryptoCipher_free(cipherHandle);
}

OS_Error_t
testServer_rpc_Cipher_process(
    OS_CryptoCipher_Handle_t cipherHandle,
    size_t                   inputSize,
    size_t*                  outputSize)
{
    *outputSize = (*outputSize <= OS_Dataport_getSize(port)) ?
                  *outputSize : OS_Dataport_getSize(port);

    return OS_CryptoCipher_process(
        cipherHandle,
        OS_Dataport_getBuf(port),
        inputSize,
        OS_Dataport_getBuf(port),
        outputSize);
}

OS_Error_t
testServer_rpc_Cipher_start(
    OS_CryptoCipher_Handle_t cipherHandle,
    size_t                   len)
{
    return OS_CryptoCipher_start(
        cipherHandle,
        OS_Dataport_getBuf(port),
        len);
}

OS_Error_t
testServer_rpc_Cipher_finalize(
    OS_CryptoCipher_Handle_t cipherHandle,
    size_t*                  tagSize)
{
    *tagSize = (*tagSize <= OS_Dataport_getSize(port)) ?
               *tagSize : OS_Dataport_getSize(port);

    return OS_CryptoCipher_finalize(
        cipherHandle,
        OS_Dataport_getBuf(port),
        tagSize);
}