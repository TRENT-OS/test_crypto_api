/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Crypto.h"
#include "CryptoRpcServer.h"

#include "TestMacros.h"

// Test location of object pointer based on exportable flag and api mode
#define TEST_LOCACTION_EXP(m, e, o) {               \
    void *p = OS_Crypto_getObject(o);               \
    if(m == OS_Crypto_MODE_LIBRARY ||               \
       (m == OS_Crypto_MODE_ROUTER && e)) {         \
        TEST_TRUE(!CryptoRpcServer_hasObject(p));   \
    } else if(m == OS_Crypto_MODE_RPC_CLIENT ||     \
              (m == OS_Crypto_MODE_ROUTER && !e)) { \
        TEST_TRUE(CryptoRpcServer_hasObject(p));    \
    }                                               \
}

// Test location of object pointer based on api mode only (used with objects
// which have no key attached and are thus independent of their exportability)
#define TEST_LOCACTION(m, o) {                      \
    void *p = OS_Crypto_getObject(o);               \
    if(m == OS_Crypto_MODE_LIBRARY ||               \
       (m == OS_Crypto_MODE_ROUTER)) {              \
        TEST_TRUE(!CryptoRpcServer_hasObject(p));   \
    } else {                                        \
        TEST_TRUE(CryptoRpcServer_hasObject(p));    \
    }                                               \
}
