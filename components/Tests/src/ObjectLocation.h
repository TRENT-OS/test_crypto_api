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
    if(m == OS_Crypto_MODE_LIBRARY_ONLY ||          \
       (m == OS_Crypto_MODE_CLIENT && e)) {         \
        TEST_TRUE(!CryptoRpcServer_hasObject(p));   \
    } else if(m == OS_Crypto_MODE_CLIENT_ONLY ||     \
              (m == OS_Crypto_MODE_CLIENT && !e)) { \
        TEST_TRUE(CryptoRpcServer_hasObject(p));    \
    }                                               \
}

// Test location of object pointer based on api mode only (used with objects
// which have no key attached and are thus independent of their exportability)
#define TEST_LOCACTION(m, o) {                      \
    void *p = OS_Crypto_getObject(o);               \
    if(m == OS_Crypto_MODE_LIBRARY_ONLY ||          \
       (m == OS_Crypto_MODE_CLIENT)) {              \
        TEST_TRUE(!CryptoRpcServer_hasObject(p));   \
    } else {                                        \
        TEST_TRUE(CryptoRpcServer_hasObject(p));    \
    }                                               \
}
