/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosCryptoApi.h"
#include "CryptoRpcServer.h"

#include "TestMacros.h"

// Test location of object pointer based on exportable flag and api mode
#define TEST_LOCACTION_EXP(m, e, o) {                   \
    void *p = SeosCryptoApi_getObject(o);               \
    if(m == SeosCryptoApi_Mode_LIBRARY ||               \
       (m == SeosCryptoApi_Mode_ROUTER && e)) {         \
        TEST_TRUE(!CryptoRpcServer_hasObject(p));       \
    } else if(m == SeosCryptoApi_Mode_RPC_CLIENT ||     \
              (m == SeosCryptoApi_Mode_ROUTER && !e)) { \
        TEST_TRUE(CryptoRpcServer_hasObject(p));        \
    }                                                   \
}

// Test location of object pointer based on api mode only (used with objects
// which have no key attached and are thus independent of their exportability)
#define TEST_LOCACTION(m, o) {                      \
    void *p = SeosCryptoApi_getObject(o);           \
    if(m == SeosCryptoApi_Mode_LIBRARY ||           \
       (m == SeosCryptoApi_Mode_ROUTER)) {          \
        TEST_TRUE(!CryptoRpcServer_hasObject(p));   \
    } else {                                        \
        TEST_TRUE(CryptoRpcServer_hasObject(p));    \
    }                                               \
}
