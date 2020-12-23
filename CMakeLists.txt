#
# Test Crypto API
#
# Copyright (C) 2019-2020, Hensoldt Cyber GmbH
#

cmake_minimum_required(VERSION 3.7.2)

os_set_config_file(config.h)



#-------------------------------------------------------------------------------
project(tests_crypto_api C)

DeclareCAmkESComponent(
    test_OS_Crypto
    SOURCES
        components/Tests/src/test_OS_Crypto.c
        components/Tests/src/test_OS_CryptoSignature.c
        components/Tests/src/test_OS_CryptoCipher.c
        components/Tests/src/test_OS_CryptoRng.c
        components/Tests/src/test_OS_CryptoDigest.c
        components/Tests/src/test_OS_CryptoMac.c
        components/Tests/src/test_OS_CryptoAgreement.c
        components/Tests/src/test_OS_CryptoKey.c
    C_FLAGS
        -Wall
        -Werror
    LIBS
        os_core_api
        lib_compiler
        lib_macros
        os_crypto
)

DeclareCAmkESComponent(
    TestServer
    SOURCES
        components/TestServer/src/testServer_rpc.c
    C_FLAGS
        -Wall
        -Werror
    LIBS
        os_core_api
        lib_debug
        lib_util
        os_crypto
)

EntropySource_DeclareCAmkESComponent(
    EntropySource
)

DeclareAndCreateCamkESSystem(main.camkes)
GenerateSimulateScript()
