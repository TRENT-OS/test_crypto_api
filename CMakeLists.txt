cmake_minimum_required(VERSION 3.7.2)

seos_set_config_file(config.h)

seos_use_libs(
    SEOS_LIBS
    SEOS_LIBS_LOGGER
    SEOS_CRYPTO_WITH_RPC_CLIENT
    SEOS_CRYPTO_WITH_RPC_SERVER
    SEOS_CRYPTO_IMPL_MBEDTLS
)

project(tests_crypto_api C)

DeclareCAmkESComponent(test_OS_Crypto
    INCLUDES
        common
        components/CryptoRpcServer/src
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
        -Wall -Werror
    LIBS
        seos_core_api
        seos_crypto_with_rpc_client
)

DeclareCAmkESComponent(CryptoRpcServer
    INCLUDES
        common
        components/CryptoRpcServer/src
    SOURCES
        components/CryptoRpcServer/src/CryptoRpcServer.c
    C_FLAGS
        -Wall -Werror
    LIBS
        seos_core_api
        seos_libs
        seos_crypto_with_rpc_server
)

DeclareCAmkESRootserver(main.camkes)
GenerateCAmkESRootServer()
GenerateSimulateScript()
