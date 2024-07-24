cmake_minimum_required(VERSION 3.22.1)
enable_language(C)

project(Cryptopals)

add_library(core_functions)
target_sources(core_functions PRIVATE core_functions.c)
target_compile_options(core_functions PRIVATE -Wall -Wextra -Wpedantic)

add_library(aes_ciphers)
target_sources(aes_ciphers PRIVATE aes_ciphers.c)
target_link_libraries(aes_ciphers crypto)
target_compile_options(aes_ciphers PRIVATE -Wall -Wextra -Wpedantic)


add_executable(1.1cryptopals 1.1_HexToBase64.c)
target_link_libraries(1.1cryptopals core_functions)
target_compile_options(1.1cryptopals PRIVATE -Wall -Wextra -Wpedantic)

add_executable(1.2cryptopals 1.2_FixedXor.c)
target_link_libraries(1.2cryptopals core_functions)
target_compile_options(1.2cryptopals PRIVATE -Wall -Wextra -Wpedantic)

add_executable(1.3cryptopals 1.3_SingleByteXorCipher.c)
target_link_libraries(1.3cryptopals core_functions)
target_compile_options(1.3cryptopals PRIVATE -Wall -Wextra -Wpedantic)

add_executable(1.4cryptopals 1.4_DetectSingleCharXor.c)
target_link_libraries(1.4cryptopals core_functions)
target_compile_options(1.4cryptopals PRIVATE -Wall -Wextra -Wpedantic)

add_executable(1.5cryptopals 1.5_RepeatingKeyXor.c)
target_link_libraries(1.5cryptopals core_functions)
target_compile_options(1.5cryptopals PRIVATE -Wall -Wextra -Wpedantic)

add_executable(1.6cryptopals 1.6_BreakRepeatingKeyXor.c)
target_link_libraries(1.6cryptopals core_functions)
target_compile_options(1.6cryptopals PRIVATE -Wall -Wextra -Wpedantic)

add_executable(1.7cryptopals 1.7_AesInEcbMode.c)
target_link_libraries(1.7cryptopals core_functions aes_ciphers)
target_compile_options(1.7cryptopals PRIVATE -Wall -Wextra -Wpedantic)

add_executable(1.8cryptopals 1.8_DetectEcbMode.c)
target_link_libraries(1.8cryptopals core_functions aes_ciphers)
target_compile_options(1.8cryptopals PRIVATE -Wall -Wextra -Wpedantic)

add_executable(2.1cryptopals 2.1_PkcsPadding.c)
target_link_libraries(2.1cryptopals core_functions aes_ciphers)
target_compile_options(2.1cryptopals PRIVATE -Wall -Wextra -Wpedantic)

add_executable(2.2cryptopals 2.2_CbcMode.c)
target_link_libraries(2.2cryptopals core_functions aes_ciphers)
target_compile_options(2.2cryptopals PRIVATE -Wall -Wextra -Wpedantic)

add_executable(2.3cryptopals 2.3_EcbCbcOracle.c)
target_link_libraries(2.3cryptopals core_functions aes_ciphers)
target_compile_options(2.3cryptopals PRIVATE -Wall -Wextra -Wpedantic)

add_executable(2.4cryptopals 2.4_ByteEcbDecryption.c)
target_link_libraries(2.4cryptopals core_functions aes_ciphers)
target_compile_options(2.4cryptopals PRIVATE -Wall -Wextra -Wpedantic)

add_executable(2.5cryptopals 2.5_EcbCutPaste.c)
target_link_libraries(2.5cryptopals core_functions aes_ciphers)
target_compile_options(2.5cryptopals PRIVATE -Wall -Wextra -Wpedantic)

add_executable(2.6cryptopals 2.6_HardByteEcbDecryption.c)
target_link_libraries(2.6cryptopals core_functions aes_ciphers)
target_compile_options(2.6cryptopals PRIVATE -Wall -Wextra -Wpedantic)

add_executable(2.7cryptopals 2.7_PkcsPaddingValidation.c)
target_link_libraries(2.7cryptopals core_functions aes_ciphers)
target_compile_options(2.7cryptopals PRIVATE -Wall -Wextra -Wpedantic)

add_executable(2.8cryptopals 2.8_CbcBitflipping.c)
target_link_libraries(2.8cryptopals core_functions aes_ciphers)
target_compile_options(2.8cryptopals PRIVATE -Wall -Wextra -Wpedantic)
