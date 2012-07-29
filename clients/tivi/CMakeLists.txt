cmake_minimum_required (VERSION 2.6)

# setup the Thread include and lib
find_package(Threads)
if(CMAKE_HAVE_PTHREAD_H)
  set(HAVE_PTHREAD_H TRUE)
endif()
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})

#to make sure includes are first taken - it contains config.h
include_directories(BEFORE ${CMAKE_BINARY_DIR})
include_directories (${CMAKE_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/zrtp ${CMAKE_SOURCE_DIR}/srtp)

set(cryptcommon_srcs
    ${CMAKE_SOURCE_DIR}/cryptcommon/twofish.c
    ${CMAKE_SOURCE_DIR}/cryptcommon/twofish_cfb.c
    ${CMAKE_SOURCE_DIR}/cryptcommon/aescrypt.c
    ${CMAKE_SOURCE_DIR}/cryptcommon/aeskey.c
    ${CMAKE_SOURCE_DIR}/cryptcommon/aestab.c
    ${CMAKE_SOURCE_DIR}/cryptcommon/aes_modes.c
    ${CMAKE_SOURCE_DIR}/cryptcommon/macSkein.cpp
    ${CMAKE_SOURCE_DIR}/cryptcommon/skein.c
    ${CMAKE_SOURCE_DIR}/cryptcommon/skein_block.c
    ${CMAKE_SOURCE_DIR}/cryptcommon/skeinApi.c)

set(zrtp_tivi_src
    ${CMAKE_CURRENT_SOURCE_DIR}/CtZrtpSession.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CtZrtpStream.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Thread.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/MutexClass.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/EventClass.cpp)

set(srtp_src
    ${CMAKE_SOURCE_DIR}/srtp/CryptoContext.cpp
    ${CMAKE_SOURCE_DIR}/srtp/CryptoContextCtrl.cpp
    ${CMAKE_SOURCE_DIR}/srtp/SrtpHandler.cpp)

set(crypto_src_srtp
   ${CMAKE_SOURCE_DIR}/srtp/crypto/hmac.cpp
   ${CMAKE_SOURCE_DIR}/srtp/crypto/SrtpSymCrypto.cpp
   ${CMAKE_SOURCE_DIR}/srtp/crypto/sha1.c)

set(zrtpcpp_src ${zrtp_src} ${zrtp_tivi_src} ${zrtp_crypto_src} ${bnlib_src} ${srtp_src} ${crypto_src_srtp} ${cryptcommon_srcs})

# for the Thread classes etc.
add_definitions(-DLINUX -DNANO_SECOND_SLEEP)

if(BUILD_STATIC AND NOT BUILD_SHARED)
    set(LIBRARY_BUILD_TYPE STATIC)
else()
    set(LIBRARY_BUILD_TYPE SHARED)
endif()

add_library(${zrtplibName} ${LIBRARY_BUILD_TYPE} ${zrtpcpp_src})
set_target_properties(${zrtplibName} PROPERTIES VERSION ${VERSION} SOVERSION ${SOVERSION})
target_link_libraries(${zrtplibName} ${LIBS})

# **** A small test program ****
#
add_executable(testdriver testdriver.cpp)
target_link_libraries(testdriver ${zrtplibName})
add_dependencies(testdriver ${zrtplibName})

# **** Setup packing environment ****
#
if(${PROJECT_NAME} STREQUAL ${CMAKE_PROJECT_NAME})
    include(${CMAKE_SOURCE_DIR}/cmake/Modules/GeneratePackage.cmake)

    GENERATE_PACKAGING(${PACKAGE} ${VERSION})
endif()

# **** Create the external files for RPM and pkgconfig ****
#
set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix ${prefix}/bin)
set(libdir ${prefix}/${LIBDIRNAME})
set(includedir ${prefix}/include)
set(PACKAGE pkgconfig)

configure_file(${CMAKE_SOURCE_DIR}/libzrtpcpp.pc.cmake ${CMAKE_CURRENT_BINARY_DIR}/lib${zrtplibName}.pc @ONLY)
configure_file(${CMAKE_SOURCE_DIR}/libzrtpcpp.spec.cmake ${CMAKE_CURRENT_BINARY_DIR}/lib${zrtplibName}.spec @ONLY)

# **** install files ****
#
set(tivi_inst
    ${CMAKE_CURRENT_SOURCE_DIR}/CtZrtpNew.h)

install(FILES
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCodes.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpConfigure.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCallback.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCWrapper.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpUserCallback.h ${ccrtp_inst} DESTINATION include/libzrtpcpp)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/lib${zrtplibName}.pc DESTINATION ${LIBDIRNAME}/pkgconfig)

install(TARGETS ${zrtplibName} DESTINATION ${LIBDIRNAME})

if(${PROJECT_NAME} STREQUAL ${CMAKE_PROJECT_NAME})

    ########### Add uninstall target ###############
    configure_file("${CMAKE_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake" IMMEDIATE @ONLY)
    add_custom_target(uninstall "${CMAKE_COMMAND}" -P "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake")

endif()
