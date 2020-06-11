cmake_minimum_required (VERSION 2.6)

# setup the Thread include and lib
find_package(Threads)
if(CMAKE_HAVE_PTHREAD_H)
  set(HAVE_PTHREAD_H TRUE)
endif()
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})


# to make sure these includes are taken first - it contains config.h
include_directories(BEFORE ${CMAKE_BINARY_DIR})
include_directories (${CMAKE_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/zrtp ${CMAKE_SOURCE_DIR}/srtp)

set(crypto_src
        ${zrtp_botan_crypto_src})

if (SRTP)
   include_directories(${CMAKE_SOURCE_DIR}/srtp ${CMAKE_SOURCE_DIR}/srtp/crypto)
   set (zrtp_srtp_src
           ${CMAKE_SOURCE_DIR}/srtp/CryptoContext.cpp
           ${CMAKE_SOURCE_DIR}/srtp/CryptoContextCtrl.cpp
           ${CMAKE_SOURCE_DIR}/srtp/SrtpHandler.cpp
           ${CMAKE_SOURCE_DIR}/srtp/crypto/hmac.h
           ${CMAKE_SOURCE_DIR}/srtp/crypto/SrtpSymCrypto.h
           ${CMAKE_SOURCE_DIR}/srtp/crypto/botan/hmac.cpp
           ${CMAKE_SOURCE_DIR}/srtp/crypto/botan/macSkein.cpp
           ${CMAKE_SOURCE_DIR}/srtp/crypto/botan/SrtpSymCrypto.cpp)
endif()

set(genericFilter_src
        GenericPacketFilter.cpp
        GenericPacketFilter.h)

set(zrtpcpp_src ${zrtp_src} ${crypto_src} ${zrtp_srtp_src} ${genericFilter_src})

if(BUILD_STATIC AND NOT BUILD_SHARED)
    set(LIBRARY_BUILD_TYPE STATIC)
else()
    set(LIBRARY_BUILD_TYPE SHARED)
    if (ANDROID)
        set(logLib log)
    endif()
endif()

add_library(${zrtplibName} ${LIBRARY_BUILD_TYPE} ${zrtpcpp_src} )
set_target_properties(${zrtplibName} PROPERTIES VERSION ${VERSION} SOVERSION ${SOVERSION})
target_link_libraries(${zrtplibName} ${logLib} ${sidhLibNameStatic} ${LIBS})

if (NOT ANDROID)
    # **** Setup packing environment ****
    #
    if(${PROJECT_NAME} STREQUAL ${CMAKE_PROJECT_NAME})
        include(${CMAKE_SOURCE_DIR}/cmake/Modules/GeneratePackage.cmake)

        GENERATE_PACKAGING(${PACKAGE} ${VERSION} "")
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
    install(FILES
            ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCodes.h
            ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpConfigure.h
            ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCallback.h
            ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCWrapper.h
            ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpUserCallback.h DESTINATION include/libzrtpcpp)

    install(FILES ${CMAKE_SOURCE_DIR}/common/osSpecifics.h DESTINATION include/libzrtpcpp/common)

    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/lib${zrtplibName}.pc DESTINATION ${LIBDIRNAME}/pkgconfig)

    install(TARGETS ${zrtplibName} DESTINATION ${LIBDIRNAME})

    if(${PROJECT_NAME} STREQUAL ${CMAKE_PROJECT_NAME})

        ########### Add uninstall target ###############
        configure_file("${CMAKE_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake" IMMEDIATE @ONLY)
        add_custom_target(uninstall "${CMAKE_COMMAND}" -P "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake")
    endif()
endif()

