cmake_minimum_required (VERSION 2.6)

# setup the Thread include and lib
find_package(Threads)
if(CMAKE_HAVE_PTHREAD_H)
  set(HAVE_PTHREAD_H TRUE)
endif()
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})

if (USES_CCRTP_INCLUDE_DIRS)
    message(STATUS "  Using local commoncpp dependency")
else()
    pkg_check_modules(USES_CCRTP libccrtp>=2.0.0)
    if (NOT USES_CCRTP_FOUND)
        message(FATAL_ERROR "CCRTP library and development headers not found")
    endif()
endif()
include_directories(${USES_CCRTP_INCLUDE_DIRS})
link_directories(${USES_CCRTP_LIBRARY_DIRS})
add_definitions(${USES_CCRTP_CFLAGS})
set (LIBS ${LIBS} ${USES_CCRTP_LDFLAGS} ${USES_CCRTP_LIBRARIES})

include_directories (${CMAKE_CURRENT_SOURCE_DIR})

# **** setup the various crypto interface implementations ***
# Twofish is a special case: its always a standalone module and thus
# not specific to a library.

set(zrtp_ccrtp_src
        ${CMAKE_CURRENT_SOURCE_DIR}/ZrtpQueue.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtpccrtp.h)


set(zrtpcpp_src ${zrtp_src} ${zrtp_ccrtp_src} ${zrtp_crypto_src})

if(BUILD_STATIC AND NOT BUILD_SHARED)
    set(LIBRARY_BUILD_TYPE STATIC)
else()
    set(LIBRARY_BUILD_TYPE SHARED)
endif()

add_library(${zrtplibName} ${LIBRARY_BUILD_TYPE} ${zrtpcpp_src})
set_target_properties(${zrtplibName} PROPERTIES VERSION ${VERSION} SOVERSION ${SOVERSION})
target_link_libraries(${zrtplibName} ${LIBS})

# add_dependencies(${zrtplibName} ccrtp)

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
set(ccrtp_inst
    ${CMAKE_CURRENT_SOURCE_DIR}/ZrtpQueue.h
    ${CMAKE_CURRENT_SOURCE_DIR}/zrtpccrtp.h
        )

install(FILES
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCodes.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpConfigure.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCallback.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCWrapper.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpUserCallback.h ${ccrtp_inst} DESTINATION include/libzrtpcpp)

install(FILES ${CMAKE_SOURCE_DIR}/common/osSpecifics.h DESTINATION include/libzrtpcpp/common)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/lib${zrtplibName}.pc DESTINATION ${LIBDIRNAME}/pkgconfig)

install(TARGETS ${zrtplibName} DESTINATION ${LIBDIRNAME})

if(${PROJECT_NAME} STREQUAL ${CMAKE_PROJECT_NAME})

    ########### Add uninstall target ###############
    configure_file("${CMAKE_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake" IMMEDIATE @ONLY)
    add_custom_target(uninstall "${CMAKE_COMMAND}" -P "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake")

endif()


