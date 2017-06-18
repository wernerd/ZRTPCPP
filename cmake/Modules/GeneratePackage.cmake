
MACRO(GENERATE_PACKAGING PACKAGE VERSION EXCLUDE_FILES)

    # The following components are regex's to match anywhere (unless anchored)
    # in absolute path + filename to find files or directories to be excluded
    # from source tarball.
    # The caller may specify additional files to exclude
    SET(CPACK_SOURCE_IGNORE_FILES
            #svn files
            "\\\\.svn/"
            "\\\\.cvsignore$"
            # temporary files
            "\\\\.swp$"
            # backup files
            "~$"
            # eclipse files
            "\\\\.cdtproject$"
            "\\\\.cproject$"
            "\\\\.project$"
            "\\\\.settings/"
            # KDevelop files
            "\\\\.kdev4/"
            "\\\\.kdev4$"
            "\\\\.kdev4_include_paths$"
            # CLion ide files
            "\\\\.idea/"
            # others
            "\\\\.#"
            "/#"
            "/build*"
            "/cmake-build-*"
            "/helper/"
            "/docLocal/"
            "/autom4te\\\\.cache/"
            "/_build/"
            "/doc/html/"
            "/\\\\.git/"
            # used before
            "/CVS/"
            "/\\\\.libs/"
            "/\\\\.deps/"
            "\\\\.o$"
            "\\\\.lo$"
            "\\\\.la$"
            "\\\\.sh$"
            "Makefile\\\\.in$"
            "\\\\.directory$"
            "\\\\._.DS_Store$"
            "\\\\.DS_Store$"
            "\\\\._buildmac$"
            ${EXCLUDE_FILES})

    SET(CPACK_PACKAGE_VENDOR "Werner Dittmann")
    #SET(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/ReadMe.txt")
    #SET(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/Copyright.txt")
    #SET(CPACK_PACKAGE_VERSION_MAJOR ${version_major})
    #SET(CPACK_PACKAGE_VERSION_MINOR ${version_minor})
    #SET(CPACK_PACKAGE_VERSION_PATCH ${version_patch})
    SET(CPACK_GENERATOR "TBZ2")
    SET(CPACK_SOURCE_GENERATOR "TBZ2")
    SET(CPACK_SOURCE_PACKAGE_FILE_NAME "${PACKAGE}-${VERSION}")
    INCLUDE(CPack)

    #  SPECFILE()

    ADD_CUSTOM_TARGET(gitcheck
            COMMAND cd $(CMAKE_SOURCE_DIR) && test -z \"`git status -uno --porcelain`\")

    SET(AUTOBUILD_COMMAND
            COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/*.tar.bz2
            COMMAND ${CMAKE_MAKE_PROGRAM} package_source
            )

    ADD_CUSTOM_TARGET(srcpackage_local
            ${AUTOBUILD_COMMAND})

    ADD_CUSTOM_TARGET(srcpackage
            COMMAND ${CMAKE_MAKE_PROGRAM} gitcheck
            ${AUTOBUILD_COMMAND})

ENDMACRO(GENERATE_PACKAGING)
