find_path(LIBOQS_INCLUDE_DIRS
    NAMES oqs/oqs.h
    PATH_SUFFIXES include)

find_library(LIBOQS_LIBRARIES
    NAMES oqs
    PATH_SUFFIXES lib)

if(LIBOQS_INCLUDE_DIRS)
    if(EXISTS ${LIBOQS_INCLUDE_DIRS}/oqs/oqsconfig.h)
        file(READ ${LIBOQS_INCLUDE_DIRS}/oqs/oqsconfig.h LIBOQS_CONFIG_CONTENTS)

        string(REGEX MATCH "#define OQS_VERSION_TEXT \"([^\"]*)\"" _dummy ${LIBOQS_CONFIG_CONTENTS})
        set(LIBOQS_VERSION ${CMAKE_MATCH_1})

        string(REGEX MATCH "#define OQS_USE_OPENSSL ([0-1])" _dummy ${LIBOQS_CONFIG_CONTENTS})
        set(LIBOQS_USE_OPENSSL ${CMAKE_MATCH_1})
        
        if(LIBOQS_USE_OPENSSL)
            find_package(OpenSSL 1.1.1 REQUIRED)
            list(APPEND LIBOQS_LIBRARIES OpenSSL::Crypto)
        endif()
    endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(liboqs
    REQUIRED_VARS LIBOQS_LIBRARIES LIBOQS_INCLUDE_DIRS
    VERSION_VAR LIBOQS_VERSION)
