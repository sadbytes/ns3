check_include_file_cxx(stdint.h HAVE_STDINT_H)
if(HAVE_STDINT_H)
    add_definitions(-DHAVE_STDINT_H)
endif()

set(examples_as_tests_sources)
if(${ENABLE_EXAMPLES})
    set(examples_as_tests_sources
        #test/node-manager-examples-test-suite.cc
        )
endif()

find_package(OpenSSL REQUIRED)

build_lib(
    LIBNAME node-manager
    SOURCE_FILES model/node-manager.cc
                 helper/node-manager-helper.cc
    HEADER_FILES model/node-manager.h
                 helper/node-manager-helper.h
    LIBRARIES_TO_LINK 
        ${libcore}
        ${libmobility}
        ${libnetwork}
        ${libwifi}
        ${libinternet}
        ${libpoint-to-point}
        ${libapplications}
        ${libutils}
        ${OPENSSL_LIBRARIES} 
    TEST_SOURCES test/node-manager-test-suite.cc
                 ${examples_as_tests_sources}
)
