check_include_file_cxx(stdint.h HAVE_STDINT_H)
if(HAVE_STDINT_H)
    add_definitions(-DHAVE_STDINT_H)
endif()

set(examples_as_tests_sources)
if(${ENABLE_EXAMPLES})
    set(examples_as_tests_sources
        #test/sink-manager-examples-test-suite.cc
        )
endif()

find_package(OpenSSL REQUIRED)


build_lib(
    LIBNAME sink-manager
    SOURCE_FILES model/sink-manager.cc
                 helper/sink-manager-helper.cc
    HEADER_FILES model/sink-manager.h
                 helper/sink-manager-helper.h
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
    TEST_SOURCES test/sink-manager-test-suite.cc
                 ${examples_as_tests_sources}
)
