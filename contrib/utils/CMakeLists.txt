check_include_file_cxx(stdint.h HAVE_STDINT_H)
if(HAVE_STDINT_H)
    add_definitions(-DHAVE_STDINT_H)
endif()

set(examples_as_tests_sources)
if(${ENABLE_EXAMPLES})
    set(examples_as_tests_sources
        #test/utils-examples-test-suite.cc
        )
endif()

find_package(OpenSSL REQUIRED)


build_lib(
    LIBNAME utils
    SOURCE_FILES model/utils.cc
                 helper/utils-helper.cc
    HEADER_FILES model/utils.h
                 helper/utils-helper.h
    LIBRARIES_TO_LINK
        ${libcore}
        ${OPENSSL_LIBRARIES} 
    TEST_SOURCES test/utils-test-suite.cc
                 ${examples_as_tests_sources}
)
