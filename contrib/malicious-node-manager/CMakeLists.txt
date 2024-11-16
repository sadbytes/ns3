check_include_file_cxx(stdint.h HAVE_STDINT_H)
if(HAVE_STDINT_H)
    add_definitions(-DHAVE_STDINT_H)
endif()

set(examples_as_tests_sources)
if(${ENABLE_EXAMPLES})
    set(examples_as_tests_sources
        #test/malicious-node-manager-examples-test-suite.cc
        )
endif()

build_lib(
    LIBNAME malicious-node-manager
    SOURCE_FILES model/malicious-node-manager.cc
                 helper/malicious-node-manager-helper.cc
    HEADER_FILES model/malicious-node-manager.h
                 helper/malicious-node-manager-helper.h
    LIBRARIES_TO_LINK
        ${libcore}
        ${libmobility}
        ${libnetwork}
        ${libwifi}
        ${libinternet}
        ${libnode-manager}
    TEST_SOURCES test/malicious-node-manager-test-suite.cc
                 ${examples_as_tests_sources}
)
