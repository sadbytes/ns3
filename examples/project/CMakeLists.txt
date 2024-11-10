build_example(
    NAME AuthSimulation
    SOURCE_FILES AuthSimulation.cc
    LIBRARIES_TO_LINK
      ${libcore}
      ${libmobility}
      ${libnetwork}
      ${libwifi}
      ${libinternet}
      ${libcsma}
      ${libpoint-to-point}
      ${libapplications}
      ${libnode-manager}
      ${libsink-manager}
      ${libmalicious-node-manager}
      ${libutils}
  )


  build_example(
    NAME testauth
    SOURCE_FILES test-auth.cc
    LIBRARIES_TO_LINK
      ${libcore}
      ${libmobility}
      ${libnetwork}
      ${libwifi}
      ${libinternet}
      ${libpoint-to-point}
      ${libapplications}
      ${libnode-manager}
      ${libsink-manager}
  )
