add_executable(fuzz_pcap onefile.cpp fuzz_pcap.cpp)
target_link_libraries(fuzz_pcap ${ARGN} ${LIBRARY_NAME}_static ${PCAP_LINK_LIBRARIES})
if(NOT "${SANITIZER_FLAGS}" STREQUAL "")
  set_target_properties(fuzz_pcap PROPERTIES
      LINK_FLAGS "${SANITIZER_FLAGS}")
endif()

add_executable(fuzz_filter onefile.cpp fuzz_filter.cpp)
target_link_libraries(fuzz_filter ${ARGN} ${LIBRARY_NAME}_static ${PCAP_LINK_LIBRARIES})
if(NOT "${SANITIZER_FLAGS}" STREQUAL "")
  set_target_properties(fuzz_filter PROPERTIES
      LINK_FLAGS "${SANITIZER_FLAGS}")
endif()

add_executable(fuzz_both onefile.cpp fuzz_both.cpp)
target_link_libraries(fuzz_both ${ARGN} ${LIBRARY_NAME}_static ${PCAP_LINK_LIBRARIES})
if(NOT "${SANITIZER_FLAGS}" STREQUAL "")
  set_target_properties(fuzz_both PROPERTIES
      LINK_FLAGS "${SANITIZER_FLAGS}")
endif()
