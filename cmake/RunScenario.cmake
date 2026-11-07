# Scenario regression test: synth -> replay -> compare with the reference output, then make sure
# the output contains no card numbers.
#   -DPCAPTOOL= -DSCENARIO= -DCONFIG= -DEXPECTED= -DWORKDIR= [-DPANSCAN=] [-DUPDATE=ON]
get_filename_component(name "${SCENARIO}" NAME_WE)
file(MAKE_DIRECTORY "${WORKDIR}")
set(pcap "${WORKDIR}/${name}.pcap")
set(out "${WORKDIR}/${name}.jsonl")

execute_process(COMMAND "${PCAPTOOL}" synth --scenario "${SCENARIO}" --out "${pcap}"
                RESULT_VARIABLE rc ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "synth failed (${rc}): ${err}")
endif()
execute_process(COMMAND "${PCAPTOOL}" replay --pcap "${pcap}" --config "${CONFIG}" --test-secret --strip
                        --out "${out}"
                RESULT_VARIABLE rc ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "replay failed (${rc}): ${err}")
endif()

if(UPDATE)
  configure_file("${out}" "${EXPECTED}" COPYONLY)
  message(STATUS "updated ${EXPECTED}")
  return()
endif()
if(NOT EXISTS "${EXPECTED}")
  message(FATAL_ERROR "no reference output ${EXPECTED}; run with -DUPDATE=ON to create it")
endif()
file(READ "${out}" got)
file(READ "${EXPECTED}" want)
if(NOT got STREQUAL want)
  message(FATAL_ERROR "output differs from ${EXPECTED}\n--- expected\n${want}\n--- got\n${got}\nreplay: ${err}")
endif()

if(PANSCAN)
  execute_process(COMMAND "${PANSCAN}" "${out}" RESULT_VARIABLE rc OUTPUT_VARIABLE scan)
  if(NOT rc EQUAL 0)
    message(FATAL_ERROR "card number candidates in the output:\n${scan}")
  endif()
endif()
