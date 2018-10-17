
####################
# UNIT TESTS
####################

# Add test specific include paths
set(unittest-includes ${unittest-includes}
  ../features/cellular/framework/mux
)

# Source files
set(unittest-sources
  ../features/cellular/framework/mux/mbed_mux.cpp
  ../features/cellular/framework/mux/mbed_mux_data_service.cpp
)

# Test files
set(unittest-test-sources
  features/cellular/framework/mux/muxtest.cpp
  features/cellular/framework/mux/equeue_stub.cpp
  features/cellular/framework/mux/EventQueue_stub.cpp
  stubs/mbed_assert_stub.c
  stubs/FileHandle_stub.cpp
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DMBED_CONF_CELLULAR_DEBUG_AT=true -DOS_STACK_SIZE=2048")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DMBED_CONF_CELLULAR_DEBUG_AT=true -DOS_STACK_SIZE=2048")
