####################
# UNIT TESTS
####################

# Add test specific include paths
set(unittest-includes ${unittest-includes}
  features/cellular/framework/common/util
  ../features/cellular/framework/common
  ../features/cellular/framework/AT
  ../features/netsocket/cellular
)

# Source files
set(unittest-sources
  ../features/cellular/framework/AT/AT_ControlPlane_netif.cpp
)

# Test files
set(unittest-test-sources
  features/cellular/framework/AT/at_controlplane_netif/at_controlplanenetiftest.cpp
  stubs/ATHandler_stub.cpp
  stubs/EventQueue_stub.cpp
  stubs/FileHandle_stub.cpp  
  stubs/AT_CellularBase_stub.cpp
)
