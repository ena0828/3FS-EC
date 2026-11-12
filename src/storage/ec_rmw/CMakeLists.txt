# Shared arithmetic/authentication only. No Storage server/runtime dependency.
target_add_lib(ec-rmw-core storage-fbs ec-codec ec-repair common)
set_property(TARGET ec-rmw-core PROPERTY SOURCES
  EcRmwPlan.cc EcRmwPlan.h
  EcRmwAuthorization.cc EcRmwAuthorization.h
  EcRmwComputation.cc EcRmwComputation.h
  EcRmwExecution.cc EcRmwExecution.h
  EcRmwPatchBuffer.cc EcRmwPatchBuffer.h
  EcRmwWire.cc EcRmwWire.h
)
