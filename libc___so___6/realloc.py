import simuvex
from simuvex.s_type import SimTypeLength, SimTypeTop

import logging
l = logging.getLogger("simuvex.procedures.libc.realloc")

######################################
# realloc
######################################

class realloc(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, ptr, size):

        #additional code
        trace_data = ("realloc", {"ptr": (ptr, ptr.symbolic), "size": (size, size.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        self.state.add_constraints(size <= self.state.libc.max_variable_size)
        size_int = self.state.se.max_int(size)

        l.debug("Size: %d", size_int)
        self.state.add_constraints(size_int == size)

        self.argument_types = { 0: self.ty_ptr(SimTypeTop()),
                                1: SimTypeLength(self.state.arch) }
        self.return_type = self.ty_ptr(SimTypeTop(size))

        addr = self.state.libc.heap_location
        v = self.state.memory.load(ptr, size_int)
        self.state.memory.store(addr, v)
        self.state.libc.heap_location += size_int

        return addr
