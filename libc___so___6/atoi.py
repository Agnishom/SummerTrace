import simuvex
from simuvex.s_type import SimTypeString, SimTypeInt

import logging
l = logging.getLogger("simuvex.procedures.libc.strlen")


class atoi(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, s):
        #pylint:disable=attribute-defined-outside-init

        #additional code
        trace_data = ("atoi", {"s": (s, s.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code


        self.argument_types = {0: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeInt(self.state.arch, True)

        strtol = simuvex.SimProcedures['libc.so.6']['strtol']
        return strtol.strtol_inner(s, self.state, self.state.memory, 10, True)[1]
