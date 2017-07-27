import simuvex
from simuvex.s_type import SimTypeFd, SimTypeLength

import logging
l = logging.getLogger("simuvex.procedures.libc.fflush")

class fflush(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd):
        #pylint:disable=attribute-defined-outside-init

        #additional code
        trace_data = ("fflush", {"fd": (fd, fd.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        self.argument_types = {0: SimTypeFd()}
        self.return_type = SimTypeLength(self.state.arch)

        return self.state.se.BVV(0, self.state.arch.bits)
