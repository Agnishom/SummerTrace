import simuvex
from simuvex.s_type import SimTypeInt

import logging
l = logging.getLogger("simuvex.procedures.libc.sleep")

class sleep(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, seconds):

    	#additional code
        trace_data = ("sleep", {"seconds": (seconds, seconds.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: SimTypeInt(self.state.arch.bits, True)}
        self.return_type = SimTypeInt(self.state.arch.bits, True)

        return self.state.se.BVV(0, self.state.arch.bits)
