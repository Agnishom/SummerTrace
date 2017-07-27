import simuvex
from simuvex.s_type import SimTypeInt
import logging

l = logging.getLogger("simuvex.procedures.usleep")


class usleep(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, n): #pylint:disable=unused-argument

    	#additional code - logging calls
        trace_data = ("usleep", {"n": (n, n.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)

        #end of additional code


        self.argument_types = {0: SimTypeInt(32, False)}
        self.return_type = SimTypeInt(32, True)
        return 0
