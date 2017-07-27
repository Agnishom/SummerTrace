import simuvex
from simuvex.s_type import SimTypeTop

######################################
# free
######################################
class free(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, ptr): #pylint:disable=unused-argument

        #additional code
        trace_data = ("free", {"ptr": (ptr, ptr.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code


        self.argument_types = {0: self.ty_ptr(SimTypeTop())}
        return self.state.se.Unconstrained('free', self.state.arch.bits)
