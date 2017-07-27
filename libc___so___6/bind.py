import simuvex

######################################
# bind (but not really)
######################################
import logging
l = logging.getLogger("simuvex.procedures.libc.bind")

class bind(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd): #pylint:disable=unused-argument
        #additional code
        trace_data = ("bind", {"fd": (fd, fd.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        return self.state.se.Unconstrained('bind', self.state.arch.bits)
