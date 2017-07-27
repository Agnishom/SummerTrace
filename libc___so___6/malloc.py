import simuvex
from simuvex.s_type import SimTypeLength, SimTypeTop
import itertools

######################################
# malloc
######################################

malloc_mem_counter = itertools.count()

class malloc(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, sim_size):

        #additional code
        trace_data = ("malloc", {"sim_size": (sim_size, sim_size.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        self.argument_types = {0: SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(SimTypeTop(sim_size))

        if self.state.se.symbolic(sim_size):
            size = self.state.se.max_int(sim_size)
            if size > self.state.libc.max_variable_size:
                size = self.state.libc.max_variable_size
        else:
            size = self.state.se.any_int(sim_size)

        addr = self.state.libc.heap_location
        self.state.libc.heap_location += size
        return addr
