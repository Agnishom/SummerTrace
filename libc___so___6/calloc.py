import simuvex
from simuvex.s_type import SimTypeLength, SimTypeArray, SimTypeTop

######################################
# calloc
######################################

class calloc(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, sim_nmemb, sim_size):

        #additional code
        trace_data = ("calloc", {"sim_nmemb": (sim_nmemb, sim_nmemb.symbolic), "sim_size": (sim_size, sim_size.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        self.argument_types = { 0: SimTypeLength(self.state.arch),
                                1: SimTypeLength(self.state.arch)}
        plugin = self.state.get_plugin('libc')

        self.return_type = self.ty_ptr(SimTypeArray(SimTypeTop(sim_size), sim_nmemb))

        if self.state.se.symbolic(sim_nmemb):
            # TODO: find a better way
            nmemb = self.state.se.max_int(sim_nmemb)
        else:
            nmemb = self.state.se.any_int(sim_nmemb)

        if self.state.se.symbolic(sim_size):
            # TODO: find a better way
            size = self.state.se.max_int(sim_size)
        else:
            size = self.state.se.any_int(sim_size)

        final_size = size * nmemb
        if final_size > plugin.max_variable_size:
            final_size = plugin.max_variable_size

        addr = plugin.heap_location
        plugin.heap_location += final_size
        v = self.state.se.BVV(0, final_size * 8)
        self.state.memory.store(addr, v)

        return addr
