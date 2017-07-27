import simuvex

class munmap(simuvex.SimProcedure):

    IS_SYSCALL = True

    def run(self, addr, length): #pylint:disable=arguments-differ,unused-argument

    	#additional code
        trace_data = ("mnumap", {"addr": (addr, addr.symbolic), "length": (length, length.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        # TODO: actually do something
        return self.state.se.BVV(0, self.state.arch.bits)
