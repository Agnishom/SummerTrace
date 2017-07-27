import simuvex

class mprotect(simuvex.SimProcedure):

    IS_SYSCALL = True

    def run(self, addr, length, prot): #pylint:disable=arguments-differ,unused-argument

    	#additional code
        trace_data = ("mprotect", {"addr": (addr, addr.symbolic), "length": (length, length.symbolic), "prot": (prot, prot.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        # TODO: Actually handle this syscall
        return self.state.se.BVV(0, self.state.arch.bits)
