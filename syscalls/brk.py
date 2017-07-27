import simuvex

class brk(simuvex.SimProcedure):
    """
    This implements the brk system call.
    """

    IS_SYSCALL = True

    #pylint:disable=arguments-differ

    def run(self, new_brk):

    	#additional code
        trace_data = ("brk", {"new_brk": (new_brk, new_brk.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        return self.state.posix.set_brk(new_brk)
