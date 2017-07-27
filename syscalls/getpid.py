import simuvex

class getpid(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    def run(self):

    	#additional code
        trace_data = ("getpid")
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        return self.state.posix.pid
