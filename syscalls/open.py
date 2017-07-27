import simuvex

######################################
# open
######################################

class open(simuvex.SimProcedure): #pylint:disable=W0622
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    def run(self, path, flags):

    	#additional code
        trace_data = ("open", {"path": (path, path.symbolic), "flags": (flags, flags.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        return self.state.posix.open(path, flags)
