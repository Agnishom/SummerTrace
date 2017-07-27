import simuvex

######################################
# close
######################################

class close(simuvex.SimProcedure):
    def run(self, fd):  # pylint:disable=arguments-differ

    	#additional code
        trace_data = ("close", {"fd": (fd, fd.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        self.state.posix.close(fd)

        return self.state.se.BVV(0, self.state.arch.bits)
