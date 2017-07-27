import simuvex

######################################
# read
######################################

class read(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    def run(self, fd, dst, length):

    	#additional code
        trace_data = ("read", {"fd": (fd, fd.symbolic), "dst": (dst, dst.symbolic), "length": (length, length.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        self.state.posix.read(fd, dst, length)
        return length
