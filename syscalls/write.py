import simuvex

######################################
# write
######################################

class write(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    def run(self, fd, src, length):

    	#additional code
        trace_data = ("write", {"fd": (fd, fd.symbolic), "src": (src, src.symbolic), "length": (length, length.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        data = self.state.memory.load(src, length)
        length = self.state.posix.write(fd, data, length)
        return length
