import simuvex

######################################
# recvfrom
######################################

class recvfrom(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, dst, length, flags): #pylint:disable=unused-argument

    	#additional code
        trace_data = ("recvfrom", {"fd": (fd, fd.symbolic), "dst": (dst, dst.symbolic), "length": (length, length.symbolic), "flags": (flags, flags.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        bytes_recvd = self.state.posix.read(fd, dst, self.state.se.any_int(length))
        return bytes_recvd
