import simuvex
from simuvex.s_type import SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength

######################################
# read
######################################

class read(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, dst, length):

    	#additional code
        trace_data = ("read", {"fd": (fd, fd.symbolic), "dst": (dst, dst.symbolic), "length": (length, length.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code


        self.argument_types = {0: SimTypeFd(),
                               1: self.ty_ptr(SimTypeArray(SimTypeChar(), length)),
                               2: SimTypeLength(self.state.arch)}
        self.return_type = SimTypeLength(self.state.arch)

        # TODO handle errors
        length = self.state.posix.read(fd, dst, length)

        return length
