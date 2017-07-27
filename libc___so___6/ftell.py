import simuvex

from . import io_file_data_for_arch

######################################
# ftell
######################################

class ftell(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, file_ptr):

    	#additional code
        trace_data = ("ftell", {"file_ptr": (file_ptr, file_ptr.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fd = self.state.mem[file_ptr + fd_offset : ].int.resolved

        return self.state.posix.pos(fd)
