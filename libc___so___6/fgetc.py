import simuvex
from simuvex.s_type import SimTypeInt

from . import io_file_data_for_arch

######################################
# fgetc
######################################


class fgetc(simuvex.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, file_ptr):

    	#additional code
        trace_data = ("fgetc", {"file_ptr": (file_ptr, file_ptr.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        self.return_type = SimTypeInt(32, True)

        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fd = self.state.mem[file_ptr + fd_offset : ].int.resolved

        data = self.inline_call(
            simuvex.SimProcedures['libc.so.6']['_IO_getc'], fd).ret_expr
        return data
