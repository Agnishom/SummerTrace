import simuvex

from . import io_file_data_for_arch

######################################
# fputs
######################################

class fputs(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, str_addr, file_ptr):

        #additional code
        trace_data = ("fputs", {"str_addr": (str_addr, str_addr.symbolic), "file_ptr": (file_ptr, file_ptr.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        # TODO handle errors
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fileno = self.state.mem[file_ptr + fd_offset:].int.resolved

        strlen = simuvex.SimProcedures['libc.so.6']['strlen']
        p_strlen = self.inline_call(strlen, str_addr)
        str_expr = self.state.memory.load(str_addr, p_strlen.max_null_index, endness='Iend_BE')
        str_val = self.state.se.any_str(str_expr)

        self.state.posix.write(fileno, str_val, p_strlen.max_null_index)

        return 1
