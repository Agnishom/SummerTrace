import simuvex

from . import io_file_data_for_arch

######################################
# fputc
######################################

class feof(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, file_ptr):

        #additional code
        trace_data = ("file_ptr", {"file_ptr": (file_ptr, file_ptr.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        # TODO handle errors
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fileno = self.state.mem[file_ptr + fd_offset:].int.concrete

        if fileno in self.state.posix.files:
            f = self.state.posix.files[fileno]
            if f.size is None or self.state.se.is_true(f.pos < f.size):
                return 0
            else:
                return 1
        else:
            return -1
