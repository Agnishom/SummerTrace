import simuvex

from . import io_file_data_for_arch

######################################
# fputc
######################################

class ungetc(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, c, file_ptr):

    	#additional code
        trace_data = ("ungetc", {"c": (c, c.symbolic), "file_ptr": (file_ptr, file_ptr.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        # TODO handle errors
        # TODO THIS DOESN'T WORK IN ANYTHING BUT THE TYPICAL CASE
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fileno = self.state.mem[file_ptr + fd_offset:].int.concrete
        self.state.posix.files[fileno].pos -= 1

        return c & 0xff
