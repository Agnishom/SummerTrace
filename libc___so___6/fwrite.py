import simuvex

from . import io_file_data_for_arch

######################################
# fwrite
######################################

class fwrite(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, src, size, nmemb, file_ptr):

    	#additional code
        trace_data = ("fwrite", {"src": (src, src.symbolic), "size": (size, size.symbolic), "nmemb": (nmemb, nmemb.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        # TODO handle errors
        data = self.state.memory.load(src, size * nmemb, endness="Iend_BE")
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fileno = self.state.mem[file_ptr + fd_offset:].int.resolved
        written = self.state.posix.write(fileno, data, size*nmemb)

        return written
