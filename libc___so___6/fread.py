import simuvex

from . import io_file_data_for_arch

######################################
# fread
######################################

class fread(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst, size, nm, file_ptr):

    	#additional code
        trace_data = ("fread", {"dst": (dst, dst.symbolic), "size": (size, size.symbolic), "nm": (nm, nm.symbolic), "file_ptr": (file_ptr, file_ptr.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        # TODO handle errors

        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fd = self.state.mem[file_ptr + fd_offset:].int.resolved
        ret = self.state.posix.read(fd, dst, size * nm)
        return self.state.se.If(self.state.se.Or(size == 0, nm == 0), 0, ret / size)
