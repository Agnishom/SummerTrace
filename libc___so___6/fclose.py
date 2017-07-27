import simuvex

from . import io_file_data_for_arch

######################################
# fclose
######################################

class fclose(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd_p):

    	#additional code
        trace_data = ("fclose", {"fd_p": (fd_p, fd_p.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        # Resolve file descriptor
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fileno = self.state.mem[fd_p + fd_offset:].int.resolved

        sys_close = simuvex.SimProcedures['syscalls']['close']

        # Call system close and return
        retval = self.inline_call(sys_close, fileno).ret_expr

        return retval
