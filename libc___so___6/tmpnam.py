import simuvex
import tempfile

######################################
# tmpnam
######################################

class tmpnam(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, tmp_file_path_addr):
        L_tmpnam = 20

        #additional code
        trace_data = ("tmpnam", {"tmp_file_path_addr": (tmp_file_path_addr, tmp_file_path_addr.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        if self.state.se.any_int(tmp_file_path_addr) != 0:
            return tmp_file_path_addr

        tmp_file_path = tempfile.mktemp()
        malloc = simuvex.SimProcedures['libc.so.6']['malloc']
        addr = self.inline_call(malloc, L_tmpnam).ret_expr
        self.state.memory.store(addr,
                                tmp_file_path + '\x00')

        return addr
