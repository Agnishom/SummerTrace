import simuvex
from simuvex.s_type import SimTypeInt

######################################
# getchar
######################################


class getchar(simuvex.SimProcedure):

    def run(self):

    	#additional code
        trace_data = ("getchar")
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        self.return_type = SimTypeInt(32, True)
        data = self.inline_call(
            simuvex.SimProcedures['libc.so.6']['_IO_getc'], 0).ret_expr  # stdin
        return data
