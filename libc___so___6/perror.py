import simuvex

######################################
# perror
######################################

class perror(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, string):

    	#additional code
        trace_data = ("perror", {"string": (string, string.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code


        write = simuvex.SimProcedures['syscalls']['write']
        strlen = simuvex.SimProcedures['libc.so.6']['strlen']

        length = self.inline_call(strlen, string).ret_expr
        self.inline_call(write, 2, string, length)
