import simuvex

######################################
# putchar
######################################

class putchar(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, string):

    	#additional code
        trace_data = ("putchar", {"string": (string, string.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        self.state.posix.write(1, string[7:0], 1)
        return string[7:0].zero_extend(self.state.arch.bits - 8)
