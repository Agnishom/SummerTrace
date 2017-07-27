import simuvex
######################################
# htons (yes, really)
######################################

class htons(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, to_convert):

    	#additional code
        trace_data = ("htons", {"to_convert": (to_convert, to_convert.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        if self.state.arch.memory_endness == "Iend_LE":
            return to_convert.reversed
        else:
            return to_convert
