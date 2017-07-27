import simuvex

class rand(simuvex.SimProcedure):
    IS_FUNCTION = True
    def run(self):

    	#additional code
        trace_data = ("rand")
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        rval = self.state.se.BVS('rand', 31)
        return rval.zero_extend(self.state.arch.bits - 31)
