import simuvex

class srand(simuvex.SimProcedure):
    IS_FUNCTION = True
    def run(self, seed):

    	#additional code
        trace_data = ("srand", {"seed": (seed, seed.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        self.ret()
