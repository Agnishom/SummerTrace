import simuvex

class fork(simuvex.SimProcedure):
    def run(self):

    	#additional code
        trace_data = ("fork")
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        return self.state.se.If(self.state.se.BoolS('fork_parent'),
                self.state.se.BVV(1338, self.state.arch.bits),
                self.state.se.BVV(0, self.state.arch.bits))
