import simuvex

######################################
# Doing nothing
######################################

class pthread_cond_signal(simuvex.SimProcedure):
    def run(self):

    	#additional code
        trace_data = ("pthread_cond_signal")
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        _ = self.arg(0)
