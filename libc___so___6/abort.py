import simuvex

######################################
# abort
######################################

class abort(simuvex.SimProcedure):
    NO_RET = True

    def run(self):
    	#additional code
    	try:
    		self.state.procedure_data.global_variables["trace"].append("abort")
    	except KeyError:
    		self.state.procedure_data.global_variables["trace"] = []
    		self.state.procedure_data.global_variables["trace"].append("abort")
    	#end of additional code
        self.exit(1)
