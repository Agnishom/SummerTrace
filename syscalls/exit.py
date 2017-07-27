import simuvex

######################################
# exit
######################################

#pylint:disable=redefined-builtin,arguments-differ
class exit(simuvex.SimProcedure):
    NO_RET = True
    IS_SYSCALL = True


    def run(self, exit_code):

    	#additional code
        trace_data = ("exit", {"exit_code": (exit_code, exit_code.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

       	self.exit(exit_code)

