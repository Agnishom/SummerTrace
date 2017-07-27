import simuvex

######################################
# exit
######################################

class exit(simuvex.SimProcedure): #pylint:disable=redefined-builtin
    #pylint:disable=arguments-differ

    NO_RET = True
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
