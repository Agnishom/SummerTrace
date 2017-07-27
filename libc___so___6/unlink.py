import simuvex

######################################
# unlink
######################################

class unlink(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, path):

    	#additional code
        trace_data = ("unlink", {"path": (path, path.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        unlink_sys = simuvex.SimProcedures['syscalls']['unlink']
        return self.inline_call(unlink_sys, path).ret_expr
