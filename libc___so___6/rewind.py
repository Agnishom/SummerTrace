import simuvex

######################################
# rewind
######################################

class rewind(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, file_ptr):

    	#additional code
        trace_data = ("rewind", {"file_ptr": (file_ptr, file_ptr.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code


        fseek = simuvex.SimProcedures['libc.so.6']['fseek']
        self.inline_call(fseek, file_ptr, 0, 0)

        return None
