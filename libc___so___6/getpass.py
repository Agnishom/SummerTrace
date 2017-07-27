import simuvex

######################################
# getpass
######################################

class getpass(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, prompt):

        #additional code
        trace_data = ("getpass", {"getpass": (getpass, getpass.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        # write out the prompt
        self.inline_call(simuvex.SimProcedures['libc.so.6']['puts'], prompt)

        # malloc a buffer
        buf = self.inline_call(simuvex.SimProcedures['libc.so.6']['malloc'], 1024).ret_expr

        # read into the buffer
        self.inline_call(simuvex.SimProcedures['libc.so.6']['read'], 0, buf, 1024)

        # return the buffer
        return buf
