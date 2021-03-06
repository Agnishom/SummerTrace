import simuvex
from simuvex.s_type import SimTypeString

class strdup(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, s):

        #additional code
        trace_data = ("strdup", {"s": (s, s.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        self.argument_types = {0: self.ty_ptr(SimTypeString())}
        self.return_type = self.ty_ptr(SimTypeString())

        strlen = simuvex.SimProcedures['libc.so.6']['strlen']
        strncpy = simuvex.SimProcedures['libc.so.6']['strncpy']
        malloc = simuvex.SimProcedures['libc.so.6']['malloc']

        src_len = self.inline_call(strlen, s).ret_expr
        new_s = self.inline_call(malloc, src_len+1).ret_expr

        self.inline_call(strncpy, new_s, s, src_len+1, src_len=src_len)

        return new_s
