import simuvex
from simuvex.s_type import SimTypeString, SimTypeInt

import logging
l = logging.getLogger("simuvex.procedures.strcmp")

class strcmp(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, a_addr, b_addr):

        #additional code
        trace_data = ("strcmp", {"a_addr": (a_addr, a_addr.symbolic), "b_addr": (b_addr, b_addr.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                       1: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeInt(32, True)

        strlen = simuvex.SimProcedures['libc.so.6']['strlen']

        a_strlen = self.inline_call(strlen, a_addr)
        b_strlen = self.inline_call(strlen, b_addr)
        maxlen = self.state.se.BVV(max(a_strlen.max_null_index, b_strlen.max_null_index), self.state.arch.bits)

        strncmp = self.inline_call(simuvex.SimProcedures['libc.so.6']['strncmp'], a_addr, b_addr, maxlen, a_len=a_strlen, b_len=b_strlen)
        return strncmp.ret_expr
