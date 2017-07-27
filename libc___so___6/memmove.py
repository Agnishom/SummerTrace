import simuvex
from simuvex.s_type import SimTypeTop, SimTypeLength

import logging
l = logging.getLogger("simuvex.procedures.libc.memmove")

class memmove(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst_addr, src_addr, limit):

        #additional code
        trace_data = ("memmove", {"dst_addr": (dst_addr, dst_addr.symbolic), "src_addr": (src_addr, src_addr.symbolic), "limit": (limit, limit.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        # TODO: look into smarter types here
        self.argument_types = {0: self.ty_ptr(SimTypeTop()),
                               1: self.ty_ptr(SimTypeTop()),
                               2: SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(SimTypeTop())

        memcpy = simuvex.SimProcedures['libc.so.6']['memcpy']

        self.inline_call(memcpy, dst_addr, src_addr, limit)
        return dst_addr
