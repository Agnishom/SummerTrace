import logging
from simuvex.s_format import FormatParser

l = logging.getLogger("simuvex.procedures.sprintf")

######################################
# sprintf
######################################

class sprintf(FormatParser):
    #pylint:disable=arguments-differ

    def run(self, dst_ptr):

        #additional code
        trace_data = ("sprintf", {"dst_ptr": (dst_ptr, dst_ptr.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        # The format str is at index 1
        fmt_str = self._parse(1)
        out_str = fmt_str.replace(2, self.arg)
        self.state.memory.store(dst_ptr, out_str)

        # place the terminating null byte
        self.state.memory.store(dst_ptr + (out_str.size() / 8), self.state.se.BVV(0, 8))

        # size_t has size arch.bits
        return self.state.se.BVV(out_str.size()/8, self.state.arch.bits)
