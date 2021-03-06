import logging
from simuvex.s_format import FormatParser

l = logging.getLogger("simuvex.procedures.snprintf")

######################################
# snprintf
######################################

class snprintf(FormatParser):

    def run(self, dst_ptr, size):  # pylint:disable=arguments-differ,unused-argument

    	#additional code
        trace_data = ("snprintf", {"dst_ptr": (dst_ptr, dst_ptr.symbolic), "size": (size, size.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        # The format str is at index 2
        fmt_str = self._parse(2)
        out_str = fmt_str.replace(3, self.arg)
        self.state.memory.store(dst_ptr, out_str)

        # place the terminating null byte
        self.state.memory.store(dst_ptr + (out_str.size() / 8), self.state.se.BVV(0, 8))

        # size_t has size arch.bits
        return self.state.se.BVV(out_str.size()/8, self.state.arch.bits)
