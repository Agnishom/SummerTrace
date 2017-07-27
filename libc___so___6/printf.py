import logging
from simuvex.s_format import FormatParser

l = logging.getLogger("simuvex.procedures.libc_so_6.printf")

######################################
# _printf
######################################

class printf(FormatParser):

    def run(self):

    	#additional code
        trace_data = ("printf")
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        # The format str is at index 0
        fmt_str = self._parse(0)
        out_str = fmt_str.replace(1, self.arg)

        self.state.posix.write(1, out_str, out_str.size() / 8)

        # This function returns
        # Add another exit to the retn_addr that is at the top of the stack now
        return out_str.size() / 8
        # l.debug("Got return address for %s: 0x%08x.", __file__, self._exits[0].concretize())
