import simuvex

######################################
# __vsnprintf
######################################

class vsnprintf(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, str_ptr, size, fmt, ap): #pylint:disable=unused-argument
        # This function returns
        # Add another exit to the retn_addr that is at the top of the stack now

        #additional code
        trace_data = ("vsnprintf", {"str_ptr": (str_ptr, str_ptr.symbolic), "size": (size, size.symbolic), "fmt": (fmt, fmt.symbolic), "ap": (ap, ap.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        self.state.memory.store(str_ptr, "\x00")

        return size - 1
