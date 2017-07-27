import simuvex
from .open import open

class opendir(simuvex.SimProcedure):
    def run(self, fname):

    	#additional code
        trace_data = ("opendir", {"fname": (fname, fname.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        p_open = self.inline_call(open, fname, 0o200000) # O_DIRECTORY
        # using the same hack we used to use for fopen etc... using the fd as a pointer
        return p_open.ret_expr
