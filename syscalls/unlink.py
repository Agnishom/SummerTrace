import simuvex

######################################
# unlink
######################################

class unlink(simuvex.SimProcedure): #pylint:disable=W0622
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    def run(self, path_addr):

        #additional code
        trace_data = ("unlink", {"path_addr": (path_addr, path_addr.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        # This is a dummy for now
        strlen = simuvex.SimProcedures['libc.so.6']['strlen']

        p_strlen = self.inline_call(strlen, path_addr)
        str_expr = self.state.memory.load(path_addr, p_strlen.max_null_index, endness='Iend_BE')
        str_val = self.state.se.any_str(str_expr)

        ret = self.state.posix.remove(str_val)

        return self.state.se.BVV(ret, self.state.arch.bits)
