import simuvex
from simuvex.s_type import SimTypeString, SimTypeInt, SimTypeFd

######################################
# open
######################################

class open(simuvex.SimProcedure): #pylint:disable=W0622
    #pylint:disable=arguments-differ

    def run(self, p_addr, flags):

        #additional code
        trace_data = ("open", {"p_addr": (p_addr, p_addr.symbolic), "flags": (flags, flags.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                               1: SimTypeInt(32, True)}
        self.return_type = SimTypeFd()

        strlen = simuvex.SimProcedures['libc.so.6']['strlen']

        p_strlen = self.inline_call(strlen, p_addr)
        p_expr = self.state.memory.load(p_addr, p_strlen.max_null_index, endness='Iend_BE')
        path = self.state.se.any_str(p_expr)

        fd = self.state.posix.open(path, flags)
        return fd
