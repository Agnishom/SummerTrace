import simuvex

class mmap(simuvex.SimProcedure):
    def run(self, addr, length, prot, flags, fd, offset): #pylint:disable=arguments-differ,unused-argument

    	#additional code
        trace_data = ("mmap", {"addr": (addr, addr.symbolic), "length": (length, length.symbolic), "prot": (prot, prot.symbolic),  "flags": (flags, flags.symbolic), "fd": (fd, fd.symbolic), "offset": (offset, offset.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        return self.inline_call(simuvex.SimProcedures['syscalls']['mmap'],
                                addr,
                                length,
                                prot,
                                flags,
                                fd,
                                offset,
                                ).ret_expr
