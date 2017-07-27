import simuvex

class setvbuf(simuvex.SimProcedure):
    def run(self, stream, buf, type_, size):

    	#additional code
        trace_data = ("setvbuf", {"stream": (stream, stream.symbolic), "buf": (buf, buf.symbolic), "type_": (type_, type_.symbolic), "size": (size, size.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        return 0
