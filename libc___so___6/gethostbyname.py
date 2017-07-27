import simuvex

from .malloc import malloc

class gethostbyname(simuvex.SimProcedure):
    def run(self, name):

    	#additional code
        trace_data = ("gethostbyname", {"name": (name, name.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        place = self.inline_call(malloc, 32).ret_expr
        self.state.memory.store(place, self.state.se.BVS('h_name', 64), endness='Iend_LE')
        self.state.memory.store(place, self.state.se.BVS('h_aliases', 64), endness='Iend_LE')
        self.state.memory.store(place, self.state.se.BVS('h_addrtype', 64), endness='Iend_LE')
        self.state.memory.store(place, self.state.se.BVS('h_length', 64), endness='Iend_LE')
        self.state.memory.store(place, self.state.se.BVS('h_addr_list', 64), endness='Iend_LE')
        return place
