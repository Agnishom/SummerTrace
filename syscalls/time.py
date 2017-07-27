import simuvex

class time(simuvex.SimProcedure):
    IS_SYSCALL = True
    KEY = 'sys_last_time'

    @property
    def last_time(self):
        return self.state.procedure_data.global_variables.get(self.KEY, None)

    @last_time.setter
    def last_time(self, v):
        self.state.procedure_data.global_variables[self.KEY] = v

    def run(self, pointer):

        #additional code
        trace_data = ("time", {"pointer": (pointer, pointer.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        result = self.state.se.BVS('sys_time', self.state.arch.bits)
        if self.last_time is not None:
            self.state.add_constraints(result >= self.last_time)
        self.last_time = result
        return result
