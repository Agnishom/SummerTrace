import simuvex
from simuvex.s_type import SimTypeFd, SimTypeTop

from . import io_file_data_for_arch

import logging
l = logging.getLogger("simuvex.procedures.fileno")


######################################
# fileno
######################################


class fileno(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, f):
        #additional code
        trace_data = ("fileno", {"f": (f, f.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        self.argument_types = {0: self.ty_ptr(SimTypeTop())}
        self.return_type = SimTypeFd()

        # Get FILE struct
        io_file_data = io_file_data_for_arch(self.state.arch)

        # Get the file descriptor from FILE struct
        fd = self.state.se.any_int(self.state.memory.load(f + io_file_data['fd'],
                                                          4 * 8,  # int
                                                          endness=self.state.arch.memory_endness))
        return fd
