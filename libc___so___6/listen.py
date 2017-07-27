import simuvex

######################################
# listen (but not really)
######################################
import logging
l = logging.getLogger("simuvex.procedures.libc.listen")

class listen(simuvex.SimProcedure):

    #pylint:disable=arguments-differ

    def run(self, sockfd, backlog): #pylint:disable=unused-argument

    	#additional code
        trace_data = ("listen", {"sockfd": (sockfd, sockfd.symbolic), "backlog": (backlog, backlog.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        return self.state.se.Unconstrained('listen', self.state.arch.bits)

