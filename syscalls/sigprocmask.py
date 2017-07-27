import simuvex

class sigprocmask(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    def run(self, how, set_, oldset, sigsetsize):

        #additional code
        trace_data = ("sigprocmask", {"how": (how, how.symbolic), "set_": (set_, set_.symbolic), "oldset": (oldset, oldset.symbolic), "sigsetsize": (sigsetsize, sigsetsize.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        self.state.memory.store(oldset, self.state.posix.sigmask(sigsetsize=sigsetsize), condition=oldset != 0)
        self.state.posix.sigprocmask(how, self.state.memory.load(set_, sigsetsize), sigsetsize, valid_ptr=set_!=0)

        # TODO: EFAULT
        return self.state.se.If(self.state.se.And(
            how != self.state.posix.SIG_BLOCK,
            how != self.state.posix.SIG_UNBLOCK,
            how != self.state.posix.SIG_SETMASK),
            self.state.se.BVV(self.state.posix.EINVAL, self.state.arch.bits),
            self.state.se.BVV(0, self.state.arch.bits),
        )
