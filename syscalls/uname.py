import simuvex

class uname(simuvex.SimProcedure):

    IS_SYSCALL = True

    def run(self, uname_buf): # pylint: disable=arguments-differ

        #additional code
        trace_data = ("uname", {"uname_buf": (uname_buf, uname_buf.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

         # struct utsname {
         #     char sysname[];    /* Operating system name (e.g., "Linux") */
         #     char nodename[];   /* Name within "some implementation-defined
         #                           network" */
         #     char release[];    /* Operating system release (e.g., "2.6.28") */
         #     char version[];    /* Operating system version */
         #     char machine[];    /* Hardware identifier */
         # };

        off = self._store(uname_buf, "Linux", 0)
        off += self._store(uname_buf, "localhost", off)
        off += self._store(uname_buf, "4.0.0", off)
        off += self._store(uname_buf, "#1 SMP Mon Jan 01 00:00:00 GMT 1970", off)
        self._store(uname_buf, "x86_64", off)

        return self.state.se.BVV(0, 64) # success

    def _store(self, uname_buf, val, off):
        self.state.memory.store(uname_buf + off, val + ("\0" * (65 - len(val))))
        return 65