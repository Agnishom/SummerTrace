import simuvex

import logging
l = logging.getLogger('simuvex.procedures.syscalls.mmap')


PROT_READ       = 0x1  #    /* Page can be read.  */
PROT_WRITE      = 0x2  #    /* Page can be written.  */
PROT_EXEC       = 0x4  #    /* Page can be executed.  */
PROT_NONE       = 0x0  #    /* Page can not be accessed.  */
MAP_SHARED      = 0x01 #    /* Share changes.  */
MAP_PRIVATE     = 0x02 #    /* Changes are private.  */
MAP_ANONYMOUS   = 0x20 #    /* Don't use a file.  */
MAP_FIXED       = 0x10 #    /* Interpret addr exactly.  */


class mmap(simuvex.SimProcedure):

    IS_SYSCALL = True

    def run(self, addr, length, prot, flags, fd, offset): #pylint:disable=arguments-differ,unused-argument

        #additional code
        trace_data = ("mmap", {"addr": (addr, addr.symbolic), "length": (length, length.symbolic), "prot": (prot, prot.symbolic), "flags": (flags, flags.symbolic), "fd": (fd, fd.symbolic), "offset": (offset, offset.symbolic)})
        try:
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        except KeyError:
            self.state.procedure_data.global_variables["trace"] = []
            self.state.procedure_data.global_variables["trace"].append(trace_data)
        #end of additional code

        #if self.state.se.symbolic(flags) or self.state.se.any_int(flags) != 0x22:
        #   raise Exception("mmap with other than MAP_PRIVATE|MAP_ANONYMOUS unsupported")

        #
        # Length
        #

        if self.state.se.symbolic(length):
            size = self.state.se.max_int(length)
            if size > self.state.libc.max_variable_size:
                l.warn("mmap size requested of %d exceeds libc.max_variable_size. Using size %d instead.", size,self.state.libc.max_variable_size)
                size = self.state.libc.max_variable_size
        else:
            size = self.state.se.any_int(length)

        #
        # Addr
        #

        # Not handling symbolic addr for now
        addrs = self.state.se.any_n_int(addr,2)
        if len(addrs) == 2:
            err = "Cannot handle symbolic addr argument for mmap."
            l.error(err)
            raise simuvex.s_errors.SimPosixError(err)

        addr = addrs[0]

        # Call is asking for system to provide an address
        if addr == 0:
            addr = self.allocate_memory(size)

        #
        # Flags
        #

        # Only want concrete flags
        flags = self.state.se.any_n_int(flags,2)

        if len(flags) == 2:
            err = "Cannot handle symbolic flags arugment for mmap."
            l.error(err)
            raise simuvex.s_errors.SimPosixError(err)

        flags =  flags[0]

        # Sanity check. All mmap must have exactly one of MAP_SHARED or MAP_PRIVATE
        if (flags & MAP_SHARED and flags & MAP_PRIVATE) or flags & (MAP_SHARED | MAP_PRIVATE) == 0:
            return self.state.se.BVV(-1, self.state.arch.bits)

        while True:
            try:
                self.state.memory.map_region(addr, size, prot[2:0], init_zero=bool(flags & MAP_ANONYMOUS))
                return addr

            except simuvex.SimMemoryError:
                # This page is already mapped

                if flags & MAP_FIXED:
                    return self.state.se.BVV(-1, self.state.arch.bits)

                # Can't give you that address. Find a different one.
                addr = self.allocate_memory(size)


    def allocate_memory(self,size):

        addr = self.state.libc.mmap_base
        new_base = addr + size

        if new_base & 0xfff:
            new_base = (new_base & ~0xfff) + 0x1000

        self.state.libc.mmap_base = new_base

        return addr
