Watch an [asciinema](https://asciinema.org/a/0233XWHanplUs8sT9alMGRF8O) of this happening, [here](https://asciinema.org/a/0233XWHanplUs8sT9alMGRF8O)

```
agnishom@agnishomPC ~/Documents/code/SummerTrace/example $ workon angr
(angr) agnishom@agnishomPC ~/Documents/code/SummerTrace $ python -i tools/uniqPaths.py
WARNING | 2017-08-01 13:59:49,960 | claripy | Claripy is setting the recursion limit to 15000. If Python segfaults, I am sorry.
>>> obj = symbolicLibcCalls("/tmp/fauxware") 
>>> path = next(obj)
>>> for event in path:
...     print event
... 
('malloc', {'sim_size': (<BV64 0x300>, False)})
('malloc', {'sim_size': (<BV64 0x8>, False)})
('malloc', {'sim_size': (<BV64 0x600>, False)})
('malloc', {'sim_size': (<BV64 0x8>, False)})
('malloc', {'sim_size': (<BV64 0x600>, False)})
('malloc', {'sim_size': (<BV64 0x8>, False)})
('puts', {'string': (<SAO <BV64 0x40097d>>, False)})
('strlen', {'s': (<SAO <BV64 0x40097d>>, False)})
('write', {'src': (<SAO <BV64 0x40097d>>, False), 'length': (<SAO <BV64 0xa>>, False), 'fd': (<BV64 0x1>, False)})
('read', {'dst': (<SAO <BV64 0x7fffffffffeff38>>, False), 'fd': (<SAO <BV64 0x0>>, False), 'length': (<SAO <BV64 0x8>>, False)})
('read', {'dst': (<SAO <BV64 0x7fffffffffeff34>>, False), 'fd': (<SAO <BV64 0x0>>, False), 'length': (<SAO <BV64 0x1>>, False)})
('puts', {'string': (<SAO <BV64 0x400988>>, False)})
('strlen', {'s': (<SAO <BV64 0x400988>>, False)})
('write', {'src': (<SAO <BV64 0x400988>>, False), 'length': (<SAO <BV64 0xa>>, False), 'fd': (<BV64 0x1>, False)})
('read', {'dst': (<SAO <BV64 0x7fffffffffeff48>>, False), 'fd': (<SAO <BV64 0x0>>, False), 'length': (<SAO <BV64 0x8>>, False)})
('read', {'dst': (<SAO <BV64 0x7fffffffffeff34>>, False), 'fd': (<SAO <BV64 0x0>>, False), 'length': (<SAO <BV64 0x1>>, False)})
('strcmp', {'b_addr': (<SAO <BV64 0x400938>>, False), 'a_addr': (<SAO <BV64 0x7fffffffffeff48>>, False)})
('strlen', {'s': (<SAO <BV64 0x7fffffffffeff48>>, False)})
('strlen', {'s': (<SAO <BV64 0x400938>>, False)})
('strncmp', {'a_len': <SimProcedure strlen>, 'b_addr': (<SAO <BV64 0x400938>>, False), 'a_addr': (<SAO <BV64 0x7fffffffffeff48>>, False), 'limit': (<BV64 0x8>, False), 'b_len': <SimProcedure strlen>})
('open', {'p_addr': (<SAO <BV64 0x7fffffffffeff38>>, False), 'flags': (<SAO <BV64 0x0>>, False)})
('strlen', {'s': (<SAO <BV64 0x7fffffffffeff38>>, False)})
('read', {'dst': (<SAO <BV64 0x7fffffffffefee8>>, False), 'fd': (<SAO <BV64 0x3>>, False), 'length': (<SAO <BV64 0x8>>, False)})
('puts', {'string': (<SAO <BV64 0x400948>>, False)})
('strlen', {'s': (<SAO <BV64 0x400948>>, False)})
('write', {'src': (<SAO <BV64 0x400948>>, False), 'length': (<SAO <BV64 0x2b>>, False), 'fd': (<BV64 0x1>, False)})
('strcmp', {'b_addr': (<SAO <BV64 0x7fffffffffefee8>>, False), 'a_addr': (<SAO <BV64 0x7fffffffffeff48>>, False)})
('strlen', {'s': (<SAO <BV64 0x7fffffffffeff48>>, False)})
('strlen', {'s': (<SAO <BV64 0x7fffffffffefee8>>, False)})
('strncmp', {'a_len': <SimProcedure strlen>, 'b_addr': (<SAO <BV64 0x7fffffffffefee8>>, False), 'a_addr': (<SAO <BV64 0x7fffffffffeff48>>, False), 'limit': (<BV64 0x8>, False), 'b_len': <SimProcedure strlen>})
>>> path = next(obj)
>>> for event in path:
...     print event
... 
('malloc', {'sim_size': (<BV64 0x300>, False)})
('malloc', {'sim_size': (<BV64 0x8>, False)})
('malloc', {'sim_size': (<BV64 0x600>, False)})
('malloc', {'sim_size': (<BV64 0x8>, False)})
('malloc', {'sim_size': (<BV64 0x600>, False)})
('malloc', {'sim_size': (<BV64 0x8>, False)})
('puts', {'string': (<SAO <BV64 0x40097d>>, False)})
('strlen', {'s': (<SAO <BV64 0x40097d>>, False)})
('write', {'src': (<SAO <BV64 0x40097d>>, False), 'length': (<SAO <BV64 0xa>>, False), 'fd': (<BV64 0x1>, False)})
('read', {'dst': (<SAO <BV64 0x7fffffffffeff38>>, False), 'fd': (<SAO <BV64 0x0>>, False), 'length': (<SAO <BV64 0x8>>, False)})
('read', {'dst': (<SAO <BV64 0x7fffffffffeff34>>, False), 'fd': (<SAO <BV64 0x0>>, False), 'length': (<SAO <BV64 0x1>>, False)})
('puts', {'string': (<SAO <BV64 0x400988>>, False)})
('strlen', {'s': (<SAO <BV64 0x400988>>, False)})
('write', {'src': (<SAO <BV64 0x400988>>, False), 'length': (<SAO <BV64 0xa>>, False), 'fd': (<BV64 0x1>, False)})
('read', {'dst': (<SAO <BV64 0x7fffffffffeff48>>, False), 'fd': (<SAO <BV64 0x0>>, False), 'length': (<SAO <BV64 0x8>>, False)})
('read', {'dst': (<SAO <BV64 0x7fffffffffeff34>>, False), 'fd': (<SAO <BV64 0x0>>, False), 'length': (<SAO <BV64 0x1>>, False)})
('strcmp', {'b_addr': (<SAO <BV64 0x400938>>, False), 'a_addr': (<SAO <BV64 0x7fffffffffeff48>>, False)})
('strlen', {'s': (<SAO <BV64 0x7fffffffffeff48>>, False)})
('strlen', {'s': (<SAO <BV64 0x400938>>, False)})
('strncmp', {'a_len': <SimProcedure strlen>, 'b_addr': (<SAO <BV64 0x400938>>, False), 'a_addr': (<SAO <BV64 0x7fffffffffeff48>>, False), 'limit': (<BV64 0x8>, False), 'b_len': <SimProcedure strlen>})
('open', {'p_addr': (<SAO <BV64 0x7fffffffffeff38>>, False), 'flags': (<SAO <BV64 0x0>>, False)})
('strlen', {'s': (<SAO <BV64 0x7fffffffffeff38>>, False)})
('read', {'dst': (<SAO <BV64 0x7fffffffffefee8>>, False), 'fd': (<SAO <BV64 0x3>>, False), 'length': (<SAO <BV64 0x8>>, False)})
('puts', {'string': (<SAO <BV64 0x400948>>, False)})
('strlen', {'s': (<SAO <BV64 0x400948>>, False)})
('write', {'src': (<SAO <BV64 0x400948>>, False), 'length': (<SAO <BV64 0x2b>>, False), 'fd': (<BV64 0x1>, False)})
('strcmp', {'b_addr': (<SAO <BV64 0x7fffffffffefee8>>, False), 'a_addr': (<SAO <BV64 0x7fffffffffeff48>>, False)})
('strlen', {'s': (<SAO <BV64 0x7fffffffffeff48>>, False)})
('strlen', {'s': (<SAO <BV64 0x7fffffffffefee8>>, False)})
('strncmp', {'a_len': <SimProcedure strlen>, 'b_addr': (<SAO <BV64 0x7fffffffffefee8>>, False), 'a_addr': (<SAO <BV64 0x7fffffffffeff48>>, False), 'limit': (<BV64 0x8>, False), 'b_len': <SimProcedure strlen>})
printf
('strlen', {'s': (<SAO <BV64 0x400974>>, False)})
('puts', {'string': (<SAO <BV64 0x400948>>, False)})
('strlen', {'s': (<SAO <BV64 0x400948>>, False)})
('write', {'src': (<SAO <BV64 0x400948>>, False), 'length': (<SAO <BV64 0x2b>>, False), 'fd': (<BV64 0x1>, False)})
('exit', {'exit_code': (<SAO <BV64 0x1>>, False)})
>>> path = next(obj)
>>> for event in path:
...     print event
... 
('malloc', {'sim_size': (<BV64 0x300>, False)})
('malloc', {'sim_size': (<BV64 0x8>, False)})
('malloc', {'sim_size': (<BV64 0x600>, False)})
('malloc', {'sim_size': (<BV64 0x8>, False)})
('malloc', {'sim_size': (<BV64 0x600>, False)})
('malloc', {'sim_size': (<BV64 0x8>, False)})
('puts', {'string': (<SAO <BV64 0x40097d>>, False)})
('strlen', {'s': (<SAO <BV64 0x40097d>>, False)})
('write', {'src': (<SAO <BV64 0x40097d>>, False), 'length': (<SAO <BV64 0xa>>, False), 'fd': (<BV64 0x1>, False)})
('read', {'dst': (<SAO <BV64 0x7fffffffffeff38>>, False), 'fd': (<SAO <BV64 0x0>>, False), 'length': (<SAO <BV64 0x8>>, False)})
('read', {'dst': (<SAO <BV64 0x7fffffffffeff34>>, False), 'fd': (<SAO <BV64 0x0>>, False), 'length': (<SAO <BV64 0x1>>, False)})
('puts', {'string': (<SAO <BV64 0x400988>>, False)})
('strlen', {'s': (<SAO <BV64 0x400988>>, False)})
('write', {'src': (<SAO <BV64 0x400988>>, False), 'length': (<SAO <BV64 0xa>>, False), 'fd': (<BV64 0x1>, False)})
('read', {'dst': (<SAO <BV64 0x7fffffffffeff48>>, False), 'fd': (<SAO <BV64 0x0>>, False), 'length': (<SAO <BV64 0x8>>, False)})
('read', {'dst': (<SAO <BV64 0x7fffffffffeff34>>, False), 'fd': (<SAO <BV64 0x0>>, False), 'length': (<SAO <BV64 0x1>>, False)})
('strcmp', {'b_addr': (<SAO <BV64 0x400938>>, False), 'a_addr': (<SAO <BV64 0x7fffffffffeff48>>, False)})
('strlen', {'s': (<SAO <BV64 0x7fffffffffeff48>>, False)})
('strlen', {'s': (<SAO <BV64 0x400938>>, False)})
('strncmp', {'a_len': <SimProcedure strlen>, 'b_addr': (<SAO <BV64 0x400938>>, False), 'a_addr': (<SAO <BV64 0x7fffffffffeff48>>, False), 'limit': (<BV64 0x8>, False), 'b_len': <SimProcedure strlen>})
('open', {'p_addr': (<SAO <BV64 0x7fffffffffeff38>>, False), 'flags': (<SAO <BV64 0x0>>, False)})
('strlen', {'s': (<SAO <BV64 0x7fffffffffeff38>>, False)})
('read', {'dst': (<SAO <BV64 0x7fffffffffefee8>>, False), 'fd': (<SAO <BV64 0x3>>, False), 'length': (<SAO <BV64 0x8>>, False)})
('puts', {'string': (<SAO <BV64 0x400948>>, False)})
('strlen', {'s': (<SAO <BV64 0x400948>>, False)})
('write', {'src': (<SAO <BV64 0x400948>>, False), 'length': (<SAO <BV64 0x2b>>, False), 'fd': (<BV64 0x1>, False)})
('strcmp', {'b_addr': (<SAO <BV64 0x7fffffffffefee8>>, False), 'a_addr': (<SAO <BV64 0x7fffffffffeff48>>, False)})
('strlen', {'s': (<SAO <BV64 0x7fffffffffeff48>>, False)})
('strlen', {'s': (<SAO <BV64 0x7fffffffffefee8>>, False)})
('strncmp', {'a_len': <SimProcedure strlen>, 'b_addr': (<SAO <BV64 0x7fffffffffefee8>>, False), 'a_addr': (<SAO <BV64 0x7fffffffffeff48>>, False), 'limit': (<BV64 0x8>, False), 'b_len': <SimProcedure strlen>})
printf
('strlen', {'s': (<SAO <BV64 0x400974>>, False)})
('puts', {'string': (<SAO <BV64 0x400948>>, False)})
('strlen', {'s': (<SAO <BV64 0x400948>>, False)})
('write', {'src': (<SAO <BV64 0x400948>>, False), 'length': (<SAO <BV64 0x2b>>, False), 'fd': (<BV64 0x1>, False)})
('exit', {'exit_code': (<SAO <BV64 0x1>>, False)})
>>> path = next(obj)
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
StopIteration
>>> obj = straceSysCalls("/tmp/fauxware") 
>>> path = next(obj)
Username: 
Password: 
Welcome to the admin console, trusted user!
>>> for entry in path:
...     print entry.category, entry.elapsed_time, entry.pid, entry.syscall_name, entry.syscall_arguments
... 
None None None execve ['"/tmp/fauxware"', '["/tmp/fauxware"]', '[/* 57 vars */]']
None None None brk ['NULL']
IO None None access ['"/etc/ld.so.nohwcap"', 'F_OK']
IO None None mmap ['NULL', '8192', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0']
IO None None access ['"/etc/ld.so.preload"', 'R_OK']
IO None None open ['"/etc/ld.so.cache"', 'O_RDONLY|O_CLOEXEC']
IO None None fstat ['6', '{st_mode=S_IFREG|0644, st_size=111512, ...}']
IO None None mmap ['NULL', '111512', 'PROT_READ', 'MAP_PRIVATE', '6', '0']
IO None None close ['6']
IO None None access ['"/etc/ld.so.nohwcap"', 'F_OK']
IO None None open ['"/lib/x86_64-linux-gnu/libc.so.6"', 'O_RDONLY|O_CLOEXEC']
IO None None read ['6', '"\\177ELF\\2\\1\\1\\3\\0\\0\\0\\0\\0\\0\\0\\0\\3\\0>\\0\\1\\0\\0\\0P\\t\\2\\0\\0\\0\\0\\0"...', '832']
IO None None fstat ['6', '{st_mode=S_IFREG|0755, st_size=1868984, ...}']
IO None None mmap ['NULL', '3971488', 'PROT_READ|PROT_EXEC', 'MAP_PRIVATE|MAP_DENYWRITE', '6', '0']
None None None mprotect ['0x2aad185ce000', '2097152', 'PROT_NONE']
IO None None mmap ['0x2aad187ce000', '24576', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE', '6', '0x1c0000']
IO None None mmap ['0x2aad187d4000', '14752', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS', '-1', '0']
IO None None close ['6']
IO None None mmap ['NULL', '4096', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0']
IO None None mmap ['NULL', '4096', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0']
None None None arch_prctl ['ARCH_SET_FS', '0x2aad1822ab40']
None None None mprotect ['0x2aad187ce000', '16384', 'PROT_READ']
None None None mprotect ['0x600000', '4096', 'PROT_READ']
None None None mprotect ['0x2aad1840b000', '4096', 'PROT_READ']
None None None munmap ['0x2aad1820e000', '111512']
IO None None fstat ['1', '{st_mode=S_IFCHR|0620, st_rdev=makedev(136, 1), ...}']
None None None brk ['NULL']
None None None brk ['0x6cf000']
IO None None write ['1', '"Username: \\n"', '11']
IO None None read ['0', '"\\0\\0\\0\\0\\0\\0\\0\\0"', '8']
IO None None read ['0', '"\\0"', '1']
IO None None write ['1', '"Password: \\n"', '11']
IO None None read ['0', '"SOSNEAKY"', '8']
IO None None read ['0', '"\\0"', '1']
IO None None write ['1', '"Welcome to the admin console, tr"...', '44']
None None None exit_group ['0']
None 0 None EXIT []
>>> path = next(obj)
Username: 
Password: 
Go afor entry in path:
...     print entry.category, entry.elapsed_time, entry.pid, entry.syscall_name, entry.syscall_arguments
... 
None None None execve ['"/tmp/fauxware"', '["/tmp/fauxware"]', '[/* 57 vars */]']
None None None brk ['NULL']
IO None None access ['"/etc/ld.so.nohwcap"', 'F_OK']
IO None None mmap ['NULL', '8192', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0']
IO None None access ['"/etc/ld.so.preload"', 'R_OK']
IO None None open ['"/etc/ld.so.cache"', 'O_RDONLY|O_CLOEXEC']
IO None None fstat ['6', '{st_mode=S_IFREG|0644, st_size=111512, ...}']
IO None None mmap ['NULL', '111512', 'PROT_READ', 'MAP_PRIVATE', '6', '0']
IO None None close ['6']
IO None None access ['"/etc/ld.so.nohwcap"', 'F_OK']
IO None None open ['"/lib/x86_64-linux-gnu/libc.so.6"', 'O_RDONLY|O_CLOEXEC']
IO None None read ['6', '"\\177ELF\\2\\1\\1\\3\\0\\0\\0\\0\\0\\0\\0\\0\\3\\0>\\0\\1\\0\\0\\0P\\t\\2\\0\\0\\0\\0\\0"...', '832']
IO None None fstat ['6', '{st_mode=S_IFREG|0755, st_size=1868984, ...}']
IO None None mmap ['NULL', '3971488', 'PROT_READ|PROT_EXEC', 'MAP_PRIVATE|MAP_DENYWRITE', '6', '0']
None None None mprotect ['0x2b4ad3ba9000', '2097152', 'PROT_NONE']
IO None None mmap ['0x2b4ad3da9000', '24576', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE', '6', '0x1c0000']
IO None None mmap ['0x2b4ad3daf000', '14752', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS', '-1', '0']
IO None None close ['6']
IO None None mmap ['NULL', '4096', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0']
IO None None mmap ['NULL', '4096', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0']
None None None arch_prctl ['ARCH_SET_FS', '0x2b4ad3805b40']
None None None mprotect ['0x2b4ad3da9000', '16384', 'PROT_READ']
None None None mprotect ['0x600000', '4096', 'PROT_READ']
None None None mprotect ['0x2b4ad39e6000', '4096', 'PROT_READ']
None None None munmap ['0x2b4ad37e9000', '111512']
IO None None fstat ['1', '{st_mode=S_IFCHR|0620, st_rdev=makedev(136, 1), ...}']
None None None brk ['NULL']
None None None brk ['0x10d3000']
IO None None write ['1', '"Username: \\n"', '11']
IO None None read ['0', '"\\0\\0\\0\\0\\0\\0\\0\\0"', '8']
IO None None read ['0', '"\\0"', '1']
IO None None write ['1', '"Password: \\n"', '11']
IO None None read ['0', '"S@\\2\\200@\\200\\300\\0"', '8']
IO None None read ['0', '"\\0"', '1']
IO None None open ['""', 'O_RDONLY']
IO None None read ['-1', '0x7ffd906f1910', '8']
IO None None write ['1', '"Go away!"', '8']
None None None exit_group ['1']
None 0 None EXIT []
>>> path = next(obj)
Username: 
Password: 
Go a    print entry.category, entry.elapsed_time, entry.pid, entry.syscall_name, entry.syscall_arguments
  File "<stdin>", line 1
    print entry.category, entry.elapsed_time, entry.pid, entry.syscall_name, entry.syscall_arguments
    ^
IndentationError: unexpected indent
>>> for entry in path:
...     print entry.category, entry.elapsed_time, entry.pid, entry.syscall_name, entry.syscall_arguments
... 
None None None execve ['"/tmp/fauxware"', '["/tmp/fauxware"]', '[/* 57 vars */]']
None None None brk ['NULL']
IO None None access ['"/etc/ld.so.nohwcap"', 'F_OK']
IO None None mmap ['NULL', '8192', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0']
IO None None access ['"/etc/ld.so.preload"', 'R_OK']
IO None None open ['"/etc/ld.so.cache"', 'O_RDONLY|O_CLOEXEC']
IO None None fstat ['6', '{st_mode=S_IFREG|0644, st_size=111512, ...}']
IO None None mmap ['NULL', '111512', 'PROT_READ', 'MAP_PRIVATE', '6', '0']
IO None None close ['6']
IO None None access ['"/etc/ld.so.nohwcap"', 'F_OK']
IO None None open ['"/lib/x86_64-linux-gnu/libc.so.6"', 'O_RDONLY|O_CLOEXEC']
IO None None read ['6', '"\\177ELF\\2\\1\\1\\3\\0\\0\\0\\0\\0\\0\\0\\0\\3\\0>\\0\\1\\0\\0\\0P\\t\\2\\0\\0\\0\\0\\0"...', '832']
IO None None fstat ['6', '{st_mode=S_IFREG|0755, st_size=1868984, ...}']
IO None None mmap ['NULL', '3971488', 'PROT_READ|PROT_EXEC', 'MAP_PRIVATE|MAP_DENYWRITE', '6', '0']
None None None mprotect ['0x2b838fd7f000', '2097152', 'PROT_NONE']
IO None None mmap ['0x2b838ff7f000', '24576', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE', '6', '0x1c0000']
IO None None mmap ['0x2b838ff85000', '14752', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS', '-1', '0']
IO None None close ['6']
IO None None mmap ['NULL', '4096', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0']
IO None None mmap ['NULL', '4096', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0']
None None None arch_prctl ['ARCH_SET_FS', '0x2b838f9dbb40']
None None None mprotect ['0x2b838ff7f000', '16384', 'PROT_READ']
None None None mprotect ['0x600000', '4096', 'PROT_READ']
None None None mprotect ['0x2b838fbbc000', '4096', 'PROT_READ']
None None None munmap ['0x2b838f9bf000', '111512']
IO None None fstat ['1', '{st_mode=S_IFCHR|0620, st_rdev=makedev(136, 1), ...}']
None None None brk ['NULL']
None None None brk ['0x110c000']
IO None None write ['1', '"Username: \\n"', '11']
IO None None read ['0', '"\\0\\0\\0\\0\\0\\0\\0\\0"', '8']
IO None None read ['0', '"\\0"', '1']
IO None None write ['1', '"Password: \\n"', '11']
IO None None read ['0', '"S\\200\\200\\200\\200@\\200@"', '8']
IO None None read ['0', '"\\0"', '1']
IO None None open ['""', 'O_RDONLY']
IO None None read ['-1', '0x7ffca05f88d0', '8']
IO None None write ['1', '"Go away!"', '8']
None None None exit_group ['1']
None 0 None EXIT []
>>> path = next(obj)
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
StopIteration
>>> 
```
