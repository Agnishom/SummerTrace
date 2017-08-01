import angr
import claripy
import strace
import subprocess

def straceSysCalls(path_to_binary):
    p = angr.Project(path_to_binary)
    pg = p.factory.path_group()
    while len(pg.active) > 0:
        deadNow = len(pg.deadended)
        pg.step()
        if len(pg.deadended) > deadNow:
            path = pg.deadended[-1]
            testCase = path.state.posix.dumps(0)
            process = subprocess.Popen(["strace", "-ttt", "-o", "worktmp.out", str(path_to_binary)],  stdin=subprocess.PIPE)
            process.communicate(testCase)
            with open("worktmp.out") as f:
                yield strace.StraceInputStream(f)



def symbolicLibcCalls(path_to_binary, use_sim_procedures=True, try_multiple_args = False, binaryArch=64):
    p = angr.Project(path_to_binary, use_sim_procedures=use_sim_procedures)
    if try_multiple_args:
        argc = claripy.BVS('argc', binaryArch)
        max_args = 20
        max_arg_length = 50
        argv = [claripy.BVS('argv_%d' % i, 8*max_arg_length) for i in xrange(max_args)]
        state = p.factory.entry_state(args=argv, argc=argc)
        state.add_constraints(argc < max_args)
        pg = p.factory.path_group(state)
    else:
        pg = p.factory.path_group()
    while len(pg.active) > 0:
        deadNow = len(pg.deadended)
        pg.step()
        if len(pg.deadended) > deadNow:
            path = pg.deadended[-1]
            yield path.state.procedure_data.global_variables["trace"]
