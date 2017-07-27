# Installation Instructions

## Install angr

The idea is to create a `virtualenv` to install the `angr` libraries. This is the reccommended method.

Requirements: `pip`, `virtualenv`

1. `$ mkvirtualenv angr --python=/usr/bin/python2`
2. `$ workon angr`
3. `$ pip install angr`

If this does not work, see [angr's installation instructions](http://angr.io/install.html)

## Add the patches

### Figure out where the simuvex libraries are installed

1. `$ workon angr`
2. `$ python`

Now that `python` is open:

3. `>>> import angr`
4. `>>> print angr.simuvex`

You should get something like `<module 'simuvex' from '/home/agnishom/.virtualenvs/angr/lib/python2.7/site-packages/simuvex/__init__.pyc'>`

5. `cd` over to the indicated directory, i.e, `simuvex`.
6. `$ cd procedures`
7. Locate the directories `syscalls` and `libc__so__6`.

### Download this git repository

Requirements: `git` (or can be downloaded manually)

1. `$ git clone <bla>`
2. Locate the directories `syscalls` and `libc__so__6` inside the repository.

### Replace the directories

Replace the original directories with those from the repository

---

# The Tools

## An word on the patches

The patches are simply modifications of the angr library which ensure a log of which SimProcedures were called. The tools supplied are an example of how the binary might be explored to use these.

To see the lines that have been injected into the original `angr/simuvex` codebase, one is advised to look at the lines laballed `# additional code` inside the patched libraries.

One might be able to utilise these capabilities better by using different approaches of exploring the binary using other tools of the [angr library](https://docs.angr.io/docs/surveyors.html).

## symbolicLibcCalls

`symbolicLibcCalls` uses angr's framework to use symbolic execution to explore the paths in the binary. Calling the function with a string for the path to the binary reutrns a generator. The generator keeps following a path until a deadend is reached, in which case it yields a list of the `libc` calls (and occassionally, some of the system calls) which were performed along that path.

### Structure of the return value

The return value of the function is a list, with the following structure:

```
[
("libcCallFunctionName1", {"argument1": (argumentValue, argument.isSymbolic), "argument2": (argumentValue, argument.isSymbolic), ...}),
("libcCallFunctionName2", {"argument1": (argumentValue, argument.isSymbolic), "argument2": (argumentValue, argument.isSymbolic), ...}),
...
]
```

* `argumentValue` is a symbolic claripy object.
* `argument.isSymbolic` shows whether a particular argument is truly symbolic (as opposed to concrete). This can be used as a way to understand whether a particular library call depends on some kind of input.

### Options

* If you intend to log system calls only, you can use the option `use_sim_procedures=False` while calling this function. However, this feature is not fully reliable.
* By default, the number of args passed to the binary is the concrete value `0`. If you want to symbolically explore the number of args being passed, then turn on `try_multiple_args = True`. Also, change `binaryArch=64` to `32` if the binary is 32-bit. This feature is not reliable, either.

## straceSysCalls

**Requirements:** `strace`

This tool uses angr's framework to use symbolic execution to explore the paths in the binary, as well. However, it records the syscalls along the path by actually calling `strace` in a shell. This severely limits the capabilities of this exploration, since the inputs are limited to `STDIN` inputs only. However, the brighter side is that this analysis is more accurate and can be used when the binary is in hand is an experimental toy.

### Structure of the return value

The input of strace is passed through the [`pystrace` libraries](https://github.com/dirtyharrycallahan/pystrace) for parsing, which are included within the tools directory.

When `straceSysCalls` is run, a generator is returned. The generator yields [`strace.StraceInputStream` instances](https://github.com/dirtyharrycallahan/pystrace/blob/master/strace.py#L148). These are, again, iterables. Each entry of the iterable is a [`strace.StraceEntry` object](https://github.com/dirtyharrycallahan/pystrace/blob/master/strace.py#L115), representing each line of strace. Inside these objects lie the following members:
`['category', 'elapsed_time', 'pid', 'return_value', 'syscall_arguments', 'syscall_name', 'timestamp', 'was_unfinished']`
