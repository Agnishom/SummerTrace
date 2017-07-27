The [afl-fuzz.c]() included in the AFL-tools directory is a modification of the original `afl-fuzz.c` in the original source. This modification makes AFL dump the testcases into a file.

`logsyscalls.sh` could be used along with this testcases to capture the corresponding `strace` outputs.
