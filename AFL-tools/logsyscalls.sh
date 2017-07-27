#! /bin/sh

# usage: logsyscalls.sh executable input output

while IFS='' read -r line || [[ -n "$line" ]]
do
	if [[ ${line:0:1} == "2" ]]
	then
		echo "${line:2}" | strace "$1" 2>> "$3"
	fi
done < "$2"
