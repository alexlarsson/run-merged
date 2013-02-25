run-merged: run-merged.c
	gcc -O1 -g run-merged.c -o run-merged

run-merged-setuid: run-merged
	chown root run-merged; chmod u+s run-merged

