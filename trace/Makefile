all: example trace

trace: trace.cc
	g++ -Wall -Wextra -pedantic -std=c++17 -o trace trace.cc -fpermissive

debug: trace.cc
	g++ -Wall -Wextra -pedantic -std=c++17 -o trace trace.cc -fpermissive -DDEBUG

example: example.s
	gcc -m64 -nostdlib -no-pie -o example example.s

clean:
	rm trace example 
