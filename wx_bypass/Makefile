all: test wx_block

wx_block: wx_block.cc
	g++ -Wall -Wextra -pedantic -std=c++17 -o wx_block wx_block.cc -fpermissive

debug: wx_block.cc
	g++ -Wall -Wextra -pedantic -std=c++17 -o wx_block wx_block.cc -fpermissive -DDEBUG

test: test1.cpp test2.cpp
	g++ -o test1 test1.cpp -O2
	g++ -o test2 test2.cpp -O2

clean:
	rm wx_block test1 test2
