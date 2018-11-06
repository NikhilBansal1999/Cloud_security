all: lib_test.so read_so load_lib

lib_test.so: test_lib.c
	gcc -shared -fPIC -o lib_test.so test_lib.c

read_so: read_so.c
	gcc -o read_so read_so.c -ldl 

load_lib: load_lib.c
	gcc -o load_lib load_lib.c

.PHONY: clean

clean:
	rm -f lib_test.so read_so load_lib

