all: lib_test.so read_so load_lib load_lib_v2

lib_test.so: test_lib.c
	gcc -shared -fPIC -o lib_test.so test_lib.c

read_so: read_so.c
	gcc -o read_so read_so.c -ldl

load_lib: load_lib.c
	gcc -o load_lib load_lib.c

load_lib_v2: load_lib_v2.c
	gcc -o load_lib_v2 load_lib_v2.c

.PHONY: clean

clean:
	rm -f lib_test.so read_so load_lib load_lib_v2
