#include<stdio.h>
#include<stdlib.h>
#include<dlfcn.h>

int main(int argc, char *argv[])
{
  void *handle;
  int (*fibo)(int);
  handle=dlopen("./lib_test.so",RTLD_LAZY);

  fibo = (int (*)(int))dlsym(handle, "fibonacci");
  printf("%d",(*fibo)(atoi(argv[1])));
  return 0;
}
