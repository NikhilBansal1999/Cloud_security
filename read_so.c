#include<stdio.h>
#include<stdlib.h>
#include<dlfcn.h>

int main(int argc, char *argv[])
{
  void *handle;
  int (*fibo)(int);
  handle=dlopen("./lib_test.so",RTLD_LAZY);
  if(handle == NULL)
  {
    printf("Error loading library\n");
    printf("%s\n",dlerror());
  }
  else
  {
    fibo = (int (*)(int))dlsym(handle, "fibonacci");
    if(fibo == NULL)
    {
      printf("Error getting function\n");
    }
    else
    {
      printf("%d\n",(*fibo)(atoi(argv[1])));
    }
  }
  return 0;
}
