#include <stdio.h>
int fibonacci(int num)
{
    int a=0,b=1,n=2;
    if(num<=0)
    {
      return -1;
    }
    else if(num==1)
    {
      return 0;
    }
    else if(num==2)
    {
      return 1;
    }
    else
    {
      while(n<num)
      {
        n++;
        b=b+a;
        a=b-a;
      }
      return b;
    }
}
