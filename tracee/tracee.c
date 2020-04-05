#include <stdio.h>
#include <unistd.h>

static void f1(int a){
	printf("%d\n",a);
}


int main(void){

	int i = 0;
	while(i != 1000){
		f1(i);
		i++;
		sleep(1);
	}
	return 0;
}
