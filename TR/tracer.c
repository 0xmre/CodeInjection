#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>

/*******************************************************************************
	Declaration of my global variable, the reason i choose to declare them global
	is because i use them in several functions and this avoid to declare them many
	time
*******************************************************************************/
static FILE* fd;
static const unsigned char bp = 0xCC;
static size_t tracee_pid_len;

/*
	Return the pid of the processus specify
	Parameter : proc_name -> name of the processus
*/
static pid_t get_pid(const char* proc_name){
	char pid[16];
	int result;

	// construction of the command 'pgrep proc_name'
	size_t pgrep_len = strlen(proc_name) + strlen("pgrep ") + 1;
	char * pgrep_command = malloc(sizeof(char) * pgrep_len);
	snprintf(pgrep_command, sizeof(char) * pgrep_len ,"pgrep %s", proc_name);

	// execute the command 'pgrep proc_name'
	if(NULL == (fd = popen(pgrep_command,"r"))){
		perror("pgrep_command failed");
		return -1;
	}
	// store the value of previous command in pid
	fgets(pid,16,fd);

	// Cast it to an integer
	result = atoi(pid);

	/* Initialisation of the global variable tracee_pid_len */
	tracee_pid_len = strlen(pid);


	pclose(fd);
	free(pgrep_command);

	return result;
}

/*
	Compute the address of a function in the tracee by adding its offset find in
	the symbol table and the base address of the main function
	Parameter : pid -> pid of the tracee
              prog_name -> name of the programme in wich reside the function
							func_name -> name of the function that we want the address of
*/
static unsigned long get_function_addr(const pid_t pid, const char* prog_name,
	                                     const char* func_name)
{
	unsigned long result;
	char starting_address[128];
	char offset_function[128];

	/* Construction of the cat command to display the memory mapping */
	const size_t maps_len = strlen("cat /proc//maps") + tracee_pid_len;
	char * maps_command = malloc(sizeof(char) * maps_len);
	snprintf(maps_command, maps_len, "cat /proc/%d/maps", pid);

	if(NULL == (fd = popen(maps_command,"r"))){
		perror("head_command failed");
		exit(-1);
	}
	int find = 0;
	char * temp = malloc(sizeof(char) * 256);
	while(fgets(temp,256,fd) && find==0){
		/* Check if the name of the tracee and r--p is present */
		if(strstr(temp,"r--p") != NULL && strstr(temp, prog_name) != NULL){
			/* Keep the part before the '-' that is the begining of the main */
			strtok(temp,"-");
			snprintf(starting_address, 128, "%s", temp);
			find = 1;
		}
	}
	pclose(fd);

	/* construction of the nm command and display the symbol of the func_name only */
	const size_t nm_len = strlen("nm  | grep ") + strlen(prog_name) +
	                      strlen(func_name) + 1;
	char * nm_command = malloc(sizeof(char) * nm_len);
	snprintf(nm_command, nm_len, "nm %s | grep %s", prog_name, func_name);

	if(NULL == (fd = popen(nm_command,"r"))){
		perror("nm_command failed");
		exit(-1);
	}

	temp = realloc(temp, sizeof(char) * 128);
	fgets(temp,128,fd);
	// get the string before the first space which is the offset
	strtok(temp," ");
	snprintf(offset_function, 128, "%s", temp);

	pclose(fd);
	free(temp);
	free(maps_command);
	free(nm_command);

	/* Compute the address of the fonction specify by func_name */
	result = (unsigned long)strtol(starting_address,NULL,16) +
	         (unsigned long)strtol(offset_function,NULL,16);
	return result;
}



/*
	 Return the address in long format of the address of the function_to_call
 	 which reside in the libc.
	 Parameter : tracee_pid -> pid of the tracee
	 						 function_to_call ->  the address of the wanted function
*/
static unsigned long get_libc_function_address(const pid_t tracee_pid,
	                                         const unsigned long function_to_call)
{
	unsigned long libc_function_address;

	/* Starting address of the libc of the tracee and the tracer */
	char* libc_address_tracee = malloc(sizeof(char)*128);
	char* libc_address_tracer = malloc(sizeof(char)*128);

	const pid_t tracer_pid = getpid();

	const size_t maps_len = strlen("cat /proc//maps") + tracee_pid_len;
	char *maps = malloc(sizeof(char) * maps_len);
	snprintf(maps,sizeof(char) * maps_len, "cat /proc/%d/maps", tracee_pid);

	/* Open the maps to find the adress of the libc for the tracee */
	if(NULL == (fd = popen(maps,"r"))){
		perror("can't open the memory mapping");
		exit(-1);
	}
	char *temp=malloc(sizeof(char)*128);
	while(fgets(temp,128,fd)){
		/* Check if "*r-xp*libc" is included in the file */
		if((strstr(temp,"r-xp")!=NULL) && (strstr(temp,"libc")!=NULL)){
			/* Get the base address of the libc */
			strtok(temp,"-");
			snprintf(libc_address_tracee,128,"%s",temp);
		}
	}
	pclose(fd);
	/* Free the variable that are going to be reused */
	free(temp);
	free(maps);

	maps = malloc(sizeof(char) * maps_len);
	snprintf(maps,sizeof(char) * maps_len,"cat /proc/%d/maps", tracer_pid);

	/* Do the same thing for the tracer */
	if(NULL == (fd = popen(maps,"r"))){
		perror("can't open the memory mapping");
		exit(-1);
	}
	temp=malloc(sizeof(char)*128);
	while(fgets(temp,128,fd)){
		if((strstr(temp,"r-xp")!=NULL) && (strstr(temp,"libc")!=NULL)){
			strtok(temp,"-");
			snprintf(libc_address_tracer,128,"%s",temp);
		}
	}
	pclose(fd);
	free(temp);
	free(maps);

	/* The functions in the libc are always at the same place but the libc start
	 	 at different address in each programme */
	libc_function_address = function_to_call -
													(unsigned long)strtol(libc_address_tracer,NULL,16) +
													(unsigned long)strtol(libc_address_tracee,NULL,16);

	free(libc_address_tracee);
	free(libc_address_tracer);

	return libc_function_address;

}


/*
	Call the function at the address specify by function_to_call_address by the
	way of a jump instruction and a end instruction
	the specify function should takes an integer as parameter
	Parameter : pid -> pid of the tracee
							running_function -> address of the function currently running
							function_to_call_address -> address of the function to call
							parameter -> the parameter of the function called
*/
static void trampoline(const pid_t pid, const unsigned long running_function,
							         const unsigned long function_to_call_address,
						 	         const int parameter)
{

	struct user_regs_struct regs;
	int wstatus;

	unsigned char jump[2]={0x48,0xB8};
	unsigned char endi[3]={0xFF,0xE0,0xC3};

	// get the memory file of the process
	const size_t mem_len = strlen("/proc//mem") + tracee_pid_len;
	char * mem = malloc(sizeof(char) * mem_len);
	snprintf(mem, sizeof(char) * mem_len,"/proc/%d/mem",pid);
	if(NULL == (fd = fopen(mem,"r+"))){
		fprintf(stderr,"Can't open file at line %d\n",__LINE__);
	}

	fseek(fd, (long)running_function, SEEK_SET);
	/* Need to put a breakpoint inside the running function address to get the
																								right value for the registers */
	if(fwrite(&bp,1,1,fd) != 1){
		fprintf(stderr,"Failed to write the code at line %d\n",__LINE__);
	}
	// close the file to apply the modification
	fclose(fd);

	/* Restart the process with the breakpoint inside the running funcion */
	if(ptrace(PTRACE_CONT,pid,NULL,NULL) < 0){
		fprintf(stderr,"Fail to restart the processus at line %d\n",__LINE__);
	}
	if(pid != waitpid(pid,&wstatus,WCONTINUED)){
		fprintf(stderr,"Error waipid at line %d\n",__LINE__);
	}

	/* get the value of the registers's processus while the program  is trapped
		 in the execution of f1 */

	if(ptrace(PTRACE_GETREGS,pid,NULL,&regs) < 0){
		fprintf(stderr,"Fail to get the registers at line %d\n",__LINE__);
	}

	/* Set the new value for the registers */
	regs.rip = running_function;
	regs.rdi = (unsigned long)parameter;

	if(ptrace(PTRACE_SETREGS,pid,NULL,&regs) < 0){
		fprintf(stderr,"Fail to set the registers at line %d\n",__LINE__);
	}

	/* Open the memory to write the code in it */
	if(NULL == (fd = fopen(mem,"r+"))){
		fprintf(stderr,"Can't open file at line %d\n",__LINE__);
	}

	fseek(fd, (long)running_function, SEEK_SET);
	/* Start to write the jump instruction in the begining of the running function */
	if(fwrite(jump,sizeof(char)*sizeof(jump),1,fd) == 0){
		fprintf(stderr,"Failed to inject the code at line %d\n",__LINE__);
	}
	/* Then write the address that we want to call */
	if(fwrite(&function_to_call_address,6,1,fd) == 0){
		fprintf(stderr,"Failed to inject the code at line %d\n",__LINE__);
	}
	/* Finally write the ending instruction */
	if(fwrite(endi,sizeof(char)*sizeof(endi),1,fd) == 0){
		fprintf(stderr,"Failed to inject the code at line %d\n",__LINE__);
	}
	fclose(fd);
	free(mem);
}


/*
	Call the function at the address specify by function_to_call_address,
	the specify function should return an integer and takes no parameter
	Parameter : pid -> pid of the tracee
							running_function -> address of the function currently running
							function_to_call_address -> address of the function to call
							code -> instruction injected at the beginning of the running function
*/
static int call_getpagesize(const pid_t pid,
	                          const unsigned long running_function,
														const unsigned long function_to_call_address,
														unsigned char * code)
{

	struct user_regs_struct regs, backup_regs;
	int wstatus;

	unsigned char * backup = malloc(sizeof(char) * strlen((char*)code));

	// get the memory file of the process
	const size_t mem_len = strlen("/proc//mem") + tracee_pid_len;
	char * mem = malloc(sizeof(char) * mem_len);
	snprintf(mem, sizeof(char) * mem_len, "/proc/%d/mem", pid);

	if(NULL == (fd = fopen(mem,"r+"))){
		fprintf(stderr,"Can't open file at line %d\n",__LINE__);
	}

	fseek(fd, (long)running_function, SEEK_SET);

	// get the code that is going to be replace
	fread(backup,sizeof(char)*strlen((char*)code),1,fd);

	fseek(fd, (long)running_function, SEEK_SET);
	/* Need to put a breakpoint inside the running function address to get the
																								right value for the registers */
	if(fwrite(&bp,1,1,fd) != 1){
		fprintf(stderr,"Failed to write the code at line %d\n",__LINE__);
	}
	// close the file to apply the modification
	fclose(fd);

	/* Restart the process with the breakpoint inside the running funcion */
	if(ptrace(PTRACE_CONT,pid,NULL,NULL) < 0){
		fprintf(stderr,"Fail to restart the processus at line %d\n",__LINE__);
	}
	if(pid != waitpid(pid,&wstatus,WCONTINUED)){
		fprintf(stderr,"Error waipid at line %d\n",__LINE__);
	}

	/* get the value of the registers's processus while the program  is trapped
		 in the execution of f1 */
	if(ptrace(PTRACE_GETREGS,pid,NULL,&backup_regs) < 0){
		fprintf(stderr,"Fail to get the registers at line %d\n",__LINE__);
	}
	//printf("**BACKUP**\nrax : %llx, rip : %llx\n", backup_regs.rax,backup_regs.rip);
	if(ptrace(PTRACE_GETREGS,pid,NULL,&regs) < 0){
		fprintf(stderr,"Fail to get the registers at line %d\n",__LINE__);
	}

	/* Set the new value for the registers */
	regs.rax = function_to_call_address;
	regs.rip = running_function;

	if(ptrace(PTRACE_SETREGS,pid,NULL,&regs) < 0){
		fprintf(stderr,"Fail to set the registers at line %d\n",__LINE__);
	}
	//printf("**NEW**\nrax : %llx, rip : %llx\n", regs.rax,regs.rip);

	/* Open the memory to write the code in it */
	if(NULL == (fd = fopen(mem,"r+"))){
		fprintf(stderr,"Can't open file at line %d\n",__LINE__);
	}
	fseek(fd, (long)running_function, SEEK_SET);
	// inject the code
	if(fwrite(code,sizeof(char)*strlen((char*)code),1,fd) == 0){
		fprintf(stderr,"Failed to inject the code at line %d\n",__LINE__);
	}
	fclose(fd);

	// restart the process to execute the injected code
	if(ptrace(PTRACE_CONT,pid,NULL,NULL) < 0){
		fprintf(stderr,"Failed to restart the processus at line %d\n",__LINE__);
	}
	// wait for it to finish
	if(pid != waitpid(pid,&wstatus,WCONTINUED)){
		fprintf(stderr,"Error waipid at line %d\n",__LINE__);
	}

	/* Get the return value after the code has been executed */
	if(ptrace(PTRACE_GETREGS,pid,NULL,&regs) < 0){
		fprintf(stderr,"Fail to get the registers at line %d\n",__LINE__);
	}
	/* Return value of getpagesize is of type int so we can cast the rax to int */
	int return_value = (int)regs.rax;

	// open the file again to restore the memory
	if(NULL == (fd = fopen(mem,"r+"))){
		fprintf(stderr,"Can't open file at line %d\n",__LINE__);
	}

	fseek(fd, (long)running_function, SEEK_SET);

	// Restore the previous code
	if(fwrite(backup,sizeof(char)*strlen((char*)code),1,fd) == 0){
		fprintf(stderr,"Failed to write the backup at line %d\n",__LINE__);
	}
	//set the registers to their original value
	if(ptrace(PTRACE_SETREGS,pid,NULL,&backup_regs) < 0){
		fprintf(stderr,"Fail to set the registers at line %d\n",__LINE__);
	}
	fclose(fd);
	free(mem);
	free(backup);

	return return_value;
}




/*
	Call posix_memalign in the tracee and return the starting address of the
 	allocated memory block
	Parameter : pid -> pid of the tracee
							running_function -> address of the function currently running
							function_to_call_address -> address of the function to call
							code -> instruction injected at the beginning of the running function
							alignment, size -> parameter of posix_memalign()
*/
static unsigned long call_memalign(const pid_t pid,
	                                 const unsigned long running_function,
						 		          	       const unsigned long function_to_call_address,
																	 unsigned char * code,
																	 const size_t alignment,
																	 const size_t size)
{

	struct user_regs_struct regs, backup_regs;
	int wstatus;
	const size_t mem_len = strlen("/proc//mem") + tracee_pid_len;
	char * mem = malloc(sizeof(char) * mem_len);
	unsigned char * backup = malloc(sizeof(char)*strlen((char*)code));

	// get the memory file of the process
	snprintf(mem, sizeof(char) * mem_len, "/proc/%d/mem", pid);
	if(NULL == (fd = fopen(mem,"r+"))){
		fprintf(stderr,"Can't open file at line %d\n",__LINE__);
	}

	fseek(fd, (long)running_function, SEEK_SET);

	// get the code that is going to be replace
	fread(backup,sizeof(char)*strlen((char*)code),1,fd);

	fseek(fd, (long)running_function, SEEK_SET);

	/* Need to put a breakpoint inside the running function address to get the
		 right value for the registers */
	if(fwrite(&bp,1,1,fd) != 1){
		fprintf(stderr,"Failed to write the code at line %d\n",__LINE__);
	}
	// close the file to apply the modification
	fclose(fd);

	/* Restart the process with the breakpoint inside the running funcion */

	if(ptrace(PTRACE_CONT,pid,NULL,NULL) < 0){
		fprintf(stderr,"Fail to restart the processus at line %d\n",__LINE__);
	}
	if(pid != waitpid(pid,&wstatus,WCONTINUED)){
		fprintf(stderr,"Error waipid at line %d\n",__LINE__);
	}

	/* get the value of the registers's processus while the program  is trapped
		 in the execution of the running_function */
	if(ptrace(PTRACE_GETREGS,pid,NULL,&backup_regs) < 0){
 		fprintf(stderr,"Fail to get the registers at line %d\n",__LINE__);
 	}
	if(ptrace(PTRACE_GETREGS,pid,NULL,&regs) < 0){
		fprintf(stderr,"Fail to get the registers at line %d\n",__LINE__);
	}

	/* Set the new value for the registers */
	regs.rax = function_to_call_address;
	regs.rip = running_function;
	regs.rdi = regs.rsp - 32;
	regs.rsi = alignment;
	regs.rdx = size;

	if(ptrace(PTRACE_SETREGS,pid,NULL,&regs) < 0){
		fprintf(stderr,"Fail to set the registers at line %d\n",__LINE__);
	}

	/* Open the memory to write the code in it */
	if(NULL == (fd = fopen(mem,"r+"))){
		fprintf(stderr,"Can't open file at line %d\n",__LINE__);
	}
	fseek(fd, (long)running_function, SEEK_SET);
	// inject the code
	if(fwrite(code,sizeof(char)*strlen((char*)code),1,fd) == 0){
		fprintf(stderr,"Failed to inject the code at line %d\n",__LINE__);
	}
	fclose(fd);

	// restart the process to execute the injected code
	if(ptrace(PTRACE_CONT,pid,NULL,NULL) < 0){
		fprintf(stderr,"Failed to restart the processus at line %d\n",__LINE__);
	}
	// wait for it to finish
	if(pid != waitpid(pid,&wstatus,WCONTINUED)){
		fprintf(stderr,"Error waipid at line %d\n",__LINE__);
	}

	/* Get the return value after the code has been executed */
	if(ptrace(PTRACE_GETREGS,pid,NULL,&regs) < 0){
		fprintf(stderr,"Fail to get the registers at line %d\n",__LINE__);
	}

	/* Check the return value of posix_memalign, 0 on success */
	if (regs.rax != 0){
		perror("Error when calling posix_memalign");
		exit(-1);
	}

	/* Get the allocated address */
	unsigned long return_address = regs.rdi;

	// Set the registers to their original value
	if(ptrace(PTRACE_SETREGS,pid,NULL,&backup_regs) < 0){
		fprintf(stderr,"Fail to set the registers at line %d\n",__LINE__);
	}

	// open the file again to restore the memory
	if(NULL == (fd = fopen(mem,"r+"))){
		fprintf(stderr,"Can't open file at line %d\n",__LINE__);
	}

	fseek(fd, (long)running_function, SEEK_SET);
	// Restore the previous code
	if(fwrite(backup,sizeof(char)*strlen((char*)code),1,fd) == 0){
		fprintf(stderr,"Failed to write the backup at line %d\n",__LINE__);
	}
	fclose(fd);
	free(mem);
	free(backup);

	/* Return the memory allocated */
	return return_address;
}


/*
	Get the size of a function inside a given executable
	Parameter : function_name -> name of the function that we want the size
	 						prog_name -> name of the program in wich reside the function
*/
static int get_function_size(const char* function_name, const char* prog_name){
	/*
	  construction of the commands to output the symbol and the size in decimal
		of the wanted function inside the object file
	*/
	const size_t nm_len = strlen("nm -S -t d  | grep ") + strlen(function_name) +
	                      strlen(prog_name);
	char * nm_command = malloc(sizeof(char) * nm_len);
	snprintf(nm_command, sizeof(char)*nm_len, "nm -S -t d %s | grep %s",
	         prog_name, function_name);

	// execute the command
	if(NULL == (fd = popen(nm_command,"r"))){
		perror("nm_command failed");
		return -1;
	}

	int result;
	char * temp = malloc(sizeof(char)*64);
	char * function_size;

	fgets(temp,64,fd);
	strtok(temp," ");
	/* Get the second part of the previous result and keep the part before the
  	 'T' because the functions symbols are stored in the .text section*/
	function_size = strtok(NULL," T");
	result = atoi(function_size);
	pclose(fd);
	free(temp);
	free(nm_command);

	return result;
}

/* Dummy function for the injection */
static int virus(int param){
	param *= 1000;
	return param;
}


/*
	Call mprotect in the tracee and return the return value of mprotect
	Parameter : pid -> pid of the tracee
							running_function -> address of the function currently running
							function_to_call_address -> address of the function to call
							code -> instruction injected at the beginning of the running function
							addr, len, prot -> parameter of mprotect()
*/
static void call_mprotect(const pid_t pid,
	                        const unsigned long running_function,
	                        const unsigned long function_to_call_address,
									        unsigned char * code,
									        const unsigned long addr,
									        const size_t len,
									        const int prot)
{

	struct user_regs_struct regs, backup_regs;
	int wstatus;
	const size_t mem_len = strlen("/proc//mem") + tracee_pid_len;
	char * mem = malloc(sizeof(char) * mem_len);
	unsigned char * backup = malloc(sizeof(char)*strlen((char*)code));

	// get the memory file of the process
	snprintf(mem, sizeof(char) * mem_len, "/proc/%d/mem", pid);
	if(NULL == (fd = fopen(mem,"r+"))){
		fprintf(stderr,"Can't open file at line %d\n",__LINE__);
	}

	fseek(fd, (long)running_function, SEEK_SET);

	// get the code that is going to be replace
	fread(backup,sizeof(char)*strlen((char*)code),1,fd);

	fseek(fd, (long)running_function, SEEK_SET);

	/* Need to put a breakpoint inside the running function address to get the
		 right value for the registers */
	if(fwrite(&bp,1,1,fd) != 1){
		fprintf(stderr,"Failed to write the code at line %d\n",__LINE__);
	}
	// close the file to apply the modification
	fclose(fd);

	/* Restart the process with the breakpoint inside the running funcion */
	if(ptrace(PTRACE_CONT,pid,NULL,NULL) < 0){
		fprintf(stderr,"Fail to restart the processus at line %d\n",__LINE__);
	}
	if(pid != waitpid(pid,&wstatus,WCONTINUED)){
		fprintf(stderr,"Error waipid at line %d\n",__LINE__);
	}

	/* get the value of the registers's processus while the program  is trapped
		 in the execution of the running_function */
	if(ptrace(PTRACE_GETREGS,pid,NULL,&backup_regs) < 0){
		fprintf(stderr,"Fail to get the registers at line %d\n",__LINE__);
	}

	if(ptrace(PTRACE_GETREGS,pid,NULL,&regs) < 0){
		fprintf(stderr,"Fail to get the registers at line %d\n",__LINE__);
	}

	/* Set the new value for the registers */
	regs.rip = running_function;
	regs.rax = function_to_call_address;
	regs.rdi = addr;
	regs.rsi = len;
	regs.rdx = (unsigned long long)prot;

	if(ptrace(PTRACE_SETREGS,pid,NULL,&regs) < 0){
		fprintf(stderr,"Fail to set the registers at line %d\n",__LINE__);
	}

	/* Open the memory to write the code in it */
	if(NULL == (fd = fopen(mem,"r+"))){
		fprintf(stderr,"Can't open file at line %d\n",__LINE__);
	}

	/* Write the code at the begining of the running function */
	fseek(fd, (long)running_function, SEEK_SET);
	if(fwrite(code,sizeof(char)*strlen((char*)code),1,fd) == 0){
		fprintf(stderr,"Failed to inject the code at line %d\n",__LINE__);
	}
	fclose(fd);

	// restart the process to execute the injected code
	if(ptrace(PTRACE_CONT,pid,NULL,NULL) < 0){
		fprintf(stderr,"Failed to restart the processus at line %d\n",__LINE__);
	}
	// wait for it to finish
	if(pid != waitpid(pid,&wstatus,WCONTINUED)){
		fprintf(stderr,"Error waipid at line %d\n",__LINE__);
	}

	/* Get the return value after the code has been executed */
	if(ptrace(PTRACE_GETREGS,pid,NULL,&regs) < 0){
		fprintf(stderr,"Fail to get the registers at line %d\n",__LINE__);
	}

	/* Check the return value of mprotect, 0 on success */
	if(regs.rax != 0){
		perror("Error when calling mprotect");
		exit(-1);
	}

	//set the registers to their original value
	if(ptrace(PTRACE_SETREGS,pid,NULL,&backup_regs) < 0){
		fprintf(stderr,"Fail to set the registers at line %d\n",__LINE__);
	}

	// open the file again to restore the memory
	if(NULL == (fd = fopen(mem,"r+"))){
		fprintf(stderr,"Can't open file at line %d\n",__LINE__);
	}

	fseek(fd, (long)running_function, SEEK_SET);
	// Restore the previous code
	if(fwrite(backup,sizeof(char)*strlen((char*)code),1,fd) == 0){
		fprintf(stderr,"Failed to write the backup at line %d\n",__LINE__);
	}
	fclose(fd);
	free(mem);
	free(backup);
}

/*
	Get content from the memory of a running program and store it the array data
	Parameter : pid -> pid of the running program
	            address_to_read -> point to the begining of the block to read
							size -> size of the block to read
							data -> pointer to the content of the memory
*/
static void getdata(const pid_t pid, const long address_to_read, const int size,
	                  unsigned char * data)
{
	/* open the memory of the specify pid */
	const size_t mem_len = strlen("/proc//mem") + tracee_pid_len;
	char * mem = malloc(sizeof(char) * mem_len);
	snprintf(mem, sizeof(char) * mem_len, "/proc/%d/mem", pid);
	if(NULL == (fd = fopen(mem,"r+"))){
		fprintf(stderr,"Error when opening file at line %d\n",__LINE__);
	}

	/* Seek to the address where the wanted data start */
	fseek(fd, address_to_read, SEEK_SET);

	/* Read size amount of bytes and store it in the array data */
	fread(data, sizeof(char) * (size_t)size, 1, fd);

	free(mem);
	fclose(fd);
}


/*
	Put data inside a processus memory
	Parameter : pid -> pid of the processus we want to modify
						  address_to_write -> address where the data need to be write
							data -> the data that we want to write
							size -> size of the data to write
*/
static void putdata(const pid_t pid, const unsigned long address_to_write,
	                  const int size,
	                  const unsigned char * data)
{
	/* Open the memory of a process specify by pid */
	const size_t mem_len = strlen("/proc//mem") + tracee_pid_len;
	char * mem = malloc(sizeof(char) * mem_len);
	snprintf(mem, sizeof(char) * mem_len, "/proc/%d/mem", pid);
	if(NULL == (fd = fopen(mem,"r+"))){
		fprintf(stderr,"Can't open file at line %d\n",__LINE__);
	}

	/* Seek to the address where we want to write */
	fseek(fd, (long)address_to_write, SEEK_SET);

	/* Write the content of data at the address specify */
	if(fwrite(data,sizeof(char) * (size_t)size, 1, fd) == 0){
			fprintf(stderr,"Error fwrite at line %d\n",__LINE__);
	}
	free(mem);
	fclose(fd);
}

/*
	Check if the address specify is in an executable memory block of the heap
	Return 1 if true, 0 otherwise.
	Parameter : pid -> pid of the process that we will check the heap
	            address -> address to check
*/
int isAddrInHeap(pid_t pid, unsigned long address){
	int result = 0;

	const size_t maps_len = strlen("cat /proc//maps") + tracee_pid_len;
	char* maps = malloc(sizeof(char) * maps_len);
	snprintf(maps,sizeof(char) * maps_len, "cat /proc/%d/maps", pid);

	/* Open the maps to find the address of the heap */
	if(NULL == (fd = popen(maps,"r"))){
		perror("can't open the memory mapping");
		exit(-1);
	}

	char * start = malloc(sizeof(char)*128);
	char * end;
	int find = 0;
	do
	{
		fgets(start,128,fd);
		/* Check if "*rwxp*heap" is present */
		if((strstr(start,"rwxp") != NULL) && (strstr(start,"heap") != NULL)){
			/* Get the base address of the executable heap */
			strtok(start,"-");
			/* Get the end address of the executable heap */
			end = strtok(NULL," rwxp");
			find = 1;
		}
	}
	while(find==0);

	if ((unsigned long)strtol(start,NULL,16) <= address &&
			(unsigned long)strtol(end,NULL,16) >= address )
	{
		result = 1;
	}
	free(maps);
	free(start);
	fclose(fd);

	return result;
}


int main(int argc, char* argv[]){

	if(argc != 3){
		printf("Wrong number of parameters, expected 2 got %d\n",argc-1 );
		printf("Usage :\t`tracer [processus name] [function name]`\n\nThe processus secify need to be run before the execution of the tracer.\nThe function specify need to be an existing function in the tracee. \n");
		return -1;
	}
	int wstatus;

	/* instruction of an indirect call, we put a breakpoint (0xCC) after the call
	   to regain control of the execution of the tracee */
	unsigned char indirect_call[3] = {0xFF,0xD0,bp};

	/* Get the pid of the tracee */
	const pid_t tracee_pid = get_pid(argv[1]);

	/*****************************************************************************
		Gather all the addresses of the functions that are going to be needed during
		the injection process
	*****************************************************************************/

	/* address of the function that is currently running in the tracee */
	const unsigned long running_func_addr = get_function_addr(tracee_pid,
		                                                        argv[1],argv[2]);

	/* address of getpagesize() in the tracee */
	const unsigned long getpagesize_addr = get_libc_function_address(tracee_pid,
		                                                (unsigned long)getpagesize);

	/* adress of posix_memalign() in the tracee */
	const unsigned long posix_memalign_addr = get_libc_function_address(tracee_pid,
																								 (unsigned long)posix_memalign);

	/* adress of mprotect() in the tracee */
	const unsigned long mprotect_addr = get_libc_function_address(tracee_pid,
		                                                   (unsigned long)mprotect);


	 /************************************
 		Beginning of the injection process
 	************************************/

	/* Attach to the processus and wait for it to finish */
	if(ptrace(PTRACE_ATTACH,tracee_pid,NULL,NULL) < 0){
		fprintf(stderr,"Can't attach processus at line %d\n",__LINE__);
	}
	if(tracee_pid != waitpid(tracee_pid,&wstatus,0)) {
		fprintf(stderr,"Error waipid at line %d\n",__LINE__);
	}

	/* Make the tracee call getpagesize() */
	const int pagesize = call_getpagesize(tracee_pid, running_func_addr,
                                        getpagesize_addr, indirect_call);

	/* get the size of the function that is going to be injected */
	const int sizeofvirus = get_function_size("virus","tracer");

	/* Make the tracee call posix_memalign() to allocate some memory in the heap
		 and store the address of the allocated memory */
  const unsigned long allocated_mem=call_memalign(tracee_pid, running_func_addr,
	 	                                              posix_memalign_addr,
	 																								indirect_call,
	 																				        64, (size_t)pagesize);

	/* The formuma below assure that the address pass to mprotect is align to the
     page size, for calling mprotect the right way */
  const unsigned long align_allocated_mem = allocated_mem &
	                                          ~((unsigned long)pagesize - 1);

	/* NEED to put all 3 protection because mprotect overwrite previous ones
		 and the heap has rw- privilege */
  call_mprotect(tracee_pid, running_func_addr, mprotect_addr, indirect_call,
		            align_allocated_mem, (size_t)pagesize,
								PROT_EXEC|PROT_WRITE|PROT_READ);

	/* Check if everything works until now */
	if(isAddrInHeap(tracee_pid, allocated_mem) == 0){
		perror("The memory allocated is not in an executable block of the heap");
		return -1;
	}

	/* Declaration of the array that will contain the content of the virus */
	unsigned char * data = malloc(sizeof(char) * (size_t)sizeofvirus);

	/* Get the content of the virus directly from the memory of the tracer */
	getdata(getpid(), (long)virus, sizeofvirus, data);

	/* Write the content of the virus at the specify address in the tracee */
	putdata(tracee_pid, allocated_mem, sizeofvirus, data);

	free(data);

	/* Create a trampoline in the running function */
	trampoline(tracee_pid, running_func_addr, allocated_mem, 9);


	/* Detach and restart the process, at this point the virus is called every
	   time the running function (f1) is called */
	if(ptrace(PTRACE_DETACH,tracee_pid,NULL,NULL) < 0){
		perror("Error when detaching process\n");
		return -1;
	}

	return 0;
}
