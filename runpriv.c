/*  James Zheng
 *  jzzheng
 *  READ ME
 * This program uses Macro ID for the user id. 
 * 
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <time.h>

#define ID 1002
void verification();
void check_sniff_type(struct stat *buff);
void check_sniff_access(struct stat buff);
void check_sniff_modification_time(struct stat buff);
void change_sniff_ownership();
int main(){
	struct stat buff;
	stat("./sniff", &buff);

		printf("=======verification=======\n");
	//	verification();
		printf("=======check_sniff_type=======\n");
	//	check_sniff_type(&buff);
		printf("=======check_sniff_access========\n");
	//	check_sniff_access(buff);
		printf("========check_sniff_modification_time=======\n");
	//	check_sniff_modification_time(buff);
		printf("========change_sniff_ownership===========\n");
		change_sniff_ownership();

	return 0;
}

void change_sniff_ownership(){
	int pid;
	int status;
	pid = fork();
	if(pid < 0){
		fprintf(stderr, "ERROR: fork failed");
	}
	else if(pid == 0){//child process
		char *myargv[] = { "/usr/bin/chown", "root:proj","./sniff",  NULL};
		int result;
	//	result = execve(myargv[0], myargv, NULL);
	//	fprintf(stderr, "ERROR: failed to use chown.\n");
		exit(1);
	}
	
	else{//parent
		int status;
		if(wait(&status) == -1){
			fprintf(stderr, "ERROR: child failed to use chown\n");
			exit(1);
		}
		printf("child status is %d", status);
		
	/*if(chmod("./sniff", 04550) == -1){
		// "chmod failed\n");
		fprintf(stderr, "ERROR: chmod failed\n");
		exit(1);
	}
		*/
}
	
}
/*
	Verify user with password file
*/
void verification(){

	/*Get file stream for password file*/
	int user_id = getuid();
	if(user_id < 0){
		fprintf(stderr, "ERROR: user verification failed");
		exit(1);
	}
	// Verifying getuid: " << user_id << endl
	if((user_id != ID) & (user_id != 0)){
		fprintf(stderr, "ERROR: Access denied\n");
		exit(1);
	}
}

void check_sniff_type(struct stat* buff){
	// check if sniff is in current directory
	if(stat("./sniff", buff) == -1){
		fprintf(stderr, "ERROR: file not found.\n");
		exit(1);
	}

	//check if sniff is regular file type
	if((buff->st_mode & S_IFMT) != S_IFREG){
		fprintf(stderr, "ERROR: it is a not regular file\n");
		exit(1);
	}
}

void check_sniff_access(struct stat buff){
	mode_t m = buff.st_mode;
	//check if sniff own by current user
	if(buff.st_uid != ID){
		fprintf(stderr, "ERROR: sniff not own by ID\n");
		exit(1);
	}

	// "check if sniff is executable by user
	if(!(m & S_IXUSR)){
		fprintf(stderr, "ERROR: user cannot execute sniff\n");
		exit(1);
	}

	// "check if other people can execute it
	if((m & S_IRGRP) | (m & S_IWGRP) | (m & S_IXGRP)
		| (m & S_IROTH) | (m & S_IWOTH) | (m & S_IXOTH )){
		// "ERROR: others can r,w,e sniff \n");
		fprintf(stderr, "ERROR: others can r w e sniff\n");
	exit(1);
	}
}

void check_sniff_modification_time(struct stat buff){
	time_t now;
	time(&now);
	// "current time is " << ctime(&now) ;
	// "file modification time is " << ctime(&(buff.st_mtime)) ;
	unsigned int diff = difftime(now, buff.st_mtime);

	// "difference in seconds is " << diff << endl;

	if(diff > 60){
		// "ERROR: file modified too long ago\n");
		fprintf(stderr, "ERROR: file modified too long ago.\n");
		exit(1);
	}
}

