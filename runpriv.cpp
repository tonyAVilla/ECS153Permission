/*
 *  READ ME
 * This program uses Macro ID for the user id. 
 * The program will also make a log called logfile.txt for debugging purposes,
 * or to assist the TA with grading this program. The program will output errors
 * with a general description of the errors.
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <stdexcept>
#include <time.h>

using namespace std;
ofstream log("logfile.txt", ios_base::out);
#define ID 1000
void verification();
void check_sniff_type(struct stat *buff);
void check_sniff_access(struct stat buff);
void check_sniff_modification_time(struct stat buff);
void change_sniff_ownership();
int main(){
	struct stat buff;
	try{
		log << "=======verification=======\n";
		//verification();
		log << "=======check_sniff_type=======\n";
		//check_sniff_type(&buff);
		log << "=======check_sniff_access========\n";
		//check_sniff_access(buff);
		log << "========check_sniff_modification_time=======\n";
		//check_sniff_modification_time(buff);
		log << "========change_sniff_ownership===========\n";
		change_sniff_ownership();
	}

	catch(const char* msg){
		cerr << msg << endl;
	}
	return 0;
}

/*
	Verify user with password file
*/
void verification(){

	/*Get file stream for password file*/
	int user_id = getuid();
	if(user_id < 0){
		throw "ERROR: user verification failed";
	}
	log << "Verifying getuid: " << user_id << endl;
	if(user_id != ID & user_id != 0){
		log << "ERROR: user verification failed";
		throw "ERROR: Access denied.";
	}
}

void check_sniff_type(struct stat* buff){
	log << "Checking if sniff is in current directory.\n";
	if(stat("./sniff", buff) == -1){
		log << "ERROR: sniff not found.\n";
		throw "ERROR: file not found.\n";
	}
	log << "Checking if sniff is regular file type\n";

	if((buff->st_mode & S_IFMT) != S_IFREG){
		log << "sniff is not regular file\n";
		throw "ERROR: it is a not regular file";
	}
}

void check_sniff_access(struct stat buff){
	mode_t m = buff.st_mode;
	log << "check if sniff own by current user\n";
	if(buff.st_uid != ID){
		log << "ERROR: sniff not own by user\n";
		throw "ERROR: sniff not own by ID";
	}

	log << "check if sniff is executable by user\n";
	if(!(m & S_IXUSR)){
		log << "ERROR: user " << ID << " cannot execute sniff\n";
		throw "ERROR: user cannot execute sniff";
	}

	log << "check if other people can execute it\n";
	if((m & S_IRGRP) | (m & S_IWGRP) | (m & S_IXGRP)
		| (m & S_IROTH) | (m & S_IWOTH) | (m & S_IXOTH )){
		log << "ERROR: others can r,w,e sniff \n";
		throw "ERROR: others can rwe sniff\n";
	}
}

void check_sniff_modification_time(struct stat buff){
	time_t now;
	time(&now);
	log << "current time is " << ctime(&now) ;
	log << "file modification time is " << ctime(&(buff.st_mtime)) ;
	unsigned int diff = difftime(now, buff.st_mtime);

	log << "difference in seconds is " << diff << endl;

	if(diff > 60){
		log << "ERROR: file modified too long ago\n";
		throw "ERROR: file modified too long ago.";
	}
}

void change_sniff_ownership(){
	if(chmod("./sniff", 0455) == -1){
		log << "chmod failed\n";
		throw "Error: chmod failed";
	}
	log<<flush;
	char *argv[] = { "/usr/bin/chown", "root:proj", "sniff", NULL};
	int result = execve("/usr/bin/chown", argv, NULL);
	log << "Result of execve is " << result;
	log<<flush;
	throw "Error: failed to use chown.";
}