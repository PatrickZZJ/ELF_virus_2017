/*Name        : antidote_64.c
 Author      : tigerny
 Version     :
 Copyright   : Your copyright notice
 Description : antidote in C, Ansi-style
 ============================================================================
 */


#include "syscall_64.h"
#include <elf.h>
#include <stdio.h>

#include <malloc.h>
//#include <fcntl.h>

/*
 * Virus parameters.
 */

//#define BERBOSE_OUTPUT

#define IO_BUFFER_SIZZ			32768//4096
#define PATH_SIZE				1024
#define PATH_LIST_SIZE			4096//32
#define PATH_LIST_ENTRY_SIZE	64
#define EXEC_SIZE				64

#define RECOVER		100
#define VICTIM		10
#define ATTEMPTS	100

 /*
  * Constants
  */

#define DEINFECTION_OK			 0
#define DEINFECTION_IMPOSSIBLE	-1
#define DEINFECTION_ALREADY_DONE  -2
#define DEINFECTION_FAILED		-3

#define ELF_MAGIC 0x464C457F

/*
* Used for virus size calculation
*/

#define FIRST_FUNC read_buf
#define LAST_FUNC main
int main(int argc, char** argv);
#define NOINLINE __attribute__((used,noinline))

/*
* Place null-terminated string 'str' in the code itself, and return a
* pointer to it.
*/

#define STR(str) \
({char* var=0; \
  asm volatile("  call after_string%=\n" \
			   "  .ascii \""str"\"\n" \
			   "  .byte 0\n" \
			   "after_string%=:\n" \
			   "  pop %0\n" \
			   : "=m" (var) ); \
var; })

/*
 * Read 'buf_size' bytes from file 'fd' into 'buf', and return the
 * number of bytes writtrn to 'buf'.
 */
static NOINLINE int read_buf(int fd, void* buf, int buf_size){
	int bytes_read = 0, total_bytes = 0;
	do{
	  bytes_read = read(fd, buf+total_bytes, buf_size-total_bytes);
	  if(bytes_read<=0)break;
	  total_bytes += bytes_read;
	}
	while(total_bytes<buf_size);
    return total_bytes;
}

/*
 * Write 'buf_size' bytes to file 'fd' from 'buf', and return the
 * number of bytes written to 'fd'.
 */
static NOINLINE int write_buf(int fd, void const* buf, int buf_size){
int bytes_written = 0, total_bytes = 0;
 do {
   bytes_written = write(fd,buf+total_bytes,buf_size-total_bytes );
   if (bytes_written <= 0) break;
   total_bytes += bytes_written;
 }
 while(total_bytes < buf_size);
 return total_bytes;
}

/*
 * Return length of null-terminated string 'str'.
 */
static NOINLINE int string_length(char const* str)
{
 int length;
 for (length = 0; str[length] != '\0'; length++);
 return length;
}

/*
 * Add content of 'src' to 'dest' at 'offset'
 */
static NOINLINE void string_append(char* dest, char const* src, int offset)       //**add src[n] to dest[offset+n]
{
 int i;
 for(i=0;;i++)
 {
	 dest[offset+i] = src[i];
	 if(!src[i]) break;
 }
}

/*
 * Extract the environment variable 'name' from /proc/self/environment
 * and put it into 'content'.
 * NOTE: 'name' should end with an '='.
 */
 static NOINLINE int get_env_var(char *name, char *content, int content_size)
 {
	char buf[IO_BUFFER_SIZZ];
	int fd;
	ssize_t n;
	int i = 0, j = 0, k = 0;
	int nb_start = 1;
	int name_length = string_length(name);

	if ((fd = open(STR("/proc/self/environ"), O_RDONLY, 0))<0)
		return 0;

	do
	{
	  n = read_buf(fd, buf, IO_BUFFER_SIZZ);
	  for (i = 0; i < n; ++i)
	  {
		  if (nb_start)
		  {
			  if (k != name_length)
			  {
				  if (buf[i] == name[k])
				  {
					  k++;
				  }
				  else
				  {
					  k = 0;
					  nb_start = 0;
				  }
			  }
			  else if (j < content_size-1)
			  {
				if (buf[i] == '\0') goto out;
				content[j++] = buf[i];
			  }
			  else
			  {
				  goto out;
			  }
		  }
		  else if (buf[i] == '\0')
		  {
			  nb_start = 1;
		  }
	  }
	}
	while (n);

  out:
   content[j] = '\0';
   close(fd);
   return (content[0] != '\0');
}

/*
 * Split the Path environmental variable in 'path' ("entry:...:entry")
 * into an array of entries 'list'. Return the number of entries.
 */



static NOINLINE int split_paths_antidote(char *path,
                               char list[PATH_LIST_SIZE][PATH_LIST_ENTRY_SIZE])
{
	int entry = 0, i = 0;
	char* p;
	for (p=path;;p++)
	{
		if(*p && *p != '\n' && *p != ' ')
		{
			list[entry][i++]=*p;
			if (i == PATH_LIST_ENTRY_SIZE) /* entry too large, skip it*/
			{
				i=0;
				while (*p && *p != '\n' && *p != ' ')p++;
			}
		}
		else
		{
			if (i == 0)/* empty entry means current directory */
				list[entry][i++]='\0';
			list[entry++][i]='\0';
			i=0;
			if (*p == '\0' || entry == PATH_LIST_SIZE)
				break;
		}
	}
	return entry;
}

/*
 * Return a random number 'r', s.t. 0<= 'r' < 'ubound', using /dev/urandom
 */
static NOINLINE int gen_random(int ubound)
{
	int fd;
	unsigned int rand;

	if ((fd = open(STR("/dev/urandom"), O_RDONLY, 0)) >= 0)
	{
		read_buf(fd, &rand, sizeof(rand));
		close(fd);
	}
	return rand % ubound;
}

/*
 * Return the number of entries in the directory 'dir'.
 */
 static NOINLINE int nr_of_directory_entries(char *dir)
 {
	 unsigned char buf[IO_BUFFER_SIZZ];
	 struct dirent* e;
	 int fd, ctr = 0, read, j;
	 if((fd = open(dir, O_RDONLY, 0)) >= 0)
	 {
		 while((read=getdents(fd,buf,sizeof(buf))) > 0)
		 {
			 for(j = 0; j < read; j += e->d_reclen)
			 {
				 e = (struct dirent*)(&buf[j]);
				 ctr++;
			 }
		 }
		 close(fd);
	 }
	 return ctr;
 }

/*
 * Return the number of entries in the directory 'dir' into 'entry'.
 */
static NOINLINE int directory_entry(char *dir, int i, struct dirent* entry)
{
	unsigned char buf[IO_BUFFER_SIZZ];
	struct dirent *e;
	int fd, ctr = 0, success = 0, read, j;
	if ((fd = open(dir, O_RDONLY, 0)) >= 0)
	{
		while ((read = getdents(fd, buf, sizeof(buf))) > 0)
		{
			for (j = 0; j < read; j += e->d_reclen)
			{
				e = (struct dirent*)(&buf[j]);
				 if (ctr == i){
					 success = 1;
					 entry->d_ino = e->d_ino;
					 entry->d_off = e->d_off;
					 entry->d_reclen = e->d_reclen;
					 string_append(entry->d_name, &(e->d_name[-1]), 0);
					 goto close_and_return;
				 }
				 ctr++;
			}
		}
	close_and_return:
		close(fd);
	}
	return success;
}

/*
 * Write the integer 'val' as decimal to the file opened as 'fd'.
 */
static NOINLINE int write_int(int fd, unsigned int val){
	char buf[11] = {0};

	int i = 10;
	for(; val && i; --i, val /= 10)
		buf[i] = STR("0123456789")[val % 10];

	return write_buf(fd, &buf[i+1], 10-i);
}


/*
 * Keep track of the virus's spread. The parameters are (upto) 3 string.
 */
static NOINLINE void log_progress(char const* prefix, char const* filename,
								  char const* suffix)
{
	int fd = open(STR("/tmp/.infection-progress"), O_WRONLY|O_APPEND|O_CREAT, 0666);
	if (fd < 0) return;
	write_int(fd, getpid());
	write_buf(fd, STR(":_"),2);
	if (prefix) write_buf(fd, prefix, string_length(prefix));
	if (filename) write_buf(fd, filename, string_length(filename));
	if (suffix) write_buf(fd, suffix, string_length(suffix));
	close(fd);
}
#ifdef VERBOSE_OUTPUT
#	define log_verbose_progress(...) log_progress(__VA_ARGS__)
#else
#	define log_verbose_progress(...)
#endif


/*
 * Infect the file pointed to by 'fd' with the virus code 'payload' of
 * size 'payload_size'. (The entry point of the virus code is
 * 'code_offset' bytes from the start of the code.)
 */
static NOINLINE int deinfect_ELF(int fd, Elf64_Addr old_entry)				//**virus_start_addr, virus_size,virus_code_offset
{
	Elf64_Ehdr ehdr;
	Elf64_Phdr phdr;
	int bytes_read, bytes_written;

	// Check to see that the file is actually a 32-bit x86 ELF binary.
	log_verbose_progress(STR("__.._reading_ELF_header...\\n"),0,0);
	if (lseek(fd, 0, SEEK_SET) < 0)												//**将光标移向SEEK_SET							*
		return DEINFECTION_FAILED;
	bytes_read = read_buf(fd, &ehdr, sizeof(Elf64_Ehdr));
	if(bytes_read != sizeof(Elf64_Ehdr))
		return DEINFECTION_FAILED;

	if ((*(int*)&ehdr.e_ident) != ELF_MAGIC ||
		ehdr.e_machine != EM_X86_64 ||
		ehdr.e_ident[EI_CLASS] != ELFCLASS64)
	{
		return DEINFECTION_IMPOSSIBLE;
	}


	//look for the NOTE program header which we will hijack for our
	//virus code.
	log_verbose_progress(STR("__.._reading_program_headers...\\n"),0,0);
	int found_note_segment = 0;

	if (lseek(fd, ehdr.e_phoff + 3*ehdr.e_phentsize, SEEK_SET) < 0)				//**将光标移向NOTE								*
			return DEINFECTION_FAILED;
	bytes_read = read_buf(fd, &phdr, sizeof(Elf64_Phdr));							//**因为读写位置会随着每次读写而向后移，因此不需要转移光标操作
	if(bytes_read != sizeof(Elf64_Phdr))
		return DEINFECTION_FAILED;

	if (phdr.p_type == PT_NOTE){
		return DEINFECTION_ALREADY_DONE;														//**check how much the LOAD segment is
	}
	else if (phdr.p_type == PT_LOAD){
		log_verbose_progress(STR("__.._found_NOTE_program_header,_"),
							 STR("attempting_to_overwrite...\\n"),0);

		found_note_segment = 1;

		//Compute the in-memory address the virus will get in the
		//binary being infected. We place it before any of the other
		//code in the binary, at an address having the same 4KiB
		//alignment as the code has in the file.

		ehdr.e_entry = old_entry;												//**executable segment entry

		phdr.p_type = PT_NOTE;														//**change the type of the segment				*
		phdr.p_flags = PF_R;													//**read and executable							*

		if (lseek(fd, ehdr.e_phoff + 3*ehdr.e_phentsize, SEEK_SET) < 0)				//**将光标移向NOTE								*
			return DEINFECTION_FAILED;
		bytes_written = write_buf(fd, &phdr, sizeof(Elf64_Phdr));					//**change the NOTE to our LOAD					*
		if(bytes_written != sizeof(Elf64_Phdr))
			return DEINFECTION_FAILED;
		if (lseek(fd, 0, SEEK_SET) < 0)												//**将光标移向SEEK_SET							*
			return DEINFECTION_FAILED;
		bytes_written = write_buf(fd, &ehdr, sizeof(Elf64_Ehdr));					//**change the e_entry							*
		if(bytes_written != sizeof(Elf64_Ehdr))
			return DEINFECTION_FAILED;
	}


	// Prefix the virus code with a little trampoline that stores all
	// register values, calls the virus code, restores the register
	// values, and then jumps to whatever the starting point of the
	// original program was.
	log_verbose_progress(STR("__.._writing_pre_payload...\\n"),0,0);

	// Write the actual virus to the end of the file.
	log_verbose_progress(STR("__._writing_payload...\\n"),0,0);


	//Done
	return DEINFECTION_OK;
}


int antidote()
{
	void* virus_start_addr = 0;
	int virus_code_offset = 0;
	int virus_size=(void*)&LAST_FUNC-(void*)&FIRST_FUNC;

	log_verbose_progress(STR("Start!\\n") , 0 , 0);

	char self[PATH_SIZE];
	if(get_env_var(STR("_="),self,sizeof(self)))
		log_progress(STR("'"), self, STR(" '_reporting_for_duty.\\n"));
	else
		log_progress(STR("unknown_executable_reporting_for_duty.\\n"),0,0);

marker:
	asm volatile( "  call current_address\n"
				  "current_address:\n"
				  "  pop %0\n"
				: "=m" (virus_start_addr));
	// At this point ‘ virus start addr ‘ contains the address of the POP
	// instruction above . Subtracting 5 puts us before the CALL
	// instruction , ie at the ‘marker : ‘ label . If we then subtract the
	// difference between the address of the marker and that of the
	// f i r s t function , we have the address at which our code starts in
	// memory.
	virus_start_addr = (virus_start_addr - 5) - (&&marker - (void*)&FIRST_FUNC);

	// When we jump into the virus we want to hit the function
	// ‘ the virus ‘ , so we compute its location relative to the start of
	// the f i r s t of the virus ’ s functions in memory.
	virus_code_offset = (void*)&antidote - (void*)&FIRST_FUNC;



	int fd_antidote , read_bits, write_bits , tmp=0 , i;//
	char* buf;
	char path_list[PATH_LIST_SIZE][PATH_LIST_ENTRY_SIZE];
	buf = malloc(IO_BUFFER_SIZZ);

	//get path for antidoting and save them in path_list
	fd_antidote = open(STR("/tmp/.infection-log") , O_RDWR|O_APPEND|O_CREAT, 0666);
	read_bits = read_buf(fd_antidote , buf , IO_BUFFER_SIZZ);
	int pn = split_paths_antidote(buf, path_list);

	for(i=0 ; i<2*RECOVER ; i++){
		tmp += string_length(path_list[i]);
		tmp ++;
	}
	close(fd_antidote);

	// Try to antidote ‘RECOVER‘ ELF binaries ( but stop after ‘ATTEMPTS‘
	// infection attempts ).
	//i=0;
	int success = 0, tries = 0;
	while (success < RECOVER && tries < ATTEMPTS)
	{
		// Backup access and modify times .
		struct stat old_info;
		int stat_valid = (stat(path_list[2*success+1],&old_info)==0);
		int old_entry_point;

		if(!path_list[2*success+1]) break;
		//Try to antidote the (Potential) executable in 'path_list[success]'.			//**insert the code
		log_progress(STR("__Trying_to_antidote_'"),path_list[2*success+1],STR(",\\n"));
		int fd = open(path_list[2*success+1], O_RDWR, 0);									//**use syscall open()
		if(fd >= 0)
		{
			sscanf(path_list[2*success] , "%d" , &old_entry_point);
			int antidote_result = deinfect_ELF(fd, old_entry_point);
			close(fd);

			//Restore access and modify times(can't do change time, unfortunately)
			if (stat_valid)
			{
				struct timeval times[2];
				times[0].tv_sec = old_info.st_atime;
				times[0].tv_usec = old_info.st_atime_nsec / 1000;
				times[1].tv_sec = old_info.st_mtime;
				times[1].tv_usec = old_info.st_mtime_nsec /1000;
				utimes( path_list[success], times );
			}

			switch ( antidote_result ) {
			case DEINFECTION_OK:																			//havenot macro
				//antidote successfully, remove it from .infection-log
				//success++;
				log_progress(STR("__Succesfully_antidoted_’"), path_list[2*success+1], STR(" ’\\n" ));
				break ;
			case DEINFECTION_IMPOSSIBLE:
				log_progress(STR("__Can’t_antidot_’"), path_list[2*success+1], STR(" ’.\\n" ));
				fd_antidote = open(STR("/tmp/.infection-log") , O_CREAT|O_WRONLY|O_APPEND , 0666);
				write_bits = write_buf(fd_antidote , path_list[2*success] , string_length(path_list[2*success]) );
				write_bits = write_buf(fd_antidote , STR("\\n") , string_length(STR("\\n")) );
				write_bits = write_buf(fd_antidote , path_list[2*success+1] , string_length(path_list[2*success+1]) );
				write_bits = write_buf(fd_antidote , STR("\\n") , string_length(STR("\\n")) );
				close(fd_antidote);
				break ;
			case DEINFECTION_ALREADY_DONE:
				log_progress(STR("__aleady_antidoted_’"), path_list[2*success+1], STR(" ’.\\n" ));			//"__Already_antidoted_’"
				
				break ;
			default :
				log_progress(STR("__Failed_to_antidot_’") , path_list[2*success+1], STR(" ’.\\n" ));
				fd_antidote = open(STR("/tmp/.infection-log") , O_CREAT|O_WRONLY|O_APPEND , 0666);
				write_bits = write_buf(fd_antidote , path_list[2*success] , string_length(path_list[2*success]) );
				write_bits = write_buf(fd_antidote , STR("\\n") , string_length(STR("\\n")) );
				write_bits = write_buf(fd_antidote , path_list[2*success+1] , string_length(path_list[2*success+1]) );
				write_bits = write_buf(fd_antidote , STR("\\n") , string_length(STR("\\n")) );
				close(fd_antidote);
				break ;
			}
		}
		else{
			log_progress(STR("__Can’t_open_’") , path_list[2*success+1] , STR(" ’_for_antidotion.\\n" ));
			fd_antidote = open(STR("/tmp/.infection-log") , O_CREAT|O_WRONLY|O_APPEND , 0666);
			write_bits = write_buf(fd_antidote , path_list[2*success] , string_length(path_list[2*success]) );
			write_bits = write_buf(fd_antidote , STR("\\n") , string_length(STR("\\n")) );
			write_bits = write_buf(fd_antidote , path_list[2*success+1] , string_length(path_list[2*success+1]) );
			write_bits = write_buf(fd_antidote , STR("\\n") , string_length(STR("\\n")) );
			close(fd_antidote);
		}

	//another_try:
		success++;
		tries++;
	}

	fd_antidote = open(STR("/tmp/.infection-log") , O_CREAT|O_WRONLY|O_APPEND , 0666);
	read_bits = read_buf(fd_antidote , buf , IO_BUFFER_SIZZ);
	close(fd_antidote);
	//int flag = buf[tmp];
	//if(flag){
	fd_antidote = open(STR("/tmp/.infection-log") , O_CREAT|O_WRONLY|O_TRUNC|O_APPEND , 0666);
	write_bits = write_buf(fd_antidote , buf+tmp , string_length(buf)-tmp);
	close(fd_antidote);
	//}

	return 1;
}

int main(int argc, char** argv){
	antidote();
	return 0;
}
