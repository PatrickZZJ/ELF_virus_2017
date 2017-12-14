#include <sys/types.h>
#include <asm/stat.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/fcntl.h>
#include <dirent.h>


#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#define INLINE inline __attribute__((always_inline))
struct sockaddr {
	unsigned short sa_family;
	char sa_data[14];
	};

struct sockaddr_in {
unsigned short sin_family;                           
unsigned short sin_port;                              
unsigned int sin_addr;                           
unsigned char sin_zero[8];       
};

#undef _syscall0
#define _syscall0(type,name) \
static INLINE type name() \
{ \
	long __res ; \
	asm volatile("syscall" \
				 : "=a" (__res) \
				 : "0" (__NR_##name)); \
	return (type)(__res); \
}

#undef _syscall1
#define _syscall1(type ,name, type1 , arg1 ) \
static INLINE type name( type1 arg1 ) \
{ \
long __res ; \
asm volatile ( "syscall" \
: "=a" (__res ) \
: "0" (__NR_##name),"D" ((long)( arg1 ) ) ) ; \
return ( type )(__res); \
}

#undef _syscall2
#define _syscall2(type ,name, type1 , arg1 , type2 , arg2 ) \
static INLINE type name(type1 arg1 , type2 arg2 ) \
{ \
long __res ; \
asm volatile ( "syscall" \
: "=a" (__res) \
: "0" (__NR_##name), "D" (( long )( arg1 )) , \
"S" (( long )( arg2 ) ) ) ; \
return ( type )(__res); \
}

#undef _syscall3
#define _syscall3(type ,name, type1 , arg1 , type2 , arg2 , type3 , arg3 ) \
static INLINE type name( type1 arg1 , type2 arg2 , type3 arg3 ) \
{ \
long __res ; \
asm volatile( "syscall" \
: "=a" (__res ) \
: "0" (__NR_##name) ,"D" (( long )( arg1 )) , \
"S" (( long )( arg2 )) , "d" (( long )( arg3 ) ) ) ; \
return (type)(__res); \
}
_syscall3(int , open , const char * ,pathname , int , flags , int ,mode );
_syscall3(ssize_t , read , int , fd , void *, buf, size_t, count );
_syscall3(off_t , lseek, int, fildes, off_t, offset, int, whence);
_syscall3(ssize_t, write, int, fd, const void *, buf, size_t, count);
_syscall1(int, close, int, fd);
_syscall3(int, getdents, uint, fd, void *, buf, uint, count);
_syscall0(int, getpid);
_syscall2(long, utimes, const char*, filename, const struct timeval *, utimes);
_syscall2(int, stat, const char *, path, struct stat *, buf);
_syscall0(int,fork);
_syscall3(int, socket, int, __domain, int, __type, int, __protocol);
_syscall3(int, bind, int, socket, const struct sockaddr *, address, int, address_len);
_syscall2(int, listen, int, socket, int,backlog);
_syscall3(int, accept, int, socket, struct sockaddr *, address, int, address_len);
_syscall2(int,dup2, int, oldfd, int, newfd);
_syscall3(int, execve, const char *, filename, char * const ,argv, char * const ,envp);
