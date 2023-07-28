#include "orBit.h"

ssize_t read( int fd, void *data, size_t count )
{
    static ssize_t ( *func_read ) ( int, void *, size_t ) = NULL;
    if ( ! func_read )
        func_read = (ssize_t (*) ( int, void *, size_t )) dlsym ( RTLD_NEXT, "read");
    ssize_t res = func_read( fd, data, count );
    return ( res );
}
