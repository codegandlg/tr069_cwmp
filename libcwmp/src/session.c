/************************************************************************
 * Id: session.c                                                        *
 *                                                                      *
 * TR069 Project:  A TR069 library in C                                 *
 * Copyright (C) 2013-2014 netcwmp group                                *
 *                                                                      *
 *                                                                      *
 * Email: netcwmp ( & ) gmail dot com                                *
 *                                                                      *
 ***********************************************************************/


#include "cwmp_session.h"
#include "cwmp_cfg.h"
#include "cwmp_log.h"
#include "cwmp_cwmp.h"
#include "cwmp_private.h"
//#include <nvram.h>


static cwmp_uint32_t g_cwmp_session_sequence = 0;
static char g_cwmp_session_sequence_buffer[64];
extern BOOL transfer;

//static parameter_node_t * g_cwmp_session_root_parameters = NULL;



#define ParameterFormatEnd  ".%s"
#define ParameterFormat1    "%s"
#define ParameterFormat2 ParameterFormat1 ParameterFormatEnd
#define ParameterFormat3 ParameterFormat2 ParameterFormatEnd
#define ParameterFormat4 ParameterFormat3 ParameterFormatEnd
#define ParameterFormat5 ParameterFormat4 ParameterFormatEnd
#define ParameterFormat6 ParameterFormat5 ParameterFormatEnd
#define ParameterFormat7 ParameterFormat6 ParameterFormatEnd
#define ParameterFormat8 ParameterFormat7 ParameterFormatEnd
#define ParameterFormat9 ParameterFormat8 ParameterFormatEnd
#define ParameterFormat10 ParameterFormat9 ParameterFormatEnd
#define ParameterFormat11 ParameterFormat10 ParameterFormatEnd
#define ParameterFormat12 ParameterFormat11 ParameterFormatEnd
#define ParameterFormat13 ParameterFormat12 ParameterFormatEnd
#define ParameterFormat14 ParameterFormat13 ParameterFormatEnd
#define ParameterFormat15 ParameterFormat14 ParameterFormatEnd

#define CWMP_PARAMETER_FORMATS_MAX 15
#define MAX_COOKIE_NUM 6

char  bcookie[MAX_COOKIE_NUM][cook_len];
int nun_cookie = 0;

static char * cwmp_parameter_formats_string[] =
{
    ParameterFormat1,
    ParameterFormat2,
    ParameterFormat3,
    ParameterFormat4,
    ParameterFormat5,
    ParameterFormat6,
    ParameterFormat7,
    ParameterFormat8,
    ParameterFormat9,
    ParameterFormat10,
    ParameterFormat11,
    ParameterFormat12,
    ParameterFormat13,
    ParameterFormat14,
    ParameterFormat15
};




static char * rpc_methods[] =
{
    "GetRPCMethods",
    "SetParameterValues",
    "GetParameterValues",
    "GetParameterNames",
    //"SetParameterAttributes",
    //"GetParameterAttributes",
	//"AddObject",
	// "DeleteObject",
    "Download",
    "Upload",
    "Reboot",
    "FactoryReset",
    "Inform"
};



char * cwmp_data_append_parameter_name(pool_t * pool, int count, ...)
{

    char buffer[1024] = {0};
    char * p = NULL;
    char * format;
    va_list ap;
    if (count >0 && count <= CWMP_PARAMETER_FORMATS_MAX)
    {
        format = cwmp_parameter_formats_string[count-1];

        va_start(ap, count);
        vsprintf(buffer, format, ap);
        va_end(ap);

        p = pool_pcalloc(pool, strlen(buffer)+1);
        strcpy(p, buffer);
    }
    return p;
}

int cwmp_data_sprintf_parameter_name(char * buffer, int count, ...)
{
    int rc = 0;
    char * format;
    va_list ap;
    if (count >0 && count <= CWMP_PARAMETER_FORMATS_MAX)
    {
        format = cwmp_parameter_formats_string[count-1];


        va_start(ap, count);
        rc = vsprintf(buffer, format, ap);
        va_end(ap);
        buffer[rc] = 0;

    }
    return rc;
}




char * cwmp_data_get_parameter_value(cwmp_t * cwmp, parameter_node_t * root, const char * name, pool_t * pool)
{
    parameter_node_t * node;
    char * value = NULL;
    int rc;

	//printf("file:%s fun:%s, line:%d {}\n", __FILE__, __FUNCTION__, __LINE__);
	//printf("name:%s\n",name);
    node = cwmp_get_parameter_node(root, name);
    if (!node)
    {
    	printf("node is NULL, return NULL\n");
        return NULL;
	}

    rc = cwmp_get_parameter_node_value(cwmp, node, name, &value, pool);
    if(rc == 0)
    {
    	//printf("get return 0 \n");
        return value;
    }
    else
    {
    	printf("ret return value:%s \n", node->value);
        return node->value;
    }

}

int cwmp_data_set_parameter_value(cwmp_t * cwmp, parameter_node_t * root, const char * name, 
										const char * value, int value_length, pool_t * pool)
{
    parameter_node_t * node;
	cwmp_log_debug("value:%s, len:%d", value, value_length);
    node = cwmp_get_parameter_node(root, name);
    if (!node)
        return CWMP_ERROR;
    return cwmp_set_parameter_node_value(cwmp, node, name, value, value_length);

}







char * cwmp_session_get_sequence(pool_t * pool)
{
    g_cwmp_session_sequence++;
    TRsnprintf(g_cwmp_session_sequence_buffer, 63, "%d", g_cwmp_session_sequence);
    return g_cwmp_session_sequence_buffer;
}

int rut_get_ip(const char dev_name[], char *ip_str)
{
    int fd;
    struct ifreq ifr;
    struct sockaddr_in *sin;

    if ((ip_str == NULL) )
    {
        printf("get_ip-> parameter invalid!");
        return -1;
    }

    if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
    {
        printf("get_ip->socket operator error:%s\r\n", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    ifr.ifr_addr.sa_family = AF_INET;

    strcpy(ifr.ifr_name, dev_name);


    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0)
    {
        if (NULL != ip_str)
            strcpy(ip_str, "0.0.0.0");
        close(fd);
        return -1;
    }
    else
    {
        sin = (struct sockaddr_in *) &ifr.ifr_addr;
        if (NULL != ip_str)
        {
            strcpy(ip_str, inet_ntoa(sin->sin_addr));
        }

    }

    close(fd);
    return 0;
}


int cwmp_session_get_localip(char *hostip)
{
    register int fd,intrface,retn=0;
    struct ifreq buf[32];
    struct ifconf ifc;
    char domain_host[100] = {0};
    char local_ip_addr[20] = {0};
    char local_mac[20] = {0};
    //Get Domain Name --------------------------------------------------
    if (!hostip)
        return -1;
    if (getdomainname(&domain_host[0], 100) != 0)
    {
        return -1;
    }
    //------------------------------------------------------------------
    //Get IP Address & Mac Address ----------------------------------------
    if ((fd=socket(AF_INET,SOCK_DGRAM,0))>=0)
    {
        ifc.ifc_len=sizeof buf;
        ifc.ifc_buf=(caddr_t)buf;
        if (!ioctl(fd,SIOCGIFCONF,(char*)&ifc))
        {
            intrface=ifc.ifc_len/sizeof(struct ifreq);
            while (intrface-->0)
            {
                if (!(ioctl(fd,SIOCGIFFLAGS,(char*)&buf[intrface])))
                {
                    if (buf[intrface].ifr_flags&IFF_PROMISC)
                    {
                        retn++;
                    }
                }
                //Get IP Address
                if (!(ioctl(fd,SIOCGIFADDR,(char*)&buf[intrface])))
                {
                    sprintf(local_ip_addr, "%s", inet_ntoa(((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr));
                }
                //Get Hardware Address

            }//While
        }
    }
    if ( fd > 0 )
    {
        close(fd);
    }

    strcpy(hostip, local_ip_addr);


    return CWMP_OK;
}

cwmp_session_t * cwmp_session_create(cwmp_t * cwmp)
{


    pool_t * pool = pool_create(POOL_MIN_SIZE);
    cwmp_session_t * session = pool_pcalloc(pool, sizeof(cwmp_session_t));
    session->env = pool_pcalloc(pool, sizeof(env_cwmp));
    session->env->cwmp = cwmp;
    session->cwmp = cwmp;
    cwmp_chunk_create( &session->writers, pool);
    cwmp_chunk_create(&session->readers, pool);

    session->pool = pool;
    session->status = 0;    /*定义连接、发送、接收、关闭等不同状态*/
    session->newdata = 0;   /*session->readers是否有数据可以读*/
    session->timeout = 0;
    session->envpool = NULL;
    session->connpool = NULL;

    session->root = cwmp->root;
    session->retry_count = 0;

    return session;
}

void cwmp_session_free(cwmp_session_t * session)
{
    pool_t * pool = session->pool;
    printf("set nun_cookie to 0\n");
	nun_cookie = 0;
    if (session->envpool)
    {
        pool_destroy(session->envpool);
        session->envpool = NULL;
    }
    if (session->connpool)
    {
        pool_destroy(session->connpool);
        session->connpool = NULL;
    }
    pool_destroy(pool);

}

int cwmp_session_close(cwmp_session_t * session)
{
    pool_destroy(session->envpool);
    pool_destroy(session->connpool);
    session->envpool = NULL;
    session->connpool = NULL; 
    if (session->sock->sockdes > 0)
    {
    	printf("session fd to close\n");
		close(session->sock->sockdes);
    }
	
    return 0;
}

int cwmp_session_open(cwmp_session_t * session)
{

    pool_t *envpool = pool_create(POOL_MIN_SIZE);

    session->connpool = pool_create(POOL_MIN_SIZE);
    if (!session->connpool)
    {
        cwmp_log_error("session init: create connection pool null.");
        return CWMP_ERROR;
    }
    session->envpool = envpool;
    session->env->pool = envpool;


    //pool_cleanup_add(envpool, cwmp_chunk_clear, session->writers);
    //pool_cleanup_add(envpool, cwmp_chunk_clear, session->readers);

    return CWMP_OK;
}

static size_t cwmp_session_write_callback(char *data, size_t size, size_t nmemb, void * calldata)
{
    cwmp_session_t * session = (cwmp_session_t *)calldata;

    cwmp_chunk_write_string(session->readers, data, size * nmemb, session->envpool);

    return size * nmemb;
}

int cwmp_session_connect(cwmp_session_t * session, const char * url)
{

    http_dest_t *  dest;
    int rv;

    http_dest_create(&dest, url, session->connpool);
    session->dest = dest;
    cwmp_log_debug("session connect: dest url is %s, acs url is %s", dest->url, url);
    rv = cwmp_session_create_connection(session);
    if(rv != CWMP_OK)
    {
        return rv;
    }
    cwmp_session_set_headers(session, 0);

    return CWMP_OK;
}

int cwmp_session_set_auth(cwmp_session_t * session, const char * user, const char * pwd)
{
    char buffer[256] = {0};
    TRsnprintf(buffer, 255, "%s:%s", user==NULL?"":user, pwd==NULL?"":pwd);
    //session->dest->auth_type = HTTP_DIGEST_AUTH; // i think don't set auth_type in here
    session->dest->auth.active = CWMP_FALSE;// it's mean had been auth or not
    TRstrncpy(session->dest->user, user, URL_USER_LEN);
    TRstrncpy(session->dest->password, pwd, URL_PWD_LEN);

    return CWMP_OK;
}


int cwmp_session_set_headers(cwmp_session_t * session, int postempty)
{

    return 0;
}


int cwmp_session_create_connection(cwmp_session_t * session)
{

    cwmp_t * cwmp = session->cwmp;
    http_socket_t * sock;
    int use_ssl = 0;
    http_dest_t *  dest = session->dest;
    if(dest)
    {
        if(strncmp(dest->scheme, "https", 5) == 0)
        {
            use_ssl = 1;

        }
    }
    cwmp_log_info("session connect using ssl?(%s)\n", use_ssl==1?"yes":"no");
    int rc = http_socket_create(&sock, AF_INET, SOCK_STREAM, 0, session->connpool);
    if (rc != CWMP_OK)
    {
        cwmp_log_error("session connect: create socket error.");
        return rc;
    }



    cwmp_log_debug("dest host: %s, dest port: %d", session->dest->host, session->dest->port);

    http_socket_set_sendtimeout(sock, 30);

    rc = http_socket_connect(sock, AF_INET, session->dest->host, session->dest->port);
    if(rc != CWMP_OK)
    {
        cwmp_log_alert("connect to ACS faild. Host is %s:%d.", session->dest->host, session->dest->port);
        return rc;
    }
    else
    {
        cwmp_log_alert("***********connect to ACS success***sock:%d*************\n", sock->sockdes);		
	}

    if(use_ssl)
    {
#ifdef USE_CWMP_OPENSSL
        SSL *ssl = openssl_connect(cwmp->ssl_ctx, sock->sockdes);
        if(ssl)
        {
            sock->ssl = ssl;
            sock->use_ssl = 1;
        }
#endif

        //check_cert(ssl,host);
    }


    http_socket_set_writefunction(sock, cwmp_session_write_callback, session);
    if(session->timeout > 0)
    {

        http_socket_set_recvtimeout(sock, session->timeout);
    }

    session->sock = sock;

    return CWMP_OK;

}

header_t * cwmp_session_create_header(cwmp_session_t * session, pool_t * pool)
{

    header_t * header;
    FUNCTION_TRACE();

    header = pool_palloc(pool, sizeof(header_t));
    header->hold_requests = 0;
    header->id = cwmp_session_get_sequence(pool);
    header->no_more_requests = 0;

    strncpy(session->id, header->id, 128);

    return header;
}

device_id_t * cwmp_session_create_inform_device(cwmp_session_t * session, pool_t * pool)
{
    device_id_t * device;

    FUNCTION_TRACE();


    device = pool_palloc(pool, sizeof(device_id_t));	
  device->manufactorer = session->cwmp->cpe_mf;  //cwmp_get_parameter_value(DeviceModule, DeviceInfoModule,ManufacturerModule);    
    device->oui=session->cwmp->cpe_oui; //cwmp_get_parameter_value(DeviceModule, DeviceInfoModule, ManufacturerOUIModule);   
    device->product_class = session->cwmp->cpe_pc; //cwmp_get_parameter_value(DeviceModule, DeviceInfoModule, ProductClassModule);
    device->serial_number = session->cwmp->cpe_sn; //cwmp_get_parameter_value(DeviceModule, DeviceInfoModule, SerialNumberModule);
    device->name = session->cwmp->cpe_name;

    return device;
}

parameter_list_t * cwmp_session_create_inform_parameters(cwmp_session_t * session, pool_t * pool)
{
    parameter_list_t * pl;
    parameter_t * parameter;
	char ip_str[32]= {0};
    char * name;
    char * value;

    FUNCTION_TRACE();
	
    pl = cwmp_create_parameter_list(session->env);
	/*
	name    = CWMP_APPEND_PARAMETER_NAME(pool, 3, DeviceModule, DeviceInfoModule, ManufacturerOUIModule);
	value   = cwmp_data_get_parameter_value(session->cwmp, session->root, name, pool);
	parameter = cwmp_create_parameter(session->env,  name, value, 0, TYPE_STRING);
	cwmp_add_parameter_to_list(session->env,  pl, parameter);

	name    = CWMP_APPEND_PARAMETER_NAME(pool, 3, DeviceModule, DeviceInfoModule, ProductClassModule);
	value   = cwmp_data_get_parameter_value(session->cwmp, session->root, name, pool); 
	parameter = cwmp_create_parameter(session->env,  name, value, 0, TYPE_STRING);
	cwmp_add_parameter_to_list(session->env,  pl, parameter);

	name    = CWMP_APPEND_PARAMETER_NAME(pool, 3, DeviceModule, DeviceInfoModule, SerialNumberModule);
	value   = cwmp_data_get_parameter_value(session->cwmp, session->root, name, pool);
	parameter = cwmp_create_parameter(session->env,  name, value, 0, TYPE_STRING);
	cwmp_add_parameter_to_list(session->env,  pl, parameter);    
	*/
	name    = CWMP_APPEND_PARAMETER_NAME(pool, 3, InternetGatewayDeviceModule, DeviceInfoModule, ManufacturerOUIModule);
	value   = cwmp_data_get_parameter_value(session->cwmp, session->root, name, pool);
	parameter = cwmp_create_parameter(session->env,  name, value, 0, TYPE_STRING);
	cwmp_add_parameter_to_list(session->env,  pl, parameter);

	name    = CWMP_APPEND_PARAMETER_NAME(pool, 3, InternetGatewayDeviceModule, DeviceInfoModule, ProductClassModule);
	value   = cwmp_data_get_parameter_value(session->cwmp, session->root, name, pool); 
	parameter = cwmp_create_parameter(session->env,  name, value, 0, TYPE_STRING);
	cwmp_add_parameter_to_list(session->env,  pl, parameter);

	name    = CWMP_APPEND_PARAMETER_NAME(pool, 3, InternetGatewayDeviceModule, DeviceInfoModule, SerialNumberModule);
	value   = cwmp_data_get_parameter_value(session->cwmp, session->root, name, pool);
	parameter = cwmp_create_parameter(session->env,  name, value, 0, TYPE_STRING);
	cwmp_add_parameter_to_list(session->env,  pl, parameter);    

    name    = CWMP_APPEND_PARAMETER_NAME(pool, 3, InternetGatewayDeviceModule, DeviceInfoModule, HardwareVersionModule);
    value   = cwmp_data_get_parameter_value(session->cwmp, session->root, name, pool);
    parameter = cwmp_create_parameter(session->env,  name, value, 0, TYPE_STRING);
    cwmp_add_parameter_to_list(session->env,  pl, parameter);	
    
    name    = CWMP_APPEND_PARAMETER_NAME(pool, 3, InternetGatewayDeviceModule, DeviceInfoModule, SoftwareVersionModule);
    value   = cwmp_data_get_parameter_value(session->cwmp, session->root, name, pool);
    parameter = cwmp_create_parameter(session->env,  name, value, 0, TYPE_STRING);
    cwmp_add_parameter_to_list(session->env,  pl, parameter);
 
    name    = CWMP_APPEND_PARAMETER_NAME(pool, 3, InternetGatewayDeviceModule, ManagementServerModule, ConnectionRequestURLModule);
    value   = cwmp_data_get_parameter_value(session->cwmp, session->root, name, pool);
    parameter = cwmp_create_parameter(session->env,  name,  value, 0, TYPE_STRING);
    cwmp_add_parameter_to_list(session->env,  pl, parameter);
  
    name    = CWMP_APPEND_PARAMETER_NAME(pool, 3, InternetGatewayDeviceModule, ManagementServerModule, UsernameModule);
    value   = cwmp_data_get_parameter_value(session->cwmp, session->root, name, pool);
    parameter = cwmp_create_parameter(session->env,  name, value, 0, TYPE_STRING);
    cwmp_add_parameter_to_list(session->env,  pl, parameter);

    name    = CWMP_APPEND_PARAMETER_NAME(pool, 3, InternetGatewayDeviceModule, ManagementServerModule, PasswordModule);
    value   = cwmp_data_get_parameter_value(session->cwmp, session->root, name, pool);
    parameter = cwmp_create_parameter(session->env,  name, value, 0, TYPE_STRING);
    cwmp_add_parameter_to_list(session->env,  pl, parameter);

    name    = CWMP_APPEND_PARAMETER_NAME(pool, 3, InternetGatewayDeviceModule, ManagementServerModule, ConnectionRequestUsernameModule);
    value   = cwmp_data_get_parameter_value(session->cwmp, session->root, name, pool);
    parameter = cwmp_create_parameter(session->env,  name, value, 0, TYPE_STRING);
    cwmp_add_parameter_to_list(session->env,  pl, parameter);

    name    = CWMP_APPEND_PARAMETER_NAME(pool, 3, InternetGatewayDeviceModule, ManagementServerModule, ConnectionRequestPasswordModule);
    value   = cwmp_data_get_parameter_value(session->cwmp, session->root, name, pool);
    parameter = cwmp_create_parameter(session->env,  name, value, 0, TYPE_STRING);
    cwmp_add_parameter_to_list(session->env,  pl, parameter);

    name    = CWMP_APPEND_PARAMETER_NAME(pool, 3, InternetGatewayDeviceModule, ManagementServerModule, URLModule);
    value   = session->cwmp->acs_url;//cwmp_data_get_parameter_value(session->cwmp, session->root, name, pool); //for var stop_app , we need to change this 
    parameter = cwmp_create_parameter(session->env,  name, value, 0, TYPE_STRING);
    cwmp_add_parameter_to_list(session->env,  pl, parameter);
     
    name    = CWMP_APPEND_PARAMETER_NAME(pool, 3, InternetGatewayDeviceModule,LANModule,IPAddressModule);
    value   = cwmp_data_get_parameter_value(session->cwmp, session->root, name, pool);   
    parameter = cwmp_create_parameter(session->env,name,value , 0, TYPE_STRING);
    
    cwmp_add_parameter_to_list(session->env,  pl, parameter);
    return pl;

}


event_list_t * cwmp_session_create_inform_events(cwmp_session_t * session, pool_t * pool)
{
    event_list_t * el;
    event_code_t * ev;
    int i=0;

    FUNCTION_TRACE();

    el = cwmp_create_event_list(session->env, INFORM_MAX);


    /*
        while (i<INFORM_MAX)
        {

            if (cwmp_conf_get_int(inf->key) == 1)
            {
                ev = cwmp_create_event_code(session->env);
                ev->event = i;
                ev->code = inf->code;

                ev->command_key = 0;
                if (i == INFORM_MREBOOT || i == INFORM_BOOTSTRAP)
                {
                    ev->command_key = cwmp_conf_pool_get(session->env->pool, inf->command);
                }

                //cwmp_add_event_to_list(pool, el, ev);
                el->events[el->count++] = ev;
                ev = NULL;

            }
            i++;
        }
        */

    if (el->count == 0)
    {
        ev = cwmp_create_event_code(session->env);
        ev->event = 1;
        ev->code = CWMP_INFORM_EVENT_CODE_1;
        el->events[el->count++] = ev;
    }

    return el;
}



datatime_t *cwmp_session_create_inform_datetimes(cwmp_session_t * session, pool_t * pool)
{
    struct tm t;
    time_t tn;
    datatime_t *now;

    //FUNCTION_TRACE();
    tn = time(NULL);
    t = *localtime(&tn);
    now = pool_palloc(pool, sizeof(datatime_t));
    now->year = t.tm_year + 1900;
    now->month = t.tm_mon + 1;
    now->day = t.tm_mday;
    now->hour = t.tm_hour ;
    now->min = t.tm_min;
    now->sec = t.tm_sec;

    return now;
}




xmldoc_t *  cwmp_session_create_inform_message(cwmp_session_t * session, event_list_t * evtlist,  pool_t * pool)
{
    header_t * header;
    device_id_t * device;
    event_list_t * el;
    datatime_t * now_time;
    parameter_list_t * pl;

    FUNCTION_TRACE();
    header  = cwmp_session_create_header(session, pool);
    device  = cwmp_session_create_inform_device(session, pool);
    pl      = cwmp_session_create_inform_parameters(session, pool);
    now_time = cwmp_session_create_inform_datetimes(session, pool);

    return  cwmp_create_inform_message(session->env, header, device, evtlist, now_time, 1, session->retry_count, pl);

}

xmldoc_t *  cwmp_session_create_transfercomplete_message(cwmp_session_t * session, event_code_t * evcode,  pool_t * pool)
{

    header_t * header;
	
    FUNCTION_TRACE();
    header = cwmp_session_create_header(session, pool);    
    return  cwmp_create_transfercomplete_message(session->env, header, session->cwmp);

}


xmldoc_t *  cwmp_session_create_getrpcmethods_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }
    return cwmp_create_getrpcmethods_response_message(session->env, header, rpc_methods, sizeof(rpc_methods)/sizeof(rpc_methods[0]));
}

xmldoc_t *  cwmp_session_create_getparameternames_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv;
    char * path;
    unsigned int next_level;
    unsigned int next_subset;
    parameter_node_t * node;
    fault_code_t fault;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }

    rv = cwmp_parse_getparameternames_message(session->env, doc, &path, &next_level, &fault);

    if (path[strlen(path)-1] == '.')
    {
        next_subset = CWMP_YES;
    }
    else
    {
        next_subset = CWMP_NO;
    }

    node = cwmp_get_parameter_path_node(session->root, path);


    return cwmp_create_getparameternames_response_message(session->env, header, path, node, next_subset, next_level);
}


xmldoc_t *  cwmp_session_create_getparametervalues_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv;
    parameter_list_t * pl;
    fault_code_t fault;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }

    rv = cwmp_parse_getparametervalues_message(session->env, doc, session->root, &pl, &fault);

    return cwmp_create_getparametervalues_response_message(session->env, header, pl);
}


xmldoc_t *  cwmp_session_create_getparameterattributes_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
	header_t * header;
	int rv;
	parameter_list_t * pl;
	fault_code_t fault;
	FUNCTION_TRACE();
	rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
	if (rv != CWMP_OK)
	{
		cwmp_log_error("no header node \n");
	}

	rv = cwmp_parse_getparameterattributes_message(session->env, doc, session->root, &pl, &fault);



	return cwmp_create_getparametervalues_response_message(session->env, header, pl);


}

xmldoc_t *  cwmp_session_create_setparametervalues_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv;
    parameter_list_t * pl;
    fault_code_t fault;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }

    rv = cwmp_parse_setparametervalues_message(session->env, doc, session->root, &pl, &fault);

    if(rv != CWMP_OK)
    {
        return cwmp_create_faultcode_setparametervalues_response_message(session->env, header, pl, &fault);
    }


    return cwmp_create_setparametervalues_response_message(session->env, header, 0);
}

xmldoc_t *  cwmp_session_create_download_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv;
    char * key;
    fault_code_t fault;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }

    download_arg_t * dlarg;

    rv = cwmp_parse_download_message(session->env, doc, &dlarg, &fault);

    //add download arg to taskqueue
    //begin download process

    if(rv == CWMP_OK)
    {
        download_arg_t * newdlarg = cwmp_clone_download_arg(dlarg);
        if(newdlarg != NULL)
        {
            cwmp_t * cwmp = session->cwmp;
            queue_push(cwmp->queue, newdlarg, TASK_DOWNLOAD_TAG);
            cwmp_log_debug("push new download task to queue! url: %s ", newdlarg->url);
        }
    }

    int status = 1;
    return cwmp_create_download_response_message(session->env, header, status);



}

xmldoc_t *  cwmp_session_create_upload_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv;
    char * key;
    fault_code_t fault;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }

    upload_arg_t * uparg;

    rv = cwmp_parse_upload_message(session->env, doc, &uparg, &fault);
    if(rv == CWMP_OK)
    {
        upload_arg_t * newularg = cwmp_clone_upload_arg(uparg);
        if(newularg)
        {
            cwmp_t * cwmp = session->cwmp;
            queue_push(cwmp->queue, newularg, TASK_UPLOAD_TAG);
            cwmp_log_debug("push new upload task to queue! url: %s ", newularg->url);
        }
    }

    int status = 1;
    return cwmp_create_upload_response_message(session->env, header, status);

}



xmldoc_t *  cwmp_session_create_addobject_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv;
    int instances, status;
    fault_code_t fault;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }
    rv = cwmp_parse_addobject_message(session->env, doc, session->root, &instances, &status,  &fault);
    if(rv != CWMP_OK)
    {
        return cwmp_create_faultcode_response_message(session->env, header, &fault);
    }

    return cwmp_create_addobject_response_message(session->env, header, instances, status);
}


xmldoc_t *  cwmp_session_create_deleteobject_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv, status;
    fault_code_t fault;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }

    rv = cwmp_parse_deleteobject_message(session->env, doc, session->root, &status, &fault);

    if(rv != CWMP_OK)
    {
        return cwmp_create_faultcode_response_message(session->env, header, &fault);
    }


    return cwmp_create_deleteobject_response_message(session->env, header, status);
}



xmldoc_t *  cwmp_session_create_reboot_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv;
    char * key;
    fault_code_t fault;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }

    rv = cwmp_parse_reboot_message(session->env, doc, &key, &fault);

    cwmp_t * cwmp = session->cwmp;
    queue_push(cwmp->queue, NULL, TASK_REBOOT_TAG);

    return cwmp_create_reboot_response_message(session->env, header);
}


xmldoc_t *  cwmp_session_create_factoryreset_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv;
    char * key;
    fault_code_t fault;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }

    cwmp_t * cwmp = session->cwmp;
    queue_push(cwmp->queue, NULL, TASK_FACTORYRESET_TAG);

    return cwmp_create_factoryreset_response_message(session->env, header);
}



int cwmp_session_send_request(cwmp_session_t * session)
{

    int rv;
    http_request_t * request;
    FUNCTION_TRACE();
    cwmp_log_debug("session dest url: %s", session->dest->url);

    http_request_create(&request, session->envpool);
    request->dest = session->dest;

    if(!session->dest->auth.active)
    {
		cwmp_log_info("active is false ,no authentication\n");
		auth_action_first_post(session->sock, request);//psost head without body
		rv = cwmp_session_recv_response(session);//recv 401
		if (CWMP_ERROR == rv)
		{
			cwmp_log_error("=====can not to recv 401 mesg correct=====");
			return CWMP_ERROR;
		}
		rv = http_post(session->sock, request, session->writers, session->envpool);//post auth head with inform mesg		
		//if transfer event inform , so  we need go to outside recve state , to wirte respone
		if(session->last_method==CWMP_INFORM_METHOD && transfer == FALSE)
		{
			cwmp_session_recv_response(session);// recv auth ok and cookies
			printf("session->last method\n");
			session->last_method==CWMP_EMPTY_METHOD;
			http_write_head_only(session->sock, request, NULL, session->envpool);//psot auth head with cookies whithout body, nest recv will be 204 or 200 with mesg body
		}
		

		return CWMP_OK;
    }
    else
    {
        cwmp_log_info("Has been authentication\n");
        rv = http_post(session->sock, request, session->writers, session->envpool);
    }
   
    if (rv > 0)
    {
        cwmp_log_debug("#####http_post send ok = 0####\n");
        return CWMP_OK;
    }
    else
    {
        cwmp_log_debug("#####http_post send < 0 ,errno::%d####\n", errno);
        return CWMP_ERROR;
    }

}

int cwmp_session_recv_response(cwmp_session_t * session)
{
    int respcode;
    http_response_t * response;
    char * auth_sting;
    char * cookie;

    cwmp_log_info("-------ok ready to recve and read------\n");
    http_response_memory_create(&response, session->envpool);
    response->readers = session->readers;
    respcode= http_read_response(session->sock, response, session->envpool);
    cwmp_log_debug("=======http_read_response over=====\n");
    session->last_code = response->status;

    if(respcode != HTTP_200)
    {
        cwmp_log_error("http response NOok. return code is %d, status: %d", respcode, response->status);

        if(response->status == 401 ||response->status == 407)
        {
            session->dest->auth.active = CWMP_FALSE;
            auth_sting = http_get_variable(response->parser, "WWW-Authenticate");
            if(auth_sting)
            {
                http_parse_auth_head(auth_sting, &session->dest->auth);
                return CWMP_OK;
            }
        }
        else if (respcode == HTTP_204)
        {
            cwmp_log_info("204 the session goto over");
            return CWMP_ERROR;
        }
        else if(respcode == -1)
        {
        	cwmp_log_error("recv head error");
            cwmp_log_error("other respcode happen:%d",respcode);
            return CWMP_ERROR;
        }

    }
    else if (respcode == HTTP_200)
    {
        session->dest->auth.active = CWMP_TRUE;
		
    }


    if(session->last_method == CWMP_INFORM_METHOD)
    {
        if (session->dest->auth.auth_type == HTTP_DIGEST_AUTH)
        {
            cookie = http_get_variable(response->parser, "Set-Cookie");           
            if(cookie)
            {
            	cwmp_log_info("last_method == CWMP_INFORM_METHOD, set_cookie:%s\n",cookie);
                http_parse_cookie(cookie, session->dest->cookie);
            }
        }
        else if (session->dest->auth.auth_type == HTTP_BASIC_AUTH)
        {
            
            if(nun_cookie == 0)
            {
            	cwmp_log_info("go to parse  set_cookie ");
            	http_parse_basic_cookie(response->parser);
            }
        }

    }

    if(respcode == HTTP_200)
    {
        return CWMP_OK;
    }
    else
    {
        return CWMP_ERROR;
    }

}
