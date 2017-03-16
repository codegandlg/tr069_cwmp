//#include <nvram.h>
extern BOOL stop_app ;
//InternetGatewayDevice.ManagementServer.ConnectionRequestURL
int cpe_get_igd_ms_connectionrequesturl(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    char buf[256]={0};
    //char local_ip[32]={0};
    //cpe_get_localip("br0", local_ip);
    char * local_ip = NULL;
    local_ip = nv_cwmp_conf_pool_get(pool,   "lan_ipaddr");
    cwmp_log_info("FUN:%s, loacl_ip get :%s", __FUNCTION__, local_ip);
    int port = nv_cwmp_conf_get_int(  "cpe_http_port");
    snprintf(buf, 256, "http://%s:%d", local_ip, port);
    *value = PSTRDUP(buf);
    return FAULT_CODE_OK;
}

//InternetGatewayDevice.ManagementServer.ConnectionRequestUsername
int cpe_get_dev_ms_connectionrequestusername(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    *value = nv_cwmp_conf_pool_get(pool, "ConnectionRequestUsername");
    return FAULT_CODE_OK;
}
int cpe_set_dev_ms_connectionrequestusername(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{
	nv_cwmp_conf_set(   "ConnectionRequestUsername", value);	
	return FAULT_CODE_OK;
}


//InternetGatewayDevice.ManagementServer.ConnectionRequestPassword
int cpe_get_dev_ms_connectionrequestpassword(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool,  "ConnectionRequestPassword");
    return FAULT_CODE_OK;
}
int cpe_set_dev_ms_connectionrequestpassword(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{
	nv_cwmp_conf_set(   "ConnectionRequestPassword", value);	
	return FAULT_CODE_OK;
}


//InternetGatewayDevice.ManagementServer.PeriodicInformEnable
int cpe_get_dev_periodicEnable(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
	*value = nv_cwmp_conf_pool_get(pool,   "PeriodicInformEnable");
    return FAULT_CODE_OK;
}

int cpe_set_dev_periodicEnable(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{
	nv_cwmp_conf_set(   "PeriodicInformEnable", value);	
	cwmp->cpe_periodic = atoi(value);
    return FAULT_CODE_OK;
}

int cpe_get_dev_periodicInterval(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    *value = nv_cwmp_conf_pool_get(pool,   "PeriodicInformInterval");
    return FAULT_CODE_OK;
}
int cpe_set_dev_periodicInterval(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{

    nv_cwmp_conf_set(   "PeriodicInformInterval", value);
    cwmp->cpe_periodic_time = atoi(value);//实时跟新到内存中
    printf("cpe_periodic_time:%d\n", cwmp->cpe_periodic_time);
    cwmp_log_debug("to set stop_app ture");
	stop_app = TRUE;
    return FAULT_CODE_OK;
}
//InternetGatewayDevice.ManagementServer.Username
int cpe_get_dev_ms_username(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    *value = nv_cwmp_conf_pool_get(pool,   "ACSUsername");
    return FAULT_CODE_OK;
}
int cpe_set_dev_ms_username(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{
	nv_cwmp_conf_set(   "ACSUsername", value);
	return FAULT_CODE_OK;
}

//InternetGatewayDevice.ManagementServer.Password
int cpe_get_dev_ms_password(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    *value = nv_cwmp_conf_pool_get(pool,   "ACSPassword");
    return FAULT_CODE_OK;
}
int cpe_set_dev_ms_password(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{
	nv_cwmp_conf_set(   "ACSPassword", value);
	return FAULT_CODE_OK;

}

//InternetGatewayDevice.ManagementServer.URL
int cpe_get_dev_ms_url(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    *value = nv_cwmp_conf_pool_get(pool,   "ACSURL");
    return FAULT_CODE_OK;
}
int cpe_set_dev_ms_url(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{
	nv_cwmp_conf_set(   "ACSURL", value);
	//for this action , we need to reboot tr069 processs
	cwmp_log_debug("to set stop_app ture");
	stop_app = TRUE;
	return FAULT_CODE_OK;

}

int get_IP_address(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    *value = nv_cwmp_conf_pool_get(pool,   "lan_ipaddr");
    return FAULT_CODE_OK;
}
int set_IP_address(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{
	nv_cwmp_conf_set(   "lan_ipaddr", value);
	return FAULT_CODE_OK;
}

/*subnetMask node func*/
int get_SubnetMask(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    *value = nv_cwmp_conf_pool_get(pool,   "lan_netmask");
    return FAULT_CODE_OK;
}
int set_SubnetMask(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{
	nv_cwmp_conf_set(   "lan_netmask", value);
	return FAULT_CODE_OK;
}

