//#include <nvram.h>



int cpe_get_igd_gwmanufactureroui(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
	FUNCTION_TRACE();
	*value = nv_cwmp_conf_pool_get(pool,  "GatewayOui");
	//cwmp_log_debug("cpe_get_igd_di_manufacturer: value is %s", *value);
	return	FAULT_CODE_OK;
}

int cpe_get_igd_gwproductclass(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
	FUNCTION_TRACE();
	*value = nv_cwmp_conf_pool_get(pool,  "GatewayProductClass");
	//cwmp_log_debug("cpe_get_igd_di_manufacturer: value is %s", *value);
	return	FAULT_CODE_OK;
}

int cpe_get_igd_gwserialnumber(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
	FUNCTION_TRACE();
	*value = nv_cwmp_conf_pool_get(pool,  "GatewaySerialNum");
	//cwmp_log_debug("cpe_get_igd_di_manufacturer: value is %s", *value);
	return	FAULT_CODE_OK;
}


//InternetGatewayDevice.DeviceInfo.Manufacturer
int cpe_get_igd_di_manufacturer(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    FUNCTION_TRACE();
    *value = nv_cwmp_conf_pool_get(pool,  "DeviceManufacturer");
    //cwmp_log_debug("cpe_get_igd_di_manufacturer: value is %s", *value);
    return	FAULT_CODE_OK;
}

//InternetGatewayDevice.DeviceInfo.ManufacturerOUI
int cpe_get_igd_di_manufactureroui(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    FUNCTION_TRACE();
    *value = nv_cwmp_conf_pool_get(pool,  "DeviceOui");
    return	FAULT_CODE_OK;
}

//InternetGatewayDevice.DeviceInfo.ProductClass
int cpe_get_igd_di_productclass(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    FUNCTION_TRACE();
    *value = nv_cwmp_conf_pool_get(pool,  "DeviceProductClass");
    return	FAULT_CODE_OK;
}

//InternetGatewayDevice.DeviceInfo.SerialNumber
int cpe_get_igd_di_serialnumber(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
	FUNCTION_TRACE();
    *value = nv_cwmp_conf_pool_get(pool,  "DeviceSerialNum");
    return	FAULT_CODE_OK;
}

//InternetGatewayDevice.DeviceInfo.SpecVersion
int cpe_get_igd_di_specversion(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
	FUNCTION_TRACE();
    *value = nv_cwmp_conf_pool_get(pool,  "Specversion");
    return	FAULT_CODE_OK;
}

//InternetGatewayDevice.DeviceInfo.HardwareVersion
int cpe_get_igd_di_hardwareversion(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
	FUNCTION_TRACE();
    *value = nv_cwmp_conf_pool_get(pool,  "Hardwareversion");
    return	FAULT_CODE_OK;
}

//InternetGatewayDevice.DeviceInfo.SoftwareVersion
int cpe_get_igd_di_softwareversion(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
	FUNCTION_TRACE();
    *value = nv_cwmp_conf_pool_get(pool,  "SoftwareVersion");
    return	FAULT_CODE_OK;
}
//InternetGatewayDevice.DeviceInfo.SoftwareVersion
//add for test set 
int cpe_set_igd_di_softwareversion(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{
	FUNCTION_TRACE();
    nv_cwmp_conf_set( "SoftwareVersion", value);
    return	FAULT_CODE_OK;
}

//InternetGatewayDevice.DeviceInfo.ProvisioningCode
int cpe_get_igd_di_provisioningcode(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
	FUNCTION_TRACE();
    *value = nv_cwmp_conf_pool_get(pool,  "ProvisioningCode");
    return	FAULT_CODE_OK;
}



int cpe_get_mac_2_4(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
	
	return FAULT_CODE_OK;
}

int cpe_get_mac_client_2_4(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{

	return FAULT_CODE_OK;
}
int cpe_get_mac_5_0(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{

	return FAULT_CODE_OK;
}

int cpe_get_mac_client_5_0(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{

	return FAULT_CODE_OK;
}

int cpe_get_BuildData(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
	
	return FAULT_CODE_OK;
}







