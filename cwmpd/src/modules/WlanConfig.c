/*************************************************************************
	> File Name: WlanConfig.c
	> Author: yungen
	> Mail: deng.yun.gen@aztech.com 
	> Created Time: Thu 16 Oct 2014 02:52:16 PM CST
 ************************************************************************/
 /**************************************Device wiless parameters***********************************************************/
 /***Wireless Basic Setting page***/
int getWlanBasicEnable(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "RadioOff");	//WLANConfiguration.{i}.Enable
    return FAULT_CODE_OK;
}
int setWlanBasicEnable(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set(  "RadioOff", value); //WLANConfiguration.{i}.Enable
    return FAULT_CODE_OK;
}
int getWlanBasicEnable5G(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "RadioOff");	//WLANConfiguration.{i}.Enable
    return FAULT_CODE_OK;
}
int setWlanBasicEnable5G(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set( "RadioOff", value);	//WLANConfiguration.{i}.Enable
    return FAULT_CODE_OK;
}
   

int getWlanBasicAdvertisementEnabled(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "HideSSID");	//WLANConfiguration.{i}.SSIDAdvertisementEnabled
    return FAULT_CODE_OK;
}
int setWlanBasicAdvertisementEnabled(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set( "HideSSID", value);	//WLANConfiguration.{i}.SSIDAdvertisementEnabled
    return FAULT_CODE_OK;
}
int getWlanBasicAdvertisementEnabled5G(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "HideSSID");	//WLANConfiguration.{i}.SSIDAdvertisementEnabled
    return FAULT_CODE_OK;
}
int setWlanBasicAdvertisementEnabled5G(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set( "HideSSID", value);	//WLANConfiguration.{i}.SSIDAdvertisementEnabled
    return FAULT_CODE_OK;
}


//InternetGatewayDevice.LANDevice.WLANConfiguration.SSID
int getWlanBasicSSID(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "SSID1");		//WLANConfiguration.{i}.SSID
    return FAULT_CODE_OK;
}
int setWlanBasicSSID(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
   nv_cwmp_conf_set( "SSID1", value);		//WLANConfiguration.{i}.SSID
    return FAULT_CODE_OK;
}
int getWlanBasicSSID5G(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "SSID1");	//WLANConfiguration.{i}.SSID
    return FAULT_CODE_OK;
}
int setWlanBasicSSID5G(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set( "SSID1", value);	//WLANConfiguration.{i}.SSID
     return FAULT_CODE_OK;
}

int getWlanBasicMode(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "WirelessMode");	//WLANConfiguration.{i}.Standard
    return FAULT_CODE_OK;
}
int setWlanBasicMode(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set( "WirelessMode", value);	//WLANConfiguration.{i}.Standard
    return FAULT_CODE_OK;
}
int getWlanBasicMode5G(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "WirelessMode");	//WLANConfiguration.{i}.Standard
    return FAULT_CODE_OK;
}
int setWlanBasicMode5G(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set( "WirelessMode", value);	//WLANConfiguration.{i}.Standard
    return FAULT_CODE_OK;
}

int getWlanBasicChannel(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "Channel");	//WLANConfiguration.{i}.Channel
    return FAULT_CODE_OK;
}
int setWlanBasicChannel(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set( "Channel", value);	//WLANConfiguration.{i}.Channel
    return FAULT_CODE_OK;
}
int getWlanBasicChannel5G(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "Channel");	//WLANConfiguration.{i}.Channel
    return FAULT_CODE_OK;
}
int setWlanBasicChannel5G(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set( "Channel", value);	//WLANConfiguration.{i}.Channel
    return FAULT_CODE_OK;
}

int getWlanBasicBandWidth(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "HT_BW");	//WLANConfiguration.{i}.ChannelBandwidth
    return FAULT_CODE_OK;
}
int setWlanBasicBandWidth(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set( "HT_BW", value);	//WLANConfiguration.{i}.ChannelBandwidth
    return FAULT_CODE_OK;
}
int getWlanBasicBandWidth5G(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "HT_BW");		//WLANConfiguration.{i}.ChannelBandwidth
    return FAULT_CODE_OK;
}
int setWlanBasicBandWidth5G(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set( "HT_BW", value);		//WLANConfiguration.{i}.ChannelBandwidth
    return FAULT_CODE_OK;
}

int getWlanBasicGuardInterval(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "HT_GI");		//WLANConfiguration.{i}.GuardInterval
    return FAULT_CODE_OK;
}
int setWlanBasicGuardInterval(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set( "HT_GI", value);		//WLANConfiguration.{i}.GuardInterval
    return FAULT_CODE_OK;
}
int getWlanBasicGuardInterval5G(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "HT_GI");	//WLANConfiguration.{i}.GuardInterval
    return FAULT_CODE_OK;
}
int setWlanBasicGuardInterval5G(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set( "HT_GI", value);	//WLANConfiguration.{i}.GuardInterval
    return FAULT_CODE_OK;
}

int getWlanBasicChannelMode(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "HT_40MHZ_INTOLERANT");	//WLANConfiguration.{i}.ChannelMode
    return FAULT_CODE_OK;
}
int setWlanBasicChannelMode(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set( "HT_40MHZ_INTOLERANT", value);	//WLANConfiguration.{i}.ChannelMode
    return FAULT_CODE_OK;
}
int getWlanBasicChannelMode5G(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "HT_40MHZ_INTOLERANT");	//WLANConfiguration.{i}.ChannelMode
    return FAULT_CODE_OK;
}
int setWlanBasicChannelMode5G(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set( "HT_40MHZ_INTOLERANT", value);	//WLANConfiguration.{i}.ChannelMode
    return FAULT_CODE_OK;
}



/***Wireless Security Setting page***/
int getWlanSecurityAuthMode(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "AuthMode");	//WLANConfiguration.{i}.WPAEncryptionModes
    return FAULT_CODE_OK;
}
int setWlanSecurityAuthMode(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set( "AuthMode", value);	//WLANConfiguration.{i}.WPAEncryptionModes
    return FAULT_CODE_OK;
}
int getWlanSecurityAuthMode5G(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
   *value = nv_cwmp_conf_pool_get(pool, "AuthMode");	//WLANConfiguration.{i}.WPAEncryptionModes
    return FAULT_CODE_OK;
}
int setWlanSecurityAuthMode5G(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
   nv_cwmp_conf_set( "AuthMode", value);	//WLANConfiguration.{i}.WPAEncryptionModes
    return FAULT_CODE_OK;
}

int getWlanSecurityEncrypType(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "EncrypType");		//WLANConfiguration.{i}.KeyPassphrase
    return FAULT_CODE_OK;
}
int setWlanSecurityEncrypType(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set( "EncrypType", value);		//WLANConfiguration.{i}.KeyPassphrase
    return FAULT_CODE_OK;
}
int getWlanSecurityEncrypType5G(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
   *value = nv_cwmp_conf_pool_get(pool, "EncrypType");	//WLANConfiguration.{i}.KeyPassphrase
    return FAULT_CODE_OK;
}
int setWlanSecurityEncrypType5G(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
   nv_cwmp_conf_set( "EncrypType", value);	//WLANConfiguration.{i}.KeyPassphrase
    return FAULT_CODE_OK;
}

int getWlanSecurityWPAPSK(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "WPAPSK1");	//WLANConfiguration.{i}.KeyPassphrase
    return FAULT_CODE_OK;
}
int setWlanSecurityWPAPSK(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set( "WPAPSK1", value);	//WLANConfiguration.{i}.KeyPassphrase
     nv_cwmp_conf_set( "WPATEMPPSK", value);	//replace  default WPATEMPPSK value with new value
    return FAULT_CODE_OK;
}
int getWlanSecurityWPAPSK5G(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
   *value = nv_cwmp_conf_pool_get(pool, "WPAPSK1");	//WLANConfiguration.{i}.KeyPassphrase
    return FAULT_CODE_OK;
}
int setWlanSecurityWPAPSK5G(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
   nv_cwmp_conf_set( "WPAPSK1", value);	//WLANConfiguration.{i}.KeyPassphrase
   nv_cwmp_conf_set( "WPATEMPPSK", value);	//replace default  WPATEMPPSK value with new value
    return FAULT_CODE_OK;
}


int getWlanSecurityWPSEnable(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "WscModeOption");		//WLANConfiguration.{i}.WPS.Enable
    return FAULT_CODE_OK;
}
int setWlanSecurityWPSEnable(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set( "WscModeOption", value);		//WLANConfiguration.{i}.WPS.Enable
    return FAULT_CODE_OK;
}
int getWlanSecurityWPSEnable5G(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
   *value = nv_cwmp_conf_pool_get(pool, "WscModeOption");	//WLANConfiguration.{i}.WPS.Enable
    return FAULT_CODE_OK;
}
int setWlanSecurityWPSEnable5G(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
   nv_cwmp_conf_set( "WscModeOption", value);	//WLANConfiguration.{i}.WPS.Enable
    return FAULT_CODE_OK;
}

int getWlanSecurityWPSPw(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "WscPinCode");	//WLANConfiguration.{i}.WPS.DevicePassword
    return FAULT_CODE_OK;
}
int setWlanSecurityWPSPw(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set( "WscPinCode", value);	//WLANConfiguration.{i}.WPS.DevicePassword
    return FAULT_CODE_OK;
}
int getWlanSecurityWPSPw5G(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
   *value = nv_cwmp_conf_pool_get(pool, "WscPinCode");	//WLANConfiguration.{i}.WPS.DevicePassword
    return FAULT_CODE_OK;
}
int setWlanSecurityWPSPw5G(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
   nv_cwmp_conf_set( "WscPinCode", value);	//WLANConfiguration.{i}.WPS.DevicePassword
    return FAULT_CODE_OK;
}

/***Wireless MAC Filter Settings page***/
int getWlanMacFilterPolicy(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "AccessPolicy0");	//WLANConfiguration.{i}.MACAddressControlEnabled
    return FAULT_CODE_OK;
}
int setWlanMacFilterPolicy(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
    nv_cwmp_conf_set( "AccessPolicy0", value);	//WLANConfiguration.{i}.MACAddressControlEnabled
    return FAULT_CODE_OK;
}
int getWlanMacFilterPolicy5G(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
   *value = nv_cwmp_conf_pool_get(pool, "AccessPolicy0");		//WLANConfiguration.{i}.MACAddressControlEnabled
    return FAULT_CODE_OK;
}
int setWlanMacFilterPolicy5G(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
   nv_cwmp_conf_set( "AccessPolicy0", value);		//WLANConfiguration.{i}.MACAddressControlEnabled
    return FAULT_CODE_OK;
}
 
int getWlanMacControlList(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
    *value = nv_cwmp_conf_pool_get(pool, "AccessControlList0");		//WLANConfiguration.{i}.AssociatedDeviceMACAddress
    return FAULT_CODE_OK;
}
int setWlanMacControlList(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{     
    nv_cwmp_conf_set( "AccessControlList0", value);		//WLANConfiguration.{i}.AssociatedDeviceMACAddress
}
int getWlanMacControlList5G(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
   *value = nv_cwmp_conf_pool_get(pool, "AccessControlList0");	//WLANConfiguration.{i}.AssociatedDeviceMACAddress
    return FAULT_CODE_OK;
}
int setWlanMacControlList5G(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{    
   nv_cwmp_conf_set( "AccessControlList0", value);	//WLANConfiguration.{i}.AssociatedDeviceMACAddress
   return FAULT_CODE_OK;
}


/**************************************Gatewy wiless parameters***********************************************************/
//InternetGatewayDevice.LANDevice.WLANConfiguration.Enable
int get_gw_enable(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
	  *value = nv_cwmp_conf_pool_get(pool, "ApCliEnable");// 0==on 1== off
    return FAULT_CODE_OK;
}

int set_gw_enable(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{
	//if set this key 1, the wifi will off , and newwork will stop
	nv_cwmp_conf_set(  "ApCliEnable", value);
    return FAULT_CODE_OK;
}

int get_gw_SSIDAdvertisementEnabled(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
	  *value = nv_cwmp_conf_pool_get(pool, "HideSSID");//
    return FAULT_CODE_OK;
}

int set_gw_SSIDAdvertisementEnabled(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{	
	nv_cwmp_conf_set(  "HideSSID", value);
    return FAULT_CODE_OK;
}

int get_gw_AuthMode(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
	  *value = nv_cwmp_conf_pool_get(pool, "AuthMode");//
    return FAULT_CODE_OK;
}

int set_gw_AuthMode(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{	
	nv_cwmp_conf_set(  "AuthMode", value);
    return FAULT_CODE_OK;
}

int get_gw_EncrypMode(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
	  *value = nv_cwmp_conf_pool_get(pool, "EncrypType");//
    return FAULT_CODE_OK;
}

int set_gw_EncrypMode(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{	
	nv_cwmp_conf_set(  "EncrypType", value);
    return FAULT_CODE_OK;
}

int get_gw_wpa_auth_mode(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
	  *value = nv_cwmp_conf_pool_get(pool, "ApCliAuthMode");//
    return FAULT_CODE_OK;
}

int set_gw_wpa_auth_mode(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{	
	nv_cwmp_conf_set(  "ApCliAuthMode", value); 
    return FAULT_CODE_OK;
}

//InternetGatewayDevice.LANDevice.WLANConfiguration.WPAEncryptionModes
int get_gw_wpa_encryp_mode(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
	  *value = nv_cwmp_conf_pool_get(pool, "ApCliEncrypType");
    return FAULT_CODE_OK;
}
int set_gw_wpa_encryp_mode(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{	
	nv_cwmp_conf_set(  "ApCliEncrypType", value);
    return FAULT_CODE_OK;  
}

int get_gw_WEPKeyIndex(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
	  *value = nv_cwmp_conf_pool_get(pool, "ApCliDefaultKeyId");//
    return FAULT_CODE_OK;
}

int set_gw_WEPKeyIndex(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{	
	nv_cwmp_conf_set(  "ApCliDefaultKeyId", value);
    return FAULT_CODE_OK;
}


//InternetGatewayDevice.LANDevice.WLANConfiguration.SSID
int get_gw_ssid(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
	  *value = nv_cwmp_conf_pool_get(pool, "ApCliSsid");//
    return FAULT_CODE_OK;
}

int set_gw_ssid(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{	
	nv_cwmp_conf_set(  "ApCliSsid", value);
	sleep(1);
	return FAULT_CODE_OK;
}

//InternetGatewayDevice.LANDevice.WLANConfiguration.SSID
int get_gw_BSSID(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
	  *value = nv_cwmp_conf_pool_get(pool, "ApCliBssid");//
    return FAULT_CODE_OK;
}




//InternetGatewayDevice.LANDevice.WLANConfiguration.Channel
int get_gw_channel(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
	  *value = nv_cwmp_conf_pool_get(pool, "Channel");
    return FAULT_CODE_OK;
}

int set_gw_channel(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{	
	nv_cwmp_conf_set(  "Channel", value);
    return FAULT_CODE_OK;
}


//InternetGatewayDevice.LANDevice.WLANConfiguration.KeyPassphrase
int get_gw_passphrase(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
	  *value = nv_cwmp_conf_pool_get(pool, "ApCliWPAPSK"); 
    return FAULT_CODE_OK;
}
int set_gw_passphrase(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{	
	nv_cwmp_conf_set(  "ApCliWPAPSK", value);
    return FAULT_CODE_OK;
}

//InternetGatewayDevice.LANDevice.WLANConfiguration.Status
int get_gw_connection_status(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{    
	*value = nv_cwmp_conf_pool_get(pool, "ConnectionStatus");	
      return FAULT_CODE_OK;
}
