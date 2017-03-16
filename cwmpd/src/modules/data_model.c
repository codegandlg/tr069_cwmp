#include "cwmp_model.h"
#include "data_model.h"
#include "cwmp_module.h"
#include "InternetGatewayDevice.c"



model_func_t ModelFunction[] =
{		/*data_model get/set fun name, 				the real fun we create	*/


    {"cpe_get_igd_di_manufacturer", cpe_get_igd_di_manufacturer},
    {"cpe_get_igd_di_manufactureroui", cpe_get_igd_di_manufactureroui},
    {"cpe_get_igd_di_productclass", cpe_get_igd_di_productclass},
    {"cpe_get_igd_di_serialnumber", cpe_get_igd_di_serialnumber},
    {"cpe_get_igd_di_specversion", cpe_get_igd_di_specversion},
    {"cpe_get_igd_di_provisioningcode",cpe_get_igd_di_provisioningcode},
    {"cpe_get_igd_di_hardwareversion", cpe_get_igd_di_hardwareversion},
    {"cpe_get_igd_di_softwareversion", cpe_get_igd_di_softwareversion},
    {"cpe_set_igd_di_softwareversion", cpe_set_igd_di_softwareversion},  

	{"cpe_get_igd_gwmanufactureroui", cpe_get_igd_gwmanufactureroui},
    {"cpe_get_igd_gwproductclass", cpe_get_igd_gwproductclass},    
	{"cpe_get_igd_gwserialnumber", cpe_get_igd_gwserialnumber},
	

    {"cpe_get_igd_ms_connectionrequesturl", cpe_get_igd_ms_connectionrequesturl},
    {"cpe_get_dev_ms_connectionrequestusername", cpe_get_dev_ms_connectionrequestusername},
    {"cpe_set_dev_ms_connectionrequestusername", cpe_set_dev_ms_connectionrequestusername},
    {"cpe_get_dev_ms_connectionrequestpassword", cpe_get_dev_ms_connectionrequestpassword},
    {"cpe_set_dev_ms_connectionrequestpassword", cpe_set_dev_ms_connectionrequestpassword},
    {"cpe_get_dev_periodicEnable", cpe_get_dev_periodicEnable},
    {"cpe_set_dev_periodicEnable", cpe_set_dev_periodicEnable},
    {"cpe_get_dev_periodicInterval", cpe_get_dev_periodicInterval},
    {"cpe_set_dev_periodicInterval", cpe_set_dev_periodicInterval},
    {"cpe_get_dev_ms_username", cpe_get_dev_ms_username},
    {"cpe_set_dev_ms_username", cpe_set_dev_ms_username},
    {"cpe_get_dev_ms_password", cpe_get_dev_ms_password},
    {"cpe_set_dev_ms_password", cpe_set_dev_ms_password},
    {"cpe_get_dev_ms_url", cpe_get_dev_ms_url},
    {"cpe_set_dev_ms_url", cpe_set_dev_ms_url},

  /*for Devide WLAN settings(2.4G)*/	
     /* Device wireless basic settings page*/
    {"getWlanBasicEnable" ,getWlanBasicEnable},
    {"setWlanBasicEnable" ,setWlanBasicEnable},
    {"getWlanBasicAdvertisementEnabled", getWlanBasicAdvertisementEnabled},
    {"setWlanBasicAdvertisementEnabled", setWlanBasicAdvertisementEnabled},
    {"getWlanBasicSSID", getWlanBasicSSID},
    {"setWlanBasicSSID", setWlanBasicSSID},
    {"getWlanBasicMode", getWlanBasicMode},
    {"setWlanBasicMode", setWlanBasicMode},
    {"getWlanBasicChannel" , getWlanBasicChannel}, 
    {"setWlanBasicChannel" , setWlanBasicChannel},
    {"getWlanBasicBandWidth",getWlanBasicBandWidth},
    {"setWlanBasicBandWidth",setWlanBasicBandWidth},
    {"getWlanBasicGuardInterval",getWlanBasicGuardInterval },
    {"setWlanBasicGuardInterval",setWlanBasicGuardInterval },
    {"getWlanBasicChannelMode", getWlanBasicChannelMode},
    {"setWlanBasicChannelMode", setWlanBasicChannelMode},
     /* Device wireless security settings page*/
    {"getWlanSecurityAuthMode",getWlanSecurityAuthMode}, 
    {"setWlanSecurityAuthMode",setWlanSecurityAuthMode},
    {"getWlanSecurityEncrypType",getWlanSecurityEncrypType },
    {"setWlanSecurityEncrypType",setWlanSecurityEncrypType },
    {"getWlanSecurityWPAPSK", getWlanSecurityWPAPSK},
    {"setWlanSecurityWPAPSK", setWlanSecurityWPAPSK},
    /* Device MAC Filter  settings page*/
    {"getWlanMacFilterPolicy",getWlanMacFilterPolicy },
    {"setWlanMacFilterPolicy",setWlanMacFilterPolicy },
    {"getWlanMacControlList", getWlanMacControlList},
    {"setWlanMacControlList", setWlanMacControlList},
     /* Device WPS*/
    {"getWlanSecurityWPSEnable",getWlanSecurityWPSEnable },
    {"setWlanSecurityWPSEnable",setWlanSecurityWPSEnable },
    {"getWlanSecurityWPSPw", getWlanSecurityWPSPw},
    {"setWlanSecurityWPSPw", setWlanSecurityWPSPw},
  
 /*for Devide WLAN settings(5G)*/	
     /* Device wireless basic settings page*/
    {"getWlanBasicEnable5G" ,getWlanBasicEnable5G},   
    {"setWlanBasicEnable5G" ,setWlanBasicEnable5G},
    {"getWlanBasicAdvertisementEnabled5G", getWlanBasicAdvertisementEnabled5G},
    {"setWlanBasicAdvertisementEnabled5G", setWlanBasicAdvertisementEnabled5G},
    {"getWlanBasicSSID5G", getWlanBasicSSID5G},
    {"setWlanBasicSSID5G", setWlanBasicSSID5G},
    {"getWlanBasicMode5G", getWlanBasicMode5G},
    {"setWlanBasicMode5G", setWlanBasicMode5G},
    {"getWlanBasicChannel5G" , getWlanBasicChannel5G}, 
    {"setWlanBasicChannel5G" , setWlanBasicChannel5G},
    {"getWlanBasicBandWidth5G",getWlanBasicBandWidth5G},
    {"setWlanBasicBandWidth5G",setWlanBasicBandWidth5G},
    {"getWlanBasicGuardInterval5G",getWlanBasicGuardInterval5G },
    {"setWlanBasicGuardInterval5G",setWlanBasicGuardInterval5G },
    {"getWlanBasicChannelMode5G", getWlanBasicChannelMode5G},
    {"setWlanBasicChannelMode5G", setWlanBasicChannelMode5G},
     /* Device wireless security settings page*/
    {"getWlanSecurityAuthMode5G",getWlanSecurityAuthMode5G}, 
    {"setWlanSecurityAuthMode5G",setWlanSecurityAuthMode5G},
    {"getWlanSecurityEncrypType5G",getWlanSecurityEncrypType5G },
    {"setWlanSecurityEncrypType5G",setWlanSecurityEncrypType5G },
    {"getWlanSecurityWPAPSK5G", getWlanSecurityWPAPSK5G},
    {"setWlanSecurityWPAPSK5G", setWlanSecurityWPAPSK5G},
    /* Device MAC Filter  settings page*/
    {"getWlanMacFilterPolicy5G",getWlanMacFilterPolicy5G },
    {"setWlanMacFilterPolicy5G",setWlanMacFilterPolicy5G },
    {"getWlanMacControlList5G", getWlanMacControlList5G},
    {"setWlanMacControlList5G", setWlanMacControlList5G},
     /* Device WPS*/
    {"getWlanSecurityWPSEnable5G",getWlanSecurityWPSEnable5G },
    {"setWlanSecurityWPSEnable5G",setWlanSecurityWPSEnable5G },
    {"getWlanSecurityWPSPw5G", getWlanSecurityWPSPw5G},
    {"setWlanSecurityWPSPw5G", setWlanSecurityWPSPw5G},
	
	
  /*for gateway WLAN settings*/	
    {"get_gw_enable", get_gw_enable},
    {"set_gw_enable", set_gw_enable},
    {"get_gw_ssid", get_gw_ssid},
    {"set_gw_ssid", set_gw_ssid},
    {"get_gw_BSSID", get_gw_BSSID},  
    {"get_gw_SSIDAdvertisementEnabled", get_gw_SSIDAdvertisementEnabled},
    {"set_gw_SSIDAdvertisementEnabled", set_gw_SSIDAdvertisementEnabled},
    {"get_gw_AuthMode", get_gw_AuthMode},
    {"set_gw_AuthMode", set_gw_AuthMode},
    {"get_gw_EncrypMode", get_gw_EncrypMode},
    {"set_gw_EncrypMode", set_gw_EncrypMode},
    {"get_gw_WEPKeyIndex", get_gw_WEPKeyIndex},
    {"set_gw_WEPKeyIndex", set_gw_WEPKeyIndex},
    {"get_gw_channel", get_gw_channel},
    {"set_gw_channel", set_gw_channel},  
    {"get_gw_wpa_auth_mode",get_gw_wpa_auth_mode},
    {"set_gw_wpa_auth_mode",set_gw_wpa_auth_mode},
    {"get_gw_wpa_encryp_mode",get_gw_wpa_encryp_mode},
    {"set_gw_wpa_encryp_mode",set_gw_wpa_encryp_mode},
    {"get_gw_passphrase",get_gw_passphrase},
    {"get_gw_passphrase",get_gw_passphrase},  
    {"get_gw_connection_status", get_gw_connection_status},
		
    {"cpe_refresh_igd_wandevice", cpe_refresh_igd_wandevice},
    {"cpe_refresh_igd_wanconnectiondevice", cpe_refresh_igd_wanconnectiondevice},
    {"cpe_refresh_igd_wanipconnection", cpe_refresh_igd_wanipconnection},

    {"get_IP_address" ,get_IP_address},
    {"set_IP_address" ,set_IP_address},
    {"get_SubnetMask" ,get_SubnetMask},
    {"set_SubnetMask" ,set_SubnetMask}, 
	
};

int get_index_after_paramname(parameter_node_t * param, const char * tag_name)
{
    parameter_node_t * parent;
    parameter_node_t * tmp;
    for(parent=param->parent, tmp = param; parent; tmp = parent, parent = parent->parent)
    {
        if(TRstrcmp(parent->name, tag_name) == 0)
        {
             if(is_digit(tmp->name) == 0)
             {
                return TRatoi(tmp->name);   
             }
        }        
    }
    return -1;
}


void cwmp_model_load(cwmp_t * cwmp, const char * xmlfile)
{  

    cwmp_model_load_xml(cwmp, xmlfile, ModelFunction, sizeof(ModelFunction)/sizeof(model_func_t));
}


