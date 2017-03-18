/************************************************************************
 *                                                                      *
 * Netcwmp/Opencwmp Project                                             *
 * A software client for enabling TR-069 in embedded devices (CPE).     *
 *                                                                      *
 * Copyright (C) 2013-2014  netcwmp.netcwmp group                            *
 *                                                                      *
 * This program is free software; you can redistribute it and/or        *
 * modify it under the terms of the GNU General Public License          *
 * as published by the Free Software Foundation; either version 2       *
 * of the License, or (at your option) any later version.               *
 *                                                                      *
 * This program is distributed in the hope that it will be useful,      *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of       *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        *
 * GNU General Public License for more details.                         *
 *                                                                      *
 * You should have received a copy of the GNU Lesser General Public     *
 * License along with this library; if not, write to the                *
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,          *
 * Boston, MA  02111-1307 USA                                           *
 *                                                                      *
 * Copyright 2013-2014  Mr.x(Mr.x) <netcwmp@gmail.com>          *
 *                                                                      *
 ***********************************************************************/

#include "cwmp_module.h"
#include <cwmp_cfg.h>
//#include <nvram.h>


void cwmp_conf_init(cwmp_t * cwmp)
{
    pool_t * pool;
	//char *cpeInter="br0"
    FUNCTION_TRACE();

    pool = cwmp->pool;
    cwmp->httpd_port =  nv_cwmp_conf_get_int("cpe_http_port");
	cwmp->cpe_interface = nv_cwmp_conf_pool_get(pool, "cpe_interface");;
    cwmp->acs_url  =  nv_cwmp_conf_pool_get(pool,  "ACSURL"); 
    cwmp->acs_user = nv_cwmp_conf_pool_get(pool, "Username");
    cwmp->acs_pwd = nv_cwmp_conf_pool_get(pool, "Password");
	cwmp->cpe_periodic   =  nv_cwmp_conf_get_int("PeriodicInformEnable");
    cwmp->cpe_periodic_time = nv_cwmp_conf_get_int("PeriodicInformInterval");
    cwmp->cpe_user = nv_cwmp_conf_pool_get(pool, "ConnectionRequestUsername");
    cwmp->cpe_pwd  = nv_cwmp_conf_pool_get(pool,  "ConnectionRequestPassword");  
	
	cwmp->cpe_mf	 =	nv_cwmp_conf_pool_get(pool, "Manufacturer");
	cwmp->cpe_oui	 =	nv_cwmp_conf_pool_get(pool, "ManufacturerOUI");
	cwmp->cpe_name =	nv_cwmp_conf_pool_get(pool, "ModelName");
	cwmp->cpe_sn	 =	nv_cwmp_conf_pool_get(pool, "SerialNum"); 
	cwmp->cpe_pc	 =	nv_cwmp_conf_pool_get(pool, "ProductClass");
	
	cwmp->cpe_hv = nv_cwmp_conf_pool_get(pool, "HardwareVersion");
	cwmp->cpe_sv = nv_cwmp_conf_pool_get(pool,  "SoftwareVersion");
	
	char local_ip[64] ={0};
    rut_get_ip(cwmp->cpe_interface, local_ip);
    cwmp_log_info("%s <<<local_ip:%s>>>>", __FUNCTION__,local_ip);
    cwmp->local_ip = TRstrdup(local_ip);
    //cwmp->local_ip =  nv_cwmp_conf_pool_get(pool, RT2860_NVRAM, "lan_ipaddr");
    cwmp->event_filename = nv_cwmp_conf_pool_get(pool, "event_filename");
    
    cwmp_log_debug("url:%s\nmf:%s\noui:%s\nsn:%s\nname:%s\npc:%s\nhttpd port:%d\n",
    cwmp->acs_url, cwmp->cpe_mf, cwmp->cpe_oui, cwmp->cpe_sn, cwmp->cpe_name, cwmp->cpe_pc,cwmp->httpd_port);


}

