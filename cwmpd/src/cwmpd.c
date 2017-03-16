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

#include "cwmpd.h"

#define CWMP_VALUE_UNSET -1
#define CWMP_CONFIG 	"/etc_ro/cwmp.conf"
#define DATA_MODLE_FILE  "/etc_ro/device.xml"

#if 0	//0 printf log to stdout; 1 save log to file
#define CWMP_LOG_FILE "/var/log/cwmpd.log"
#else
#define CWMP_LOG_FILE  NULL
#endif
int              cwmp_argc;
char           **cwmp_argv;

static pool_t * cwmp_global_pool;
char local_ip[32] = {0};

void cwmp_daemon(int foreground)
{
	pid_t pid, sid;
	if (foreground) 
	{
		pid = fork();
		if (pid < 0)
			exit(EXIT_FAILURE);
		if (pid > 0)
			exit(EXIT_SUCCESS);

		sid = setsid();
		if (sid < 0) {
			cwmp_log_info("setsid() returned error\n");
			exit(EXIT_FAILURE);
		}

		char *directory = "/";

		if ((chdir(directory)) < 0) {
			cwmp_log_info("chdir() returned error\n");
			exit(EXIT_FAILURE);
		}
	}
}

void cwmp_getopt(int argc, char **argv)
{
    
}

static int cwmp_save_argv( int argc, char *const *argv)
{
    cwmp_argv = (char **) argv;
    cwmp_argc = argc;

    return 0;
}


int cwmp_set_var(cwmp_t * cwmp)
{
    FUNCTION_TRACE();
    cwmp_bzero(cwmp, sizeof(cwmp_t));
    // the first post request because of this
    cwmp->new_request = CWMP_TRUE;
    pool_t * pool = pool_create(POOL_DEFAULT_SIZE);
    cwmp->pool = pool;
    cwmp_event_init(cwmp);
    cwmp->queue = queue_create(pool);

    return CWMP_OK;
}




#ifdef USE_CWMP_OPENSSL
void cwmp_init_ssl(cwmp_t * cwmp)
{
    char * cafile = cwmp_conf_pool_get(cwmp_global_pool, "cwmp:ca_file");
    char * capasswd = cwmp_conf_pool_get(cwmp_global_pool, "cwmp:ca_password");   
    cwmp->ssl_ctx = openssl_initialize_ctx(cafile, capasswd);
}
#endif




int main(int argc, char *argv[])
{
    cwmp_pid_t pid;
    cwmp_t * cwmp;	
    int syslog_enable = 0;
    int cwmp_enable = 0;

    pid = getpid();
	cwmp_log_init(CWMP_LOG_FILE, CWMP_LOG_DEBUG);    
    cwmp_global_pool = pool_create(POOL_DEFAULT_SIZE);
    cwmp = pool_palloc(cwmp_global_pool, sizeof(cwmp_t));

    cwmp_conf_open(CWMP_CONFIG);    
	
    cwmp_set_var(cwmp);
    cwmp_daemon(1);    
    cwmp_conf_init(cwmp);

	if (argc >1)
	{		
		cwmp->acs_url = argv[1];		
	}
	
#ifdef USE_CWMP_OPENSSL
    cwmp_init_ssl(cwmp);
#endif

    cwmp_model_load(cwmp, DATA_MODLE_FILE);    
	cwmp_worker_thread_start(cwmp);
	cwmp_log_error("the end tr069 process !!!");
    return 0;
}



