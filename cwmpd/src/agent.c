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
#include "cwmp_agent.h"
#include <cwmp_session.h>
#include "modules/data_model.h"
//#include <nvram.h>

#define CWMP_TRUE   1
extern BOOL transfer;

#define MAX_SESSION_RETRY 3
/*this for periodic signal , that it's can start a neww session*/
int periodic_signal = 0;
/*before set periodic_signal var , it's need session_ing is no or periodic_signal can not be set */
int session_ing = 0;
BOOL stop_app = FALSE; //this is for stop app, TURE will exit while ,


enum
{
    CWMP_ST_START = 0,
    CWMP_ST_INFORM,
    CWMP_ST_SEND,
    CWMP_ST_RESEMD,
    CWMP_ST_RECV,
    CWMP_ST_ANSLYSE,
    CWMP_ST_RETRY,
    CWMP_ST_END,
    CWMP_ST_EXIT
};





int cwmp_agent_retry_session(cwmp_session_t * session)
{

    int sec = 0;

    srand(time(NULL));
    switch (session->retry_count)
    {
        case 0:
        {
            sec = 5 + rand()%5; //5~10
            break;
        }
        case 1:
        {
            sec = 5 + rand()%10; //5~15
            break;
        }
        case 2:
        {
            sec = 5 + rand()%20; //5~25
            break;
        }
        default:
        {
            sec = 5 + rand()%30; //5~35
            break;
        }
    }

    while (sec>0)
    {
        sleep(1);
        sec--;
    }

    if (session->retry_count > MAX_SESSION_RETRY)
    {
        session->retry_count = 0;
        return CWMP_TIMEOUT;
    }
    else
    {
        session->retry_count ++;
        return CWMP_OK;
    }

}


int cwmp_agent_create_datetimes(datatime_t *nowtime)
{
    struct tm t;
    time_t tn;


    //FUNCTION_TRACE();
    tn = time(NULL);
    t = *localtime(&tn);


    nowtime->year = t.tm_year + 1900;
    nowtime->month = t.tm_mon + 1;
    nowtime->day = t.tm_mday;
    nowtime->hour = t.tm_hour;
    nowtime->min = t.tm_min;
    nowtime->sec = t.tm_sec;

    return CWMP_OK;
}



//取得active event以及count
int cwmp_agent_get_active_event(cwmp_t *cwmp, cwmp_session_t * session,  event_list_t **pevent_list)
{
    event_list_t * event_list;
    event_code_t * ev;
    int i=0;
    FUNCTION_TRACE();
    int elsize = cwmp->el->count;
    event_list = cwmp_create_event_list(session->env, elsize);

    event_code_t ** pec = cwmp->el->events;
    printf("elsize:%d", elsize);

    for(i=0; i<elsize; i++)
    {

        if(pec[i]  && pec[i]->ref > 0)
        {

            event_code_t * ec = pec[i];
            ev = cwmp_create_event_code(session->env);
            ev->event = ec->event;
            ev->code = ec->code;
            cwmp_log_info("get_active_event :%d",ec->event);
            //if (pec[i]->event == INFORM_MREBOOT || pec[i]->event == INFORM_BOOTSTRAP)
            {
                strcpy(ev->command_key , ec->command_key);
            }


            event_list->events[event_list->count++] = ev;
            ev = NULL;

        }
    }
    /* dont need , when no event  ,boot event will add
    if (event_list->count == 0)
    {
        ev = cwmp_create_event_code(session->env);
        ev->event = INFORM_BOOT;
        ev->code = CWMP_INFORM_EVENT_CODE_1;
        event_list->events[event_list->count++] = ev;
    }
    */

    *pevent_list = event_list;

    return CWMP_OK;



}




int cwmp_agent_send_request(cwmp_session_t * session)
{
    FUNCTION_TRACE();
    return cwmp_session_send_request(session);
}

int cwmp_agent_recv_response(cwmp_session_t * session)
{
    return cwmp_session_recv_response(session);
}

void cwmp_agent_start_session(cwmp_t * cwmp)
{
    int rv;
    cwmp_session_t * session;
    int session_close = CWMP_NO;
    xmldoc_t * newdoc;
    time_t timep;
    FUNCTION_TRACE();
    event_list_t  *evtlist;
    unsigned int session_times = 0;
    static int PeriodicInformEnable=CWMP_YES;	
    while (!stop_app)/**大循环。不会退出*/
    {
        PeriodicInformEnable=nv_cwmp_conf_get_int("PeriodicInformEnable");
        /*new_request为真是执行小循环的条件*/
        if ((PeriodicInformEnable==CWMP_NO)||(cwmp->new_request == CWMP_NO && periodic_signal == CWMP_NO ))
        {
            //cwmp_log_debug("Wait for new_request to true");            
            sleep(2);
            continue;
        } 
        session_ing = CWMP_YES;
        cwmp_log_debug("----->New session connect to ACS<------\n");
        cwmp->new_request = CWMP_NO;		
		
        session = cwmp_session_create(cwmp);//here to first set session->status to START        
        session_close  = CWMP_NO;
        session->timeout = nv_cwmp_conf_get_int("cpe_http_timeout");
        //cwmp_session_set_timeout(cwmp_conf_get_int("cwmpd:http_timeout"));
        cwmp_log_debug("session timeout is %d", session->timeout);
        cwmp_session_open(session);

        while (!session_close)
        {
            //cwmp_log_debug("session status: %d", session->status);
            switch (session->status)
            {
                case CWMP_ST_START:// value 0; first set form cwmp_session_create fun
                    //create a new connection to acs
                    cwmp_log_debug("session stutus: New START\n");
                    if (cwmp_session_connect(session, cwmp->acs_url) != CWMP_OK)
                    {
                        cwmp_log_error("connect to acs: %s failed.\n", cwmp->acs_url);
                        session->status = CWMP_ST_RETRY;
                    }
                    else
                    {
                        session->status = CWMP_ST_INFORM;
                    }
                    break;
                case CWMP_ST_INFORM:
                    evtlist = NULL;
                    cwmp_log_debug("session stutus: INFORM\n");
                    if(periodic_signal ==1)
                    {
                        cwmp_log_debug("add PERIODIC event");
                        cwmp_event_set_value(cwmp, INFORM_PERIODIC, 1, "periodic", 0, 0, 0);
                    }
                    cwmp_agent_get_active_event(cwmp, session,  & evtlist);             
                    cwmp_session_set_auth(session,   cwmp->acs_user  , cwmp->acs_pwd );
                    newdoc = cwmp_session_create_inform_message(session, evtlist, session->envpool);
                    //session->writers that we need to send data
                    cwmp_write_xmldoc_to_chunk(newdoc, session->writers,  session->envpool);

                    session->last_method = CWMP_INFORM_METHOD;
                    session->status = CWMP_ST_SEND;
                    break;

                case CWMP_ST_SEND:

                    cwmp_log_debug("session stutus: SEND");
                    cwmp_log_debug("session data request length: %d", cwmp_chunk_length(session->writers));
                    session->newdata = CWMP_NO;     /*进入了发送阶段，newdata将被发送出去，状态改变*/

                    rv = cwmp_agent_send_request(session);
                    if (rv == CWMP_OK)
                    {
                        cwmp_log_debug("session data sended OK, rv=%d", rv);
                        session->status = CWMP_ST_RECV; /*状态改变为发送后等待接收返回信息*/
                    }
                    else
                    {
                        cwmp_log_debug("session data sended faild! rv=%d", rv);
                        session->status = CWMP_ST_EXIT;
                    }

                    break;

                case CWMP_ST_RECV:
                    cwmp_log_debug("session stutus: RECV");
                    cwmp_chunk_clear(session->readers);
                    rv = cwmp_agent_recv_response(session);
                    if (rv == CWMP_OK)
                    {
                        session->status = CWMP_ST_ANSLYSE;/*成功接收到了response消息后，状态改为解析状态*/
                    }
                    else
                    {
                        session->status = CWMP_ST_END;  /*是败转变为执行task状态*/
                    }
                    break;

                case CWMP_ST_ANSLYSE:
                    cwmp_log_debug("session stutus: ANSLYSE");
                    rv = cwmp_agent_analyse_session(session);
                    if (rv == CWMP_OK)
                    {
                        session->status = CWMP_ST_SEND; /*成功解析并创建了回复报文，之后又转为发送状态*/
                    }
                    else
                    {
                        session->status = CWMP_ST_END;
                    }
                    break;
                case CWMP_ST_RETRY:
                    cwmp_log_debug("session stutus: RETRY");
                    /*产生随机等待时间，并设置retry_count值*/
                    if (cwmp_agent_retry_session(session) == CWMP_TIMEOUT)
                    {
                        cwmp_log_debug("session retry timeover, go out");
                        session->status = CWMP_ST_EXIT;     /*连接ACS超时,退出*/
                    }
                    else
                    {
                        session->status = CWMP_ST_START;    /*设置retry_count之后，状态转为重新开始*/
                    }
                    break;
                case CWMP_ST_END:
                    //close connection of ACS
                    cwmp_log_debug("in stat CWMP_ST_END, session->newdata:%s", session->newdata?("yes"):("no"));                   
					
                    if (session->newdata == CWMP_YES)
                    {
                        session->status = CWMP_ST_SEND;
                    }
                    else
                    {
                        session->status = CWMP_ST_EXIT;
                    }
                    break;

                case CWMP_ST_EXIT:
                    cwmp_log_debug("session stutus: EXIT");
                    if(evtlist != NULL)
                    {
                        cwmp_event_clear_active(cwmp);
                    } 
					
                    cwmp_session_close(session);
                    if (session->reconnect == CWMP_YES)
                    {
                        session->reconnect = CWMP_NO;
                        session->status = CWMP_ST_START;
                        break;
                    }
                    session_close = CWMP_YES;       /*关闭session状态循环*/
                    break;

                default:
                    cwmp_log_debug("Unknown session stutus");
                    break;
            }//end switch



        }//end while(!session_close)

        cwmp_log_debug("session stutus: EXIT");
        cwmp_session_free(session); /*释放这个session的资源*/
        session = NULL;
       
        //to do tasks after close the session that ing.
        int newtaskres = cwmp_agent_run_tasks(cwmp);
        if(newtaskres == CWMP_YES)
        {
            cwmp->new_request = CWMP_YES;
        }

		
		time (&timep);
		if (session_times == (unsigned int)(0-1))//max value
		{
			session_times = 0;
		}
		cwmp_log_info("=====>>> NO: %u Date:%s", session_times++, ctime(&timep));
		//this for periodic ,mean that there session is over
		//put the flags end, so  when tast doing , periodic inform can not to set
        session_ing = CWMP_NO;
        periodic_signal = CWMP_NO;
        
    }//end while(TRUE)

}


int cwmp_agent_analyse_session(cwmp_session_t * session)
{
    pool_t * doctmppool  = NULL;
    char * xmlbuf;
    cwmp_uint32_t len;
    xmldoc_t *  doc;
    char * method;
    xmldoc_t *   newdoc = NULL;
    int rc;

    static char * xml_fault = "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:cwmp=\"urn:dslforum-org:cwmp-1-0\" xmlns=\"urn:dslforum-org:cwmp-1-0\"><SOAP-ENV:Body SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"  id=\"_0\"><SOAP-ENV:Fault>Error Message</SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>";

    cwmp_uint32_t msglength = cwmp_chunk_length(session->readers);
    if (msglength<= 0)
    {
        session->newdata = CWMP_NO;
        cwmp_log_debug("analyse receive length is 0");

        goto eventcheck;
    }

    doctmppool = pool_create(POOL_DEFAULT_SIZE);

    xmlbuf = pool_palloc(doctmppool, msglength+32);

    len = sprintf(xmlbuf,"<cwmp>");
    cwmp_chunk_copy(xmlbuf + len, session->readers, msglength);
    strcpy(xmlbuf+len+msglength, "</cwmp>");
    //cwmp_log_debug("agent analyse xml: \n%s", xmlbuf);
    doc = XmlParseBuffer(doctmppool, xmlbuf);
    if (!doc)
    {
        cwmp_log_debug("analyse create doc null\n");
        cwmp_chunk_write_string(session->writers, xml_fault, TRstrlen(xml_fault), session->envpool);
        goto finished;
    }

    method = cwmp_get_rpc_method_name(doc);
    cwmp_log_debug("analyse method is: %s\n", method);
    cwmp_chunk_clear(session->writers);
    pool_clear(session->envpool);


    if (TRstrcmp(method, CWMP_RPC_GETRPCMETHODS) == 0)/*GetRPCMethods */
    {
        newdoc = cwmp_session_create_getrpcmethods_response_message(session, doc, doctmppool);
    }
    else if (TRstrcmp(method, CWMP_RPC_INFORMRESPONSE) == 0)/*InformResponse */
    {
        //TODO: TransferComplete post if last_method == CWMP_DOWNLOAD_METHOD/upload     
       	if (transfer == TRUE)
        {
            //after infrom TransferComplete event over, then recve informresponse, then post TransferComplete saop mesg                   
            newdoc = cwmp_session_create_transfercomplete_message(session, doc, doctmppool);
            transfer = FALSE;
        }
        session->last_method = CWMP_INFORMRESPONSE_METHOD;
    }
    else if (TRstrcmp(method, CWMP_RPC_GETPARAMETERNAMES) == 0)/*GetParameterNames*/
    {
        session->last_method = CWMP_GETPARAMETERNAMES_METHOD;
        newdoc = cwmp_session_create_getparameternames_response_message(session, doc, doctmppool);
    }
    else if (TRstrcmp(method, CWMP_RPC_GETPARAMETERVALUES) == 0)/*GetParameterValues*/
    {
        session->last_method = CWMP_GETPARAMETERVALUES_METHOD;
        newdoc = cwmp_session_create_getparametervalues_response_message(session, doc, doctmppool);
    }
    else if (TRstrcmp(method, CWMP_RPC_GETPARAMETEATTIRBUTE) == 0)/*GetParameterAttributes*/
    {
        newdoc = cwmp_session_create_getparameterattributes_response_message(session, doc, doctmppool);
        cwmp_log_debug("unsupport now");
    }
    else if (TRstrcmp(method, CWMP_RPC_SETPARAMETERVALUES) == 0)/*SetParameterValues*/
    {
        //session->last_method = CWMP_SETPARAMETERVALUES_METHOD;
        newdoc = cwmp_session_create_setparametervalues_response_message(session, doc, doctmppool);
    }
    else if (TRstrcmp(method, CWMP_RPC_DOWNLOAD) == 0)/*Download*/
    {
        session->last_method = CWMP_DOWNLOAD_METHOD;
        newdoc = cwmp_session_create_download_response_message(session, doc, doctmppool);
    }
    else if (TRstrcmp(method, CWMP_RPC_UPLOAD) == 0)/*Upload*/
    {
        newdoc = cwmp_session_create_upload_response_message(session, doc, doctmppool);
    }
    else if (TRstrcmp(method, CWMP_RPC_TRANSFERCOMPLETERESPONSE) == 0)/*TransferCompleteResponse*/
    {
        //here , when we recve the mesg ,we need not to respone		
        newdoc = NULL;
    }
    else if (TRstrcmp(method, CWMP_RPC_REBOOT) == 0)/*reboot*/
    {
        newdoc = cwmp_session_create_reboot_response_message(session, doc, doctmppool);
    }
    else if (TRstrcmp(method, CWMP_RPC_ADDOBJECT) == 0)/*addobject*/
    {
        newdoc = cwmp_session_create_addobject_response_message(session, doc, doctmppool);
    }
    else if (TRstrcmp(method, CWMP_RPC_DELETEOBJECT) == 0)/*delete object*/
    {
        newdoc = cwmp_session_create_deleteobject_response_message(session, doc, doctmppool);
    }

    else if (TRstrcmp(method, CWMP_RPC_FACTORYRESET) == 0)/*factory reset*/
    {
        newdoc = cwmp_session_create_factoryreset_response_message(session, doc, doctmppool);
    }
    else
    {
        //check event queue
        //newdoc = cwmp_session_create_event_response_message(session, doc, doctmppool);
        cwmp_log_debug("analyse method is no support!!!!!");
    }


    cwmp_t * cwmp = session->cwmp;
    if(newdoc == NULL)
    {
        cwmp_log_debug("agent analyse newdoc is null. ");

    eventcheck:
        {

            cwmp_log_debug("agent analyse begin check global event, %d", cwmp->event_global.event_flag);
          
            //check global event for transfercomplete
            if(cwmp->event_global.event_flag & EVENT_REBOOT_TRANSFERCOMPLETE_FLAG)
            {
                cwmp->event_global.event_flag &=  ~EVENT_REBOOT_TRANSFERCOMPLETE_FLAG;
                if(!doctmppool)
                {
                    doctmppool = pool_create(POOL_DEFAULT_SIZE);
                }
                event_code_t ec;
                ec.event = INFORM_TRANSFERCOMPLETE;
                TRstrncpy(ec.command_key, cwmp->event_global.event_key, COMMAND_KEY_LEN);
                ec.fault_code = cwmp->event_global.fault_code;
                ec.start = cwmp->event_global.start;
                ec.end = cwmp->event_global.end;
                newdoc = cwmp_session_create_transfercomplete_message(session, &ec, doctmppool);

            }


        }

    }


    cwmp_log_debug("newdoc %p, msglength: %d", newdoc, msglength );
    if((newdoc != NULL) /*|| (newdoc == NULL && msglength != 0)*/) // || (newdoc == NULL && msglength == 0 && session->retry_count < 2))
    {
        session->newdata = CWMP_YES;
        cwmp_write_xmldoc_to_chunk(newdoc, session->writers,  session->envpool);
        rc = CWMP_OK;
    }
    else
    {
        rc = CWMP_ERROR;
    }

finished:
    if(doctmppool  != NULL)
    {
        pool_destroy(doctmppool);
    }

    return rc;
}


void periodic_inform()
{
    // to set a global var
    //cwmp_log_info("cpe_periodic set");
    if (session_ing == CWMP_NO)
    {
        printf("success set periodic\n");
        periodic_signal = 1;
    }
    else
    {
        printf("there is a session in. can not to set periodic");
        periodic_signal = 0;
    }
}
int periodic_time(int interval)
{
	pthread_detach(pthread_self());
    // Get system call result to determine successful or failed
    int res = 0;
    // Register printMsg to SIGALRM
    signal(SIGALRM,  periodic_inform);
    cwmp_log_debug("periodic time:%d(s)", interval);
    struct itimerval tick;
    // Initialize struct
    memset(&tick, 0, sizeof(tick));
    // Timeout to run function first time
    tick.it_value.tv_sec = 3;  // sec
    tick.it_value.tv_usec = 0; // micro sec.
    // Interval time to run function
    tick.it_interval.tv_sec = interval;
    tick.it_interval.tv_usec = 0;
    // Set timer, ITIMER_REAL : real-time to decrease timer,
    //                          send SIGALRM when timeout
    res = setitimer(ITIMER_REAL, &tick, NULL);
    if (res)
    {
        printf("Set timer failed!!\n");
    }
    // Always sleep to catch SIGALRM signal
    while(!stop_app)
    {
        pause();
    }

    return 0;
}


static void print_param(parameter_node_t * param, int level)
{
    if(!param) return;

    parameter_node_t * child;
    char fmt[64];
    //cwmp_log_debug("name: %s, type: %s, level: %d\n", param->name, cwmp_get_type_string(param->type), level);
    int i=0;
    sprintf(fmt, "|%%-%ds%%s,  get:%%p set:%%p refresh:%%p", level*4);

    //cwmp_log_debug(fmt, "----", param->name, param->get, param->set, param->refresh);
    child = param->child;

    if(!child)
        return;
    print_param(child, level+1);
    parameter_node_t * next = child->next_sibling;

    while(next)
    {
        print_param(next, level+1);
        next = next->next_sibling;
    }

}




void cwmp_agent_session(cwmp_t * cwmp)
{
    char name[1024] = {0};
    char value[124]= {0};

    char * envstr;
    char * encstr;

    envstr = "SOAP-ENV"; //cwmp_conf_get("cwmp:soap_env");
    encstr = "SOAP-ENC"; // cwmp_conf_get("cwmp:soap_enc");

    cwmp_set_envelope_ns(envstr, encstr);    

    print_param(cwmp->root, 0);
	/*下面设置节点值是为了上报 inform， 非必须上报节点无需在这里设置value*/
    //CWMP_SPRINTF_PARAMETER_NAME(name, 3, DeviceModule, ManagementServerModule, URLModule);
    //cwmp_data_set_parameter_value(cwmp, cwmp->root, name, cwmp->acs_url, TRstrlen(cwmp->acs_url), cwmp->pool);////here will user set_fun, for var stop_app , we need to change this 

    CWMP_SPRINTF_PARAMETER_NAME(name, 3, DeviceModule, ManagementServerModule, UsernameModule);
	cwmp_data_set_parameter_value(cwmp, cwmp->root, name, cwmp->acs_user, TRstrlen(cwmp->gw_sn), cwmp->pool);

	CWMP_SPRINTF_PARAMETER_NAME(name, 3, DeviceModule, ManagementServerModule, PasswordModule);
	cwmp_data_set_parameter_value(cwmp, cwmp->root, name, cwmp->acs_pwd, TRstrlen(cwmp->gw_sn), cwmp->pool);

	CWMP_SPRINTF_PARAMETER_NAME(name, 3, DeviceModule, ManagementServerModule, ConnectionRequestURLModule);   
    cwmp_data_set_parameter_value(cwmp, cwmp->root, name, cwmp->local_ip, TRstrlen(cwmp->local_ip), cwmp->pool);
	 
	CWMP_SPRINTF_PARAMETER_NAME(name, 3, DeviceModule, ManagementServerModule, ConnectionRequestUsernameModule);
	cwmp_data_set_parameter_value(cwmp, cwmp->root, name, cwmp->cpe_user, TRstrlen(cwmp->gw_sn), cwmp->pool);

	CWMP_SPRINTF_PARAMETER_NAME(name, 3, DeviceModule, ManagementServerModule, ConnectionRequestPasswordModule);
	cwmp_data_set_parameter_value(cwmp, cwmp->root, name, cwmp->cpe_pwd, TRstrlen(cwmp->gw_sn), cwmp->pool);
    
    //InternetGatewayDevice.DeviceInfo.{i}
    CWMP_SPRINTF_PARAMETER_NAME(name, 3, DeviceModule, DeviceInfoModule, ManufacturerModule);
    cwmp_data_set_parameter_value(cwmp, cwmp->root, name, cwmp->cpe_mf, TRstrlen(cwmp->cpe_mf), cwmp->pool);

    CWMP_SPRINTF_PARAMETER_NAME(name, 3, DeviceModule, DeviceInfoModule, ManufacturerOUIModule);
    cwmp_data_set_parameter_value(cwmp, cwmp->root, name, cwmp->cpe_oui, TRstrlen(cwmp->cpe_oui), cwmp->pool);

    CWMP_SPRINTF_PARAMETER_NAME(name, 3, DeviceModule, DeviceInfoModule, ProductClassModule);
    cwmp_data_set_parameter_value(cwmp, cwmp->root, name, cwmp->cpe_pc, TRstrlen(cwmp->cpe_pc), cwmp->pool);

    CWMP_SPRINTF_PARAMETER_NAME(name, 3, DeviceModule, DeviceInfoModule, SerialNumberModule);
    cwmp_data_set_parameter_value(cwmp, cwmp->root, name, cwmp->cpe_sn, TRstrlen(cwmp->cpe_sn), cwmp->pool);
    
    CWMP_SPRINTF_PARAMETER_NAME(name, 3, DeviceModule, GatewayInfoModule, ManufacturerOUIModule);
    cwmp_data_set_parameter_value(cwmp, cwmp->root, name, cwmp->gw_oui, TRstrlen(cwmp->gw_oui), cwmp->pool);

    CWMP_SPRINTF_PARAMETER_NAME(name, 3, DeviceModule, GatewayInfoModule, ProductClassModule);
    cwmp_data_set_parameter_value(cwmp, cwmp->root, name, cwmp->gw_pc, TRstrlen(cwmp->gw_pc), cwmp->pool);

    CWMP_SPRINTF_PARAMETER_NAME(name, 3, DeviceModule, GatewayInfoModule, SerialNumberModule);
    cwmp_data_set_parameter_value(cwmp, cwmp->root, name, cwmp->gw_sn, TRstrlen(cwmp->gw_sn), cwmp->pool);	

    CWMP_SPRINTF_PARAMETER_NAME(name, 3, DeviceModule,LANModule,IPAddressModule);
    cwmp_data_set_parameter_value(cwmp, cwmp->root, name, cwmp->local_ip, TRstrlen(cwmp->local_ip), cwmp->pool);

    cwmp_agent_start_session(cwmp);

}



int cwmp_agent_download_file(download_arg_t * dlarg)
{
    int faultcode = 0;
    char * fromurl = dlarg->url;
    //char * tofile = "/tmp/download.img";
   

    if(dlarg->url && TRstrncasecmp("ftp://", dlarg->url, 6) == 0)
    {
        cwmp_log_info("ftp no support");
        return 9013;
    }

    faultcode = http_receive_file(fromurl, dlarg);
    if(faultcode != CWMP_OK)
    {
        faultcode = 9010;
    }

    return faultcode;
}



int cwmp_agent_upload_file(upload_arg_t * ularg)
{
    int faultcode = 0;
    FUNCTION_TRACE();
    char * fromfile;

    if(strcmp(ularg->filetype, "1 Vendor Configuration File") == 0)
    {
        //根据实际情况, 修改这里的配置文件路径

        fromfile = "/tmp/mysystem.cfg";
    }
    else if(strcmp(ularg->filetype, "2 Vendor Log File") == 0)
    {
        //根据实际情况, 修改这里的配置文件路径
        fromfile = "/tmp/mysystem.log";
    }
    else
    {
    	printf("not support file type\n");
        fromfile = "/tmp/mysystem.cfg";
    }

    faultcode = http_send_file(fromfile, ularg);
    if(faultcode != CWMP_OK)
    {
        faultcode = 9011;
    }

    return faultcode;
}



int cwmp_agent_run_tasks(cwmp_t * cwmp)
{
    void * data;
    int tasktype = 0;;
    int ok = CWMP_NO;

    FUNCTION_TRACE();

    while(1)
    {
        tasktype = queue_pop(cwmp->queue, &data);
        if(tasktype == -1)
        {
            cwmp_log_debug("no more task to run");
            break;
        }

        ok = CWMP_YES;
        switch(tasktype)
        {
            case TASK_DOWNLOAD_TAG:
            {
                download_arg_t * dlarg = (download_arg_t*)data;
                //begin download file
                time_t starttime ;
                time(&starttime);
                int faultcode = 0;
                faultcode = cwmp_agent_download_file(dlarg);
                time_t endtime ;
                time(&endtime);                
                cwmp_event_set_value(cwmp, INFORM_TRANSFERCOMPLETE, 1,dlarg->cmdkey, faultcode, starttime, endtime);
                cwmp_event_set_value(cwmp, INFORM_MDOWNLOAD, 1,dlarg->cmdkey, faultcode, starttime, endtime);
                FREE(dlarg);
            }
            break;

            case TASK_UPLOAD_TAG:
            {
                upload_arg_t * ularg = (upload_arg_t*)data;
                //begin download file
                time_t starttime ;
                time(&starttime);
                int faultcode = 0;
                faultcode = cwmp_agent_upload_file(ularg);
                time_t endtime ;
                time(&endtime);
                cwmp_event_set_value(cwmp, INFORM_TRANSFERCOMPLETE, 1,ularg->cmdkey, faultcode, starttime, endtime);
                cwmp_event_set_value(cwmp, INFORM_MUPLOAD, 1,ularg->cmdkey, faultcode, starttime, endtime);
                FREE(ularg);
            }
            break;

            case TASK_REBOOT_TAG:
            {
                //begin reboot system
                cwmp_log_debug("reboot ...");
                cwmp_event_set_value(cwmp, INFORM_MREBOOT, 1, NULL, 0, 0, 0);
                cwmp_event_clear_active(cwmp);
                system("reboot");
            }
            break;

            case TASK_FACTORYRESET_TAG:
            {
                //begin factory reset system
                cwmp_log_debug("factory reset ...");
                cwmp_event_clear_active(cwmp);
                //system("factoryreset");
               	system("ralink_init clear 2860");
                system("ralink_init clear rtdev");
                system("ralink_init renew 2860 /etc_ro/default.cfg");
                system("ralink_init renew rtdev /etc_ro/default5g.cfg");
                sleep(1);
                system("reboot");
            }
            break;

            default:

                break;

        }
    }

    return ok;
}


