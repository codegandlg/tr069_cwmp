/************************************************************************
 * Id: cfg.c                                                            *
 *                                                                      *
 * TR069 Project:  A TR069 library in C                                 *
 * Copyright (C) 2013-2014  netcwmp.netcwmp group                                *
 *                                                                      *
 *                                                                      *
 * Email: netcwmp ( & ) gmail dot com                                *
 *                                                                      *
 ***********************************************************************/

#include <cwmp_cwmp.h>
#include <cwmp_pool.h>
#include <cwmp_log.h>
#include <cwmp_cfg.h>
#include <ini.h>
#include <stdlib.h>
#include <stdio.h>

/* The NVRAM version number stored as an NVRAM variable */
#define NVRAM_SOFTWARE_VERSION	"1"
#define NVRAM_MAGIC		0x48534C46	/* 'FLSH' */
#define NVRAM_CLEAR_MAGIC	0x0
#define NVRAM_INVALID_MAGIC	0xFFFFFFFF
#define NVRAM_VERSION		1
#define NVRAM_HEADER_SIZE	20
#define NVRAM_SPACE		0x8000
#define NVRAM_MAX_VALUE_LEN 255
#define NVRAM_MAX_PARAM_LEN 64
#define NVRAM_CRC_START_POSITION	9 /* magic, len, crc8 to be skipped */
#define NVRAM_CRC_VER_MASK	0xffffff00 /* for crc_ver_init */
#define MAP_FAILED	((void *) -1)

#define PROT_READ	0x1		/* Page can be read.  */
#define PROT_WRITE	0x2		/* Page can be written.  */
#define PROT_EXEC	0x4		/* Page can be executed.  */
#define PROT_NONE	0x0		/* Page can not be accessed.  */

/* Sharing types (must choose one and only one of these).  */
#define MAP_SHARED	0x01		/* Share changes.  */
#define MAP_PRIVATE	0x02		/* Changes are private.  */

#define PATH_DEV_NVRAM "/dev/nvram"

/* Globals */
static int nvram_fd = -1;
static char *nvram_buf = NULL;
char *cwmp_get_key_value(const char *name);


int cwmp_nvram_init(void *unused)
{
	if (nvram_fd >= 0)
		return 0;

	if ((nvram_fd = open(PATH_DEV_NVRAM, O_RDWR)) < 0)
		goto err;

	/* Map kernel string buffer into user space */
	if ((nvram_buf = mmap(NULL, NVRAM_SPACE, PROT_READ, MAP_SHARED, nvram_fd, 0)) == MAP_FAILED) {
		close(nvram_fd);
		nvram_fd = -1;
		goto err;
	}

	return 0;

 err:
	perror(PATH_DEV_NVRAM);
	return errno;
}

char *cwmp_get_key_value(const char *name)
{
	size_t count = strlen(name) + 1;
	char tmp[100], *value;
	unsigned long *off = (unsigned long *) tmp;

	if (cwmp_nvram_init(NULL))
		{
		return NULL;
		}
	if (count > sizeof(tmp)) {
		if (!(off = malloc(count)))
			return NULL;
	}

	/* Get offset into mmap() space */
	strcpy((char *) off, name);

	count = read(nvram_fd, off, count);

	if (count == sizeof(unsigned long))
		{
		value = &nvram_buf[*off];
		}
	else
		{
		value = NULL;
		}

	if (count < 0)
		perror(PATH_DEV_NVRAM);

	if (off != (unsigned long *) tmp)
		free(off);
	return value;
}

typedef struct conf_t conf_t;

struct conf_t {
        char * filename;
        FILE * fd;
};


static conf_t	* cwmp_conf_handle = NULL;

int cwmp_conf_open(const char * filename)
{
    FUNCTION_TRACE();
    cwmp_conf_handle = malloc(sizeof(cwmp_conf_handle));
    if (!cwmp_conf_handle)
    {
        cwmp_log_error("conf malloc faild.\n");
        return CWMP_ERROR;
    }
    cwmp_conf_handle->filename = TRstrdup(filename);
    return CWMP_OK;
}

void cwmp_conf_split(char * name, char **s , char **k)
{
    *s = strchr(name, ':');
    if(*s == NULL)
    {
        k = &name;
        *s = "cwmp";
    }
    else
    {
        *s[0] = 0;
        *k = *s+1;
        *s = name;
    }
}

int cwmp_conf_get(const char * key, char *value)
{
    char * s, *k;
    char name[INI_BUFFERSIZE] = {0};
    //char value[INI_BUFFERSIZE] = {0};
    FUNCTION_TRACE();
    if(key == NULL)
    {
        return -1;
    }
    TRstrncpy(name, key, INI_BUFFERSIZE);
    cwmp_conf_split(name, &s, &k);

    ini_gets(s,k,NULL,value,INI_BUFFERSIZE, cwmp_conf_handle->filename);
    return 0;
}

int cwmp_conf_set(const char * key, const char * value)
{
    char * s, *k;
    char name[INI_BUFFERSIZE] = {0};
    FUNCTION_TRACE();
    if(key == NULL)
    {
        return CWMP_ERROR;
    }
    TRstrncpy(name, key, INI_BUFFERSIZE);
    cwmp_conf_split(name, &s, &k);

    return ini_puts(s, k, value, cwmp_conf_handle->filename);
}

int nv_cwmp_conf_set(const char * key, const char * value)
{
    FUNCTION_TRACE();
    cwmp_log_info("fun:%s[key-%s, value:%s]",__FUNCTION__, key, value);
    if(key == NULL)
    {
        return CWMP_ERROR;
    }

	nvram_set(key,value);
 
    return 0;
}



char * cwmp_conf_pool_get(pool_t * pool, const char * key)
{   
    char * s, *k;
    char name[INI_BUFFERSIZE] = {0};
    char value[INI_BUFFERSIZE] = {0};
    //FUNCTION_TRACE();
    if(key == NULL)
    {
        return NULL;
    }
    TRstrncpy(name, key, INI_BUFFERSIZE);

    cwmp_conf_split(name, &s, &k);

    ini_gets(s,k,NULL,value,INI_BUFFERSIZE, cwmp_conf_handle->filename);

    return pool_pstrdup(pool, value);
}

char * nv_cwmp_conf_pool_get(pool_t * pool,const char * key)
{
   
    char name[INI_BUFFERSIZE] = {0};
    const char * value = NULL;
	FILE *fp = NULL;    
	char buf[256];

    if(key == NULL)
        return NULL;
	value = cwmp_get_key_value(key);

	cwmp_log_debug("key:%s value:%s",key, value);
    return pool_pstrdup(pool, value);
    
#if 0   
	if ((fp = popen("cat /dev/nvram", "r")) != NULL) {
			memset(buf, 0, sizeof(buf));
			while(fgets(buf, sizeof(buf)-1, fp)) {
				cwmp_log_debug("-----buf------:%s\n",buf);
				char *ptr = NULL;
				char *ptr2 = NULL;
				ptr = strstr(buf, key);
				if (ptr) {
					ptr += key_len;
					ptr2 = strchr(ptr, '\0');
					*ptr2 = '\0';
					memcpy(value,ptr,ptr2-ptr);	
				    cwmp_log_debug("-----value------:%s",value);
					break;
				}
			   
			    memset(buf, 0, sizeof(buf));
			}
			pclose(fp);
		}
#endif
}

int cwmp_conf_get_int(const char * key)
{
	 char * s, *k;
    char name[INI_BUFFERSIZE] = {0};

    FUNCTION_TRACE();
    if(key == NULL)
    {
        return 0;
    }
    TRstrncpy(name, key, INI_BUFFERSIZE);
    cwmp_conf_split(name, &s, &k);
	//printf("<<<<name:%s, s:%s, k:%s>>>>\n", name, s, k);

    return (int)ini_getl(s,k,0,cwmp_conf_handle->filename);
     
}

int nv_cwmp_conf_get_int(const char * key)
{  
	int default_value = 0;
    char name[INI_BUFFERSIZE] = {0};
	const char * value = NULL;
    FUNCTION_TRACE();
    if(key == NULL)
    {
        return 0;
    }
   	value = cwmp_get_key_value(key);
	cwmp_log_debug("key:%s value:%s",key, value);
   	int len = strlen(value);
	return (int)(len == 0) ? default_value : strtol(value,NULL,10);

}



