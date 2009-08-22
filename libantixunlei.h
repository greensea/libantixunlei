#ifndef __LIBANTIXUNLEI_H__
#define __LIBANTIXUNLEI_H__

//#define AXL_DEBUG_MAIN

/**
 * 是否附带自动封IP功能
 */
#define AXL_WITH_DENYIP	1

#ifdef AXL_WITH_DENYIP
/**
 * 封IP的持续时间，单位是秒
 */
#define AXL_DENYIP_TIME	5

#if AXL_DENYIP_TIME <= 0
#error 预定义宏 AXL_DENYIP_TIME 非法，封禁IP的时间必须为正整数
#endif

#endif	// AXL_WITH_DENYIP

#include "time.h"

#define AXL_ISXUNLEI_UNKNOWN	0
#define AXL_ISXUNLEI_YES		1
#define AXL_ISXUNLEI_NO			2

#define axl_keytype unsigned long
#define axl_valtype axl_client_node_t
#define axl_isxunlei_t char
#define axl_ftpcmd_t short int

#define AXL_KEY_COMPARE(VAL1, VAL2)	(VAL1 == VAL2)


#define AXL_FTPCMD_NONE	0
#define AXL_FTPCMD_USER	1
#define AXL_FTPCMD_PASS	2
#define AXL_FTPCMD_CWD	3
#define AXL_FTPCMD_TYPE	4
#define AXL_FTPCMD_SIZE	5
#define AXL_FTPCMD_PASV	6
#define AXL_FTPCMD_REST	7
#define AXL_FTPCMD_RETR	8
#define AXL_FTPCMD_OTHER	10


typedef struct axl_client_node_t {
	unsigned char assist_flag;
	unsigned char zero_flag;	//置零标志
	short int current_pos;
	axl_isxunlei_t is_xunlei;
	time_t assign_time;
} axl_client_node_t;

typedef struct axl_ftpcmd_tree_node {
	axl_ftpcmd_t cmd;
	short int true_pos;
	short int false_pos;
	unsigned char assist_flag;	//辅助判断标志
	axl_isxunlei_t is_xunlei;
} axl_ftpcmd_tree_node;

#ifdef AXL_WITH_DENYIP
typedef struct axl_ip_node_t {
	unsigned long next_key;
	time_t assign_time;
} axl_ip_node_t;

#endif


int alx_init();
axl_client_node_t* axl_client_addnew(unsigned long sess_id);
axl_isxunlei_t axl_recive_command(axl_ftpcmd_t cmd, unsigned long sess_id);
axl_isxunlei_t axl_recive_command_string(const char* cmd, unsigned long sess_id);
axl_isxunlei_t axl_recive_username(char* username, unsigned long sess_id);
axl_isxunlei_t axl_recive_password(char* pass, unsigned long sess_id);
int axl_session_bye(unsigned long sess_id);

#ifdef AXL_WITH_DENYIP
unsigned long ip2ulong(const char* ip);
int axl_ip_deny(unsigned long ip);
int axl_ip_denined(unsigned long ip);
void axl_ip_sweeper();
#endif

#endif
