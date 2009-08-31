#ifndef __LIBANTIXUNLEI_H__
#define __LIBANTIXUNLEI_H__

/* #define AXL_DEBUG_MAIN */

#ifndef SA_NOCLDWAIT
	#define SA_NOCLDWAIT 2
#endif

/**
 * 所应用的FTP服务端是否是使用子进程来服务每一个连接的（也就是说守护进程对于每一个连接请求会调用fork()函数产生一个新的进程来处理）
 * 
 * 出于一般性的考虑，应该不会有FTP服务器产生子进程以后，还要在子进程里面开几个线程来处理不同的会话，所以，对于libantixunlei来说，没有对子进程的线程进行同步操作，所以子进程是线程不安全的。
 */
#define AXL_WITH_FORKSUPPORT 1
	

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

#ifdef AXL_WITH_FORKSUPPORT
/**
 * 父进程的消息队列创建键值
 */
#define AXL_PARENT_MSGKEY 12448911

#endif	// END AXL_WITH_FORKSUPPORT

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
	int nul1;	/* 补充字段，把 axl_ip_node_t 补成和 axl_client_node_t 一样长的 */
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

#ifdef AXL_WITH_FORKSUPPORT
#define AXL_MTYPE_IPDENY 1
#define AXL_MTYPE_IPDENINED	2
#define AXL_MTYPE_RCVCMD 3
#define AXL_MTYPE_BYE	4
#define AXL_MTYPE_RET	5

/**
 * 子进程发送给父进程的消息格式
 */
typedef struct axl_msgbuf_t {
	int mtype;
	unsigned long sess_id;
	axl_ftpcmd_t ftpcmd;
	int retid;	/* 用于接收返回消息的消息队列编号 */
} axl_msgbuf_t;

/**
 * 下面的都是父进程返回给子进程的返回值消息
 */
typedef struct axl_msgbuf_int_t {
	int mtype;
	int msg;
} axl_msgbuf_int_t;

typedef struct axl_msgbuf_isxunlei_t {
	int mtype;
	axl_isxunlei_t msg;
} axl_msgbuf_isxunlei_t;

axl_isxunlei_t axl_recive_command_msg(axl_ftpcmd_t cmd, unsigned long sess_id);
void axl_msg_handler_rcvmsg();
#ifdef AXL_WITH_DENYIP
int axl_ip_deny_msg(unsigned long ip);
int axl_session_bye_msg(unsigned long sess_id);
int axl_ip_denined_msg(unsigned long ip);
void axl_msg_handler_ip_deny();
void axl_msg_handler_session_bye();
void axl_msg_handler_ip_denined();
#endif	/* END AXL_WITH_DENYIP */

#endif	/* END AXL_WITH_FORKSUPPORT */

#endif
