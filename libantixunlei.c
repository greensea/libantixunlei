/**
 * 编译指令：gcc -Wall -shared -fPIC -o "libantixunlei.so" "libantixunlei.c" hashtable.c linklist.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <pthread.h>

#include "libantixunlei.h"
#include "hashtable.h"

//#include "hashtable.c"

hashtable_t* axl_clients;
hashtable_t* axl_ips;
axl_ftpcmd_tree_node axl_ftpcmd_tree[10];

#ifdef AXL_WITH_DENYIP
axl_ip_node_t* axl_ip_last_deny = NULL;
unsigned long axl_ip_delete_key = 0;
axl_ip_node_t* axl_ip_delete_p = NULL;
long axl_ip_sleep_time = AXL_DENYIP_TIME;
pthread_mutex_t axl_sweeper_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/**
 * 初始化反迅雷库
 * 
 * 在使用任何反迅雷库的函数之前，必须调用该函数
 */
int axl_init(){
	/**
	 * 自定义检查部分——开始——
	 */
#ifdef AXL_WITH_DENYIP
	if (sizeof(axl_ip_node_t) > sizeof(axl_client_node_t)) {
		printf("程序错误，axl_ip_node_t 类型占用的内存大于 axl_client_node_t 占用的内存\n");
		exit(1);
	}
#endif
	/**
	 * 自定义检查部分——结束——
	 */
	int i;
	int tree_size;
	
	tree_size = sizeof(axl_ftpcmd_tree) / sizeof(axl_ftpcmd_tree[0]);
	
	// FTP指令树表
	short int false_poss[] = 
	{9, 9, 3, 9, 9, 9, 7, 9, 8, 9};
	short int true_poss[] = 
	{1, 2, 3, 4, 5, 6, 7, 8, 8, 9};
	char assist_flags[] = 
	{0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	axl_isxunlei_t is_xunleis[] = 
	{AXL_ISXUNLEI_UNKNOWN, AXL_ISXUNLEI_UNKNOWN, AXL_ISXUNLEI_UNKNOWN, AXL_ISXUNLEI_UNKNOWN, AXL_ISXUNLEI_UNKNOWN, AXL_ISXUNLEI_UNKNOWN, AXL_ISXUNLEI_UNKNOWN, AXL_ISXUNLEI_UNKNOWN, AXL_ISXUNLEI_YES, AXL_ISXUNLEI_NO};
	axl_ftpcmd_t cmds[] = 
	{AXL_FTPCMD_USER, AXL_FTPCMD_PASS, AXL_FTPCMD_CWD, AXL_FTPCMD_TYPE, AXL_FTPCMD_SIZE, AXL_FTPCMD_PASV, AXL_FTPCMD_REST, AXL_FTPCMD_RETR, AXL_FTPCMD_NONE, AXL_FTPCMD_NONE};
	
	for (i = 0; i < tree_size; i++) {
		axl_ftpcmd_tree[i].false_pos = false_poss[i];
		axl_ftpcmd_tree[i].true_pos = true_poss[i];
		axl_ftpcmd_tree[i].assist_flag = assist_flags[i];
		axl_ftpcmd_tree[i].is_xunlei = is_xunleis[i];
		axl_ftpcmd_tree[i].cmd = cmds[i];
	}
	
	// 初始化哈希链表
	axl_clients = hashtable_init(1003);

#ifdef AXL_WITH_DENYIP	
	// 创建IP封禁地址空间，同时创建清理线程
	pthread_t sweeper_pid;
	
	axl_ips = hashtable_init(1003);
	pthread_create(&sweeper_pid, NULL, (void*)axl_ip_sweeper, NULL);
#endif
	
	return 0;
}

/**
 * @param axl_ftpcmd_t cmd 接收到的FTP指令
 * @param unsigned long sess_id 当前连接的标识符
 * 
 * 当接收到客户端发送的在libantixunlei.h中已经定义的FTP指令时，必须调用此函数。如果接收到没有定义的指令，则应该使用AXL_FTPCMD_OTHER伪指令。
 */
axl_isxunlei_t axl_recive_command(axl_ftpcmd_t cmd, unsigned long sess_id){
	axl_client_node_t* client;
	axl_ftpcmd_tree_node* tnode;
	short int hypothetical_flag;
	
	client = hashtable_find(axl_clients, sess_id);
	// 如果查找无果，则将这家伙添加下去
	if (client == NULL) {
		client = axl_client_addnew(sess_id);
	}
	
	// 如果这家伙的身份已经确定，则直接返回
	else if (client->is_xunlei != AXL_ISXUNLEI_UNKNOWN) {
		//printf("confirmed\n");
		return client->is_xunlei;
	}
	
hypothetical_loop:
	// 否则处理这家伙的数据
	tnode = axl_ftpcmd_tree + client->current_pos;
	
	// 置位和跳转
	if (cmd == tnode->cmd) {
		// 重言
		if ((tnode->assist_flag | 0x0) == 0x0) {
			client->assist_flag ^= tnode->assist_flag;
			//printf("(T)flag set to %.2x;\tclient current_pos=%d\n", client->assist_flag, client->current_pos);
		}
		//printf("jump: %d-->%d\n", client->current_pos, tnode->true_pos);
		client->current_pos = tnode->true_pos;
		
		hypothetical_flag = 0;
	}
	else {
		// 假言
		//printf("%x\n", tnode->assist_flag & 0x80);
		if ((tnode->assist_flag & 0x80) == 0x80) {
			client->assist_flag ^= tnode->assist_flag;
			//printf("(F)flag set to %.2x;\tclient current_pos=%d\n", client->assist_flag, client->current_pos);
		}
		//printf("jump: %d-->%d\n", client->current_pos, tnode->false_pos);
		client->current_pos = tnode->false_pos;
		
		hypothetical_flag = 1;
	}
	
	// 最后判断是不是迅雷，然后返回值
	tnode = axl_ftpcmd_tree + client->current_pos;
	if (tnode->is_xunlei == AXL_ISXUNLEI_YES) {
		if ((client->assist_flag & client->zero_flag & 127) == 0) {
			client->is_xunlei = AXL_ISXUNLEI_YES;
		}
		else {
			client->is_xunlei = AXL_ISXUNLEI_NO;
		}
		return client->is_xunlei;
	}
	else if (tnode->is_xunlei == AXL_ISXUNLEI_NO) {
		client->is_xunlei = AXL_ISXUNLEI_NO;
	}
	else {
		client->is_xunlei = AXL_ISXUNLEI_UNKNOWN;
		
		if (hypothetical_flag == 1) {
			//printf("do_goto, cpos=%d\n", client->current_pos);
			goto hypothetical_loop;
		}	
	}
	
	return client->is_xunlei;
}

/**
 * 与  axl_recive_command() 函数类似，只是你可以直接把FTP指令字符串传进来而不用区分不同的指令来使用不同的参数区别调用 axl_recive_command();
 */
axl_isxunlei_t axl_recive_command_string(const char* cmd, unsigned long sess_id){
	int i;
	char* s;
	axl_isxunlei_t ret;
	
	// 转换成小写
	strncpy(s, cmd, 4);
	for (i = 0; i < 4; i++) {
		if (s[i] >= 'A' && s[i] <= 'Z') s[i] += 32;
	}
	
	// strcmp比较指令
	if (strcmp(cmd, "user") == 0) {
		ret = axl_recive_command(AXL_FTPCMD_USER, sess_id);
	}
	else if(strcmp(cmd, "pass") == 0) {
		ret = axl_recive_command(AXL_FTPCMD_PASS, sess_id);
	}
	else if(strcmp(cmd, "cwd") == 0) {
		ret = axl_recive_command(AXL_FTPCMD_CWD, sess_id);
	}
	else if(strcmp(cmd, "type") == 0) {
		ret = axl_recive_command(AXL_FTPCMD_TYPE, sess_id);
	}
	else if(strcmp(cmd, "size") == 0) {
		ret = axl_recive_command(AXL_FTPCMD_SIZE, sess_id);
	}
	else if(strcmp(cmd, "pasv") == 0) {
		ret = axl_recive_command(AXL_FTPCMD_PASV, sess_id);
	}
	else if(strcmp(cmd, "rest") == 0) {
		ret = axl_recive_command(AXL_FTPCMD_REST, sess_id);
	}
	else if(strcmp(cmd, "retr") == 0) {
		ret = axl_recive_command(AXL_FTPCMD_RETR, sess_id);
	}
	else {
		ret = axl_recive_command(AXL_FTPCMD_OTHER, sess_id);
	}

	return ret;
}


/**
 * @param char* username 接收到的客户端发送上来的密码
 * @param unsigned long sess_id 当前连接标识编号
 * 
 * 当接收到客户端发送的密码时，必须调用此函数
 */
axl_isxunlei_t axl_recive_password(char* pass, unsigned long sess_id){
	axl_client_node_t* client;
	
	// 查找，如果找不到这个用户，说明这个用户肯定先发送了PASS指令而没有发送USER指令，所以不是迅雷
	client = hashtable_find(axl_clients, sess_id);
	if (client == NULL) return AXL_ISXUNLEI_NO;
	
	if (strcmp(pass, "IEUser@") == 0) {
		client->zero_flag &= 254;
	//	printf("client->assist_flag set to %.2x\n", client->assist_flag);
	}
	
	return client->is_xunlei;
}

/**
 * @param char* username 接收到的客户端发送上来的用户名
 * @param unsigned long sess_id 当前连接标识编号
 * 
 * 当接收到客户端发送的用户名时，必须调用此函数
 */
axl_isxunlei_t axl_recive_username(char* username, unsigned long sess_id){
	axl_client_node_t* client;
	
	// 查找，如果找不到这个用户，说明这个用户肯定先发送了PASS指令而没有发送USER指令，所以不是迅雷
	client = hashtable_find(axl_clients, sess_id);
	if (client == NULL) return AXL_ISXUNLEI_NO;	
	
	return client->is_xunlei;
}

#ifdef __NOT_USE__
/**
 * 设置指定会话节点的IP地址，如果不调用此函数设置客户端的节点，则默认IP地址为0
 * 
 * 如果使用 AXL_WITH_DENYIP，且没有使用 AXL_IP_AS_SESSIONID，那么在会话创建后必须调用此函数来指定会话的客户端IP
 */
int axl_session_setip(unsigned long sess_id, unsigned long ip){
	axl_client_node_t* client;
	
	client = hashtable_find(axl_clients, sess_id);
	if (client == NULL) client = axl_client_addnew(sess_id);
	
	client->ip = ip;

	return 0;
}
#endif

/**
 * @param unsigned long sess_id 断开连接的标识编号
 * 
 * 当一个连接中断的时候，必须调用此函数
 */
int axl_session_bye(unsigned long sess_id){
	hashtable_delete(axl_clients, sess_id);
	
	return 0;
}

/**
 * 向哈希表中增加一个会话节点，并返回该节点指针
 */
axl_client_node_t* axl_client_addnew(unsigned long sess_id){
	axl_client_node_t c;

	c.current_pos = 0;
	c.is_xunlei = AXL_ISXUNLEI_UNKNOWN;
	c.assist_flag = 0;
	c.zero_flag = 255;
	c.assign_time = time(NULL);
	
	return hashtable_add(axl_clients, sess_id, c);
}

#ifdef AXL_WITH_DENYIP
/**
 * 将字符串的IPv4地址转换成无符号长整型
 */
unsigned long ip2ulong(const char* ip){
	unsigned long ipval[4];
	unsigned long ipnum;
	
	sscanf(ip, "%ld.%ld.%ld.%ld", ipval, ipval + 1, ipval + 2, ipval + 3);
	
	ipnum = (ipval[0] << 24) | (ipval[1] << 16) | (ipval[2] << 8) | ipval[3];
	
	return ipnum;
}

/**
 * 封禁IP
 */
int axl_ip_deny(unsigned long ip){
	axl_client_node_t cnode;
	axl_ip_node_t* ipnode;
	
	pthread_mutex_lock(&axl_sweeper_mutex);	// 进入临界区
	
	if (hashtable_find(axl_ips, ip) != NULL) {
		pthread_mutex_unlock(&axl_sweeper_mutex);	// 离开临界区
		return 0;
	}
	
	// 创建一个IP节点
	ipnode = (axl_ip_node_t*)&cnode;
	ipnode->assign_time = time(NULL);
	ipnode->next_key = 0;
	
	// 增加IP，并做好尾链
	ipnode = (axl_ip_node_t*)hashtable_add(axl_ips, ip, cnode);
	if (axl_ip_delete_key == 0) {
		axl_ip_delete_key = ip;
		axl_ip_delete_p = ipnode;
	}
	else {
		axl_ip_delete_p->next_key = ip;
		axl_ip_delete_p = ipnode;
	}

	pthread_mutex_unlock(&axl_sweeper_mutex);	// 离开临界区
	
	return 0;
}

/**
 * @param unsigned long 无符号长整型形式的IP地址
 * @return int 该IP是否已经被屏蔽。0为没有被屏蔽，1为已经被屏蔽。
 * 
 * 检查某个IP是否已经被屏蔽
 */
int axl_ip_denined(unsigned long ip){
	axl_client_node_t* p;
	
	pthread_mutex_lock(&axl_sweeper_mutex);	// 进入临界区
	p = hashtable_find(axl_ips, ip);
	pthread_mutex_unlock(&axl_sweeper_mutex);	// 离开临界区
	
	if (p == NULL) {
		return 0;
	}
	else {
		return 1;
	}
}

/**
 * 清理IP封禁记录的线程
 */
void axl_ip_sweeper(){
	unsigned long current_key;
	axl_ip_node_t* ipnode;
	
	ipnode = NULL;
	
	for (;;) {
		// 如果没有需要删除的IP，就可以进入最大程度的睡眠
		printf("axl_ip_delete_key=%lu\n", axl_ip_delete_key);
		pthread_mutex_lock(&axl_sweeper_mutex);	//进入临界区
		if (axl_ip_delete_key == 0) axl_ip_sleep_time = AXL_DENYIP_TIME;
		pthread_mutex_unlock(&axl_sweeper_mutex);	// 离开临界区
		
		// 进入睡眠
		if (axl_ip_sleep_time > 0) {
			printf("sleep for %ld seconds\n", axl_ip_sleep_time);
			sleep(axl_ip_sleep_time);
			
			if (axl_ip_delete_key == 0) {
				continue;
			}
		}
		
		// 一直删除节点，直到需要睡眠
		pthread_mutex_lock(&axl_sweeper_mutex);	//进入临界区
		
		if (ipnode == NULL) ipnode = (axl_ip_node_t*)hashtable_find(axl_ips, axl_ip_delete_key);
		
		axl_ip_sleep_time = ipnode->assign_time + AXL_DENYIP_TIME - time(NULL);
		// 若已经超时则删除
		if (axl_ip_sleep_time <= 0) {
			current_key = axl_ip_delete_key;
			axl_ip_delete_key = ipnode->next_key;
			//printf("(delete)ip=%d, time=%ld, next=%ld\n", current_key, axl_ip_sleep_time, axl_ip_delete_key);
			hashtable_delete(axl_ips, current_key);
			
			// 计算下一个休眠时间
			if (axl_ip_delete_key != 0) {
				ipnode = (axl_ip_node_t*)hashtable_find(axl_ips, axl_ip_delete_key);
				axl_ip_sleep_time = ipnode->assign_time + AXL_DENYIP_TIME - time(NULL);
			}
			else {
				ipnode = NULL;
			}
		}
		
		pthread_mutex_unlock(&axl_sweeper_mutex);	//离开临界区
	}
	
}

#endif	// AXL_WITH_DENYIP


/**
 * 下面开始到最后都是调试用的
 */
#ifdef AXL_DEBUG_MAIN

#define A(CMD, UID)	\
	printf("cmd=%d, is_xunlei=%d\n", CMD, axl_recive_command(CMD, UID));	\
	//axl_recive_command(CMD,UID);

int main(){
	axl_init();

	A(AXL_FTPCMD_USER, 1);
	A(AXL_FTPCMD_PASS, 1);
	
	//axl_recive_password("IEUser@", 1);
	
	//A(AXL_FTPCMD_CWD, 1);
	A(AXL_FTPCMD_TYPE, 1);
	A(AXL_FTPCMD_SIZE, 1);
	A(AXL_FTPCMD_PASV, 1);
	A(AXL_FTPCMD_REST, 1);
	A(AXL_FTPCMD_RETR, 1);

	A(AXL_FTPCMD_USER, 1);
	A(AXL_FTPCMD_PASS, 1);
	//axl_recive_password("IEUser@", 2);
	A(AXL_FTPCMD_CWD, 1);
	A(AXL_FTPCMD_TYPE, 1);
	A(AXL_FTPCMD_SIZE, 1);
	A(AXL_FTPCMD_PASV, 2);
	A(AXL_FTPCMD_REST, 2);
	A(AXL_FTPCMD_RETR, 2);
	
	
	printf("%d\n", axl_ip_denined(100));
	axl_ip_deny(100);
	printf("%d\n", axl_ip_denined(101));
	printf("%d\n", axl_ip_denined(100));
	
	while(1){
		static unsigned long a = 1;
		a = random() + 1;
		axl_ip_deny(a);
		usleep(random() % 6000000);
	}

	return 0;
}

#endif
