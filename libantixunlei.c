/**
 * 编译指令：gcc -Wall -shared -fPIC -o "libantixunlei.so" "libantixunlei.c" hashtable.c linklist.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include <unistd.h>
#include <pthread.h>
#include <sys/msg.h>
#include <semaphore.h>
#include <fcntl.h>
#include <sys/shm.h>

#include "libantixunlei.h"
#include "hashtable.h"

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

#ifdef AXL_WITH_FORKSUPPORT
pid_t axl_parent_pid;
pthread_t axl_hdlid_rcvcmd;
pthread_t axl_hdlid_ipdeny;
pthread_t axl_hdlid_sessbye;
pthread_t axl_hdlid_ipdenined;
int axl_pmsgid;
//int axl_pmsgid_rcvcmd;
//int axl_pmsgid_ipdeny;
//int axl_pmsgid_sessbye;
pthread_mutex_t axl_clients_mutex = PTHREAD_MUTEX_INITIALIZER;
struct sigaction axl_fork_sig, axl_fork_oldsig;
#endif

#ifdef AXL_WITH_UNIIDSUPPORT
sem_t* axl_uniid_sem;
int axl_uniid_shmid;
unsigned long *axl_uniid_num;
#endif

/**
 * 初始化反迅雷库
 * 
 * 在使用任何反迅雷库的函数之前，必须调用该函数。
 * 
 * 如果启用了 FORKSUPPORT，则只能在FTP主进程中调用这个函数一次（且仅一次）。绝不能在fork()出来的子进程中调用此函数.
 */
int axl_init(){
	AXL_DEBUG("libantixunlei axl_init(), pid=%d\n", getpid());
	/**
	 * 自定义检查部分——开始——
	 */
#ifdef AXL_WITH_DENYIP
	if (sizeof(axl_ip_node_t) > sizeof(axl_client_node_t)) {
		printf("程序错误，axl_ip_node_t 类型占用的内存与 axl_client_node_t 类型占用的内存不相等\n");
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

#ifdef AXL_WITH_FORKSUPPORT
	axl_parent_pid = getpid();
#endif

#ifdef AXL_WITH_UNIIDSUPPORT
	// 唯一编号信号量初始化
	printf("init sem\n");
	axl_uniid_sem = sem_open("axl_uniid_sem", O_CREAT, 0666, 1);
	if (axl_uniid_sem == SEM_FAILED) {
		printf("无法创建信号量 axl_uniid_sem，sem_open 函数返回 SEM_FAILED。错误信息：%s\n", strerror(errno));
		exit(2);
	}
	printf("get share memory\n");
	axl_uniid_shmid = shmget(1111, sizeof(unsigned long), IPC_CREAT | 0666);
	printf("AXL_WITH_UNIIDSUPPORT init finished\n");
#endif

#ifdef AXL_WITH_DENYIP	
	// 创建IP封禁地址空间，同时创建清理线程
	pthread_t sweeper_pid;
	
	axl_ips = hashtable_init(1003);
	pthread_create(&sweeper_pid, NULL, (void*)axl_ip_sweeper, NULL);
#endif

#ifdef AXL_WITH_FORKSUPPORT
	// 防止出现僵死进程
	sigaddset(&axl_fork_sig.sa_mask, SIGCHLD);
	axl_fork_sig.sa_flags = SA_NOCLDWAIT;
	sigaction(SIGCHLD, &axl_fork_sig, &axl_fork_oldsig);

	// 创建父进程的接收消息队列
	axl_pmsgid = msgget(AXL_PARENT_MSGKEY + getpid(), IPC_CREAT | 0666);
	if (axl_pmsgid == -1) {
		printf("(%s,%d)程序错误，无法创建消息队列，msgget函数返回%d\n", __func__, __LINE__, axl_pmsgid);
		printf("错误码：errno=%d; EACCES=%d, EEXIST=%d, ENOENT=%d, ENOMEM=%d, ENOSPC=%d\n", errno, EACCES, EEXIST, ENOENT, ENOMEM, ENOSPC);
		exit(1);
	}
	//axl_pmsgid_ipdeny = msgget(AXL_PARENT_MSGKEY + 1, IPC_CREAT | IPC_EXCL | 0666);
	//axl_pmsgid_sessbye = msgget(AXL_PARENT_MSGKEY + 2, IPC_CREAT | IPC_EXCL | 0666);
	
	// 创建消息处理线程
	printf("axl_pmsgid=%d\n", axl_pmsgid);
	if (0 != pthread_create(&axl_hdlid_rcvcmd, NULL, (void*)axl_msg_handler_rcvmsg, NULL))
	{
		printf("pthread_create fail, error: %s\n", strerror(errno));
		exit(2);
	}
	pthread_create(&axl_hdlid_ipdeny, NULL, (void*)axl_msg_handler_ip_deny, NULL);
	pthread_create(&axl_hdlid_sessbye, NULL, (void*)axl_msg_handler_session_bye, NULL);
	pthread_create(&axl_hdlid_ipdenined, NULL, (void*)axl_msg_handler_ip_denined, NULL);
	
#endif
	
	return 0;
}

int axl_destroy(){
	AXL_DEBUG("axl_destroy()\n");
	
#ifdef AXL_WITH_FORKSUPPORT
	// 终止消息处理线程，删除消息队列
	pthread_cancel(axl_hdlid_rcvcmd);
	pthread_cancel(axl_hdlid_ipdeny);
	pthread_cancel(axl_hdlid_sessbye);
	pthread_cancel(axl_hdlid_ipdenined);
	
	msgctl(axl_pmsgid, IPC_RMID, NULL);
	//msgctl(axl_pmsgid_ipdeny, IPC_RMID, NULL);
	//msgctl(axl_pmsgid_sessbye, IPC_RMID, NULL);
#endif

#ifdef AXL_WITH_UNIIDSUPPORT
	// 删除唯一编号信号量
	sem_close(axl_uniid_sem);
	//sem_unlink("/tmp/axl_uniid_sem");
	
	shmctl(axl_uniid_shmid, IPC_RMID, NULL);
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
	
#ifdef AXL_WITH_FORKSUPPORT
	// 如果FTP服务器是作为守护进程模式运行的，就进行信号处理。如果该进程是子进程则使用信号处理函数
	if (getpid() != axl_parent_pid) {
		return axl_recive_command_msg(cmd, sess_id);
	}
#endif

	pthread_mutex_lock(&axl_clients_mutex);	/* 进入临界区，信号量：clients */
	client = hashtable_find(axl_clients, sess_id);

	
	// 如果查找无果，则将这家伙添加下去
	if (client == NULL) {
		client = axl_client_addnew(sess_id);
		AXL_DEBUG("(%d)[%s] client(%lu) not found in %.8x, add to %.8x \n", getpid(), __func__, cmd, axl_clients, client);
		AXL_DEBUG("(%d)[%s] client(%.8x) current_pos=%d\n", getpid(), __func__, cmd, client, client->current_pos);
	}	
	// 如果这家伙的身份已经确定，则直接返回
	else if (client->is_xunlei != AXL_ISXUNLEI_UNKNOWN) {
AXL_DEBUG("(%d)[%s] msg '%d' client(%lu) found at \n in %.8x", getpid(), __func__, cmd, client, axl_clients);
AXL_DEBUG("(%d)[%s] client(%.8x) current_pos=%d\n", getpid(), __func__, cmd, client, client->current_pos);
		//printf("confirmed\n");
		pthread_mutex_unlock(&axl_clients_mutex);	/* 离开临界区，信号量：clients */
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
		
		pthread_mutex_unlock(&axl_clients_mutex);	/* 离开临界区，信号量：clients */
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
	
	pthread_mutex_unlock(&axl_clients_mutex);	/* 离开临界区，信号量：clients */
	return client->is_xunlei;
}

/**
 * 与  axl_recive_command() 函数类似，只是你可以直接把FTP指令字符串传进来而不用区分不同的指令来使用不同的参数区别调用 axl_recive_command();
 */
axl_isxunlei_t axl_recive_command_string(const char* cmd, unsigned long sess_id){
	int i;
	char s[5] = {0};
	axl_isxunlei_t ret;
	
	// 转换成小写
	strncpy(s, cmd, 4);
	for (i = 0; i < 4; i++) {
		if (s[i] >= 'A' && s[i] <= 'Z') s[i] += 32;
	}
	
	// strcmp比较指令
	if (strcmp(s, "user") == 0) {
		ret = axl_recive_command(AXL_FTPCMD_USER, sess_id);
	}
	else if(strcmp(s, "pass") == 0) {
		ret = axl_recive_command(AXL_FTPCMD_PASS, sess_id);
	}
	else if(strcmp(s, "cwd") == 0) {
		ret = axl_recive_command(AXL_FTPCMD_CWD, sess_id);
	}
	else if(strcmp(s, "type") == 0) {
		ret = axl_recive_command(AXL_FTPCMD_TYPE, sess_id);
	}
	else if(strcmp(s, "size") == 0) {
		ret = axl_recive_command(AXL_FTPCMD_SIZE, sess_id);
	}
	else if(strcmp(s, "pasv") == 0) {
		ret = axl_recive_command(AXL_FTPCMD_PASV, sess_id);
	}
	else if(strcmp(s, "rest") == 0) {
		ret = axl_recive_command(AXL_FTPCMD_REST, sess_id);
	}
	else if(strcmp(s, "retr") == 0) {
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
	pthread_mutex_lock(&axl_clients_mutex);	/* 进入临界区，信号量：clients */
	client = hashtable_find(axl_clients, sess_id);
	pthread_mutex_unlock(&axl_clients_mutex);	/* 离开临界区，信号量：clients */
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
	pthread_mutex_lock(&axl_clients_mutex);	/* 进入临界区，信号量：clients */
	client = hashtable_find(axl_clients, sess_id);
	pthread_mutex_unlock(&axl_clients_mutex);	/* 离开临界区，信号量：clients */
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
#ifdef AXL_WITH_FORKSUPPORT
	if (getpid() != axl_parent_pid) {
		return axl_session_bye_msg(sess_id);
	}
#endif
	
	pthread_mutex_lock(&axl_clients_mutex);	/* 进入临界区，信号量：clients */
	hashtable_delete(axl_clients, sess_id);
	pthread_mutex_unlock(&axl_clients_mutex);	/* 离开临界区，信号量：clients */
	
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
	
#ifdef AXL_WITH_FORKSUPPORT
	if (getpid() != axl_parent_pid) {
		return axl_ip_deny_msg(ip);
	}
#endif
	
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

#ifdef AXL_WITH_FORKSUPPORT
	if (getpid() != axl_parent_pid) {
		return axl_ip_denined_msg(ip);
	}
#endif
	
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

#ifdef AXL_WITH_FORKSUPPORT
	if (getpid() != axl_parent_pid) return;
#endif
	
	for (;;) {
		// 如果没有需要删除的IP，就可以进入最大程度的睡眠
		//printf("axl_ip_delete_key=%lu\n", axl_ip_delete_key);
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
		//printf("-__ipnode(%.8x)->assign_time=%ld, key=%ld\n", ipnode, ipnode->assign_time, axl_ip_delete_key);
		// 若已经超时则删除
		if (axl_ip_sleep_time <= 0) {
			current_key = axl_ip_delete_key;
			axl_ip_delete_key = ipnode->next_key;
			printf("(delete)ip=%lu, now=%ld, axl_ip_sleep_time=%ld, next=%ld\n", current_key, time(NULL), axl_ip_sleep_time, axl_ip_delete_key);
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
		//printf("next to be delete %ld\n", axl_ip_sleep_time);
		
		pthread_mutex_unlock(&axl_sweeper_mutex);	//离开临界区
	}
	
}

#endif	// AXL_WITH_DENYIP

#ifdef AXL_WITH_FORKSUPPORT
/**
 * 子进程接收到消息时，调用此函数给父进程发送收到新FTP指令的消息，并获取返回值
 */
axl_isxunlei_t axl_recive_command_msg(axl_ftpcmd_t cmd, unsigned long sess_id){
	axl_msgbuf_t msg;
	axl_msgbuf_isxunlei_t ret;
	int msgid;
	
	// 创建一个新的消息队列用于接收消息
	msgid = msgget(AXL_PARENT_MSGKEY + getpid(), IPC_CREAT | 0666);
	if (msgid == -1) {
		return AXL_ISXUNLEI_UNKNOWN;
	}
	
	msg.mtype = AXL_MTYPE_RCVCMD;
	msg.sess_id = sess_id;
	msg.ftpcmd = cmd;
	msg.retid = msgid;
	
	// 发送消息，然后等待返回
	int sndsize;
	AXL_DEBUG("(%d)[%s] msg '%d' to be send to \n", getpid(), __func__, cmd, axl_pmsgid);
	msgsnd(axl_pmsgid, &msg, sizeof(msg) - sizeof(msg.mtype), 0L);
	msgrcv(msgid, &ret, sizeof(ret) - sizeof(ret.mtype), AXL_MTYPE_RET, 0L);
	AXL_DEBUG("(%d)[%s] msg recive: %d\n", getpid(), __func__, ret.msg);
	
	msgctl(msgid, IPC_RMID, NULL);
		
	return ret.msg;
}

/**
 * 子进程进行IP屏蔽操作时，调用此函数，发送信号给父进程进行相应的操作，并获取返回值
 */
int axl_ip_deny_msg(unsigned long ip){
	axl_msgbuf_t msg;
	axl_msgbuf_int_t ret;
	int msgid;
	
	// 创建一个新的消息队列用于接收消息
	msgid = msgget(AXL_PARENT_MSGKEY + getpid(), IPC_CREAT | 0666);
	if (msgid == -1) {
		return -1;
	}
	
	msg.mtype = AXL_MTYPE_IPDENY;
	msg.sess_id = ip;
	msg.retid = msgid;
	
	// 发送消息，然后等待返回
	msgsnd(axl_pmsgid, &msg, sizeof(msg) - sizeof(msg.mtype), 0L);
	msgrcv(msgid, &ret, sizeof(ret) - sizeof(ret.mtype), AXL_MTYPE_RET, 0L);
	msgctl(msgid, IPC_RMID, NULL);
	
	return ret.msg;
}
/**
 * 子进程进行删除会话操作时，调用此函数，发送信号给父进程进行相应的操作，并获取返回值
 */
int axl_session_bye_msg(unsigned long sess_id){
	axl_msgbuf_t msg;
	axl_msgbuf_int_t ret;
	int msgid;
	
	// 创建一个新的消息队列用于接收消息
	msgid = msgget(AXL_PARENT_MSGKEY + getpid(), IPC_CREAT | 0666);
	if (msgid == -1) {
		return -1;
	}
	
	msg.mtype = AXL_MTYPE_BYE;
	msg.sess_id = sess_id;
	msg.retid = msgid;
	
	// 发送消息，然后等待返回
	msgsnd(axl_pmsgid, &msg, sizeof(msg) - sizeof(msg.mtype), 0L);
	msgrcv(msgid, &ret, sizeof(ret) - sizeof(ret.mtype), AXL_MTYPE_RET, 0L);
	msgctl(msgid, IPC_RMID, NULL);
	
	return ret.msg;
}

/**
 * 子进程进行 ip_denined 调用时，调用此函数发送信号给父进程处理，并接收返回值
 */
int axl_ip_denined_msg(unsigned long ip){
	axl_msgbuf_t msg;
	axl_msgbuf_int_t ret;
	int msgid;
	
	// 创建一个新的消息队列用于接收消息
	msgid = msgget(AXL_PARENT_MSGKEY + getpid(), IPC_CREAT | 0666);
	if (msgid == -1) {
		return -1;
	}
	
	msg.mtype = AXL_MTYPE_IPDENINED;
	msg.sess_id = ip;
	msg.retid = msgid;
	
	// 发送消息，然后等待返回
	msgsnd(axl_pmsgid, &msg, sizeof(msg) - sizeof(msg.mtype), 0L);
	msgrcv(msgid, &ret, sizeof(ret) - sizeof(ret.mtype), AXL_MTYPE_RET, 0L);
	msgctl(msgid, IPC_RMID, NULL);
	
	return ret.msg;
}

/**
 * 守护进程的 recive_ftpcmd 的消息处理线程
 */
void axl_msg_handler_rcvmsg(){
	axl_msgbuf_isxunlei_t retmsg;
	axl_msgbuf_t msg;
	axl_isxunlei_t ret;
	
	retmsg.mtype = AXL_MTYPE_RET;
	
	AXL_DEBUG("[%s] started, wait for %d\n", __func__, axl_pmsgid);
	
	for (;;) {
		// 等待消息
		msgrcv(axl_pmsgid, &msg, sizeof(msg) - sizeof(msg.mtype), AXL_MTYPE_RCVCMD, 0L);
		AXL_DEBUG("(%d)[%s] %s%d\n", getpid(), __func__, "handler recive msg from ", axl_pmsgid);
		// 收到消息以后，送入AXL进行检测，并将返回值封装成消息发回给子进程
		ret = axl_recive_command(msg.ftpcmd, msg.sess_id);
		retmsg.msg = ret;
		AXL_DEBUG("(%d)[%s] ret msg '%d' to be send to \n", getpid(), __func__, ret, msg.retid);
		
		msgsnd(msg.retid, &retmsg, sizeof(retmsg) - sizeof(retmsg.mtype), IPC_NOWAIT);
		AXL_DEBUG("(%d)[%s] %s\n", getpid(), __func__, "ret msg sent");
	}
}

/**
 * 守护进程的 IPDENY 消息处理线程
 */
void axl_msg_handler_ip_deny(){
	int ret;
	axl_msgbuf_int_t retmsg;
	axl_msgbuf_t msg;
	
	retmsg.mtype = AXL_MTYPE_RET;
	
	for (;;) {
		msgrcv(axl_pmsgid, &msg, sizeof(msg) - sizeof(msg.mtype), AXL_MTYPE_IPDENY, 0L);
		
		ret = axl_ip_deny(msg.sess_id);
		retmsg.msg = ret;
		msgsnd(msg.retid, &retmsg, sizeof(retmsg) - sizeof(retmsg.mtype), IPC_NOWAIT);
	}
}

/**
 * 守护进程的 session_bye 消息的处理线程
 */
void axl_msg_handler_session_bye(){
	int ret;
	axl_msgbuf_int_t retmsg;
	axl_msgbuf_t msg;
	
	retmsg.mtype = AXL_MTYPE_RET;
	
	for (;;) {
		msgrcv(axl_pmsgid, &msg, sizeof(msg) - sizeof(msg.mtype), AXL_MTYPE_BYE, 0L);
		
		ret = axl_session_bye(msg.sess_id);
		retmsg.msg = ret;
		msgsnd(msg.retid, &retmsg, sizeof(retmsg) - sizeof(retmsg.mtype), IPC_NOWAIT);
	}
}

/**
 * 守护进程处理 ip_denined 消息时的处理线程
 */
void axl_msg_handler_ip_denined(){
	int ret;
	axl_msgbuf_int_t retmsg;
	axl_msgbuf_t msg;
	
	retmsg.mtype = AXL_MTYPE_RET;
	
	for (;;) {
		msgrcv(axl_pmsgid, &msg, sizeof(msg) - sizeof(msg.mtype), AXL_MTYPE_IPDENINED, 0L);
		
		ret = axl_ip_denined(msg.sess_id);
		retmsg.msg = ret;
		msgsnd(msg.retid, &retmsg, sizeof(retmsg) - sizeof(retmsg.mtype), IPC_NOWAIT);
	}
}
#endif	/* END AXL_WITH_FORKSUPPORT */

#ifdef AXL_WITH_UNIIDSUPPORT
/**
 * 调用此函数可返回一个唯一的编号，线程/进程安全
 */
unsigned long axl_uniid_get(){
	unsigned long ret;
	unsigned long *num;
	
	num = (unsigned long *)shmat(axl_uniid_shmid, 0, 0);

	sem_wait(axl_uniid_sem);
	ret = ++(*num);
	sem_post(axl_uniid_sem);
	
	shmdt(num);
	
	return ret;
}
#endif /* END AXL_WITH_UNIIDSUPPORT */

/**
 * 下面开始到最后都是调试用的
 */
#ifdef AXL_DEBUG_MAIN

#define A(CMD, UID)	\
	printf("cmd=%d, is_xunlei=%d\n", CMD, axl_recive_command(CMD, UID));	\
	//axl_recive_command(CMD,UID);

//#define msgkey 11605532

int main(){
	axl_init();
	
	//printf("msgid=%d\n", msgget(msgkey, IPC_CREAT | IPC_EXCL | 0666));

/*
	A(AXL_FTPCMD_USER, 1);
	A(AXL_FTPCMD_PASS, 1);
	
	//axl_recive_password("IEUser@", 1);
	//msgid = msgget(msgkey, IPC_CREAT | IPC_EXCL | 00660);
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
	*/
	
	//axl_ip_deny(50);
	axl_ip_deny(100);
	axl_ip_deny(200);
	axl_ip_deny(300);
	
	
	while(1){
		pid_t pid;
		if ((pid = fork()) == 0) {
			//exit(0);
			printf("(fork)pid=%d\n", getpid());
			static unsigned long a = 1;
			a = random() + 1;
			printf("(%d)::%d\n", getpid(), axl_ip_deny(a));
			printf("#%d#:*%.8x\n", getpid(), axl_ip_denined(a));
			printf("#%d*:*%.8x\n", getpid(), axl_ip_denined(a + 1));
			printf("(%d):get_unique_id=%lu\n", getpid(), axl_uniid_get());
			usleep(random() % 6000000);
			printf("(child_proc %d)exit\n", getpid());
			exit(0);
		}
		else {
			static unsigned long b = 1;
			b = random() + 1;
			printf("((p)%d)::%d\n", getpid(), axl_ip_deny(b));
			printf("pid=%d\n", getpid());
		}
		usleep(random() % 6000000);
	}

	return 0;
}

#endif
