#ifndef __HASHTABLE_H__
#include "libantixunlei.h"
#include "linklist.h"

#define __HASHTABLE_H__

#define HASHTABLE_SIZE	10003	//哈希表默认大小，建议使用一个素数，不建议使用2的指数
#define HASHTABLE_MAX_CONFLICT 3	//最多冲突次数，达到此冲突次数后将从本次哈希1函数命中的节点进行二级索引的查找

typedef struct hashtable_node_t {
	axl_valtype value;
	axl_keytype key;
	linklist_node_t* linknode;
} hashtable_node_t;

typedef struct hashtable_t {
	hashtable_node_t* nodes;
	unsigned long size;
} hashtable_t;
	

axl_valtype* hashtable_find(hashtable_t* h, axl_keytype key);
hashtable_node_t* hashtable_find_1(hashtable_t* h, axl_keytype key, linklist_node_t** linknode);
axl_valtype* hashtable_add(hashtable_t* h, axl_keytype key, axl_valtype value);
int hashtable_delete(hashtable_t* h, axl_keytype key);
hashtable_t* hashtable_init(unsigned long size);
int hashtable_destroy(hashtable_t* h);
unsigned long hashtable_hashfunc_1(axl_keytype key);
unsigned long hashtable_hashfunc_2(axl_keytype key);

#define HASHTABLE_SHOW(H)	{	\
	int i; linklist_node_t* ln; printf("---- %lu ------\n", H->size); \
	for (i = 0; i < H->size; i++) {	\
		ln = H->nodes[i].linknode;	\
		printf("#%8.8x,%2lu#", H->nodes + i, H->nodes[i].key);	\
		while (ln) {	\
			printf("->(%8.8x,%2lu)", ln, ln->key);	\
			ln = ln->next;	\
		}	\
		printf("\n");	\
	}printf("---- %lu ------\n", H->size);	\
}	\
	

#endif
