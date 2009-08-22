#include <stdlib.h>

#include "hashtable.h"
#include "libantixunlei.h"

axl_valtype* hashtable_find(hashtable_t* h, axl_keytype key){
	linklist_node_t* linknode;
	hashtable_node_t* hashnode;
	
	linknode = NULL;
	
	hashnode = hashtable_find_1(h, key, &linknode);
	
	if (hashnode != NULL) {
		//printf("rturn hashnode\n");
		return &hashnode->value;
	}
	
	if (linknode != NULL) {
		//printf("find in %8.8x\n", linknode);
		//printf("return linknode: %lu\n", linklist_find(linknode, key)->next_cmd_sequence_pos);
		return linklist_find(linknode, key);
	}
	
	return NULL;
}

axl_valtype* hashtable_add(hashtable_t* h, axl_keytype key, axl_valtype value){
	linklist_node_t* linknode;
	int conflicts = 1;
	unsigned long idx, hash;
	
	hash = hashtable_hashfunc_1(key);
	idx = hash % h->size;
	if (h->nodes[idx].key == 0) {
		// 如果没有命中，则说明可以插入这个项里面
		h->nodes[idx].key = key;
		h->nodes[idx].value = value;
		return &h->nodes[idx].value;
	}
	
	// 否则，进行再哈希
	//printf("+zhx=%lu\n", key);
	while (++conflicts <= HASHTABLE_MAX_CONFLICT) {
		hash = hashtable_hashfunc_2(hash);
		idx = hash % h->size;
		//printf("+zhx->idx=%ld\n", idx);
		if (h->nodes[idx].key == 0) {
			h->nodes[idx].key = key;
			h->nodes[idx].value = value;
			return &h->nodes[idx].value;
		}
	}
	
	// 在哈希表中没有找到匹配的项，插入到链表中
	linknode = (linklist_node_t*)malloc(sizeof(linklist_node_t));
	//printf("to link, node addr=%8.8x\n", linknode);
	linknode->key = key;
	linknode->value = value;
	linknode->next = NULL;
	h->nodes[idx].linknode = linklist_add(h->nodes[idx].linknode, linknode);
		
	return &linknode->value;
}

int hashtable_delete(hashtable_t* h, axl_keytype key){
	unsigned long idx, hash;
	linklist_node_t* lnode;
	int conflicts;
	
	conflicts = 1;

	// 一次哈希
	hash = hashtable_hashfunc_1(key);
	idx = hash % h->size;
	//printf("-hx=%lu, idx=%lu\n", key, idx);
	if (AXL_KEY_COMPARE(h->nodes[idx].key, key)) {
		if (h->nodes[idx].linknode == NULL) {
			h->nodes[idx].key = 0;
		}
		else {
			lnode = h->nodes[idx].linknode;
			h->nodes[idx].key = h->nodes[idx].linknode->key;
			h->nodes[idx].value = h->nodes[idx].linknode->value;
			h->nodes[idx].linknode = h->nodes[idx].linknode->next;
			free(lnode);
		}
		
		return 0;
	}
	
	// 再哈希
	while (++conflicts <= HASHTABLE_MAX_CONFLICT) {
		hash = hashtable_hashfunc_2(hash);
		idx = hash % h->size;
		//printf("-zhx=%lu, idx=%lu, nodes[idx]=%lu, conflicts=%d\n", key, idx, h->nodes[idx].key, conflicts);
		if (AXL_KEY_COMPARE(h->nodes[idx].key, key)) {
			if (h->nodes[idx].linknode == NULL) {
				//printf("NULL");exit(0);
				h->nodes[idx].key = 0;
				h->nodes[idx].linknode = NULL;
			}
			else {
				//printf("NOTNULL");exit(0);
				lnode = h->nodes[idx].linknode;
				h->nodes[idx].key = h->nodes[idx].linknode->key;
				h->nodes[idx].value = h->nodes[idx].linknode->value;
				h->nodes[idx].linknode = h->nodes[idx].linknode->next;
				free(lnode);
			}
			
			return 0;
		}
	}
	
	// 在哈希表中找不到项，则查找链表
	if (h->nodes[idx].linknode == NULL) return -1;
	h->nodes[idx].linknode = linklist_delete(h->nodes[idx].linknode, key);

	return 0;
}

hashtable_t* hashtable_init(unsigned long size){
	hashtable_t* h;
	hashtable_node_t* n;
	unsigned long i;
	
	if (size == 0) size = HASHTABLE_SIZE;
	
	h = (hashtable_t*)malloc(sizeof(hashtable_t));
	if (!h) return NULL;
	n = (hashtable_node_t*)malloc(sizeof(hashtable_node_t) * size);
	if (!n) {
		free(h);
		return NULL;
	}
	
	for (i = 0; i < size; i++) {
		n[i].key = 0;
		n[i].linknode = NULL;
	}
	
	h->nodes = n;
	h->size = size;
	
	return h;
}
	
	
int hashtable_destroy(hashtable_t* h) {
	unsigned long i;
	hashtable_node_t* n;
	
	n = h->nodes;
	for (i = 0; i < h->size; i++) {
		if (n[i].linknode != NULL) linklist_destroy(n[i].linknode);
	}
	free(h->nodes);
	
	free(h);
	
	return 0;
}

/**
 * 在哈希表（不包括二级索引）中查找HASHTABLE_MAX_CONFLICT次，如果项在哈希表中，则返回项指针，否则返回空指针。
 * 如果最后一次哈希到的项没有命中，但是该项有指向二级索引的指针，则将linknode设为二级索引的指针，否则将linknode设为NULL
 */
hashtable_node_t* hashtable_find_1(hashtable_t* h, axl_keytype key, linklist_node_t** linknode){
	unsigned long idx, hash;
	int conflicts = 1;
	
	// 一次查找
	hash = hashtable_hashfunc_1(key);
	idx = hash % h->size;
	if (AXL_KEY_COMPARE(key, h->nodes[idx].key)) return h->nodes + idx;
	
	// 再查找，包括第一次查找，最多查找HASHTABLE_MAX_CONFLICT次
	while (++conflicts <= HASHTABLE_MAX_CONFLICT) {
		hash = hashtable_hashfunc_2(hash);
		idx = hash % h->size;
		if (AXL_KEY_COMPARE(key, h->nodes[idx].key)) return h->nodes + idx;
	}
	
	// 哈希表中查找不到匹配的结果，返回挂在此哈希节点上的二级索引指针
	*linknode =  h->nodes[idx].linknode;
	
	return NULL;
}

/**
 * 哈希函数
 */
unsigned long hashtable_hashfunc_1(axl_keytype key){
	return key;
}

/**
 * 再哈希函数
 */
unsigned long hashtable_hashfunc_2(axl_keytype key) {
	// 这其实是AP Hash函数
	unsigned long hash = 0;
	int i;
	char* str;
	
	str = (char*)&key;
 
	for (i = 0; i < 4; i++) {
		if ((i & 1) == 0) {
			hash ^= ((hash << 7) ^ (*str++) ^ (hash >> 3));
		}
		else {
			hash ^= (~((hash << 11) ^ (*str++) ^ (hash >> 5)));
		}
	}
 
	return (hash & 0x7FFFFFFF);
}

/*

int main1(){
	hashtable_t* h;
	axl_client_node_t c;
	unsigned long i;
		
	//c = (axl_client_node_t*)malloc(sizeof(axl_client_node_t));

while (1) {
	h = hashtable_init(700);
	int r;

	hashtable_add(h, 55, c);
	hashtable_add(h, 69, c);
	hashtable_add(h, 62, c);
	hashtable_add(h, 48, c);
	hashtable_add(h, 41, c);
	hashtable_add(h, 35, c);
	hashtable_add(h, 26, c);

	srand(rand());
	r = rand() % 30000;
	//printf("+r=%d\n", r);
	for (i = 0; i < r; i ++) {
		//c = (axl_client_node_t*)malloc(sizeof(axl_client_node_t));
		//c->next_cmd_sequence_pos = i + 10000;
		//c->is_thunder = ISTHUNDER_UNKNOW;
		hashtable_add(h, (i * r) % 30000, c);
	}
	srand(rand());
	r = rand() % 30000;
	printf("-r=%d\n", r);
	for (i = 0; i < r; i--) {
		hashtable_delete(h, rand());
		//printf("--%d\n", rand());
	}
	//HASHTABLE_SHOW(h);

	hashtable_destroy(h);
	
}

	return 0;
}
*/
