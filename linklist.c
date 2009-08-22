#include "libantixunlei.h"
#include "linklist.h"

#include <stdlib.h>
#include <stdio.h>

/**
 * @return 添加成功则返回头节点，否则返回NULL
 */
linklist_node_t* linklist_add(linklist_node_t* head, linklist_node_t* node){
	linklist_node_t* p;
	
	// 如果head为空则创建节点
	if (head == NULL) {
		return node;
	}
	
	// 否则的话就插入到最后去
	p = head;
	while (p->next != NULL) p = p->next;
	p->next = node;
	
	return head;
}

/**
 * @return 删除成功则返回头节点指针（可能为空），删除失败或者没有找到索引项也返回NULL
 */
linklist_node_t* linklist_delete(linklist_node_t* head, linklist_keytype key){
	linklist_node_t* prev;
	linklist_node_t* p;
	
	p = prev = head;
	while (p != NULL) {
		if (LINKLIST_KEY_COMPARE(key, p->key)) {
			// 如果是头节点，删除之，并返回下一个节点指针；
			if (p == head) {
				p = head->next;
				free(head);
				return p;
			}
			else {
				// 如果不是头节点，而是尾节点，则直接删除之
				if (p->next == NULL) {
					free(p);
					prev->next = NULL;
					return head;
				}
				else {
					// 否则这就是一个中间节点，按照一般方法删除
					prev->next = p->next;
					free(p);
					return head;
				}
			}
		}
		
		prev = p;
		p = p->next;
	}
	
	return NULL;
}


axl_client_node_t* linklist_find(linklist_node_t* head, linklist_keytype key){
	//printf("ln find in %8.8x, key=%lu\n", head, key);
	while (head != NULL) {
		//printf("%lu==%lu, addr=%8.8x\n", key, head->key, head);
		if (LINKLIST_KEY_COMPARE(key, head->key)) {
			return &head->value;
		}
		
		head = head->next;
	}
	
	return NULL;
}
	
int linklist_destroy(linklist_node_t* head){
	linklist_node_t* p;
	p = head;
	
	while (p != NULL) {
		head = head->next;
		free(p);
		p = head;
	}
	
	return 0;
}
