#ifndef __LINKLIST_H__
#define __LINKLIST_H__

#include "libantixunlei.h"

#define linklist_keytype axl_keytype
#define linklist_valtype axl_valtype

#define LINKLIST_KEY_COMPARE(VAL1, VAL2)	((VAL1) == (VAL2))


typedef struct linklist_node_t {
	linklist_keytype key;
	linklist_valtype value;
	struct linklist_node_t* next;
} linklist_node_t;


linklist_node_t* linklist_add(linklist_node_t* head, linklist_node_t* node);
linklist_node_t* linklist_delete(linklist_node_t* head, linklist_keytype key);
axl_client_node_t* linklist_find(linklist_node_t* head, linklist_keytype key);
int linklist_destroy(linklist_node_t* head);


#endif
