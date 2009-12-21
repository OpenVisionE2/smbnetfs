#ifndef __LIST_H__
#define __LIST_H__

#include <stddef.h>

typedef struct __LIST{
    struct __LIST	*next;
    struct __LIST	*prev;
} LIST;

#define list_entry(ptr, type, member)		\
    (type*)((char*)(ptr) - offsetof(type, member))

#define STATIC_LIST_INITIALIZER(list)		{ &(list), &(list) }

static inline LIST* first_list_elem(LIST *list){
    return list->next;
}

static inline LIST* last_list_elem(LIST *list){
    return list->prev;
}

static inline void add_to_list(LIST *list, LIST *elem){
    /* Yes, i want SIGSEGV for debug */
    if ((elem->next != NULL) || (elem->prev != NULL)) *((char*)NULL) = '\0';

    elem->next = list->next;
    elem->prev = list;
    list->next->prev = elem;
    list->next = elem;
}

static inline void add_to_list_back(LIST *list, LIST *elem){
    /* Yes, i want SIGSEGV for debug */
    if ((elem->next != NULL) || (elem->prev != NULL)) *((char*)NULL) = '\0';

    elem->next = list;
    elem->prev = list->prev;
    list->prev->next = elem;
    list->prev = elem;
}

static inline void insert_to_list_after(LIST *list, LIST *elem, LIST *new_elem){
    (void)list;

    /* Yes, i want SIGSEGV for debug */
    if ((new_elem->next != NULL) || (new_elem->prev != NULL)) *((char*)NULL) = '\0';

    new_elem->next = elem->next;
    new_elem->prev = elem;
    elem->next->prev = new_elem;
    elem->next = new_elem;
}

static inline void insert_to_list_before(LIST *list, LIST *elem, LIST *new_elem){
    (void)list;

    /* Yes, i want SIGSEGV for debug */
    if ((new_elem->next != NULL) || (new_elem->prev != NULL)) *((char*)NULL) = '\0';

    new_elem->next = elem;
    new_elem->prev = elem->prev;
    elem->prev->next = new_elem;
    elem->prev = new_elem;
}

static inline void replace_in_list(LIST *list, LIST *elem, LIST *new_elem){
    (void)list;
    new_elem->next = elem->next;
    new_elem->prev = elem->prev;
    elem->next->prev = new_elem;
    elem->prev->next = new_elem;
    elem->next = elem->prev = NULL;
}

static inline void remove_from_list(LIST *list, LIST *elem){
    (void)list;
    elem->prev->next = elem->next;
    elem->next->prev = elem->prev;
    elem->next = elem->prev = NULL;
}

static inline int is_list_empty(LIST *list){
    return (list == list->next);
}

static inline int is_valid_list_elem(LIST *list, LIST *elem){
    return (elem != list);
}

static inline void init_list(LIST *list){
    list->next = list->prev = list;
}

#endif	/* __LIST_H__ */
