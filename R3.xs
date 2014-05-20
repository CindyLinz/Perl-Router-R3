#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "const-c.inc"

//#define PERL_R3_DEBUG

/* __R3_SOURCE_SLOT_BEGIN__ */
/******* ../include/r3_define.h *******/
/*
 * r3_define.h
 * Copyright (C) 2014 c9s <c9s@c9smba.local>
 *
 * Distributed under terms of the MIT license.
 */

#ifndef DEFINE_H
#define DEFINE_H

#ifndef bool
typedef unsigned char bool;
#endif
#ifndef FALSE
#    define FALSE 0
#endif
#ifndef TRUE
#    define TRUE 1
#endif

// #define DEBUG 1
#ifdef DEBUG

#define info(fmt, ...) \
            do { fprintf(stderr, fmt, __VA_ARGS__); } while (0)

#define debug(fmt, ...) \
        do { fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
                                __LINE__, __func__, __VA_ARGS__); } while (0)

#else
#define info(...);
#define debug(...);
#endif

#endif /* !DEFINE_H */
/******* ../include/str_array.h *******/
/*
 * str_array.h
 * Copyright (C) 2014 c9s <c9s@c9smba.local>
 *
 * Distributed under terms of the MIT license.
 */

#ifndef TOKEN_H
#define TOKEN_H

/* #include "r3_define.h" */

typedef struct _str_array {
  char **tokens;
  int    len;
  int    cap;
} str_array;

str_array * str_array_create(int cap);

bool str_array_is_full(str_array * l);

bool str_array_resize(str_array *l, int new_cap);

bool str_array_append(str_array * list, char * token);

void str_array_free(str_array *l);

void str_array_dump(str_array *l);

str_array * split_route_pattern(char *pattern, int pattern_len);

#define str_array_fetch(t,i)  t->tokens[i]
#define str_array_len(t)  t->len
#define str_array_cap(t)  t->cap

#endif /* !TOKEN_H */
/******* ../include/r3.h *******/
/*
 * r3.h
 * Copyright (C) 2014 c9s <c9s@c9smba.local>
 *
 * Distributed under terms of the MIT license.
 */

#ifndef NODE_H
#define NODE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pcre.h>

/* #include "r3_define.h" */
/* #include "str_array.h" */


#define node_edge_pattern(node,i) node->edges[i]->pattern
#define node_edge_pattern_len(node,i) node->edges[i]->pattern_len


struct _edge;
struct _node;
struct _route;
typedef struct _edge edge;
typedef struct _node node;
typedef struct _route route;

struct _node {
    edge  ** edges;
    route ** routes;
    int      edge_len;
    int      edge_cap;
    int      route_len;
    int      route_cap;
    int endpoint;

    /** compile-time variables here.... **/

    /* the combined regexp pattern string from pattern_tokens */
    char * combined_pattern;
    int    combined_pattern_len;
    int    ov_cnt;
    int *  ov;
    pcre * pcre_pattern;
    pcre_extra * pcre_extra;

    /**
     * the pointer of route data
     */
    void * data;

};

struct _edge {
    char * pattern;
    int    pattern_len;
    bool   has_slug;
    node * child;
};

typedef struct {
    str_array * vars;
    char * path; // current path to dispatch
    int    path_len; // the length of the current path
    int    request_method;  // current request method

    void * data; // route ptr

    char * host; // the request host 
    int    host_len;

    char * remote_addr;
    int    remote_addr_len;
} match_entry;

struct _route {
    char * path;
    int    path_len;

    int    request_method; // can be (GET || POST)

    char * host; // required host name
    int    host_len;

    void * data;

    char * remote_addr_pattern;
    int    remote_addr_pattern_len;
};


node * r3_tree_create(int cap);

node * r3_node_create();

void r3_tree_free(node * tree);

void r3_edge_free(edge * edge);

edge * r3_node_add_child(node * n, char * pat , node *child);

edge * r3_node_find_edge(node * n, char * pat);

void r3_node_append_edge(node *n, edge *child);


node * r3_tree_insert_pathl(node *tree, char *path, int path_len, void * data);

#define r3_tree_insert_path(n,p,d) r3_tree_insert_pathl_(n,p,strlen(p), NULL, d)
#define r3_tree_insert_route(n,r,d) r3_tree_insert_pathl_(n, r->path, r->path_len, r, d)

/**
 * The private API to insert a path
 */
node * r3_tree_insert_pathl_(node *tree, char *path, int path_len, route * route, void * data);

void r3_tree_dump(node * n, int level);

int r3_tree_render_file(node * tree, char * format, char * filename);

int r3_tree_render_dot(node * tree);

edge * r3_node_find_edge_str(node * n, char * str, int str_len);


void r3_tree_compile(node *n);

void r3_tree_compile_patterns(node * n);

node * r3_tree_matchl(node * n, char * path, int path_len, match_entry * entry);

#define r3_tree_match(n,p,e)  r3_tree_matchl(n,p, strlen(p), e)

// node * r3_tree_match_entry(node * n, match_entry * entry);
#define r3_tree_match_entry(n, entry) r3_tree_matchl(n, entry->path, entry->path_len, entry)

bool r3_node_has_slug_edges(node *n);

edge * r3_edge_create(char * pattern, int pattern_len, node * child);

node * r3_edge_branch(edge *e, int dl);

void r3_edge_free(edge * edge);



match_entry * match_entry_createl(char * path, int path_len);

#define match_entry_create(path) match_entry_createl(path,strlen(path))

void match_entry_free(match_entry * entry);


route * r3_route_create(char * path);

route * r3_route_createl(char * path, int path_len);

int r3_route_cmp(route *r1, match_entry *r2);

void r3_node_append_route(node * n, route * route);

void r3_route_free(route * route);

route * r3_tree_match_route(node *n, match_entry * entry);

#define METHOD_GET 2
#define METHOD_POST 2<<1
#define METHOD_PUT 2<<1
#define METHOD_DELETE 2<<1

#endif /* !NODE_H */
/******* ../include/r3_list.h *******/
/*
 * r3_list.h
 * Copyright (C) 2014 c9s <c9s@c9smba.local>
 *
 * Distributed under terms of the MIT license.
 */

#ifndef LIST_H
#define LIST_H

#include <pthread.h>
 
typedef struct _list_item {
  void *value;
  struct _list_item *prev;
  struct _list_item *next;
} list_item;
 
typedef struct {
  int count;
  list_item *head;
  list_item *tail;
  pthread_mutex_t mutex;
} list;
 
list *list_create();
void list_free(list *l);
 
list_item *list_add_element(list *l, void *ptr);
int list_remove_element(list *l, void *ptr);
void list_each_element(list *l, int (*func)(list_item *));
 


#endif /* !LIST_H */
/******* ../include/r3_str.h *******/
/*
 * r3_str.h
 * Copyright (C) 2014 c9s <c9s@c9smba.local>
 *
 * Distributed under terms of the MIT license.
 */
#ifndef STR_H
#define STR_H

/* #include "r3.h" */
/* #include "config.h" */

int slug_count(char * p, int len);

char * slug_compile(char * str, int len);

bool contains_slug(char * str);

char * find_slug_pattern(char *s1, int *len);

char * find_slug_placeholder(char *s1, int *len);

char * inside_slug(char * needle, int needle_len, char *offset);

char * ltrim_slash(char* str);

void str_repeat(char *s, char *c, int len);

void print_indent(int level);

#ifndef HAVE_STRDUP
char *my_strdup(const char *s);
#endif

#ifndef HAVE_STRNDUP
char *my_strndup(const char *s, int n);
#endif


#endif /* !STR_H */

/******* ../src/edge.c *******/
/*
 * edge.c
 * Copyright (C) 2014 c9s <c9s@c9smba.local>
 *
 * Distributed under terms of the MIT license.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Jemalloc memory management
// #include <jemalloc/jemalloc.h>

// PCRE
#include <pcre.h>

// Judy array
// #include <Judy.h>
#include <config.h>

/* #include "r3.h" */
/* #include "r3_str.h" */
/* #include "str_array.h" */

edge * r3_edge_create(char * pattern, int pattern_len, node * child) {
    edge * e = (edge*) malloc( sizeof(edge) );
    e->pattern = pattern;
    e->pattern_len = pattern_len;
    e->child = child;
    return e;
}



/**
 * branch the edge pattern at "dl" offset,
 * insert a dummy child between the edges.
 *
 *
 * A -> [prefix..suffix] -> B
 * A -> [prefix] -> B -> [suffix] -> New Child (Copy Data, Edges from B)
 *
 */
node * r3_edge_branch(edge *e, int dl) {
    node *new_child;
    edge *e1;
    char * s1 = e->pattern + dl;
    int s1_len = 0;

    edge **tmp_edges = e->child->edges;
    int   tmp_edge_len = e->child->edge_len;

    // the suffix edge of the leaf
    new_child = r3_tree_create(3);
    s1_len = e->pattern_len - dl;
    e1 = r3_edge_create(my_strndup(s1, s1_len), s1_len, new_child);

    // Migrate the child edges to the new edge we just created.
    for ( int i = 0 ; i < tmp_edge_len ; i++ ) {
        r3_node_append_edge(new_child, tmp_edges[i]);
        e->child->edges[i] = NULL;
    }
    e->child->edge_len = 0;
    new_child->endpoint = e->child->endpoint;
    e->child->endpoint = 0; // reset endpoint

    r3_node_append_edge(e->child, e1);
    new_child->data = e->child->data; // copy data pointer
    e->child->data = NULL;

    // truncate the original edge pattern 
    char *op = e->pattern;
    e->pattern = my_strndup(e->pattern, dl);
    e->pattern_len = dl;
    free(op);
    return new_child;
}

void r3_edge_free(edge * e) {
    if (e->pattern) {
        free(e->pattern);
    }
    if ( e->child ) {
        r3_tree_free(e->child);
    }
}

/******* ../src/list.c *******/
/*
 * list.c
 * Copyright (C) 2014 c9s <c9s@c9smba.local>
 *
 * Distributed under terms of the MIT license.
 */
#include <stdlib.h>
/* #include "r3_list.h" */
 
/* Naive linked list implementation */
 
list *
list_create()
{
  list *l = (list *) malloc(sizeof(list));
  l->count = 0;
  l->head = NULL;
  l->tail = NULL;
  pthread_mutex_init(&(l->mutex), NULL);
  return l;
}
 
void
list_free(l)
  list *l;
{
  list_item *li, *tmp;
 
  pthread_mutex_lock(&(l->mutex));
 
  if (l != NULL) {
    li = l->head;
    while (li != NULL) {
      tmp = li->next;
      free(li);
      li = tmp;
    }
  }
 
  pthread_mutex_unlock(&(l->mutex));
  pthread_mutex_destroy(&(l->mutex));
  free(l);
}
 
list_item *
list_add_element(l, ptr)
  list *l;
  void *ptr;
{
  list_item *li;
 
  pthread_mutex_lock(&(l->mutex));
 
  li = (list_item *) malloc(sizeof(list_item));
  li->value = ptr;
  li->next = NULL;
  li->prev = l->tail;
 
  if (l->tail == NULL) {
    l->head = l->tail = li;
  }
  else {
    l->tail = li;
  }
  l->count++;
 
  pthread_mutex_unlock(&(l->mutex));
 
  return li;
}
 
int
list_remove_element(l, ptr)
  list *l;
  void *ptr;
{
  int result = 0;
  list_item *li = l->head;
 
  pthread_mutex_lock(&(l->mutex));
 
  while (li != NULL) {
    if (li->value == ptr) {
      if (li->prev == NULL) {
        l->head = li->next;
      }
      else {
        li->prev->next = li->next;
      }
 
      if (li->next == NULL) {
        l->tail = li->prev;
      }
      else {
        li->next->prev = li->prev;
      }
      l->count--;
      free(li);
      result = 1;
      break;
    }
    li = li->next;
  }
 
  pthread_mutex_unlock(&(l->mutex));
 
  return result;
}
 
void
list_each_element(l, func)
  list *l;
  int (*func)(list_item *);
{
  list_item *li;
 
  pthread_mutex_lock(&(l->mutex));
 
  li = l->head;
  while (li != NULL) {
    if (func(li) == 1) {
      break;
    }
    li = li->next;
  }
 
  pthread_mutex_unlock(&(l->mutex));
}
/******* ../src/node.c *******/
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Jemalloc memory management
// #include <jemalloc/jemalloc.h>

// PCRE
#include <pcre.h>

// Judy array
// #include <Judy.h>

/* #include "r3.h" */
/* #include "r3_define.h" */
/* #include "r3_str.h" */
/* #include "str_array.h" */

// String value as the index http://judy.sourceforge.net/doc/JudySL_3x.htm


static int strndiff(char * d1, char * d2, unsigned int n) {
    char * o = d1;
    while ( *d1 == *d2 && n-- > 0 ) { 
        d1++;
        d2++;
    }
    return d1 - o;
}

static int strdiff(char * d1, char * d2) {
    char * o = d1;
    while( *d1 == *d2 ) { 
        d1++;
        d2++;
    }
    return d1 - o;
}


/**
 * Create a node object
 */
node * r3_tree_create(int cap) {
    node * n = (node*) malloc( sizeof(node) );

    n->edges = (edge**) malloc( sizeof(edge*) * cap );
    n->edge_len = 0;
    n->edge_cap = cap;

    n->routes = NULL;
    n->route_len = 0;
    n->route_cap = 0;

    n->endpoint = 0;
    n->combined_pattern = NULL;
    n->pcre_pattern = NULL;
    n->pcre_extra = NULL;
    n->ov_cnt = 0;
    n->ov = NULL;
    return n;
}

void r3_tree_free(node * tree) {
    for (int i = 0 ; i < tree->edge_len ; i++ ) {
        if (tree->edges[i]) {
            r3_edge_free(tree->edges[ i ]);
        }
    }
    if (tree->edges)
        free(tree->edges);
    if (tree->routes)
        free(tree->routes);
    if (tree->combined_pattern)
        free(tree->combined_pattern);
    if (tree->pcre_pattern)
        free(tree->pcre_pattern);
    if (tree->pcre_extra)
        free(tree->pcre_extra);
    if (tree->ov) 
        free(tree->ov);
    free(tree);
    tree = NULL;
}



/* parent node, edge pattern, child */
edge * r3_node_add_child(node * n, char * pat , node *child) {
    // find the same sub-pattern, if it does not exist, create one

    edge * e;

    e = r3_node_find_edge(n, pat);
    if (e) {
        return e;
    }

    e = r3_edge_create( pat, strlen(pat), child);
    r3_node_append_edge(n, e);
    // str_array_append(n->edge_patterns, pat);
    // assert( str_array_len(n->edge_patterns) == n->edge_len );
    return e;
}



void r3_node_append_edge(node *n, edge *e) {
    if (n->edges == NULL) {
        n->edge_cap = 3;
        n->edges = malloc(sizeof(edge) * n->edge_cap);
    }
    if (n->edge_len >= n->edge_cap) {
        n->edge_cap *= 2;
        edge ** p = realloc(n->edges, sizeof(edge) * n->edge_cap);
        if(p) {
            n->edges = p;
        }
    }
    n->edges[ n->edge_len++ ] = e;
}

edge * r3_node_find_edge(node * n, char * pat) {
    edge * e;
    for (int i = 0 ; i < n->edge_len ; i++ ) {
        e = n->edges[i];
        if ( strcmp(e->pattern, pat) == 0 ) {
            return e;
        }
    }
    return NULL;
}

void r3_tree_compile(node *n)
{
    bool use_slug = r3_node_has_slug_edges(n);
    if ( use_slug ) {
        r3_tree_compile_patterns(n);
    } else {
        // use normal text matching...
        n->combined_pattern = NULL;
    }

    for (int i = 0 ; i < n->edge_len ; i++ ) {
        r3_tree_compile(n->edges[i]->child);
    }
}


/**
 * This function combines ['/foo', '/bar', '/{slug}'] into (/foo)|(/bar)|/([^/]+)}
 *
 */
void r3_tree_compile_patterns(node * n) {
    char * cpat;
    char * p;

    cpat = calloc(sizeof(char),128);
    if (cpat==NULL)
        return;

    p = cpat;

    strncat(p, "^", 1);
    p++;

    edge *e = NULL;
    for ( int i = 0 ; i < n->edge_len ; i++ ) {
        e = n->edges[i];
        if ( e->has_slug ) {
            char * slug_pat = slug_compile(e->pattern, e->pattern_len);
            strcat(p, slug_pat);
        } else {
            strncat(p++,"(", 1);

            strncat(p, e->pattern, e->pattern_len);
            p += e->pattern_len;

            strncat(p++,")", 1);
        }

        if ( i + 1 < n->edge_len && n->edge_len > 1 ) {
            strncat(p++,"|",1);
        }
    }

    info("pattern: %s\n",cpat);

    n->ov_cnt = (1 + n->edge_len) * 3;
    n->ov = (int*) calloc(sizeof(int), n->ov_cnt);


    n->combined_pattern = cpat;
    n->combined_pattern_len = p - cpat;


    const char *error;
    int erroffset;
    unsigned int option_bits = 0;

    if (n->pcre_pattern)
        free(n->pcre_pattern);
    if (n->pcre_extra)
        free(n->pcre_extra);

    // n->pcre_pattern;
    n->pcre_pattern = pcre_compile(
            n->combined_pattern,              /* the pattern */
            option_bits,                                /* default options */
            &error,               /* for error message */
            &erroffset,           /* for error offset */
            NULL);                /* use default character tables */
    if (n->pcre_pattern == NULL) {
        printf("PCRE compilation failed at offset %d: %s, pattern: %s\n", erroffset, error, n->combined_pattern);
        return;
    }
    n->pcre_extra = pcre_study(n->pcre_pattern, 0, &error);
    if (n->pcre_extra == NULL) {
        printf("PCRE study failed at offset %s\n", error);
        return;
    }
}


match_entry * match_entry_createl(char * path, int path_len) {
    match_entry * entry = malloc(sizeof(match_entry));
    if(!entry)
        return NULL;
    entry->vars = str_array_create(3);
    entry->path = path;
    entry->path_len = path_len;
    entry->data = NULL;
    return entry;
}

void match_entry_free(match_entry * entry) {
    str_array_free(entry->vars);
    free(entry);
}



/**
 * This function matches the URL path and return the left node
 *
 * r3_tree_matchl returns NULL when the path does not match. returns *node when the path matches.
 *
 * @param node         n        the root of the tree
 * @param char*        path     the URL path to dispatch
 * @param int          path_len the length of the URL path.
 * @param match_entry* entry match_entry is used for saving the captured dynamic strings from pcre result.
 */
node * r3_tree_matchl(node * n, char * path, int path_len, match_entry * entry) {
    info("try matching: %s\n", path);

    edge *e;
    int rc;
    int i;

    // if the pcre_pattern is found, and the pointer is not NULL, then it's
    // pcre pattern node, we use pcre_exec to match the nodes
    if (n->pcre_pattern) {
        info("pcre matching %s on %s\n", n->combined_pattern, path);

        rc = pcre_exec(
                n->pcre_pattern,   /* the compiled pattern */

                // PCRE Study makes this slow
                NULL, // n->pcre_extra,     /* no extra data - we didn't study the pattern */
                path,              /* the subject string */
                path_len,          /* the length of the subject */
                0,                 /* start at offset 0 in the subject */
                0,                 /* default options */
                n->ov,           /* output vector for substring information */
                n->ov_cnt);      /* number of elements in the output vector */

        // info("rc: %d\n", rc );
        if (rc < 0) {
            switch(rc)
            {
                case PCRE_ERROR_NOMATCH: printf("No match\n"); break;
                /*
                Handle other special cases if you like
                */
                default: printf("Matching error %d\n", rc); break;
            }
            // does not match all edges, return NULL;
            return NULL;
        }


        for (i = 1; i < rc; i++)
        {
            char *substring_start = path + n->ov[2*i];
            int   substring_length = n->ov[2*i+1] - n->ov[2*i];
            // info("%2d: %.*s\n", i, substring_length, substring_start);

            if ( substring_length > 0) {
                int restlen = path_len - n->ov[1]; // fully match to the end
                // info("matched item => restlen:%d edges:%d i:%d\n", restlen, n->edge_len, i);

                e = n->edges[i - 1];

                if (entry && e->has_slug) {
                    // append captured token to entry
                    str_array_append(entry->vars , my_strndup(substring_start, substring_length));
                }
                if (restlen == 0 ) {
                    return e->child && e->child->endpoint > 0 ? e->child : NULL;
                }
                // get the length of orginal string: $0
                return r3_tree_matchl( e->child, path + (n->ov[1] - n->ov[0]), restlen, entry);
            }
        }
        // does not match
        return NULL;
    }

    if ( (e = r3_node_find_edge_str(n, path, path_len)) != NULL ) {
        int restlen = path_len - e->pattern_len;
        if (restlen == 0) {
            return e->child && e->child->endpoint > 0 ? e->child : NULL;
        }
        return r3_tree_matchl(e->child, path + e->pattern_len, restlen, entry);
    }
    return NULL;
}

route * r3_tree_match_route(node *tree, match_entry * entry) {
    node *n;
    n = r3_tree_match_entry(tree, entry);
    if (n->routes && n->route_len > 0) {
        int i;
        for (i = 0; i < n->route_len ; i++ ) {
            if ( r3_route_cmp(n->routes[i], entry) == 0 ) {
                return n->routes[i];
            }
        }
    }
    return NULL;
}

inline edge * r3_node_find_edge_str(node * n, char * str, int str_len) {
    int i = 0;
    int matched_idx = 0;

    for (; i < n->edge_len ; i++ ) {
        if ( *str == *(n->edges[i]->pattern) ) {
            matched_idx = i;
            break;
        }
    }

    info("matching '%s' with '%s'\n", str, node_edge_pattern(n,i) );
    if ( strncmp( node_edge_pattern(n,matched_idx), str, node_edge_pattern_len(n,matched_idx) ) == 0 ) {
        return n->edges[matched_idx];
    }
    return NULL;
}



node * r3_node_create() {
    node * n = (node*) malloc( sizeof(node) );
    n->edges = NULL;
    n->edge_len = 0;
    n->edge_cap = 0;

    n->routes = NULL;
    n->route_len = 0;
    n->route_cap = 0;

    n->endpoint = 0;
    n->combined_pattern = NULL;
    n->pcre_pattern = NULL;
    return n;
}


route * r3_route_create(char * path) {
    return r3_route_createl(path, strlen(path));
}

void r3_route_free(route * route) {
    free(route);
}

route * r3_route_createl(char * path, int path_len) {
    route * info = malloc(sizeof(route));
    info->path = path;
    info->path_len = path_len;
    info->request_method = 0; // can be (GET || POST)

    info->data = NULL;

    info->host = NULL; // required host name
    info->host_len = 0;

    info->remote_addr_pattern = NULL;
    info->remote_addr_pattern_len = 0;
    return info;
}

node * r3_tree_insert_pathl(node *tree, char *path, int path_len, void * data)
{
    return r3_tree_insert_pathl_(tree, path, path_len, NULL , data);
}


/**
 * Return the last inserted node.
 */
node * r3_tree_insert_pathl_(node *tree, char *path, int path_len, route * route, void * data)
{
    node * n = tree;
    edge * e = NULL;

    /* length of common prefix */
    int prefix_len = 0;
    for( int i = 0 ; i < n->edge_len ; i++ ) {
        prefix_len = strndiff(path, n->edges[i]->pattern, n->edges[i]->pattern_len);

        // printf("prefix_len: %d   %s vs %s\n", prefix_len, path, n->edges[i]->pattern );

        // no common, consider insert a new edge
        if ( prefix_len > 0 ) {
            e = n->edges[i];
            break;
        }
    }

    // branch the edge at correct position (avoid broken slugs)
    char *slug_s;
    if ( (slug_s = inside_slug(path, path_len, path + prefix_len)) != NULL ) {
        prefix_len = slug_s - path;
    }

    // common prefix not found, insert a new edge for this pattern
    if ( prefix_len == 0 ) {
        // there are two more slugs, we should break them into several parts
        if ( slug_count(path, path_len) > 1 ) {
            int   slug_len;
            char *p = find_slug_placeholder(path, &slug_len);

#ifdef DEBUG
            assert(p);
#endif

            // find the next one
            if(p) {
                p = find_slug_placeholder(p + slug_len + 1, NULL);
            }
#ifdef DEBUG
            assert(p);
#endif

            // insert the first one edge, and break at "p"
            node * child = r3_tree_create(3);
            r3_node_add_child(n, my_strndup(path, (int)(p - path)), child);
            child->endpoint = 0;

            // and insert the rest part to the child
            return r3_tree_insert_pathl_(child, p, path_len - (int)(p - path),  route, data);
        } else {
            node * child = r3_tree_create(3);
            r3_node_add_child(n, my_strndup(path, path_len) , child);
            // info("edge not found, insert one: %s\n", path);
            child->data = data;
            child->endpoint++;

            if (route) {
                route->data = data;
                r3_node_append_route(child, route);
            }
            return child;
        }
    } else if ( prefix_len == e->pattern_len ) {    // fully-equal to the pattern of the edge

        char * subpath = path + prefix_len;
        int    subpath_len = path_len - prefix_len;

        // there are something more we can insert
        if ( subpath_len > 0 ) {
            return r3_tree_insert_pathl_(e->child, subpath, subpath_len, route, data);
        } else {
            // there are no more path to insert

            // see if there is an endpoint already
            if (e->child->endpoint > 0) {
                // XXX: return an error code instead of NULL
                return NULL;
            }
            e->child->endpoint++; // make it as an endpoint
            e->child->data = data;
            if (route) {
                route->data = data;
                r3_node_append_route(e->child, route);
            }
            return e->child;
        }

    } else if ( prefix_len < e->pattern_len ) {
        /* it's partially matched with the pattern,
         * we should split the end point and make a branch here...
         */
        char * s2 = path + prefix_len;
        int   s2_len = path_len - prefix_len;
        r3_edge_branch(e, prefix_len);
        return r3_tree_insert_pathl_(e->child, s2 , s2_len, route , data);
    } else {
        printf("unexpected route.");
        return NULL;
    }
    return n;
}

bool r3_node_has_slug_edges(node *n) {
    bool found = FALSE;
    edge *e;
    for ( int i = 0 ; i < n->edge_len ; i++ ) {
        e = n->edges[i];
        e->has_slug = contains_slug(e->pattern);
        if (e->has_slug) 
            found = TRUE;
    }
    return found;
}



void r3_tree_dump(node * n, int level) {
    print_indent(level);

    printf("(o)");

    if ( n->combined_pattern ) {
        printf(" regexp:%s", n->combined_pattern);
    }

    printf(" endpoint:%d", n->endpoint);

    if (n->data) {
        printf(" data:%p", n->data);
    }
    printf("\n");

    for ( int i = 0 ; i < n->edge_len ; i++ ) {
        edge * e = n->edges[i];
        print_indent(level + 1);
        printf("|-\"%s\"", e->pattern);

        if ( e->child ) {
            printf("\n");
            r3_tree_dump( e->child, level + 1);
        }
        printf("\n");
    }
}


/**
 * return 0 == equal
 *
 * -1 == different route
 */
int r3_route_cmp(route *r1, match_entry *r2) {
    if (r1->request_method != 0) {
        if (0 == (r1->request_method & r2->request_method) ) {
            return -1;
        }
    }

    if ( r1->path && r2->path ) {
        if ( strcmp(r1->path, r2->path) != 0 ) {
            return -1;
        }
    }

    if ( r1->host && r2->host ) {
        if (strcmp(r1->host, r2->host) != 0 ) {
            return -1;
        }
    }

    if (r1->remote_addr_pattern) {
        /*
         * XXX: consider "netinet/in.h"
        if (r2->remote_addr) {
            inet_addr(r2->remote_addr);
        }
        */
        if ( strcmp(r1->remote_addr_pattern, r2->remote_addr) != 0 ) {
            return -1;
        }
    }
    return 0;
}


/**
 * 
 */
void r3_node_append_route(node * n, route * r) {
    if (n->routes == NULL) {
        n->route_cap = 3;
        n->routes = malloc(sizeof(route) * n->route_cap);
    }
    if (n->route_len >= n->route_cap) {
        n->route_cap *= 2;
        n->routes = realloc(n->routes, sizeof(route) * n->route_cap);
    }
    n->routes[ n->route_len++ ] = r;
}


/******* ../src/str.c *******/
/*
 * str.c
 * Copyright (C) 2014 c9s <c9s@c9smba.local>
 *
 * Distributed under terms of the MIT license.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
/* #include "r3.h" */
/* #include "r3_str.h" */
/* #include "str_array.h" */

/**
 * provide a quick way to count slugs, simply search for '{'
 */
int slug_count(char * p, int len) {
    int s = 0;
    int lev = 0;
    while( len-- ) {
        if ( lev == 0 && *p == '{' )
            s++;
        if ( *p == '{' ) {
            lev++;
        }
        if ( *p == '}' ) {
            lev--;
        }
        p++;
    }
    return s;
}

bool contains_slug(char * str) {
    return strchr(str, '{') != NULL ? TRUE : FALSE;
}

char * inside_slug(char * needle, int needle_len, char *offset) {
    char * s1 = offset;
    char * s2 = offset;

    while( s1 >= needle ) {
        if ( *s1 == '{' ) {
            break;
        }
        s1--;
    }

    char *end = needle+ needle_len;
    while( s2 < end ) {
        if ( *s2 == '}' ) {
            break;
        }
        s2++;
    }

    if ( *s1 == '{' && *s2 == '}' ) {
        return s1;
    }
    return NULL;
}

char * find_slug_placeholder(char *s1, int *len) {
    char *c;
    char *s2;
    int cnt = 0;
    if ( NULL != (c = strchr(s1, '{')) ) {
        // find closing '}'
        s2 = c;
        while(*s2) {
            if (*s2 == '{' )
                cnt++;
            else if (*s2 == '}' )
                cnt--;
            if (cnt == 0)
                break;
            s2++;
        }
    } else {
        return NULL;
    }
    if (cnt!=0) {
        return NULL;
    }
    if(len) {
        *len = s2 - c + 1;
    }
    return c;
}


/**
 * given a slug string, duplicate the pattern string of the slug
 */
char * find_slug_pattern(char *s1, int *len) {
    char *c;
    char *s2;
    int cnt = 1;
    if ( NULL != (c = strchr(s1, ':')) ) {
        c++;
        // find closing '}'
        s2 = c;
        while(s2) {
            if (*s2 == '{' )
                cnt++;
            else if (*s2 == '}' )
                cnt--;
            if (cnt == 0)
                break;
            s2++;
        }

    } else {
        return NULL;
    }
    *len = s2 - c;
    return c;
}


/**
 * @param char * sep separator
 */
char * slug_compile(char * str, int len)
{
    char *s1 = NULL, *o = NULL;
    char *pat = NULL;
    char sep = '/';


    // append prefix
    int s1_len;
    s1 = find_slug_placeholder(str, &s1_len);

    if ( s1 == NULL ) {
        return my_strdup(str);
    }

    char * out = NULL;
    if ((out = calloc(sizeof(char),200)) == NULL) {
        return (NULL);
    }

    o = out;
    strncat(o, str, s1 - str); // string before slug
    o += (s1 - str);


    int pat_len;
    pat = find_slug_pattern(s1, &pat_len);

    if (pat) {
        *o = '(';
        o++;
        strncat(o, pat, pat_len );
        o += pat_len;
        *o = ')';
        o++;
    } else {
        sprintf(o, "([^%c]+)", sep);
        o+= strlen("([^*]+)");
    }
    s1 += s1_len;
    strncat(o, s1, strlen(s1));
    return out;
}


char * ltrim_slash(char* str)
{
    char * p = str;
    while (*p == '/') p++;
    return my_strdup(p);
}

void str_repeat(char *s, char *c, int len) {
    while(len--) {
        s[len - 1] = *c;
    }
}

void print_indent(int level) {
    int len = level * 2;
    while(len--) {
        printf(" ");
    }
}

#ifndef HAVE_STRDUP
char *my_strdup(const char *s) {
    char *out;
    int count = 0;
    while( s[count] )
        ++count;
    ++count;
    out = malloc(sizeof(char) * count);
    out[--count] = 0;
    while( --count >= 0 )
        out[count] = s[count];
    return out;
}
#endif

#ifndef HAVE_STRNDUP
char *my_strndup(const char *s, int n) {
    char *out;
    int count = 0;
    while( count < n && s[count] )
        ++count;
    ++count;
    out = malloc(sizeof(char) * count);
    out[--count] = 0;
    while( --count >= 0 )
        out[count] = s[count];
    return out;
}
#endif
/******* ../src/token.c *******/
/*
 * token.c
 * Copyright (C) 2014 c9s <c9s@c9smba.local>
 *
 * Distributed under terms of the MIT license.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
/* #include "str_array.h" */
/* #include "r3_str.h" */


str_array * str_array_create(int cap) {
    str_array * list = (str_array*) malloc( sizeof(str_array) );
    list->len = 0;
    list->cap = cap;
    list->tokens = (char**) malloc( sizeof(char*) * cap);
    return list;
}

void str_array_free(str_array *l) {
    for ( int i = 0; i < l->len ; i++ ) {
        char * t = l->tokens[ i ];
        free(t);
    }
    free(l);
}

bool str_array_is_full(str_array * l) {
    return l->len >= l->cap;
}

bool str_array_resize(str_array *l, int new_cap) {
    l->tokens = realloc(l->tokens, sizeof(char**) * new_cap);
    l->cap = new_cap;
    return l->tokens != NULL;
}

bool str_array_append(str_array * l, char * token) {
    if ( str_array_is_full(l) ) {
        bool ret = str_array_resize(l, l->cap + 20);
        if (ret == FALSE ) {
            return FALSE;
        }
    }
    l->tokens[ l->len++ ] = token;
    return TRUE;
}

void str_array_dump(str_array *l) {
    printf("[");
    for ( int i = 0; i < l->len ; i++ ) {
        printf("\"%s\"", l->tokens[i] );
        if ( i + 1 != l->len ) {
            printf(", ");
        }
    }
    printf("]\n");
}




/* __R3_SOURCE_SLOT_END__ */

#ifdef PERL_R3_DEBUG
void _test(){
    int route_data = 3;
    int ret;
    node * n = r3_tree_create(10);
    node *matched_node;
    match_entry * entry;

    // insert the route path into the router tree
    r3_tree_insert_path(n , "/post/{id:\\d{3}}/{id2}" , &route_data );
    r3_tree_insert_path(n , "/zoo"       , &route_data );
    r3_tree_insert_path(n , "/foo/bar"   , &route_data );
    r3_tree_insert_path(n , "/bar"       , &route_data );
    // r3_tree_insert_pathl(n , "abc"       , strlen("abc")       , &route_data );
    // r3_tree_insert_pathl(n , "ade"       , strlen("ade")       , &route_data );
    // r3_tree_insert_pathl(n , "/f/foo"       , strlen("/f/foo")       , &route_data );
    // r3_tree_insert_pathl(n , "/f/bar"       , strlen("/f/bar")       , &route_data );

    r3_tree_compile(n);


    r3_tree_dump(n, 0);

    entry = match_entry_createl( "/post/123/" , strlen("/post/123/") );
    matched_node = r3_tree_matchl(n, "/post/123/", strlen("/post/123/"), entry );
    printf("matched_node=%p\n", (void*)matched_node);
    if( matched_node ){
        printf("data=%p - %p\n", (void*)matched_node->data, (void*)&route_data);
        ret = *( (int*) matched_node->data );
        printf("ret=%d\n", ret);
    }
    match_entry_free(entry);
}
#endif

// r3_pad structure:
// (node*) r3
// (int) branch_n
// (SV*) target * branch_n
// (int) capture_n * branch_n
// (char**) first_capture_key_head * branch_n
// (char*) (capture_key_head, capture_key_end) * (sum of capture_n)
// (char) capture_key_pool * (sum of capture_key_len)

#define BRANCH_N (*(int*)( (char*)r3_pad + sizeof(node*) ))
#define ASSIGN_OFFSET \
    SV** target; \
    int* capture_n; \
    char*** first_capture_key_head; \
    char** capture_key; \
    char* capture_key_pool; \
    target = (SV**)( (char*)r3_pad + sizeof(node*) + sizeof(int) ); \
    capture_n = (int*)( (char*)target + sizeof(SV*) * branch_n ); \
    first_capture_key_head = (char***)( (char*)capture_n + sizeof(int) * branch_n ); \
    capture_key = (char**)( (char*)first_capture_key_head + sizeof(char**) * branch_n ); \
    capture_key_pool = (char*)( (char*)capture_key + sizeof(char*) * capture_n_total * 2);

MODULE = Router::R3		PACKAGE = Router::R3		

INCLUDE: const-xs.inc

#define ANALYZE_PATTERN(pattern, pattern_len) { \
    int k; \
    for(STRLEN j=0; j<pattern_len; ++j) \
        if( pattern[j] == '{' ){ \
            ++capture_n_total; \
            ++j; \
            while( j<pattern_len && pattern[j]!='}' && pattern[j]!=':' ){ \
                ++capture_key_len_total; \
                ++j; \
            } \
            k = 1; \
            while( j<pattern_len && k>0 ) { \
                switch( pattern[j] ) { \
                    case '{': \
                        ++k; \
                        break; \
                    case '}': \
                        --k; \
                        break; \
                } \
                ++j; \
            } \
        } \
}

#define FILL_PATTERN(r3, i, pattern, pattern_len, val) { \
    int this_capture_n = 0; \
    char** this_capture_key_head_cursor; \
    char* this_capture_key_pool_cursor; \
    if( val ) \
        target[i] = newSVsv(val); \
    else \
        target[i] = newSV(0); \
    if( i==0 ) \
        first_capture_key_head[0] = capture_key; \
    if( first_capture_key_head[i] == capture_key ) \
        this_capture_key_pool_cursor = capture_key_pool; \
    else \
        this_capture_key_pool_cursor = *(first_capture_key_head[i]-1); \
    this_capture_key_head_cursor = first_capture_key_head[i]; \
    for(STRLEN j=0; j<pattern_len; ++j) \
        if( pattern[j] == '{' ){ \
            ++this_capture_n; \
            *this_capture_key_head_cursor++ = this_capture_key_pool_cursor; /* head */ \
            ++j; \
            while( j<pattern_len && pattern[j]!='}' && pattern[j]!=':' ){ \
                *this_capture_key_pool_cursor++ = pattern[j]; \
                ++j; \
            } \
            *this_capture_key_head_cursor++ = this_capture_key_pool_cursor; /* end */ \
            int k = 1; \
            while( j<pattern_len && k>0 ) { \
                switch( pattern[j] ) { \
                    case '{': \
                        ++k; \
                        break; \
                    case '}': \
                        --k; \
                        break; \
                } \
                ++j; \
            } \
        } \
    capture_n[i] = this_capture_n; \
    if( i < branch_n - 1 ) \
        first_capture_key_head[i+1] = this_capture_key_head_cursor; \
    r3_tree_insert_pathl(r3, pattern, pattern_len, &target[i]); \
}

#ifdef PERL_R3_DEBUG
#define DUMP_PAD(pad) { \
    char *p = (char*)pad; \
    printf("DUMP_PAD: (%p)\n", (void*)pad); \
    printf("  r3=%p\n", (void*)(*(node**)p)); \
    p += sizeof(node*); \
    int branch_n = *(int*)p; \
    p += sizeof(int); \
    printf("  branch_n=%d\n  targets:", branch_n); \
    for(int i=0; i<branch_n; ++i) { \
        printf(" %p", (void*)(*(SV**)p)); \
        p += sizeof(SV*); \
    } \
    printf("\n  capture_n:"); \
    for(int i=0; i<branch_n; ++i) { \
        printf(" %d", *(int*)p); \
        p += sizeof(int); \
    } \
    printf("\n  first_capture_key_head:"); \
    for(int i=0; i<branch_n; ++i) { \
        printf(" %p", (void*)(*(char***)p)); \
        p += sizeof(char**); \
    } \
    printf("\n  capture_key:"); \
    for(int i=0; i<capture_n_total; ++i) { \
        printf(" (%p,%p)", (void*)(*(char**)p), (void*)(*(char**)(p + sizeof(char*)))); \
        for(char *pp=*(char**)p; pp!=*(char**)(p + sizeof(char*)); ++pp) \
            printf("%c", *pp); \
        p += sizeof(char*) * 2; \
    } \
    printf("\n  capture_key_pool: "); \
    for(int i=0; i<capture_key_len_total; ++i) { \
        printf("%c", *(char*)p); \
        ++p; \
    } \
    printf("\n"); \
}
#else
#define DUMP_PAD(pad) ;
#endif

void
new(...)
    PPCODE:
        {
            void *r3_pad;
            int branch_n = 0;
            int capture_n_total = 0;
            int capture_key_len_total = 0;
            if( items == 0 )
                croak("Router::R3::new without classname?");
            if( items == 2 && SvROK(ST(1)) ) {
                SV *rv = SvRV(ST(1));
                switch( SvTYPE(rv) ) {
                    case SVt_PVAV: { // [pattern, target, pattern, target, ...]
                        AV *av = (AV*)rv;
                        SSize_t len = av_len(av);
                        if( !(len & 1) )
                            warn("Router::R3::new with odd length array");
                        branch_n = len + 1 >> 1;
                        for(SSize_t i=0; i<=len; i+=2){
                            SV** key = av_fetch(av, i, 0);
                            if( !key || !SvPOK(*key) )
                                warn("The %dth element of the new call argument array should be a string", i);
                            STRLEN pattern_len;
                            char * pattern;
                            if( key )
                                pattern = SvPVbyte(*key, pattern_len);
                            else {
                                pattern = "";
                                pattern_len = 0;
                            }
                            ANALYZE_PATTERN(pattern, pattern_len);
                        }
                        break;
                    }
                    case SVt_PVHV: { // {pattern => target, pattern => target, ...}
                        HV *hv = (HV*)rv;
                        branch_n = hv_iterinit(hv);
                        char *pattern;
                        I32 pattern_len;
                        HE *he;
                        while( he = hv_iternext(hv) ){
                            pattern = hv_iterkey(he, &pattern_len);
                            ANALYZE_PATTERN(pattern, pattern_len);
                        }
                        break;
                    }
                    default:
                        warn("Router::R3::new with invalid reference");
                }
            } else if( items > 2 ) { // pattern, target, pattern, target, ...
                branch_n = items >> 1;
                if( !(items & 1) )
                    warn("Router::R3::new with odd arguments");
                for(I32 i=1; i<items; i+=2) {
                    SV * key = ST(i);
                    if( !SvPOK(key) )
                        warn("The %dth argument for new call should be a string", i);
                    STRLEN pattern_len;
                    char * pattern = SvPVbyte(key, pattern_len);
                    ANALYZE_PATTERN(pattern, pattern_len);
                }
            }
#ifdef PERL_R3_DEBUG
            printf("branch_n=%d, capture_n_total=%d, capture_key_len_total=%d\n", branch_n, capture_n_total, capture_key_len_total);
#endif

            Newx(
                r3_pad,

                sizeof(node*) + // r3
                sizeof(int) + // branch_n
                sizeof(SV*) * branch_n + // target[]
                sizeof(int) * branch_n + // capture_n[]
                sizeof(char**) * branch_n + // last_capture_key_end[]
                sizeof(char*) * capture_n_total * 2 + // (capture_key_head, capture_key_end)[]
                sizeof(char) * capture_key_len_total,

                char
            );
            {
                node* r3;
                ASSIGN_OFFSET;
                if( items >> 1 <= 10 )
                    r3 = r3_tree_create( items >> 1 );
                else
                    r3 = r3_tree_create(10);
                *(node**)r3_pad = r3;
                BRANCH_N = branch_n;

                if( items == 2 && SvROK(ST(1)) ) {
                    SV *rv = SvRV(ST(1));
                    switch( SvTYPE(rv) ) {
                        case SVt_PVAV: { // [pattern, target, pattern, target, ...]
                            AV *av = (AV*)rv;
                            SSize_t len = av_len(av);
                            for(SSize_t i=0; i<=len; i+=2){
                                I32 i2 = i >> 1;
                                SV ** pval = i+1 <= len ? av_fetch(av, i+1, 0) : NULL;
                                char * pattern;
                                STRLEN pattern_len;
                                SV ** pkey = av_fetch(av, i, 0);
                                if( pkey )
                                    pattern = SvPVbyte(*pkey, pattern_len);
                                else{
                                    pattern = "";
                                    pattern_len = 0;
                                }
                                FILL_PATTERN(r3, i2, pattern, pattern_len, (pval ? *pval : NULL));
                            }
                            break;
                        }
                        case SVt_PVHV: { // {pattern => target, pattern => target, ...}
                            HV *hv = (HV*)rv;
                            hv_iterinit(hv);
                            char *pattern;
                            I32 pattern_len;
                            SV *val;
                            I32 i2 = 0;
                            while( val = hv_iternextsv(hv, &pattern, &pattern_len) ){
                                FILL_PATTERN(r3, i2, pattern, pattern_len, val);
                                ++i2;
                            }
                            break;
                        }
                        default:
                            warn("Router::R3::new with invalid reference");
                    }
                } else if( items > 2 ) { // pattern, target, pattern, target, ...
                    I32 i;
                    for(i=1; i<items; i+=2) {
                        I32 i2 = i >> 1;
                        SV *val = i+1 < items ? ST(i+1) : NULL;
                        STRLEN pattern_len;
                        char * pattern = SvPVbyte(ST(i), pattern_len);
                        FILL_PATTERN(r3, i2, pattern, pattern_len, val);
                    }
                }
                DUMP_PAD(r3_pad);
                r3_tree_compile(r3);
            }

            SV* ret = newSV(0);
            SvUPGRADE(ret, SVt_RV);
            SvROK_on(ret);
            SvRV(ret) = (SV*)r3_pad;

            SV * obj = newRV_noinc(ret);
            STRLEN classname_len;
            char * classname = SvPVbyte(ST(0), classname_len);
            HV * stash = gv_stashpvn(classname, classname_len, 0);
            sv_bless(obj, stash);
            EXTEND(SP, 1);
            PUSHs(sv_2mortal(obj));
        }

void
match(SV* r3_sv, SV *str_sv)
    PPCODE:
        void* r3_pad = SvRV(SvRV(r3_sv));
        node* r3 = *(node**)r3_pad;

        char *str;
        STRLEN str_len;
        str = SvPVbyte(str_sv, str_len);

        match_entry* entry = match_entry_createl(str, str_len);
        node* matched_node = r3_tree_matchl(r3, str, str_len, entry);

        if( matched_node ){
            SV** target_p = (SV**) matched_node->data;
#ifdef PERL_R3_DEBUG
            printf("matched target_p = %p\n", (void*)target_p);
            printf("matched target = %p\n", (void*)(*(SV**)target_p));
#endif
            EXTEND(SP, 2);
            PUSHs(sv_2mortal(newSVsv(*(SV**)target_p)));

            HV* captures_hv = newHV();
            int capture_n = entry->vars->len;
            if( capture_n > 0 ) {
                int match_i = target_p - (SV**)( (char*)r3_pad + sizeof(node*) + sizeof(int) );
                int branch_n = *(int*)( (char*)r3_pad + sizeof(node*) );
                int my_capture_n = *(int*)( (char*)r3_pad + sizeof(node*) + sizeof(int) + sizeof(SV*) * branch_n + sizeof(int) * match_i );
                char **capture_key_cursor = *(char***)( (char*)r3_pad + sizeof(node*) + sizeof(int) + sizeof(SV*) * branch_n + sizeof(int) * branch_n + sizeof(char**) * match_i );
                char ** captures = entry->vars->tokens;
#ifdef PERL_R3_DEBUG
                printf("capture # = %d\n", entry->vars->len);
#endif
                for(int i=0; i<capture_n && i<my_capture_n; ++i){
#ifdef PERL_R3_DEBUG
                    printf("capture_key_cursor = %p -> %p\n", (void*)capture_key_cursor, (void*)*capture_key_cursor);
#endif
                    hv_store(
                        captures_hv,
                        *capture_key_cursor, *(capture_key_cursor+1) - *capture_key_cursor,
                        newSVpv(captures[i], 0),
                        0
                    );
                    capture_key_cursor += 2;
                }
            }
            PUSHs(sv_2mortal(newRV_noinc((SV*)captures_hv)));
        }
        match_entry_free(entry);

void DESTROY(SV* r3_sv)
    PPCODE:
        void* pad = SvRV(SvRV(r3_sv));
        int branch_n = *(int*)((char*)pad + sizeof(node*));
        SV** target = (SV**)((char*)pad + sizeof(node*) + sizeof(int));
        for(int i=0; i<branch_n; ++i)
            SvREFCNT_dec(target[i]);
        r3_tree_free(*(node**)pad);
        Safefree(pad);
        SvRV(SvRV(r3_sv)) = 0;

#ifdef PERL_R3_DEBUG

void
test()
    CODE:
        _test();

#endif

