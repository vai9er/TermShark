#include <stdlib.h>

#ifndef __filter_h
#define __filter_h

#define MAX_FILTER_LEN 100
#define MAX_SEARCH_VALUE_LEN 100

enum FilterField {
    FILTER_PROTOCOL,
    FILTER_SOURCE_IP,
    FILTER_DESTINATION_IP,
};

typedef struct FilterItem_t {
    enum FilterField field;
    int negate;
    char value[MAX_SEARCH_VALUE_LEN];
} FilterItem;

typedef struct Filters_t {
    int list_size;
    FilterItem filters[100];
    char filter_string[MAX_FILTER_LEN];
    int filter_pos;
} Filters;

#endif
