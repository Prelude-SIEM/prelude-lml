#ifndef VALUE_H
#define VALUE_H

typedef struct value_container value_container_t;

int value_container_new(value_container_t **vcont, const char *str);

void value_container_destroy(value_container_t *vcont);

void value_container_reset(value_container_t *vcont);

void *value_container_get_data(value_container_t *vcont);

void value_container_set_data(value_container_t *vcont, void *data);

prelude_string_t *value_container_resolve(value_container_t *vcont, const pcre_rule_t *rule,
                                          const lml_log_entry_t *lentry, int *ovector, size_t osize);

#endif
