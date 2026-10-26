#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void copy_input(char *user_input) {
    char buf[64];
    strcpy(buf, user_input);           // DANGEROUS_FN_STRCPY
    printf(user_input);                // FORMAT_STRING
}

int *make_array(int count, int size) {
    int *arr = malloc(count * size);   // MALLOC_MULTIPLY_OVERFLOW
    return arr;
}

void uaf_example(char *data) {
    char *ptr = malloc(128);
    memcpy(ptr, data, 128);
    free(ptr);
    printf("%s\n", ptr);               // USE_AFTER_FREE
}

void double_free_example(char *data) {
    char *ptr = malloc(64);
    free(ptr);
    free(ptr);                         // DOUBLE_FREE
}

void safe_example(const char *user_input) {
    char buf[64];
    strncpy(buf, user_input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    printf("%s\n", buf);
}
