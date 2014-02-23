/*
 * Copyright (C) 2014 Kobi Meirson
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "cJSON/cJSON.h"

typedef struct {
    
    ngx_array_t *devices;
    ngx_array_t *browsers;
    ngx_array_t *os;
} ngx_http_ua_parse_conf_t;

static ngx_int_t ngx_http_ua_parse_add_variables(ngx_conf_t *cf);

static char *ngx_http_ua_parse_list(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
    
static ngx_int_t ngx_http_ua_parse_agent_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
    
static ngx_int_t ngx_http_ua_parse_add_variables(ngx_conf_t *cf);
 
static ngx_command_t ngx_http_ua_parse_commands[] = {
    { ngx_string("uaparse_list"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_ua_parse_list,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },
 
    ngx_null_command
};
 
static ngx_http_module_t ngx_http_ua_parse_module_ctx = {
    ngx_http_ua_parse_add_variables,    /* preconfiguration */
    NULL,                               /* postconfiguration */
 
    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */
 
    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */
 
    NULL,                               /* create location configuration */
    NULL                                /* merge location configuration */
};
 
 
ngx_module_t ngx_http_ua_parse_module = {
    NGX_MODULE_V1,
    &ngx_http_ua_parse_module_ctx, /* module context */
    ngx_http_ua_parse_commands,    /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_variable_t ngx_http_ua_parse_vars[] = {

    { ngx_string("ua_parse_agent"), NULL,
      ngx_http_ua_parse_agent_variable,
      0, 0, 0 },
      
    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_int_t ngx_http_ua_parse_agent_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;
    return NGX_OK;
}

static char *
ngx_http_ua_parse_list(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
//     ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Sup?", );
    ngx_fd_t    fd;
    ngx_str_t   *value;
    u_char      *regexFile;
    value = cf->args->elts;
    regexFile = (u_char*)value[1].data;
    
    fd = ngx_open_file(regexFile, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_CRIT, cf->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", regexFile);
    }
    return NGX_CONF_OK;
failed:
    if (fd != NGX_INVALID_FILE) {
        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", regexFile);
        }
    }
    return NGX_CONF_ERROR;
}

static ngx_int_t
ngx_http_ua_parse_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;
    
    for (v = ngx_http_ua_parse_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }
        var->get_handler = v->get_handler;
        var->data = v->data;
    }
    
    return NGX_OK;
}