/*
 * Copyright (C) 2014 Kobi Meirson
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "cJSON/cJSON.h"

typedef struct {
	ngx_regex_compile_t *rgc;
	ngx_str_t			*replacement;
  ngx_str_t     *ver_replacement;
} ngx_http_ua_parse_elem_t;

typedef struct {
  // Kind regexes
  ngx_regex_compile_t *tabletKindRegex;
  ngx_regex_compile_t *mobileKindRegex;
  ngx_regex_compile_t *botKindRegex;
} ngx_http_ua_parse_mod_conf_t;

typedef struct {
  ngx_str_t *filename;
  ngx_array_t *devices;
  ngx_array_t *browsers;
  ngx_array_t *os;
  ngx_array_t *brands;
  ngx_array_t *models;
} ngx_http_ua_parse_srv_conf_t;

typedef struct {
    ngx_flag_t enabled;
} ngx_http_ua_parse_loc_conf_t;

static ngx_str_t *ngx_http_ua_copy_json(cJSON *jsonSrc, ngx_conf_t *cf);

static ngx_int_t ngx_http_ua_parse_add_variables(ngx_conf_t *cf);

static char *ngx_http_ua_parse_list(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_ua_parse_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_ua_parse_kind_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static void * ngx_http_ua_parse_create_mod_conf(ngx_conf_t *cf);
static char * ngx_http_ua_parse_init_mod_conf(ngx_conf_t *cf, void *conf);
static void * ngx_http_ua_parse_create_srv_conf(ngx_conf_t *cf);
static char * ngx_http_ua_parse_merge_srv_conf(ngx_conf_t *cf, void *prev, void *conf);
static void * ngx_http_ua_parse_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_ua_parse_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf);

static ngx_array_t * ngx_http_ua_parse_load_from_json(ngx_conf_t *cf, cJSON *current);

static ngx_command_t ngx_http_ua_parse_commands[] = {
    { ngx_string("uaparse_list"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_ua_parse_list,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("uaparse_enable"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ua_parse_loc_conf_t, enabled),
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_ua_parse_module_ctx = {
    ngx_http_ua_parse_add_variables,    /* preconfiguration */
    NULL,                               /* postconfiguration */

    ngx_http_ua_parse_create_mod_conf,  /* create main configuration */
    ngx_http_ua_parse_init_mod_conf,    /* init main configuration */

    ngx_http_ua_parse_create_srv_conf,  /* create server configuration */
    ngx_http_ua_parse_merge_srv_conf,   /* merge server configuration */

    ngx_http_ua_parse_create_loc_conf,  /* create location configuration */
    ngx_http_ua_parse_merge_loc_conf,   /* merge location configuration */
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

#define NGX_UA_PARSE_DEVICE_FAMILY 0
#define NGX_UA_PARSE_OS_FAMILY 1
#define NGX_UA_PARSE_BROWSER_FAMILY 2
#define NGX_UA_PARSE_BROWSER_VERSION 3
#define NGX_UA_PARSE_DEVICE_BRAND 4
#define NGX_UA_PARSE_DEVICE_MODEL 5
#define NGX_UA_PARSE_OS_VERSION 6

#define NGX_UA_PARSE_SIZE_THRESHOLD 200

static ngx_http_variable_t ngx_http_ua_parse_vars[] = {
    { ngx_string("ua_parse_device"), NULL,
      ngx_http_ua_parse_variable,
      NGX_UA_PARSE_DEVICE_FAMILY, 0, 0 },

    { ngx_string("ua_parse_os"), NULL,
      ngx_http_ua_parse_variable,
      NGX_UA_PARSE_OS_FAMILY, 0, 0 },

    { ngx_string("ua_parse_os_ver"), NULL,
      ngx_http_ua_parse_variable,
      NGX_UA_PARSE_OS_VERSION, 0, 0 },

    { ngx_string("ua_parse_browser"), NULL,
      ngx_http_ua_parse_variable,
      NGX_UA_PARSE_BROWSER_FAMILY, 0, 0 },

    { ngx_string("ua_parse_browser_ver"), NULL,
      ngx_http_ua_parse_variable,
      NGX_UA_PARSE_BROWSER_VERSION, 0, 0 },

    { ngx_string("ua_parse_device_kind"), NULL,
      ngx_http_ua_parse_kind_variable,
      0, 0, 0 },

    { ngx_string("ua_parse_device_brand"), NULL,
      ngx_http_ua_parse_variable,
      NGX_UA_PARSE_DEVICE_BRAND, 0, 0 },

    { ngx_string("ua_parse_device_model"), NULL,
      ngx_http_ua_parse_variable,
      NGX_UA_PARSE_DEVICE_MODEL, 0, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

// Copy json attributes (just to be able to destroy the cJSON obj afterwards)
static ngx_str_t *
ngx_http_ua_copy_json(cJSON *jsonSrc, ngx_conf_t *cf) {
    ngx_str_t     *str;
    u_char        *src = (u_char*)jsonSrc->valuestring;

    if (src == NULL) {
      return NULL;
    }

    str = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
    if (str == NULL) {
      return NULL;
    }

    str->len = ngx_strlen(src) + 1;
    str->data = ngx_pcalloc(cf->pool, str->len);
    (void)ngx_copy(str->data, src, str->len);

    return str;
}

// Create configuration
static void *
ngx_http_ua_parse_create_mod_conf(ngx_conf_t *cf)
{
    ngx_http_ua_parse_mod_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ua_parse_mod_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

// Init configuration
static char *
ngx_http_ua_parse_init_mod_conf(ngx_conf_t *cf, void *conf)
{
  ngx_http_ua_parse_mod_conf_t    *upcf = conf;
  char						*rc;
  u_char						errstr[NGX_MAX_CONF_ERRSTR];

  rc = NGX_CONF_ERROR;

  // Mobile (regex taken from https://gist.github.com/dalethedeveloper/1503252)
  upcf->mobileKindRegex = ngx_pcalloc(cf->pool, sizeof(ngx_regex_compile_t));
  upcf->mobileKindRegex->pattern = (ngx_str_t)ngx_string("Mobile|iP(hone|od|ad)|Android|BlackBerry|IEMobile|Kindle|NetFront|Silk-Accelerated|(hpw|web)OS|Fennec|Minimo|Opera M(obi|ini)|Blazer|Dolfin|Dolphin|Skyfire|Zune");
  upcf->mobileKindRegex->options = NGX_REGEX_CASELESS;
  upcf->mobileKindRegex->pool = cf->pool;
  upcf->mobileKindRegex->err.len = NGX_MAX_CONF_ERRSTR;
  upcf->mobileKindRegex->err.data = errstr;
  if (ngx_regex_compile(upcf->mobileKindRegex) != NGX_OK) {
    ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                  "ngx_regex_compile() \"%s\" failed", upcf->mobileKindRegex->pattern.data);
    goto failed;
  }

  // Tablet (regex taken from https://gist.github.com/dalethedeveloper/1503252)
  upcf->tabletKindRegex = ngx_pcalloc(cf->pool, sizeof(ngx_regex_compile_t));
  upcf->tabletKindRegex->pattern = (ngx_str_t)ngx_string("(tablet|ipad|playbook|silk)|(android(?!.*mobile))");
  upcf->tabletKindRegex->options = NGX_REGEX_CASELESS;
  upcf->tabletKindRegex->pool = cf->pool;
  upcf->tabletKindRegex->err.len = NGX_MAX_CONF_ERRSTR;
  upcf->tabletKindRegex->err.data = errstr;
  if (ngx_regex_compile(upcf->tabletKindRegex) != NGX_OK) {
    ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                  "ngx_regex_compile() \"%s\" failed", upcf->tabletKindRegex->pattern.data);
    goto failed;
  }

  // Bot/crawler
  upcf->botKindRegex = ngx_pcalloc(cf->pool, sizeof(ngx_regex_compile_t));
  upcf->botKindRegex->pattern = (ngx_str_t)ngx_string("bot|crawler|spider|crawling");
  upcf->botKindRegex->options = NGX_REGEX_CASELESS;
  upcf->botKindRegex->pool = cf->pool;
  upcf->botKindRegex->err.len = NGX_MAX_CONF_ERRSTR;
  upcf->botKindRegex->err.data = errstr;
  if (ngx_regex_compile(upcf->botKindRegex) != NGX_OK) {
    ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                  "ngx_regex_compile() \"%s\" failed", upcf->botKindRegex->pattern.data);
    goto failed;
  }

  rc = NGX_CONF_OK;

 failed:
  return rc;
}

// Create srv conf
static void * ngx_http_ua_parse_create_srv_conf(ngx_conf_t *cf)
{
  ngx_http_ua_parse_srv_conf_t *conf;
  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ua_parse_srv_conf_t));

  if (conf == NULL) {
    return NGX_CONF_ERROR;
  }

  conf->devices = NGX_CONF_UNSET_PTR;
  conf->browsers = NGX_CONF_UNSET_PTR;
  conf->os = NGX_CONF_UNSET_PTR;
  conf->brands = NGX_CONF_UNSET_PTR;
  conf->models = NGX_CONF_UNSET_PTR;

  conf->filename = NGX_CONF_UNSET_PTR;

  return conf;
}

// Merge srv conf
static char * ngx_http_ua_parse_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_ua_parse_srv_conf_t *prev = parent;
  ngx_http_ua_parse_srv_conf_t *this = child;

  ngx_conf_merge_ptr_value(this->devices, prev->devices, NGX_CONF_UNSET_PTR);
  ngx_conf_merge_ptr_value(this->browsers, prev->browsers, NGX_CONF_UNSET_PTR);
  ngx_conf_merge_ptr_value(this->os, prev->os, NGX_CONF_UNSET_PTR);
  ngx_conf_merge_ptr_value(this->brands, prev->brands, NGX_CONF_UNSET_PTR);
  ngx_conf_merge_ptr_value(this->models, prev->models, NGX_CONF_UNSET_PTR);

  ngx_conf_merge_ptr_value(this->filename, prev->filename, NGX_CONF_UNSET_PTR);

  return NGX_CONF_OK;
}

// Create loc conf
static void * ngx_http_ua_parse_create_loc_conf(ngx_conf_t *cf)
{
  ngx_http_ua_parse_loc_conf_t *conf;
  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ua_parse_loc_conf_t));
  if (conf == NULL) {
    return NGX_CONF_ERROR;
  }

  conf->enabled = NGX_CONF_UNSET;

  return conf;
}

// Merge loc conf
static char * ngx_http_ua_parse_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_ua_parse_loc_conf_t *prev = parent;
  ngx_http_ua_parse_loc_conf_t *this = child;

  ngx_conf_merge_value(this->enabled, prev->enabled, 0);

  return NGX_CONF_OK;
}

// Kind (other/mobile/tablet)
static ngx_int_t ngx_http_ua_parse_kind_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
	ngx_http_ua_parse_mod_conf_t *upcf;
  ngx_http_ua_parse_loc_conf_t *loc_conf;
	u_char *str;
	ngx_regex_compile_t *mobileKind, *tabletKind, *botKind;

	upcf = ngx_http_get_module_main_conf(r, ngx_http_ua_parse_module);
  loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_ua_parse_module);
  if (!loc_conf->enabled) {
    v->valid = 0;
    v->not_found = 1;
    return NGX_OK;
  }

	str = (u_char*) "other";

  if (!r->headers_in.user_agent) {
    v->valid = 0;
    goto not_found;
  }

  // first we check if it is a bot
  if (ngx_regex_exec(upcf->botKindRegex->regex, &(r->headers_in.user_agent->value), NULL, 0) >= 0) {
    str = (u_char*)"bot";
  } else {
    // the if the device is mobile
    if (ngx_regex_exec(upcf->mobileKindRegex->regex, &(r->headers_in.user_agent->value), NULL, 0) >= 0) {
      // and it is also a tablet...
      if (ngx_regex_exec(upcf->tabletKindRegex->regex, &(r->headers_in.user_agent->value), NULL, 0) >= 0) {
        str = (u_char*)"tablet";
      } else { // it is just a mobile device
        str = (u_char*)"mobile";
      }
    }
  }


	v->data = str;
	v->len = ngx_strlen(v->data);
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

 not_found:

	if (v->valid != 1) {
		v->not_found = 1;
	}

	return NGX_OK;
}

// Get family
static ngx_int_t ngx_http_ua_parse_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_ua_parse_srv_conf_t *upcf;
    ngx_http_ua_parse_loc_conf_t *loc_conf;
    ngx_uint_t n, i, captures_amount, replacement_len = 0;
    ngx_http_ua_parse_elem_t *ptr, *cur;
    int rc, *captures = NULL;
    ngx_array_t *lst;
    ngx_str_t str;
    u_char *p, *foundStr;

    upcf = ngx_http_get_module_srv_conf(r, ngx_http_ua_parse_module);
    loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_ua_parse_module);
    v->valid = 0;
    if (!loc_conf->enabled) {
      v->not_found = 1;
      return NGX_OK;
    }


    switch (data) {
    case NGX_UA_PARSE_DEVICE_FAMILY:
    	lst = upcf->devices;
    	break;
    case NGX_UA_PARSE_OS_FAMILY:
    	lst = upcf->os;
    	break;
    case NGX_UA_PARSE_OS_VERSION:
      lst = upcf->os;
      break;
    case NGX_UA_PARSE_BROWSER_FAMILY:
    	lst = upcf->browsers;
    	break;
    case NGX_UA_PARSE_BROWSER_VERSION:
      lst = upcf->browsers;
      break;
    case NGX_UA_PARSE_DEVICE_BRAND:
      lst = upcf->brands;
      break;
    case NGX_UA_PARSE_DEVICE_MODEL:
      lst = upcf->models;
      break;
    default:
    	goto not_found;
    }

    if (lst == NULL) {
        goto not_found;
    }

    if (!r->headers_in.user_agent) {
      goto not_found;
    }

    ptr = lst->elts;
    for (i = 0; i < lst->nelts; i++) {
        cur = &ptr[i];
        n = (cur->rgc->captures + 1) * 3;
        if (n > 20) {
        	n = 15; // 4+1 * 3
          captures_amount = 4;
        } else {
          captures_amount = cur->rgc->captures;
        }
        captures = ngx_pcalloc(r->pool, n * sizeof(int));
        rc = ngx_regex_exec(cur->rgc->regex, &r->headers_in.user_agent->value, captures, n);
        if (rc < 0) {
        	continue;
        }

        // if we have 0 captures, we have no right to access captures[3], and captures[2] contain no meaningful info
        // so we just take the whole match (captures[1] - captures[0])
        str.data = (u_char *) (r->headers_in.user_agent->value.data + captures[0]);
        str.len = captures[1] - captures[0];

        // Match the first one (captures[2] is the start, captures[3] is the end) in most conditions
        if (captures_amount > 0 && (captures[3] - captures[2] < 0 && str.len > NGX_UA_PARSE_SIZE_THRESHOLD)) {
          str.data = (u_char *) (r->headers_in.user_agent->value.data + captures[2]);
          str.len = captures[3] - captures[2];
        }

        if ((data == NGX_UA_PARSE_BROWSER_VERSION || data == NGX_UA_PARSE_OS_VERSION) && cur->rgc->captures > 1) {
          while (captures_amount > 1) {
            if (captures[captures_amount * 2 + 1] != -1) {
              str.data = (u_char *) (r->headers_in.user_agent->value.data + captures[4]);
              str.len = captures[captures_amount * 2 + 1] - captures[4];
              break;
            } else {
              captures_amount = captures_amount - 1;
            }
          }
        }

        // we use all matches since we'll most likely replace them with something later on
        if (data == NGX_UA_PARSE_DEVICE_MODEL || data == NGX_UA_PARSE_DEVICE_BRAND) {
          while (captures_amount > 1) {
            if (captures[captures_amount * 2 + 1] != - 1) {
              str.data = (u_char *) (r->headers_in.user_agent->value.data + captures[2]);
              str.len = captures[captures_amount * 2 + 1] - captures[2];
              break;
            } else {
              captures_amount = captures_amount - 1;
            }
          }
        }

        if ((cur->replacement && data != NGX_UA_PARSE_BROWSER_VERSION && data != NGX_UA_PARSE_OS_VERSION) || (cur->ver_replacement && (data == NGX_UA_PARSE_OS_VERSION))) {
        	// Copy the string to the foundStr place...
        	foundStr = ngx_pcalloc(r->pool, (str.len + 1) * sizeof(u_char));
          // Something's wrong, fail the match and proceed
          if (!foundStr) {
            goto not_found;
          }
        	ngx_memzero(foundStr, (str.len + 1) * sizeof(u_char)); // Make sure there will be '\0' in the end
        	ngx_memcpy(foundStr, str.data, str.len * sizeof(u_char));

        	// Now we can use sprintf() safely (else it would copy the whole user agent string..)
          if (data == NGX_UA_PARSE_OS_VERSION) {
            replacement_len = cur->ver_replacement->len;
          } else {
            replacement_len = cur->replacement->len;
          }
          str.data = p = ngx_pcalloc(r->pool, (replacement_len + str.len + 1) * sizeof(u_char));
          // Could not allocate memory in pool for str.data/p
          if (!p) {
            ngx_pfree(r->pool, foundStr);
            goto not_found;
          }
          ngx_memzero(p, (replacement_len + str.len + 1) * sizeof(u_char));

          if (data == NGX_UA_PARSE_OS_VERSION) {
            p = ngx_snprintf(p, (size_t) (replacement_len + str.len + 1) * sizeof(u_char), (const char *)cur->ver_replacement->data, foundStr);
          } else {
            p = ngx_snprintf(p, (size_t) (replacement_len + str.len + 1) * sizeof(u_char), (const char *)cur->replacement->data, foundStr);
          }
        	*p = '\0';
        	str.len = p - str.data;

          // Finally free foundStr after we've used it
          ngx_pfree(r->pool, foundStr);
        }

        v->data = str.data;
		v->len = str.len;
		v->valid = 1;
		v->no_cacheable = 0;
		v->not_found = 0;
		break;
    }

not_found:
	if (v->valid != 1) {
		v->not_found = 1;
	}

  if (captures) {
    ngx_pfree(r->pool, captures);
  }
    return NGX_OK;
}

static ngx_array_t * ngx_http_ua_parse_load_from_json(ngx_conf_t *cf, cJSON *current)
{
	int            				i, arraySize;
	ngx_array_t					*lst;
	cJSON						*arr;
	ngx_http_ua_parse_elem_t	*elem;
	ngx_str_t					*str;
	u_char						errstr[NGX_MAX_CONF_ERRSTR];

	arraySize = cJSON_GetArraySize(current);
	lst = ngx_array_create(cf->pool, arraySize, sizeof(ngx_http_ua_parse_elem_t));
	if (lst == NULL) {
		goto failed;
	}
	for (i = 0; i < arraySize; i++) {
		arr = cJSON_GetArrayItem(current, i);
		elem = ngx_array_push(lst);
    ngx_memzero(elem, sizeof(ngx_http_ua_parse_elem_t));
		if (elem == NULL) {
			goto failed;
		}
    str = ngx_http_ua_copy_json(cJSON_GetObjectItem(arr, "regex"), cf);

    elem->rgc = ngx_pcalloc(cf->pool, sizeof(ngx_regex_compile_t));

		elem->rgc->pattern = *str;
		elem->rgc->pool = cf->pool;
		elem->rgc->err.len = NGX_MAX_CONF_ERRSTR;
		elem->rgc->err.data = errstr;
		if (ngx_regex_compile(elem->rgc) != NGX_OK) {
			goto failed;
		}
		if (cJSON_GetObjectItem(arr, "replacement") != NULL) {
            elem->replacement = ngx_http_ua_copy_json(cJSON_GetObjectItem(arr, "replacement"), cf);
		}
    if (cJSON_GetObjectItem(arr, "version_replacement") != NULL) {
      elem->ver_replacement = ngx_http_ua_copy_json(cJSON_GetObjectItem(arr, "version_replacement"), cf);
    }
	}
failed:
	return lst;
}

static char *
ngx_http_ua_parse_list(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_fd_t        fd = NGX_INVALID_FILE;
    ngx_str_t       *value, *filename;
    u_char          *regexFile;
    char            *buf = NULL;
    size_t          len;
    ngx_file_info_t fi;
    off_t           size;
    char*           rc;
    cJSON           *root = NULL;
    ngx_http_ua_parse_srv_conf_t    *upcf = conf;

    rc = NGX_CONF_ERROR;

    value = cf->args->elts;
    regexFile = (u_char*)value[1].data;

    if (upcf->filename != NGX_CONF_UNSET_PTR) {
      // file already present here
      rc = NGX_CONF_OK;
      goto failed;
    } else {
      filename = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
      filename->len = ngx_strlen(regexFile) + 1;
      filename->data = ngx_pcalloc(cf->pool, filename->len);
      upcf->filename = filename;
    }

    fd = ngx_open_file(regexFile, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_CRIT, cf->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", regexFile);
        goto failed;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                      ngx_fd_info_n " \"%s\" failed", regexFile);
        goto failed;
    }
    size = ngx_file_size(&fi);

    // TODO: this value is hardcoded. Is this really the only way to go? Slight changes to json db will definitely disturb the process
    len = (off_t) 174781 > size ? (size_t) size : 174781;

    buf = ngx_alloc(len, cf->log);
    if (buf == NULL) {
        goto failed;
    }

    if (ngx_read_fd(fd, buf, len) == -1) {
    	goto failed;
    }

    root = cJSON_Parse(buf);

    if (!root) {
      goto failed;
    }

    upcf->os = ngx_http_ua_parse_load_from_json(cf, cJSON_GetObjectItem(root, "os"));
    upcf->devices = ngx_http_ua_parse_load_from_json(cf, cJSON_GetObjectItem(root, "devices"));
    upcf->browsers = ngx_http_ua_parse_load_from_json(cf, cJSON_GetObjectItem(root, "browsers"));
    upcf->brands = ngx_http_ua_parse_load_from_json(cf, cJSON_GetObjectItem(root, "brands"));
    upcf->models = ngx_http_ua_parse_load_from_json(cf, cJSON_GetObjectItem(root, "models"));

    rc = NGX_CONF_OK;

failed:
    if (root != NULL) {
        cJSON_Delete(root);
    }
    if (fd != NGX_INVALID_FILE) {
        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", regexFile);
        }
    }
    if (buf != NULL) {
        ngx_free(buf);
    }
    return rc;
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
