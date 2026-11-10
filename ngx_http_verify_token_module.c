// Copyright (c) 2026 Gedalya Nie
// SPDX-License-Identifier: GPL-2.0-or-later

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdint.h>
#include <string.h>
#include <blake3.h>
#include <endian.h>

#define VERIFY_TOKEN_SUCCESS  1
#define VERIFY_TOKEN_FAILURE  0
#define VERIFY_TOKEN_UNKNOWN -1
#define VERIFY_TOKEN_ERROR   -2

#define VERIFY_TOKEN_HEADER_INVALID  0
#define VERIFY_TOKEN_HEADER_ALWAYS   1
#define VERIFY_TOKEN_HEADER_VALID    2
#define VERIFY_TOKEN_HEADER_EXPIRING 3

typedef struct {
	unsigned phase_handler_required:1;
	unsigned header_filter_required:1;
} verify_token_main_conf_t;

typedef struct {
	ngx_http_complex_value_t *name;
	ngx_http_complex_value_t *value;
	time_t ttl;
	ngx_array_t *status;
	unsigned condition:2;
} verify_token_headers_t;

typedef struct {
	unsigned redir_enabled:1;
	unsigned add_header_enabled:1;
	time_t expiry;
	ngx_str_t cookie_name;
	ngx_str_t extra_str;
	u_char *secrets[2];
	ngx_http_complex_value_t *token_to_verify;
	ngx_http_complex_value_t *redir_location;
	ngx_http_complex_value_t *redir_arg;
	ngx_array_t *headers;
} verify_token_conf_t;

static char *set_secret(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *set_redir_location(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *set_add_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *create_main_conf(ngx_conf_t *cf);
static ngx_int_t verify_token_handler(ngx_http_request_t *r);
static ngx_int_t header_filter(ngx_http_request_t *r);
static ngx_int_t init(ngx_conf_t *cf);
static void *create_conf(ngx_conf_t *cf);
static char *merge_conf(ngx_conf_t *cf, void *parent, void *child);
static int do_verify_token(ngx_http_request_t *r, verify_token_conf_t *conf, time_t *ttl);
static int get_token(const ngx_http_request_t *r, const verify_token_conf_t *conf, ngx_str_t *token);
static ngx_int_t add_variables(ngx_conf_t *cf);
static ngx_int_t var_verify_token_result(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t var_verify_token_token(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t var_verify_token_escaped_uri(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static ngx_command_t verify_token_commands[] = {
	{
		ngx_string("verify_token_expiry"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_sec_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(verify_token_conf_t, expiry),
		NULL
	},
	{
		ngx_string("verify_token_cookie"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(verify_token_conf_t, cookie_name),
		NULL
	},
	{
		ngx_string("verify_token_secret"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		set_secret,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(verify_token_conf_t, secrets[0]),
		NULL
	},
	{
		ngx_string("verify_token_secret_alt"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		set_secret,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(verify_token_conf_t, secrets[1]),
		NULL
	},
	{
		ngx_string("verify_token_extra_str"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(verify_token_conf_t, extra_str),
		NULL
	},
	{
		ngx_string("verify_token_verify"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_http_set_complex_value_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(verify_token_conf_t, token_to_verify),
		NULL
	},
	{
		ngx_string("verify_token"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE12,
		set_redir_location,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(verify_token_conf_t, redir_location),
		NULL
	},
	{
		ngx_string("verify_token_add_header"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_1MORE,
		set_add_header,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(verify_token_conf_t, headers),
		NULL
	},
	ngx_null_command
};

static ngx_http_module_t verify_token_ctx = {
	add_variables,
	init,
	create_main_conf,
	NULL,
	NULL,
	NULL,
	create_conf,
	merge_conf
};

ngx_module_t ngx_http_verify_token_module = {
	NGX_MODULE_V1,
	&verify_token_ctx,
	verify_token_commands,
	NGX_HTTP_MODULE,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NGX_MODULE_V1_PADDING
};

static ngx_http_variable_t verify_token_vars[] = {
	{ ngx_string("verify_token_result"), NULL,
	var_verify_token_result, 0,
	NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE, 0 },

	{ ngx_string("verify_token_token"), NULL,
	var_verify_token_token, 0,
	NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE, 0 },

	{ ngx_string("verify_token_escaped_uri"), NULL,
	var_verify_token_escaped_uri, 0,
	NGX_HTTP_VAR_CHANGEABLE, 0 },

	{ ngx_string("verify_token_escaped_uri_component"), NULL,
	var_verify_token_escaped_uri, 1,
	NGX_HTTP_VAR_CHANGEABLE, 0 },

	ngx_http_null_variable
};

static void *create_main_conf(ngx_conf_t *cf)
{
	verify_token_main_conf_t *mcf;
	mcf = ngx_pcalloc(cf->pool, sizeof(verify_token_main_conf_t));
	if (mcf == NULL) {
		return NULL;
	}
	return mcf;
}

static char *set_secret(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	char *p = conf;
	ngx_str_t *value;
	u_char *buf;
	u_char *in;
	u_char **out = (u_char **) (p + cmd->offset);

	if (*out) {
		return "is duplicate";
	}

	value = cf->args->elts;
	value++;
	if (value->len != 64) {
		return "Secret is of incorrect length. Must be 32 bytes (64 hex characters) long";
	}
	in = value->data;

	buf = ngx_palloc(cf->pool, 32);
	if (buf == NULL) {
		return NGX_CONF_ERROR;
	}

	u_char val = 0;
	for (int c = 0, cb = 0; c < 64;) {
		u_char ch = *in++;
		if (ch >= '0' && ch <= '9') {
			val += (ch - '0');
		} else {
			ch |= 0x20;
			if (ch >= 'a' && ch <= 'f') {
				val += (ch - 'a' + 10);
			} else {
				return "Secret contains non-hex characters";
			}
		}
		c++;
		if (c & 1) {
			val <<= 4;
		} else {
			buf[cb++] = val;
			val = 0;
		}
	}
	*out = buf;

	return NGX_CONF_OK;
}

static char *set_redir_location(ngx_conf_t *cf, ngx_command_t *cmd, void *cp)
{
	ngx_str_t *value;
	ngx_http_compile_complex_value_t ccv;
	verify_token_main_conf_t *vtmcf;
	verify_token_conf_t *conf = cp;
	ngx_uint_t nelts = cf->args->nelts;

	if (conf->redir_location != NGX_CONF_UNSET_PTR) {
		return "is duplicate";
	}

	value = cf->args->elts;
	nelts--;
	value++;

	if (
		value->len == 0
		||
		(value->len == 3 && memcmp(value->data, "off", 3) == 0)
	) {
		// disabled
		// prevent inheritance in merge_conf():
		conf->redir_location = NULL;
		conf->redir_arg = NULL;
		return NGX_CONF_OK;
	} else {
		vtmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_verify_token_module);
		vtmcf->phase_handler_required = 1;
		conf->redir_enabled = 1;
	}

	conf->redir_location = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
	if (conf->redir_location == NULL) {
		return NGX_CONF_ERROR;
	}

	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

	ccv.cf = cf;
	ccv.value = value;
	ccv.complex_value = conf->redir_location;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	nelts--;
	if (!nelts) {
		return NGX_CONF_OK;
	}
	value++;

	conf->redir_arg = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
	if (conf->redir_arg == NULL) {
		return NGX_CONF_ERROR;
	}

	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

	ccv.cf = cf;
	ccv.value = value;
	ccv.complex_value = conf->redir_arg;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static char *set_add_header(ngx_conf_t *cf, ngx_command_t *cmd, void *cp)
{
	ngx_str_t *value;
	verify_token_headers_t *h;
	ngx_http_compile_complex_value_t ccv;
	verify_token_main_conf_t *vtmcf;
	verify_token_conf_t *conf = cp;
	ngx_uint_t nelts = cf->args->nelts;

	value = cf->args->elts;
	nelts--;
	value++;

	if (
		value->len == 0
		||
		(value->len == 3 && memcmp(value->data, "off", 3) == 0)
	) {
		if (conf->headers && conf->headers != NGX_CONF_UNSET_PTR) {
			return "used earlier in the same scope and then set to off";
		}
		// disabled
		// prevent inheritance in merge_conf():
		conf->headers = NULL;
		return NGX_CONF_OK;
	}

	if (conf->headers == NULL) {
		return "set to off earlier in the same scope and then used";
	}
	if (conf->headers == NGX_CONF_UNSET_PTR) {
		conf->headers = ngx_array_create(cf->pool, 1, sizeof(verify_token_headers_t));
		if (conf->headers == NULL) {
			return NGX_CONF_ERROR;
		}
	}
	h = ngx_array_push(conf->headers);
	if (h == NULL) {
		return NGX_CONF_ERROR;
	}
	h->condition = VERIFY_TOKEN_HEADER_INVALID;
	h->status = NULL;

	vtmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_verify_token_module);
	vtmcf->header_filter_required = 1;
	conf->add_header_enabled = 1;

	h->name = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
	if (h->name == NULL) {
		return NGX_CONF_ERROR;
	}

	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

	ccv.cf = cf;
	ccv.value = value;
	ccv.complex_value = h->name;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	nelts--;
	if (!nelts) {
		h->value = NULL;
		return NGX_CONF_OK;
	}
	value++;

	h->value = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
	if (h->value == NULL) {
		return NGX_CONF_ERROR;
	}

	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

	ccv.cf = cf;
	ccv.value = value;
	ccv.complex_value = h->value;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	int condition_set = 0;
	while (--nelts && value++) {
		if (value->len == 6 && memcmp(value->data, "always", 6) == 0) {
			if (condition_set) {
				return "condition [always|valid|invalid|expiring] can only be set once";
			}
			condition_set = 1;
			h->condition = VERIFY_TOKEN_HEADER_ALWAYS;
		} else if (value->len == 5 && memcmp(value->data, "valid", 5) == 0) {
			if (condition_set) {
				return "condition [always|valid|invalid|expiring] can only be set once";
			}
			condition_set = 1;
			h->condition = VERIFY_TOKEN_HEADER_VALID;
		} else if (value->len == 7 && memcmp(value->data, "invalid", 7) == 0) {
			if (condition_set) {
				return "condition [always|valid|invalid|expiring] can only be set once";
			}
			condition_set = 1;
			// h->condition = VERIFY_TOKEN_HEADER_INVALID; // redundant
		} else if (value->len == 8 && memcmp(value->data, "expiring", 8) == 0) {
			if (condition_set) {
				return "condition [always|valid|invalid|expiring] can only be set once";
			}
			condition_set = 1;
			h->condition = VERIFY_TOKEN_HEADER_EXPIRING;
			nelts--;
			if (!nelts) {
				return "\"expiring\" must be followed by a time value";
			}
			value++;
			h->ttl = ngx_parse_time(value, 1);
			if (h->ttl == (time_t) NGX_ERROR) {
				return "invalid time value";
			}
		} else if (value->len == 6 && memcmp(value->data, "status", 6) == 0) {
			if (h->status) {
				return "status can only be set once";
			}
			h->status = ngx_array_create(cf->pool, 1, sizeof(ngx_uint_t));
			if (h->status == NULL) {
				return NGX_CONF_ERROR;
			}
			ngx_uint_t status;
			ngx_uint_t c = 0;
			while (--nelts) {
				++value;
				if ((status = ngx_atoi(value->data, value->len)) == NGX_ERROR) {
					--value;
					break;
				}
				ngx_uint_t *s = ngx_array_push(h->status);
				if (s == NULL) {
					return NGX_CONF_ERROR;
				}
				*s = status;
				c++;
			}
			if (!c) {
				return "\"status\" must be followed by one or more status code";
			}
			++nelts;
		} else {
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "Unrecognized: \"%V\"", value);
			return "Unrecognized argument";
		}
	}

	return NGX_CONF_OK;
}

static ngx_int_t add_variables(ngx_conf_t *cf) {
	ngx_http_variable_t *var, *v;

	for (v = verify_token_vars; v->name.len; v++) {
		var = ngx_http_add_variable(cf, &v->name, v->flags);
		if (var == NULL) {
			return NGX_ERROR;
		}

		var->get_handler = v->get_handler;
		var->data = v->data;
	}

	return NGX_OK;
}

static ngx_int_t init(ngx_conf_t *cf)
{
	ngx_http_core_main_conf_t *cmcf;
	verify_token_main_conf_t *mcf;
	ngx_http_handler_pt *h;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
	mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_verify_token_module);
	if (mcf->phase_handler_required) {
		h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
		if (h == NULL) {
			return NGX_ERROR;
		}
		*h = verify_token_handler;
	}

	if (mcf->header_filter_required) {
		ngx_http_next_header_filter = ngx_http_top_header_filter;
		ngx_http_top_header_filter = header_filter;
	}

	return NGX_OK;
}

static void *create_conf(ngx_conf_t *cf)
{
	verify_token_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(verify_token_conf_t));
	if (conf == NULL)
	{
		return NULL;
	}
	conf->expiry = NGX_CONF_UNSET;
	conf->cookie_name.data = NULL;
	conf->extra_str.data = NULL;
	conf->token_to_verify = NGX_CONF_UNSET_PTR;
	conf->redir_location = NGX_CONF_UNSET_PTR;
	conf->redir_arg = NGX_CONF_UNSET_PTR;
	conf->headers = NGX_CONF_UNSET_PTR;
	conf->secrets[0] = NULL;
	conf->secrets[1] = NULL;
	return conf;
}

static char *merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	const verify_token_conf_t *prev = parent;
	verify_token_conf_t *conf = child;

	if (conf->redir_location == NGX_CONF_UNSET_PTR && prev->redir_location != NGX_CONF_UNSET_PTR) {
		conf->redir_location = prev->redir_location;
		conf->redir_enabled = prev->redir_enabled;
		if (conf->redir_arg == NGX_CONF_UNSET_PTR && prev->redir_arg != NGX_CONF_UNSET_PTR) {
			conf->redir_arg = prev->redir_arg;
		}
	}
	if (conf->headers == NGX_CONF_UNSET_PTR && prev->headers != NGX_CONF_UNSET_PTR) {
		conf->headers = prev->headers;
		conf->add_header_enabled = prev->add_header_enabled;
	}
	ngx_conf_merge_sec_value(conf->expiry, prev->expiry, 3600);
	if (!conf->cookie_name.data && prev->cookie_name.data) {
		conf->cookie_name.len = prev->cookie_name.len;
		conf->cookie_name.data = prev->cookie_name.data;
	}
	if (!conf->extra_str.data && prev->extra_str.data) {
		conf->extra_str.len = prev->extra_str.len;
		conf->extra_str.data = prev->extra_str.data;
	}
	if (!conf->secrets[0] && prev->secrets[0]) {
		conf->secrets[0] = prev->secrets[0];
	}
	if (!conf->secrets[1] && prev->secrets[1]) {
		conf->secrets[1] = prev->secrets[1];
	}
	if (conf->token_to_verify == NGX_CONF_UNSET_PTR && prev->token_to_verify != NGX_CONF_UNSET_PTR) {
		conf->token_to_verify = prev->token_to_verify;
	}
	return NGX_CONF_OK;
}

static int do_verify_token(ngx_http_request_t *r, verify_token_conf_t *conf, time_t *ttl) {
	ngx_str_t token_c, token;
	time_t ttime, curtime;
	size_t len;
	u_char *buf;
	u_char obuf[BLAKE3_OUT_LEN];
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	if (conf->token_to_verify != NGX_CONF_UNSET_PTR && conf->token_to_verify) {
		if (ngx_http_complex_value(r, conf->token_to_verify, &token_c) != NGX_OK) {
			return VERIFY_TOKEN_ERROR;
		}
	} else if (conf->cookie_name.len) {
		if (
#if nginx_version >= 1029006
	ngx_http_parse_cookie_lines
#else
	ngx_http_parse_multi_header_lines
#endif
	(r, r->headers_in.cookie, &conf->cookie_name, &token_c) == NULL) {
			return VERIFY_TOKEN_FAILURE;
		}
	} else {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "verify_token: verify_token_cookie or verify_token_verify must be set");
		return VERIFY_TOKEN_ERROR;
	}

	token.data = ngx_pnalloc(r->pool, ngx_base64_decoded_length(token_c.len));
	if (token.data == NULL) {
		return VERIFY_TOKEN_ERROR;
	}
	if (ngx_decode_base64(&token, &token_c) != NGX_OK || token.len != sizeof(time_t) + BLAKE3_OUT_LEN) {
		return VERIFY_TOKEN_FAILURE;
	}

	curtime = ngx_time();
	ttime = le64toh(*(time_t *) token.data);
	time_t rttl = (ttime + conf->expiry) - curtime;
	if (rttl <= 0 || ttime > curtime + 60) {
		return VERIFY_TOKEN_FAILURE;
	}
	if (ttl != NULL) {
		*ttl = rttl;
	}
	buf = ngx_pnalloc(r->pool, sizeof(time_t) + sizeof(struct in6_addr) + conf->extra_str.len);
	if (buf == NULL) {
		return VERIFY_TOKEN_ERROR;
	}

	*(time_t *) buf = *(time_t *) token.data;
	len = sizeof(time_t);

	switch (r->connection->sockaddr->sa_family) {
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
			memcpy(buf + len, &sin6->sin6_addr.s6_addr, sizeof(struct in6_addr));
			len += sizeof(struct in6_addr);
			break;
		case AF_INET:
			sin = (struct sockaddr_in *) r->connection->sockaddr;
			*(in_addr_t *) (buf + len) = sin->sin_addr.s_addr;
			len += sizeof(in_addr_t);
			break;
		default:
			// possibly UNIX socket
			return VERIFY_TOKEN_FAILURE;
	}
	if (conf->extra_str.len) {
		memcpy(buf + len, conf->extra_str.data, conf->extra_str.len);
		len += conf->extra_str.len;
	}

	for (int c = 0; c < 2; c++) {
		if (!conf->secrets[c]) {
			continue;
		}
		blake3_hasher hasher;
		blake3_hasher_init_keyed(&hasher, conf->secrets[c]);
		blake3_hasher_update(&hasher, buf, len);
		blake3_hasher_finalize(&hasher, obuf, BLAKE3_OUT_LEN);
		if (!memcmp(obuf, token.data + sizeof(time_t), BLAKE3_OUT_LEN)) {
			return VERIFY_TOKEN_SUCCESS;
		}
	}

	return 0;
}

static int get_token(const ngx_http_request_t *r, const verify_token_conf_t *conf, ngx_str_t *token) {
	ngx_str_t token_bin;
	size_t len;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	u_char *buf;
	u_char obuf[sizeof(time_t) + BLAKE3_OUT_LEN];
	time_t curtime;

	size_t tokenlen = ngx_base64_encoded_length(sizeof(time_t) + BLAKE3_OUT_LEN);
	token->data = ngx_pnalloc(r->pool, tokenlen);
	buf = ngx_pnalloc(r->pool, sizeof(time_t) + sizeof(struct in6_addr) + conf->extra_str.len);
	if (token->data == NULL || buf == NULL) {
		return NGX_ERROR;
	}
	token_bin.len = sizeof(obuf);
	token_bin.data = (u_char *) &obuf;

	curtime = htole64(ngx_time());
	*(time_t *) buf = curtime;
	len = sizeof(time_t);
	time_t *obuft = (time_t *)&obuf;
	*obuft = curtime;

	switch (r->connection->sockaddr->sa_family) {
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
			memcpy(buf + len, &sin6->sin6_addr.s6_addr, sizeof(struct in6_addr));
			len += sizeof(struct in6_addr);
			break;
		case AF_INET:
			sin = (struct sockaddr_in *) r->connection->sockaddr;
			*(in_addr_t *) (buf + len) = sin->sin_addr.s_addr;
			len += sizeof(in_addr_t);
			break;
		default:
			// possibly UNIX socket
			return 0;
	}

	if (conf->extra_str.len) {
		memcpy(buf + len, conf->extra_str.data, conf->extra_str.len);
		len += conf->extra_str.len;
	}

	blake3_hasher hasher;
	blake3_hasher_init_keyed(&hasher, conf->secrets[0]);
	blake3_hasher_update(&hasher, buf, len);
	blake3_hasher_finalize(&hasher, &obuf[sizeof(time_t)], BLAKE3_OUT_LEN);

	ngx_encode_base64(token, &token_bin);

	return 1;
}

static ngx_int_t verify_token_handler(ngx_http_request_t *r)
{
	ngx_str_t rloc, argdata;
	int arg = 0;
	int verified = VERIFY_TOKEN_UNKNOWN;
	time_t ttl;

	verify_token_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_verify_token_module);

	if (!conf->redir_enabled) {
		return NGX_DECLINED;
	}

	if (ngx_http_complex_value(r, conf->redir_location, &rloc) != NGX_OK) {
		return NGX_ERROR;
	}

	if (
		rloc.len == 0
		||
		(rloc.len == 3 && memcmp(rloc.data, "off", 3) == 0)
	) {
		return NGX_DECLINED;
	}
	arg = conf->redir_arg && conf->redir_arg != NGX_CONF_UNSET_PTR;

	if (!conf->secrets[0]) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "verify_token: secret unset");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (verified == VERIFY_TOKEN_UNKNOWN) {
		verified = do_verify_token(r, conf, NULL);
		if (verified == VERIFY_TOKEN_ERROR) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		verified = verified == VERIFY_TOKEN_SUCCESS;
	}
	if (verified) {
		return NGX_DECLINED;
	}

	ngx_int_t rc;
	if (rloc.len == 3 && (rc = ngx_atoi(rloc.data, 3)) != NGX_ERROR) {
		switch (rc) {
			case 301:
			case 302:
			case 303:
			case 307:
			case 308:
				if (arg) {
					if (arg && ngx_http_complex_value(r, conf->redir_arg, &argdata) != NGX_OK) {
						return NGX_ERROR;
					}
					r->headers_out.location = ngx_list_push(&r->headers_out.headers);
					if (r->headers_out.location == NULL) {
						return NGX_ERROR;
					}
					r->headers_out.location->hash = 1;
					ngx_str_set(&r->headers_out.location->key, "Location");
					r->headers_out.location->value = argdata;
				}
		}
		r->headers_out.status = rc;
		return rc;
	}

	if (rloc.data[0] == '@') {
		ngx_http_named_location(r, &rloc);
	} else {
		ngx_http_internal_redirect(r, &rloc, &r->args);
	}

	ngx_http_finalize_request(r, NGX_DONE);
	return NGX_DONE;
}


static ngx_int_t header_filter(ngx_http_request_t *r)
{
	verify_token_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_verify_token_module);
	int verified = VERIFY_TOKEN_UNKNOWN;

	if (! conf->add_header_enabled) {
		return ngx_http_next_header_filter(r);
	}

	if (!conf->secrets[0]) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "verify_token: secret unset");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	verify_token_headers_t *he = conf->headers->elts;
	for (int i = 0; i < conf->headers->nelts; i++) {
		ngx_str_t h_name, h_value;
		verify_token_headers_t h = he[i];
		int condition = h.condition;
		int auto_cookie = 0;

		if (condition != VERIFY_TOKEN_HEADER_ALWAYS) {
			time_t ttl;
			if (verified == VERIFY_TOKEN_UNKNOWN) {
				verified = do_verify_token(r, conf, &ttl);
				if (verified == VERIFY_TOKEN_ERROR) {
					return NGX_HTTP_INTERNAL_SERVER_ERROR;
				}
				verified = verified == VERIFY_TOKEN_SUCCESS;
			}
			if (
				(condition == VERIFY_TOKEN_HEADER_INVALID && verified)
				||
				(condition == VERIFY_TOKEN_HEADER_VALID && !verified)
				||
				(condition == VERIFY_TOKEN_HEADER_EXPIRING && verified && ttl > h.ttl)
			) {
				continue;
			}
		}

		if (h.status) {
			ngx_uint_t *status = h.status->elts;
			int found = 0;
			for (int si = 0; si < h.status->nelts; si++) {
				if (r->headers_out.status == status[si]) {
					found = 1;
				}
			}
			if (!found) {
				continue;
			}
		}

		if (ngx_http_complex_value(r, h.name, &h_name) != NGX_OK) {
			return NGX_ERROR;
		}

		if (h_name.len == 0) {
			continue;
		}
		if (h_name.len == 3 && memcmp(h_name.data, "off", 3) == 0) {
			break;
		}
		else if (h_name.len == 6 && memcmp(h_name.data, "cookie", 6) == 0) {
			auto_cookie = 1;
			if (!conf->cookie_name.len) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "verify_token: cookie name unset");
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}
		}
		if (h.value) {
			if (ngx_http_complex_value(r, h.value, &h_value) != NGX_OK) {
				return NGX_ERROR;
			}
			if (! auto_cookie && ! h_value.len) {
				continue;
			}
		} else if (!auto_cookie) {
			continue;
		}

		ngx_table_elt_t *ha;
		ha = ngx_list_push(&r->headers_out.headers);
		if (ha == NULL) {
			return NGX_ERROR;
		}
		ha->hash = 1;
		if (auto_cookie) {
			ngx_str_t token;
			if (!get_token(r, conf, &token)) {
				return NGX_ERROR;
			}
			ha->value.data = ngx_pnalloc(r->pool,
				conf->cookie_name.len + token.len + NGX_TIME_T_LEN + 28);
			if (ha->value.data == NULL) {
				return NGX_ERROR;
			}
			ngx_str_set(&ha->key, "Set-Cookie");
			ha->value.len = ngx_sprintf(ha->value.data,
				"%V=%V; path=/; max-age=%i; Secure", &conf->cookie_name,
				&token, conf->expiry)
				- ha->value.data;
		} else {
			ha->key.len = h_name.len;
			ha->key.data = h_name.data;
			ha->value.len = h_value.len;
			ha->value.data = h_value.data;
			continue;
		}
	}

    return ngx_http_next_header_filter(r);
}

static ngx_int_t var_verify_token_result(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	verify_token_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_verify_token_module);
	int verified = 0;

	if (!conf->secrets[0]) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "While getting $verify_token_result: secret unset");
		return NGX_ERROR;
	}

	verified = do_verify_token(r, conf, NULL) == VERIFY_TOKEN_SUCCESS;

	v->no_cacheable = 1; // in testing this was redundant
	// The NGX_HTTP_VAR_NOCACHEABLE flag does the job
	v->valid = 1;
	v->not_found = 0;
	v->len = 1;
	v->data = (u_char *) (verified ? "1" : "0");

	return NGX_OK;
}

static ngx_int_t var_verify_token_token(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	verify_token_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_verify_token_module);

	if (!conf->secrets[0]) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "While getting $verify_token_token: secret unset");
		return NGX_ERROR;
	}

	ngx_str_t token;
	if (!get_token(r, conf, &token)) {
		return NGX_ERROR;
	}

	v->no_cacheable = 1;
	v->valid = 1;
	v->not_found = 0;
	v->len = token.len;
	v->data = token.data;

	return NGX_OK;
}

static ngx_int_t var_verify_token_escaped_uri(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
	uintptr_t len;
	len = 2 * ngx_escape_uri(NULL, r->unparsed_uri.data, r->unparsed_uri.len,
		data ? NGX_ESCAPE_URI_COMPONENT : NGX_ESCAPE_ARGS) + r->unparsed_uri.len;
	u_char *buf = ngx_pnalloc(r->pool, len);
	if (buf == NULL) {
		return NGX_ERROR;
	}
	ngx_escape_uri(buf, r->unparsed_uri.data, r->unparsed_uri.len,
		data ? NGX_ESCAPE_URI_COMPONENT : NGX_ESCAPE_ARGS);

	v->no_cacheable = 0;
	v->valid = 1;
	v->not_found = 0;
	v->len = len;
	v->data = buf;

	return NGX_OK;
}
