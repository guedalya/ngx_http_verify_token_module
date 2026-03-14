#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdint.h>
#include <string.h>
#include <blake3.h>
#include <endian.h>

typedef struct {
	unsigned required;
} verify_token_main_conf_t;

typedef struct {
	unsigned redir_enabled:1;
	unsigned add_header_enabled:1;
	unsigned add_header_if_invalid:1;
	time_t expiry;
	ngx_str_t cookie_name;
	ngx_str_t extra_str;
	u_char *secrets[2];
	ngx_http_complex_value_t *redir_location;
	ngx_http_complex_value_t *redir_arg;
	ngx_http_complex_value_t *add_header;
	ngx_http_complex_value_t *add_header_value;
} verify_token_conf_t;

static char *set_secret(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *set_redir_location(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *set_add_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *create_main_conf(ngx_conf_t *cf);
static ngx_int_t verify_token_handler(ngx_http_request_t *r);
static ngx_int_t init(ngx_conf_t *cf);
static void *create_conf(ngx_conf_t *cf);
static char *merge_conf(ngx_conf_t *cf, void *parent, void *child);
static int do_verify_cookie(ngx_http_request_t *r, verify_token_conf_t *conf);
static int get_token(const ngx_http_request_t *r, const verify_token_conf_t *conf, ngx_str_t *token);
static ngx_int_t add_variables(ngx_conf_t *cf);
static ngx_int_t var_verify_token_result(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t var_verify_token_token(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t var_verify_token_escaped_uri(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

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
		ngx_string("verify_token"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE12,
		set_redir_location,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(verify_token_conf_t, redir_location),
		NULL
	},
	{
		ngx_string("verify_token_add_header"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE123,
		set_add_header,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(verify_token_conf_t, add_header),
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
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"Secret is of incorrect length. Must be 32 bytes (64 hex characters) long");
		return NGX_CONF_ERROR;
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
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					"Secret contains non-hex characters");
				return NGX_CONF_ERROR;
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
		(value->len == 3 && strncmp(value->data, "off", 3) == 0)
	) {
		// disabled
		// prevent inheritance in merge_conf():
		conf->redir_location = NULL;
		conf->redir_arg = NULL;
		return NGX_CONF_OK;
	} else {
		vtmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_verify_token_module);
		vtmcf->required = 1;
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
	ngx_http_compile_complex_value_t ccv;
	verify_token_main_conf_t *vtmcf;
	verify_token_conf_t *conf = cp;
	ngx_uint_t nelts = cf->args->nelts;

	if (conf->add_header != NGX_CONF_UNSET_PTR) {
		return "is duplicate";
	}

	value = cf->args->elts;
	nelts--;
	value++;

	if (
		value->len == 0
		||
		(value->len == 3 && strncmp(value->data, "off", 3) == 0)
	) {
		// disabled
		// prevent inheritance in merge_conf():
		conf->add_header = NULL;
		conf->add_header_value = NULL;
		return NGX_CONF_OK;
	}

	/* if (nelts < 2) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"Header value missing");
		return NGX_CONF_ERROR;
	} */

	vtmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_verify_token_module);
	vtmcf->required = 1;
	conf->add_header_enabled = 1;

	conf->add_header = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
	if (conf->add_header == NULL) {
		return NGX_CONF_ERROR;
	}

	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

	ccv.cf = cf;
	ccv.value = value;
	ccv.complex_value = conf->add_header;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	nelts--;
	if (!nelts) {
		conf->add_header_value = NULL;
		return NGX_CONF_OK;
	}
	value++;

	conf->add_header_value = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
	if (conf->add_header_value == NULL) {
		return NGX_CONF_ERROR;
	}

	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

	ccv.cf = cf;
	ccv.value = value;
	ccv.complex_value = conf->add_header_value;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	nelts--;
	if (!nelts) {
		return NGX_CONF_OK;
	}
	value++;

	if (value->len == 10 && strncmp(value->data, "if-invalid", 10) == 0) {
		conf->add_header_if_invalid = 1;
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
	if (mcf->required) {
		h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
		if (h == NULL) {
			return NGX_ERROR;
		}
		*h = verify_token_handler;
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
	conf->redir_location = NGX_CONF_UNSET_PTR;
	conf->redir_arg = NGX_CONF_UNSET_PTR;
	conf->add_header = NGX_CONF_UNSET_PTR;
	conf->add_header_value = NGX_CONF_UNSET_PTR;
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
	if (conf->add_header == NGX_CONF_UNSET_PTR && prev->add_header != NGX_CONF_UNSET_PTR) {
		conf->add_header = prev->add_header;
		conf->add_header_value = prev->add_header_value;
		conf->add_header_enabled = prev->add_header_enabled;
		conf->add_header_if_invalid = prev->add_header_if_invalid;
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

	return NGX_CONF_OK;
}

static int do_verify_cookie(ngx_http_request_t *r, verify_token_conf_t *conf) {
	ngx_str_t token_c, token;
	time_t ttime, curtime;
	size_t len;
	u_char *buf;
	u_char obuf[BLAKE3_OUT_LEN];
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	if (! conf->cookie_name.len) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "verify_token: cookie name unset");
		return NGX_ERROR;
	}

	if (ngx_http_parse_multi_header_lines(r, r->headers_in.cookie, &conf->cookie_name, &token_c) == NULL) {
		return 0;
	}
	token.data = ngx_pnalloc(r->pool, ngx_base64_decoded_length(token_c.len));
	if (token.data == NULL) {
		return NGX_ERROR;
	}
	if (ngx_decode_base64(&token, &token_c) != NGX_OK || token.len != sizeof(time_t) + BLAKE3_OUT_LEN) {
		return 0;
	}

	curtime = ngx_time();
	ttime = le64toh(*(time_t *) token.data);
	if (ttime + conf->expiry < curtime || ttime > curtime + 60) {
		return 0;
	}
	buf = ngx_pnalloc(r->pool, sizeof(time_t) + sizeof(struct in6_addr) + conf->extra_str.len);
	if (buf == NULL) {
		return NGX_ERROR;
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
			return 0;
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
			return 1;
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
	ngx_str_t rloc, argdata, add_header, add_header_value;
	int arg = 0, verified = 0, auto_cookie = 0;
	int redir_enabled, add_header_enabled, if_invalid;

	verify_token_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_verify_token_module);

	redir_enabled = conf->redir_enabled;
	if (redir_enabled) {
		if (ngx_http_complex_value(r, conf->redir_location, &rloc) != NGX_OK) {
			return NGX_ERROR;
		}

		if (
			rloc.len == 0
			||
			(rloc.len == 3 && strncmp(rloc.data, "off", 3) == 0)
		) {
			redir_enabled = 0;
		}
		arg = conf->redir_arg && conf->redir_arg != NGX_CONF_UNSET_PTR;
	}

	add_header_enabled = conf->add_header_enabled;
	if_invalid = conf->add_header_if_invalid;
	if (add_header_enabled) {
		if (ngx_http_complex_value(r, conf->add_header, &add_header) != NGX_OK) {
			return NGX_ERROR;
		}

		if (
			add_header.len == 0
			||
			(add_header.len == 3 && strncmp(add_header.data, "off", 3) == 0)
		) {
			add_header_enabled = 0;
		}
		else if (add_header.len == 6 && strncmp(add_header.data, "cookie", 6) == 0) {
			auto_cookie = 1;
			if (!conf->cookie_name.len) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "verify_token: cookie name unset");
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}
		}
		if (conf->add_header_value) {
			if (ngx_http_complex_value(r, conf->add_header_value, &add_header_value) != NGX_OK) {
				return NGX_ERROR;
			}
			if (add_header_value.len == 0 && !auto_cookie) {
				add_header_enabled = 0;
			}
			else if (auto_cookie &&
				add_header_value.len == 10 &&
				strncmp(add_header_value.data, "if-invalid", 10) == 0
			) {
				if_invalid = 1;
			}
		} else if (!auto_cookie) {
			add_header_enabled = 0;
		}
	}

	if (!redir_enabled && !add_header_enabled) {
		return NGX_DECLINED;
	}

	if (!conf->secrets[0]) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "verify_token: secret unset");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (redir_enabled || (add_header_enabled && if_invalid)) {
		verified = do_verify_cookie(r, conf);
		if (verified == NGX_ERROR) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		verified = verified == 1;
	}

	if (add_header_enabled && !verified) {
		ngx_table_elt_t *h;
		h = ngx_list_push(&r->headers_out.headers);
		if (h == NULL) {
			return NGX_ERROR;
		}
		h->hash = 1;
		if (auto_cookie) {
			ngx_str_t token;
			if (!get_token(r, conf, &token)) {
				return NGX_ERROR;
			}
			h->value.data = ngx_pnalloc(r->pool,
				conf->cookie_name.len + token.len + NGX_TIME_T_LEN + 28);
			if (h->value.data == NULL) {
				return NGX_ERROR;
			}
			ngx_str_set(&h->key, "Set-Cookie");
			h->value.len = ngx_sprintf(h->value.data,
				"%V=%V; path=/; max-age=%i; Secure", &conf->cookie_name,
				&token, conf->expiry)
				- h->value.data;
		} else {
			h->key.len = add_header.len;
			h->key.data = add_header.data;
			h->value.len = add_header_value.len;
			h->value.data = add_header_value.data;
		}
	}

	if (redir_enabled && !verified) {
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

	return NGX_DECLINED;
}

static ngx_int_t var_verify_token_result(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	verify_token_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_verify_token_module);
	int verified = 0;

	if (!conf->secrets[0]) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "While getting $verify_token_result: secret unset");
		return NGX_ERROR;
	}

	verified = do_verify_cookie(r, conf) == 1;

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
