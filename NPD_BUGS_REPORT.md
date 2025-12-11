# Null Pointer Dereference (NPD) Bugs Report

**Analysis Date:** 2025-12-11
**Codebase:** OpenLDAP Libraries
**Total High-Confidence NPD Bugs Found:** 4

---

## Bug #1: NPD in `ldif_open_mem` function

**Severity:** HIGH
**File:** `libraries/libldap/ldif.c`
**Lines:** 753-755

### Code Block
```c
LDIFFP *
ldif_open_mem(
	char *ldif,
	size_t size,
	LDAP_CONST char *mode
)
{
#ifdef HAVE_FMEMOPEN
	FILE *fp = fmemopen( ldif, size, mode );
	LDIFFP *lfp = NULL;

	if ( fp ) {
		lfp = ber_memalloc( sizeof( LDIFFP ));  // Line 753: Can return NULL
		lfp->fp = fp;                            // Line 754: NPD - lfp can be NULL
		lfp->prev = NULL;                        // Line 755: NPD - lfp can be NULL
	}
	return lfp;
#else
	return NULL;
#endif
}
```

### Analysis
- **Null Source:** `ber_memalloc` at line 753 can return NULL if memory allocation fails
- **Guaranteed Dereference:** Lines 754 and 755 unconditionally dereference `lfp` without NULL check
- **Impact:** Crash when memory allocation fails and `fp` is valid

### Recommended Fix
Add NULL check after `ber_memalloc`:
```c
if ( fp ) {
	lfp = ber_memalloc( sizeof( LDIFFP ));
	if ( lfp == NULL ) {
		fclose( fp );
		return NULL;
	}
	lfp->fp = fp;
	lfp->prev = NULL;
}
```

---

## Bug #2: NPD in `ldif_open_url` function

**Severity:** HIGH
**File:** `libraries/libldap/fetch.c`
**Lines:** 71-80

### Code Block
```c
FILE *
ldif_open_url(
	LDAP_CONST char *urlstr )
{
	FILE *url;

	if( strncasecmp( "file:", urlstr, sizeof("file:")-1 ) == 0 ) {
		char *p;
		urlstr += sizeof("file:")-1;

		/* ... path validation ... */

		p = ber_strdup( urlstr );                // Line 71: Can return NULL

		/* But we should convert to LDAP_DIRSEP before use */
		if ( LDAP_DIRSEP[0] != '/' ) {
			char *s = p;                         // Line 75: Uses p without check
			while (( s = strchr( s, '/' )))     // Line 76: strchr called on p
				*s++ = LDAP_DIRSEP[0];
		}

		ldap_pvt_hex_unescape( p );              // Line 80: NPD - p can be NULL

		url = fopen( p, "rb" );

		ber_memfree( p );
	} else {
		/* ... */
	}
	return url;
}
```

### Analysis
- **Null Source:** `ber_strdup` at line 71 can return NULL if memory allocation fails
- **Guaranteed Dereferences:**
  - Line 75: Assignment to `s` without NULL check
  - Line 76: `strchr(s, '/')` dereferences the pointer
  - Line 80: `ldap_pvt_hex_unescape(p)` dereferences the pointer
- **Impact:** Multiple crash points when memory allocation fails

### Recommended Fix
Add NULL check after `ber_strdup`:
```c
p = ber_strdup( urlstr );
if ( p == NULL ) {
	return NULL;
}

if ( LDAP_DIRSEP[0] != '/' ) {
	char *s = p;
	while (( s = strchr( s, '/' )))
		*s++ = LDAP_DIRSEP[0];
}

ldap_pvt_hex_unescape( p );
url = fopen( p, "rb" );
ber_memfree( p );
```

---

## Bug #3: NPD in `ldap_pvt_sasl_cbinding` function

**Severity:** HIGH
**File:** `libraries/libldap/cyrus.c`
**Lines:** 416-421

### Code Block
```c
void *ldap_pvt_sasl_cbinding( void *ssl, int type, int is_server )
{
#if defined(SASL_CHANNEL_BINDING) && defined(HAVE_TLS)
	char unique_prefix[] = "tls-unique:";
	char endpoint_prefix[] = "tls-server-end-point:";
	char cbinding[ 64 ];
	struct berval cbv = { 64, cbinding };
	unsigned char *cb_data;
	sasl_channel_binding_t *cb;
	char *prefix;
	int plen;

	switch (type) {
	case LDAP_OPT_X_SASL_CBINDING_NONE:
		return NULL;
	case LDAP_OPT_X_SASL_CBINDING_TLS_UNIQUE:
		if ( !ldap_pvt_tls_get_unique( ssl, &cbv, is_server ))
			return NULL;
		prefix = unique_prefix;
		plen = sizeof(unique_prefix) -1;
		break;
	case LDAP_OPT_X_SASL_CBINDING_TLS_ENDPOINT:
		if ( !ldap_pvt_tls_get_endpoint( ssl, &cbv, is_server ))
			return NULL;
		prefix = endpoint_prefix;
		plen = sizeof(endpoint_prefix) -1;
		break;
	default:
		return NULL;
	}

	cb = ldap_memalloc( sizeof(*cb) + plen + cbv.bv_len );  // Line 416: Can return NULL
	cb->len = plen + cbv.bv_len;                             // Line 417: NPD
	cb->data = cb_data = (unsigned char *)(cb+1);           // Line 418: NPD
	memcpy( cb_data, prefix, plen );                        // Line 419: Uses cb_data
	memcpy( cb_data + plen, cbv.bv_val, cbv.bv_len );      // Line 420: Uses cb_data
	cb->name = "ldap";                                      // Line 421: NPD
	cb->critical = 0;

	return cb;
#else
	return NULL;
#endif
}
```

### Analysis
- **Null Source:** `ldap_memalloc` at line 416 can return NULL if memory allocation fails
- **Guaranteed Dereferences:**
  - Line 417: `cb->len` dereference
  - Line 418: `cb+1` pointer arithmetic and dereference
  - Line 421: `cb->name` dereference
- **Impact:** Crash when memory allocation fails during SASL channel binding setup

### Recommended Fix
Add NULL check after `ldap_memalloc`:
```c
cb = ldap_memalloc( sizeof(*cb) + plen + cbv.bv_len );
if ( cb == NULL ) {
	return NULL;
}
cb->len = plen + cbv.bv_len;
cb->data = cb_data = (unsigned char *)(cb+1);
memcpy( cb_data, prefix, plen );
memcpy( cb_data + plen, cbv.bv_val, cbv.bv_len );
cb->name = "ldap";
cb->critical = 0;

return cb;
```

---

## Bug #4: NPD in `ldap_pvt_sasl_mutex_new` function

**Severity:** HIGH
**File:** `libraries/libldap/cyrus.c`
**Lines:** 1255-1258

### Code Block
```c
void *ldap_pvt_sasl_mutex_new(void)
{
	ldap_pvt_thread_mutex_t *mutex;

	mutex = (ldap_pvt_thread_mutex_t *) LDAP_CALLOC( 1,
		sizeof(ldap_pvt_thread_mutex_t) );       // Line 1255-1256: Can return NULL

	if ( ldap_pvt_thread_mutex_init( mutex ) == 0 ) { // Line 1258: NPD
		return mutex;
	}
	LDAP_FREE( mutex );
#ifndef LDAP_DEBUG_R_SASL
	assert( 0 );
#endif
	return NULL;
}
```

### Analysis
- **Null Source:** `LDAP_CALLOC` at lines 1255-1256 can return NULL if memory allocation fails
- **Guaranteed Dereference:** Line 1258 calls `ldap_pvt_thread_mutex_init(mutex)` which dereferences the mutex pointer to initialize the structure
- **Impact:** Crash when memory allocation fails during mutex creation for SASL

### Recommended Fix
Add NULL check after `LDAP_CALLOC`:
```c
void *ldap_pvt_sasl_mutex_new(void)
{
	ldap_pvt_thread_mutex_t *mutex;

	mutex = (ldap_pvt_thread_mutex_t *) LDAP_CALLOC( 1,
		sizeof(ldap_pvt_thread_mutex_t) );

	if ( mutex == NULL ) {
		return NULL;
	}

	if ( ldap_pvt_thread_mutex_init( mutex ) == 0 ) {
		return mutex;
	}
	LDAP_FREE( mutex );
#ifndef LDAP_DEBUG_R_SASL
	assert( 0 );
#endif
	return NULL;
}
```

---

## Summary

### Pattern Analysis
All 4 bugs follow the same vulnerability pattern:
1. **Null Source**: Memory allocation functions can return NULL on failure
   - `ber_memalloc()`, `ber_strdup()`, `ldap_memalloc()`, `LDAP_CALLOC()`
2. **Missing Check**: No NULL validation after allocation
3. **Guaranteed Dereference**: Pointer is immediately used without protection

### Risk Assessment
- **Probability**: Low to Medium (depends on memory availability)
- **Impact**: HIGH (application crash, potential DoS)
- **Exploitability**: Medium (requires triggering OOM conditions)

### Verification Method
Each bug was identified through:
1. Static code analysis
2. Control flow verification
3. Confirmation of unconditional dereference path

### Files Affected
- `libraries/libldap/ldif.c` (1 bug)
- `libraries/libldap/fetch.c` (1 bug)
- `libraries/libldap/cyrus.c` (2 bugs)

### Recommendations
1. Add NULL checks immediately after all memory allocations
2. Implement consistent error handling for allocation failures
3. Consider using wrapper functions with built-in NULL checking
4. Add unit tests for OOM scenarios
5. Review other allocation sites in the codebase for similar patterns

---

**Report Generated By:** Automated Static Analysis
**Confidence Level:** HIGH (All bugs have provable null source and guaranteed dereference)
