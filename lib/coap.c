/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifndef CURL_DISABLE_COAP

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "urldata.h"
#include <curl/curl.h>
#include "transfer.h"
#include "sendf.h"

#include "progress.h"
#include "dict.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

#include "urldata.h"

/*
 * Forward declarations.
 */


static CURLcode coap_do(struct connectdata *conn, bool *done);
static CURLcode coap_done(struct connectdata *, CURLcode, bool);
static CURLcode coap_doing(struct connectdata *conn, bool *done);
static CURLcode coap_disconnect(struct connectdata *conn, bool done);
static CURLcode coap_connect_it(struct connectdata *conn, bool *done);
static CURLcode coap_connecting(struct connectdata *conn, bool *done);
static CURLcode coap_setup_connection(struct connectdata *conn);
static int coap_proto_getsock(struct connectdata *conn, curl_socket_t *socks, int numsocks);
static CURLcode coap_readwrite(struct Curl_easy *data, struct connectdata *conn, ssize_t *nread, bool *readmore);
static unsigned int coap_connection_check(struct connectdata *conn, unsigned int checks_to_perform);

/*
 * COAP protocol handler.
 */

const struct Curl_handler Curl_handler_coap = {
        "COAP",                               /* scheme */
        coap_setup_connection,                /* setup_connection */
        coap_do,                              /* do_it */
        coap_done,                            /* done */
        ZERO_NULL,                            /* do_more */
        coap_connect_it,                      /* connect_it */
        coap_connecting,                      /* connecting */
        coap_doing,                           /* doing */
        coap_proto_getsock,                   /* proto_getsock */
        ZERO_NULL,                            /* doing_getsock */
        ZERO_NULL,                            /* domore_getsock */
        ZERO_NULL,                            /* perform_getsock */
        coap_disconnect,                      /* disconnect */
        coap_readwrite,                       /* readwrite */
        coap_connection_check,                /* connection check */
        PORT_COAP,                            /* defport */
        CURLPROTO_COAP,                       /* protocol */
        PROTOPT_NONE | PROTOPT_NOURLQUERY     /* flags */
};

static CURLcode coap_connect_it(struct connectdata *conn, bool *done) {
    printf("CoAP connect it");
    return CURLE_OK;
}

static CURLcode coap_connecting(struct connectdata *conn, bool *done) {
    printf("Coap connecting");
    return CURLE_OK;
}

static CURLcode coap_setup_connection(struct connectdata *conn) {
    printf("Coap setup connection");
    return CURLE_OK;
}

static CURLcode coap_do(struct connectdata *conn, bool *done) {
    printf("CoAP hello world\n");
    return CURLE_OK;
}

static CURLcode coap_done(struct connectdata *conn, CURLcode curl_code, bool done) {
    printf("It's done\n");
    return CURLE_OK;
}

static CURLcode coap_doing(struct connectdata *conn, bool *done) {
    printf("It's done\n");
    return CURLE_OK;
}

static CURLcode coap_disconnect(struct connectdata *conn, bool done) {
    printf("It's done\n");
    return CURLE_OK;
}

static int coap_proto_getsock(struct connectdata *conn, curl_socket_t *socks, int numsocks){
    return 0;
}

static CURLcode coap_readwrite(struct Curl_easy *data, struct connectdata *conn, ssize_t *nread, bool *readmore){
    return CURLE_OK;
}

static unsigned int coap_connection_check(struct connectdata *conn, unsigned int checks_to_perform){
    printf("Perform connection check\n");
    return 0;
}

/*
 * address.h -- representation of network addresses
 *
 * Copyright (C) 2010-2011,2015-2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file address.h
 * @brief Representation of network addresses
 */

#ifndef COAP_ADDRESS_H_
#define COAP_ADDRESS_H_

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#if defined(WITH_LWIP)

#include <lwip/ip_addr.h>

typedef struct coap_address_t {
  uint16_t port;
  ip_addr_t addr;
} coap_address_t;

#define _coap_address_equals_impl(A, B) \
        ((A)->port == (B)->port        \
        && (!!ip_addr_cmp(&(A)->addr,&(B)->addr)))

#define _coap_address_isany_impl(A)  ip_addr_isany(&(A)->addr)

#define _coap_is_mcast_impl(Address) ip_addr_ismulticast(&(Address)->addr)

#elif defined(WITH_CONTIKI)

#include "uip.h"

typedef struct coap_address_t {
  uip_ipaddr_t addr;
  uint16_t port;
} coap_address_t;

#define _coap_address_equals_impl(A,B) \
        ((A)->port == (B)->port        \
        && uip_ipaddr_cmp(&((A)->addr),&((B)->addr)))

/** @todo implementation of _coap_address_isany_impl() for Contiki */
#define _coap_address_isany_impl(A)  0

#define _coap_is_mcast_impl(Address) uip_is_addr_mcast(&((Address)->addr))

#else /* WITH_LWIP || WITH_CONTIKI */

 /** multi-purpose address abstraction */
typedef struct coap_address_t {
  socklen_t size;           /**< size of addr */
  union {
    struct sockaddr         sa;
    struct sockaddr_in      sin;
    struct sockaddr_in6     sin6;
  } addr;
} coap_address_t;

/**
 * Compares given address objects @p a and @p b. This function returns @c 1 if
 * addresses are equal, @c 0 otherwise. The parameters @p a and @p b must not be
 * @c NULL;
 */
int coap_address_equals(const coap_address_t *a, const coap_address_t *b);

COAP_STATIC_INLINE int
_coap_address_isany_impl(const coap_address_t *a) {
  /* need to compare only relevant parts of sockaddr_in6 */
  switch (a->addr.sa.sa_family) {
  case AF_INET:
    return a->addr.sin.sin_addr.s_addr == INADDR_ANY;
  case AF_INET6:
    return memcmp(&in6addr_any,
                  &a->addr.sin6.sin6_addr,
                  sizeof(in6addr_any)) == 0;
  default:
    ;
  }

  return 0;
}
#endif /* WITH_LWIP || WITH_CONTIKI */

/**
 * Resets the given coap_address_t object @p addr to its default values. In
 * particular, the member size must be initialized to the available size for
 * storing addresses.
 *
 * @param addr The coap_address_t object to initialize.
 */
COAP_STATIC_INLINE void
coap_address_init(coap_address_t *addr) {
  assert(addr);
  memset(addr, 0, sizeof(coap_address_t));
#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI)
  /* lwip and Contiki have constant address sizes and doesn't need the .size part */
  addr->size = sizeof(addr->addr);
#endif
}

/* Convenience function to copy IPv6 addresses without garbage. */

COAP_STATIC_INLINE void
coap_address_copy( coap_address_t *dst, const coap_address_t *src ) {
#if defined(WITH_LWIP) || defined(WITH_CONTIKI)
  memcpy( dst, src, sizeof( coap_address_t ) );
#else
  memset( dst, 0, sizeof( coap_address_t ) );
  dst->size = src->size;
  if ( src->addr.sa.sa_family == AF_INET6 ) {
    dst->addr.sin6.sin6_family = src->addr.sin6.sin6_family;
    dst->addr.sin6.sin6_addr = src->addr.sin6.sin6_addr;
    dst->addr.sin6.sin6_port = src->addr.sin6.sin6_port;
    dst->addr.sin6.sin6_scope_id = src->addr.sin6.sin6_scope_id;
  } else if ( src->addr.sa.sa_family == AF_INET ) {
    dst->addr.sin = src->addr.sin;
  } else {
    memcpy( &dst->addr, &src->addr, src->size );
  }
#endif
}

#if defined(WITH_LWIP) || defined(WITH_CONTIKI)
/**
 * Compares given address objects @p a and @p b. This function returns @c 1 if
 * addresses are equal, @c 0 otherwise. The parameters @p a and @p b must not be
 * @c NULL;
 */
COAP_STATIC_INLINE int
coap_address_equals(const coap_address_t *a, const coap_address_t *b) {
  assert(a); assert(b);
  return _coap_address_equals_impl(a, b);
}
#endif

/**
 * Checks if given address object @p a denotes the wildcard address. This
 * function returns @c 1 if this is the case, @c 0 otherwise. The parameters @p
 * a must not be @c NULL;
 */
COAP_STATIC_INLINE int
coap_address_isany(const coap_address_t *a) {
  assert(a);
  return _coap_address_isany_impl(a);
}

#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI)

/**
 * Checks if given address @p a denotes a multicast address. This function
 * returns @c 1 if @p a is multicast, @c 0 otherwise.
 */
int coap_is_mcast(const coap_address_t *a);
#else /* !WITH_LWIP && !WITH_CONTIKI */
/**
 * Checks if given address @p a denotes a multicast address. This function
 * returns @c 1 if @p a is multicast, @c 0 otherwise.
 */
COAP_STATIC_INLINE int
coap_is_mcast(const coap_address_t *a) {
  return a && _coap_is_mcast_impl(a);
}
#endif /* !WITH_LWIP && !WITH_CONTIKI */

#endif /* COAP_ADDRESS_H_ */
/*
 * async.h -- state management for asynchronous messages
 *
 * Copyright (C) 2010-2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file async.h
 * @brief State management for asynchronous messages
 */

#ifndef COAP_ASYNC_H_
#define COAP_ASYNC_H_

#include "net.h"

#ifndef WITHOUT_ASYNC

/**
 * @defgroup coap_async Asynchronous Messaging
 * @{
 * Structure for managing asynchronous state of CoAP resources. A
 * coap_resource_t object holds a list of coap_async_state_t objects that can be
 * used to generate a separate response in case a result of an operation cannot
 * be delivered in time, or the resource has been explicitly subscribed to with
 * the option @c observe.
 */
typedef struct coap_async_state_t {
  unsigned char flags;  /**< holds the flags to control behaviour */

  /**
   * Holds the internal time when the object was registered with a
   * resource. This field will be updated whenever
   * coap_register_async() is called for a specific resource.
   */
  coap_tick_t created;

  /**
   * This field can be used to register opaque application data with the
   * asynchronous state object.
   */
  void *appdata;
  uint16_t message_id;       /**< id of last message seen */
  coap_session_t *session;         /**< transaction session */
  coap_tid_t id;                   /**< transaction id */
  struct coap_async_state_t *next; /**< internally used for linking */
  size_t tokenlen;                 /**< length of the token */
  uint8_t token[8];                /**< the token to use in a response */
} coap_async_state_t;

/* Definitions for Async Status Flags These flags can be used to control the
 * behaviour of asynchronous response generation.
 */
#define COAP_ASYNC_CONFIRM   0x01  /**< send confirmable response */
#define COAP_ASYNC_SEPARATE  0x02  /**< send separate response */
#define COAP_ASYNC_OBSERVED  0x04  /**< the resource is being observed */

/** release application data on destruction */
#define COAP_ASYNC_RELEASE_DATA  0x08

/**
 * Allocates a new coap_async_state_t object and fills its fields according to
 * the given @p request. The @p flags are used to control generation of empty
 * ACK responses to stop retransmissions and to release registered @p data when
 * the resource is deleted by coap_free_async(). This function returns a pointer
 * to the registered coap_async_t object or @c NULL on error. Note that this
 * function will return @c NULL in case that an object with the same identifier
 * is already registered.
 *
 * @param context  The context to use.
 * @param session  The session that is used for asynchronous transmissions.
 * @param request  The request that is handled asynchronously.
 * @param flags    Flags to control state management.
 * @param data     Opaque application data to register. Note that the
 *                 storage occupied by @p data is released on destruction
 *                 only if flag COAP_ASYNC_RELEASE_DATA is set.
 *
 * @return         A pointer to the registered coap_async_state_t object or @c
 *                 NULL in case of an error.
 */
coap_async_state_t *
coap_register_async(coap_context_t *context,
                    coap_session_t *session,
                    coap_pdu_t *request,
                    unsigned char flags,
                    void *data);

/**
 * Removes the state object identified by @p id from @p context. The removed
 * object is returned in @p s, if found. Otherwise, @p s is undefined. This
 * function returns @c 1 if the object was removed, @c 0 otherwise. Note that
 * the storage allocated for the stored object is not released by this
 * functions. You will have to call coap_free_async() to do so.
 *
 * @param context The context where the async object is registered.
 * @param session  The session that is used for asynchronous transmissions.
 * @param id      The identifier of the asynchronous transaction.
 * @param s       Will be set to the object identified by @p id after removal.
 *
 * @return        @c 1 if object was removed and @p s updated, or @c 0 if no
 *                object was found with the given id. @p s is valid only if the
 *                return value is @c 1.
 */
int coap_remove_async(coap_context_t *context,
                      coap_session_t *session,
                      coap_tid_t id,
                      coap_async_state_t **s);

/**
 * Releases the memory that was allocated by coap_async_state_init() for the
 * object @p s. The registered application data will be released automatically
 * if COAP_ASYNC_RELEASE_DATA is set.
 *
 * @param state The object to delete.
 */
void
coap_free_async(coap_async_state_t *state);

/**
 * Retrieves the object identified by @p id from the list of asynchronous
 * transactions that are registered with @p context. This function returns a
 * pointer to that object or @c NULL if not found.
 *
 * @param context The context where the asynchronous objects are registered
 *                with.
 * @param session  The session that is used for asynchronous transmissions.
 * @param id      The id of the object to retrieve.
 *
 * @return        A pointer to the object identified by @p id or @c NULL if
 *                not found.
 */
coap_async_state_t *coap_find_async(coap_context_t *context, coap_session_t *session, coap_tid_t id);

/**
 * Updates the time stamp of @p s.
 *
 * @param s The state object to update.
 */
COAP_STATIC_INLINE void
coap_touch_async(coap_async_state_t *s) { coap_ticks(&s->created); }

/** @} */

#endif /*  WITHOUT_ASYNC */

#endif /* COAP_ASYNC_H_ */
/*
 * bits.h -- bit vector manipulation
 *
 * Copyright (C) 2010-2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file bits.h
 * @brief Bit vector manipulation
 */

#ifndef COAP_BITS_H_
#define COAP_BITS_H_

#include <stdint.h>

/**
 * Sets the bit @p bit in bit-vector @p vec. This function returns @c 1 if bit
 * was set or @c -1 on error (i.e. when the given bit does not fit in the
 * vector).
 *
 * @param vec  The bit-vector to change.
 * @param size The size of @p vec in bytes.
 * @param bit  The bit to set in @p vec.
 *
 * @return     @c -1 if @p bit does not fit into @p vec, @c 1 otherwise.
 */
COAP_STATIC_INLINE int
bits_setb(uint8_t *vec, size_t size, uint8_t bit) {
  if (size <= ((size_t)bit >> 3))
    return -1;

  *(vec + (bit >> 3)) |= (uint8_t)(1 << (bit & 0x07));
  return 1;
}

/**
 * Clears the bit @p bit from bit-vector @p vec. This function returns @c 1 if
 * bit was cleared or @c -1 on error (i.e. when the given bit does not fit in
 * the vector).
 *
 * @param vec  The bit-vector to change.
 * @param size The size of @p vec in bytes.
 * @param bit  The bit to clear from @p vec.
 *
 * @return     @c -1 if @p bit does not fit into @p vec, @c 1 otherwise.
 */
COAP_STATIC_INLINE int
bits_clrb(uint8_t *vec, size_t size, uint8_t bit) {
  if (size <= ((size_t)bit >> 3))
    return -1;

  *(vec + (bit >> 3)) &= (uint8_t)(~(1 << (bit & 0x07)));
  return 1;
}

/**
 * Gets the status of bit @p bit from bit-vector @p vec. This function returns
 * @c 1 if the bit is set, @c 0 otherwise (even in case of an error).
 *
 * @param vec  The bit-vector to read from.
 * @param size The size of @p vec in bytes.
 * @param bit  The bit to get from @p vec.
 *
 * @return     @c 1 if the bit is set, @c 0 otherwise.
 */
COAP_STATIC_INLINE int
bits_getb(const uint8_t *vec, size_t size, uint8_t bit) {
  if (size <= ((size_t)bit >> 3))
    return -1;

  return (*(vec + (bit >> 3)) & (1 << (bit & 0x07))) != 0;
}

#endif /* COAP_BITS_H_ */
/*
 * block.h -- block transfer
 *
 * Copyright (C) 2010-2012,2014-2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef COAP_BLOCK_H_
#define COAP_BLOCK_H_

#include "encode.h"
#include "option.h"
#include "pdu.h"

struct coap_resource_t;
struct coap_session_t;

/**
 * @defgroup block Block Transfer
 * API functions for handling PDUs using CoAP BLOCK options
 * @{
 */

#ifndef COAP_MAX_BLOCK_SZX
/**
 * The largest value for the SZX component in a Block option.
 */
#define COAP_MAX_BLOCK_SZX      6
#endif /* COAP_MAX_BLOCK_SZX */

/**
 * Structure of Block options.
 */
typedef struct {
  unsigned int num;       /**< block number */
  unsigned int m:1;       /**< 1 if more blocks follow, 0 otherwise */
  unsigned int szx:3;     /**< block size */
} coap_block_t;

/**
 * Returns the value of the least significant byte of a Block option @p opt.
 * For zero-length options (i.e. num == m == szx == 0), COAP_OPT_BLOCK_LAST
 * returns @c NULL.
 */
#define COAP_OPT_BLOCK_LAST(opt) \
  (coap_opt_length(opt) ? (coap_opt_value(opt) + (coap_opt_length(opt)-1)) : 0)

/** Returns the value of the More-bit of a Block option @p opt. */
#define COAP_OPT_BLOCK_MORE(opt) \
  (coap_opt_length(opt) ? (*COAP_OPT_BLOCK_LAST(opt) & 0x08) : 0)

/** Returns the value of the SZX-field of a Block option @p opt. */
#define COAP_OPT_BLOCK_SZX(opt)  \
  (coap_opt_length(opt) ? (*COAP_OPT_BLOCK_LAST(opt) & 0x07) : 0)

/**
 * Returns the value of field @c num in the given block option @p block_opt.
 */
unsigned int coap_opt_block_num(const coap_opt_t *block_opt);

/**
 * Checks if more than @p num blocks are required to deliver @p data_len
 * bytes of data for a block size of 1 << (@p szx + 4).
 */
COAP_STATIC_INLINE int
coap_more_blocks(size_t data_len, unsigned int num, uint16_t szx) {
  return ((num+1) << (szx + 4)) < data_len;
}

#if 0
/** Sets the More-bit in @p block_opt */
COAP_STATIC_INLINE void
coap_opt_block_set_m(coap_opt_t *block_opt, int m) {
  if (m)
    *(coap_opt_value(block_opt) + (coap_opt_length(block_opt) - 1)) |= 0x08;
  else
    *(coap_opt_value(block_opt) + (coap_opt_length(block_opt) - 1)) &= ~0x08;
}
#endif

/**
 * Initializes @p block from @p pdu. @p type must be either COAP_OPTION_BLOCK1
 * or COAP_OPTION_BLOCK2. When option @p type was found in @p pdu, @p block is
 * initialized with values from this option and the function returns the value
 * @c 1. Otherwise, @c 0 is returned.
 *
 * @param pdu   The pdu to search for option @p type.
 * @param type  The option to search for (must be COAP_OPTION_BLOCK1 or
 *              COAP_OPTION_BLOCK2).
 * @param block The block structure to initilize.
 *
 * @return      @c 1 on success, @c 0 otherwise.
 */
int coap_get_block(coap_pdu_t *pdu, uint16_t type, coap_block_t *block);

/**
 * Writes a block option of type @p type to message @p pdu. If the requested
 * block size is too large to fit in @p pdu, it is reduced accordingly. An
 * exception is made for the final block when less space is required. The actual
 * length of the resource is specified in @p data_length.
 *
 * This function may change *block to reflect the values written to @p pdu. As
 * the function takes into consideration the remaining space @p pdu, no more
 * options should be added after coap_write_block_opt() has returned.
 *
 * @param block       The block structure to use. On return, this object is
 *                    updated according to the values that have been written to
 *                    @p pdu.
 * @param type        COAP_OPTION_BLOCK1 or COAP_OPTION_BLOCK2.
 * @param pdu         The message where the block option should be written.
 * @param data_length The length of the actual data that will be added the @p
 *                    pdu by calling coap_add_block().
 *
 * @return            @c 1 on success, or a negative value on error.
 */
int coap_write_block_opt(coap_block_t *block,
                         uint16_t type,
                         coap_pdu_t *pdu,
                         size_t data_length);

/**
 * Adds the @p block_num block of size 1 << (@p block_szx + 4) from source @p
 * data to @p pdu.
 *
 * @param pdu       The message to add the block.
 * @param len       The length of @p data.
 * @param data      The source data to fill the block with.
 * @param block_num The actual block number.
 * @param block_szx Encoded size of block @p block_number.
 *
 * @return          @c 1 on success, @c 0 otherwise.
 */
int coap_add_block(coap_pdu_t *pdu,
                   unsigned int len,
                   const uint8_t *data,
                   unsigned int block_num,
                   unsigned char block_szx);

/**
 * Adds the appropriate part of @p data to the @p response pdu.  If blocks are
 * required, then the appropriate block will be added to the PDU and sent.
 * Adds a ETAG option that is the hash of the entire data if the data is to be
 * split into blocks
 * Used by a GET request handler.
 *
 * @param resource   The resource the data is associated with.
 * @param session    The coap session.
 * @param request    The requesting pdu.
 * @param response   The response pdu.
 * @param token      The token taken from the (original) requesting pdu.
 * @param media_type The format of the data.
 * @param maxage     The maxmimum life of the data. If @c -1, then there
 *                   is no maxage.
 * @param length     The total length of the data.
 * @param data       The entire data block to transmit.
 *
 */
void
coap_add_data_blocked_response(struct coap_resource_t *resource,
                               struct coap_session_t *session,
                               coap_pdu_t *request,
                               coap_pdu_t *response,
                               const coap_binary_t *token,
                               uint16_t media_type,
                               int maxage,
                               size_t length,
                               const uint8_t* data);

/**@}*/

#endif /* COAP_BLOCK_H_ */
/*
 * coap_debug.h -- debug utilities
 *
 * Copyright (C) 2010-2011,2014 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef COAP_DEBUG_H_
#define COAP_DEBUG_H_

/**
 * @defgroup logging Logging Support
 * API functions for logging support
 * @{
 */

#ifndef COAP_DEBUG_FD
/**
 * Used for output for @c LOG_DEBUG to @c LOG_ERR.
 */
#define COAP_DEBUG_FD stdout
#endif

#ifndef COAP_ERR_FD
/**
 * Used for output for @c LOG_CRIT to @c LOG_EMERG.
 */
#define COAP_ERR_FD stderr
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
/**
 * Logging type.  One of LOG_* from @b syslog.
 */
typedef short coap_log_t;
#else
/** Pre-defined log levels akin to what is used in \b syslog. */
typedef enum {
  LOG_EMERG=0, /**< Emergency */
  LOG_ALERT,   /**< Alert */
  LOG_CRIT,    /**< Critical */
  LOG_ERR,     /**< Error */
  LOG_WARNING, /**< Warning */
  LOG_NOTICE,  /**< Notice */
  LOG_INFO,    /**< Information */
  LOG_DEBUG    /**< Debug */
} coap_log_t;
#endif

/**
 * Get the current logging level.
 *
 * @return One of the LOG_* values.
 */
coap_log_t coap_get_log_level(void);

/**
 * Sets the log level to the specified value.
 *
 * @param level One of the LOG_* values.
 */
void coap_set_log_level(coap_log_t level);

/**
 * Logging call-back handler definition.
 *
 * @param level One of the LOG_* values.
 * @param message Zero-terminated string message to log.
 */
typedef void (*coap_log_handler_t) (coap_log_t level, const char *message);

/**
 * Add a custom log callback handler.
 *
 * @param handler The logging handler to use or @p NULL to use default handler.
 */
void coap_set_log_handler(coap_log_handler_t handler);

/**
 * Get the library package name.
 *
 * @return Zero-terminated string with the name of this library.
 */
const char *coap_package_name(void);

/**
 * Get the library package version.
 *
 * @return Zero-terminated string with the library version.
 */
const char *coap_package_version(void);

/**
 * Writes the given text to @c COAP_ERR_FD (for @p level <= @c LOG_CRIT) or @c
 * COAP_DEBUG_FD (for @p level >= @c LOG_ERR). The text is output only when
 * @p level is below or equal to the log level that set by coap_set_log_level().
 *
 * Internal function.
 *
 * @param level One of the LOG_* values.
 & @param format The format string to use.
 */
#if (defined(__GNUC__))
void coap_log_impl(coap_log_t level,
              const char *format, ...) __attribute__ ((format(printf, 2, 3)));
#else
void coap_log_impl(coap_log_t level, const char *format, ...);
#endif

#ifndef coap_log
/**
 * Logging function.
 * Writes the given text to @c COAP_ERR_FD (for @p level <= @c LOG_CRIT) or @c
 * COAP_DEBUG_FD (for @p level >= @c LOG_ERR). The text is output only when
 * @p level is below or equal to the log level that set by coap_set_log_level().
 *
 * @param level One of the LOG_* values.
 */
#define coap_log(level, ...) do { \
  if ((int)((level))<=(int)coap_get_log_level()) \
     coap_log_impl((level), __VA_ARGS__); \
} while(0)
#endif

#include "pdu.h"

/**
 * Defines the output mode for the coap_show_pdu() function.
 *
 * @param use_fprintf @p 1 if the output is to use fprintf() (the default)
 *                    @p 0 if the output is to use coap_log().
 */
void coap_set_show_pdu_output(int use_fprintf);

/**
 * Display the contents of the specified @p pdu.
 * Note: The output method of coap_show_pdu() is dependent on the setting of
 * coap_set_show_pdu_output().
 *
 * @param level The required minimum logging level.
 * @param pdu The PDU to decode.
 */
void coap_show_pdu(coap_log_t level, const coap_pdu_t *pdu);

/**
 * Display the current (D)TLS library linked with and built for version.
 *
 * @param level The required minimum logging level.
 */
void coap_show_tls_version(coap_log_t level);

/**
 * Build a string containing the current (D)TLS library linked with and
 * built for version.
 *
 * @param buffer The buffer to put the string into.
 * @param bufsize The size of the buffer to put the string into.
 *
 * @return A pointer to the provided buffer.
 */
char *coap_string_tls_version(char *buffer, size_t bufsize);

struct coap_address_t;

/**
 * Print the address into the defined buffer.
 *
 * Internal Function.
 *
 * @param address The address to print.
 * @param buffer The buffer to print into.
 * @param size The size of the buffer to print into.
 *
 * @return The amount written into the buffer.
 */
size_t coap_print_addr(const struct coap_address_t *address,
                       unsigned char *buffer, size_t size);

/** @} */

/**
 * Set the packet loss level for testing.  This can be in one of two forms.
 *
 * Percentage : 0% to 100%.  Use the specified probability.
 * 0% is send all packets, 100% is drop all packets.
 *
 * List: A comma separated list of numbers or number ranges that are the
 * packets to drop.
 *
 * @param loss_level The defined loss level (percentage or list).
 *
 * @return @c 1 If loss level set, @c 0 if there is an error.
 */
int coap_debug_set_packet_loss(const char *loss_level);

/**
 * Check to see whether a packet should be sent or not.
 *
 * Internal function
 *
 * @return @c 1 if packet is to be sent, @c 0 if packet is to be dropped.
 */
int coap_debug_send_packet(void);


#endif /* COAP_DEBUG_H_ */
/*
 * coap_dtls.h -- (Datagram) Transport Layer Support for libcoap
 *
 * Copyright (C) 2016 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2017 Jean-Claude Michelou <jcm@spinetix.com>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef COAP_DTLS_H_
#define COAP_DTLS_H_

#include "coap_time.h"

struct coap_context_t;
struct coap_session_t;
struct coap_dtls_pki_t;

/**
 * @defgroup dtls DTLS Support
 * API functions for interfacing with DTLS libraries.
 * @{
 */

/**
 * Check whether DTLS is available.
 *
 * @return @c 1 if support for DTLS is enabled, or @c 0 otherwise.
 */
int coap_dtls_is_supported(void);

/**
 * Check whether TLS is available.
 *
 * @return @c 1 if support for TLS is enabled, or @c 0 otherwise.
 */
int coap_tls_is_supported(void);

#define COAP_TLS_LIBRARY_NOTLS 0 /**< No DTLS library */
#define COAP_TLS_LIBRARY_TINYDTLS 1 /**< Using TinyDTLS library */
#define COAP_TLS_LIBRARY_OPENSSL 2 /**< Using OpenSSL library */
#define COAP_TLS_LIBRARY_GNUTLS 3 /**< Using GnuTLS library */

/**
 * The structure used for returning the underlying (D)TLS library
 * information.
 */
typedef struct coap_tls_version_t {
  uint64_t version; /**< (D)TLS runtime Library Version */
  int type; /**< Library type. One of COAP_TLS_LIBRARY_* */
  uint64_t built_version; /**< (D)TLS Built against Library Version */
} coap_tls_version_t;

/**
 * Determine the type and version of the underlying (D)TLS library.
 *
 * @return The version and type of library libcoap was compiled against.
 */
coap_tls_version_t *coap_get_tls_library_version(void);

/**
 * Additional Security setup handler that can be set up by
 * coap_context_set_pki().
 * Invoked when libcoap has done the validation checks at the TLS level,
 * but the application needs to do some additional checks/changes/updates.
 *
 * @param tls_session The security session definition - e.g. SSL * for OpenSSL.
 *                    NULL if server call-back.
 *                    This will be dependent on the underlying TLS library -
 *                    see coap_get_tls_library_version()
 * @param setup_data A structure containing setup data originally passed into
 *                   coap_context_set_pki() or coap_new_client_session_pki().
 *
 * @return @c 1 if successful, else @c 0.
 */
typedef int (*coap_dtls_security_setup_t)(void* tls_session,
                                        struct coap_dtls_pki_t *setup_data);

/**
 * CN Validation call-back that can be set up by coap_context_set_pki().
 * Invoked when libcoap has done the validation checks at the TLS level,
 * but the application needs to check that the CN is allowed.
 * CN is the SubjectAltName in the cert, if not present, then the leftmost
 * Common Name (CN) component of the subject name.
 *
 * @param cn  The determined CN from the certificate
 * @param asn1_public_cert  The ASN.1 DER encoded X.509 certificate
 * @param asn1_length  The ASN.1 length
 * @param coap_session  The CoAP session associated with the certificate update
 * @param depth  Depth in cert chain.  If 0, then client cert, else a CA
 * @param validated  TLS layer can find no issues if 1
 * @param arg  The same as was passed into coap_context_set_pki()
 *             in setup_data->cn_call_back_arg
 *
 * @return @c 1 if accepted, else @c 0 if to be rejected.
 */
typedef int (*coap_dtls_cn_callback_t)(const char *cn,
             const uint8_t *asn1_public_cert,
             size_t asn1_length,
             struct coap_session_t *coap_session,
             unsigned depth,
             int validated,
             void *arg);

/**
 * The enum used for determining the provided PKI ASN.1 (DER) Private Key
 * formats.
 */
typedef enum coap_asn1_privatekey_type_t {
  COAP_ASN1_PKEY_NONE,     /**< NONE */
  COAP_ASN1_PKEY_RSA,      /**< RSA type */
  COAP_ASN1_PKEY_RSA2,     /**< RSA2 type */
  COAP_ASN1_PKEY_DSA,      /**< DSA type */
  COAP_ASN1_PKEY_DSA1,     /**< DSA1 type */
  COAP_ASN1_PKEY_DSA2,     /**< DSA2 type */
  COAP_ASN1_PKEY_DSA3,     /**< DSA3 type */
  COAP_ASN1_PKEY_DSA4,     /**< DSA4 type */
  COAP_ASN1_PKEY_DH,       /**< DH type */
  COAP_ASN1_PKEY_DHX,      /**< DHX type */
  COAP_ASN1_PKEY_EC,       /**< EC type */
  COAP_ASN1_PKEY_HMAC,     /**< HMAC type */
  COAP_ASN1_PKEY_CMAC,     /**< CMAC type */
  COAP_ASN1_PKEY_TLS1_PRF, /**< TLS1_PRF type */
  COAP_ASN1_PKEY_HKDF      /**< HKDF type */
} coap_asn1_privatekey_type_t;

/**
 * The enum used for determining the PKI key formats.
 */
typedef enum coap_pki_key_t {
  COAP_PKI_KEY_PEM = 0,   /**< The PKI key type is PEM */
  COAP_PKI_KEY_ASN1,      /**< The PKI key type is ASN.1 (DER) */
} coap_pki_key_t;

/**
 * The structure that holds the PKI PEM definitions.
 */
typedef struct coap_pki_key_pem_t {
  const char *ca_file;       /**< File location of Common CA in PEM format */
  const char *public_cert;   /**< File location of Public Cert in PEM format */
  const char *private_key;   /**< File location of Private Key in PEM format */
} coap_pki_key_pem_t;

/**
 * The structure that holds the PKI ASN.1 (DER) definitions.
 */
typedef struct coap_pki_key_asn1_t {
  const uint8_t *ca_cert;     /**< ASN1 (DER) Common CA Cert */
  const uint8_t *public_cert; /**< ASN1 (DER) Public Cert */
  const uint8_t *private_key; /**< ASN1 (DER) Private Key */
  size_t ca_cert_len;         /**< ASN1 CA Cert length */
  size_t public_cert_len;     /**< ASN1 Public Cert length */
  size_t private_key_len;     /**< ASN1 Private Key length */
  coap_asn1_privatekey_type_t private_key_type; /**< Private Key Type */
} coap_pki_key_asn1_t;

/**
 * The structure that holds the PKI key information.
 */
typedef struct coap_dtls_key_t {
  coap_pki_key_t key_type;          /**< key format type */
  union {
    coap_pki_key_pem_t pem;         /**< for PEM keys */
    coap_pki_key_asn1_t asn1;       /**< for ASN.1 (DER) keys */
  } key;
} coap_dtls_key_t;

/**
 * Server Name Indication (SNI) Validation call-back that can be set up by
 * coap_context_set_pki().
 * Invoked if the SNI is not previously seen and prior to sending a certificate
 * set back to the client so that the appropriate certificate set can be used
 * based on the requesting SNI.
 *
 * @param sni  The requested SNI
 * @param arg  The same as was passed into coap_context_set_pki()
 *             in setup_data->sni_call_back_arg
 *
 * @return New set of certificates to use, or @c NULL if SNI is to be rejected.
 */
typedef coap_dtls_key_t *(*coap_dtls_sni_callback_t)(const char *sni,
             void* arg);


#define COAP_DTLS_PKI_SETUP_VERSION 1 /**< Latest PKI setup version */

/**
 * The structure used for defining the PKI setup data to be used.
 */
typedef struct coap_dtls_pki_t {
  uint8_t version; /** Set to 1 to support this version of the struct */

  /* Options to enable different TLS functionality in libcoap */
  uint8_t verify_peer_cert;        /**< 1 if peer cert is to be verified */
  uint8_t require_peer_cert;       /**< 1 if peer cert is required */
  uint8_t allow_self_signed;       /**< 1 if self signed certs are allowed */
  uint8_t allow_expired_certs;     /**< 1 if expired certs are allowed */
  uint8_t cert_chain_validation;   /**< 1 if to check cert_chain_verify_depth */
  uint8_t cert_chain_verify_depth; /**< recommended depth is 3 */
  uint8_t check_cert_revocation;   /**< 1 if revocation checks wanted */
  uint8_t allow_no_crl;            /**< 1 ignore if CRL not there */
  uint8_t allow_expired_crl;       /**< 1 if expired crl is allowed */
  uint8_t reserved[6];             /**< Reserved - must be set to 0 for
                                        future compatibility */
                                   /* Size of 6 chosen to align to next
                                    * parameter, so if newly defined option
                                    * it can use one of the reserverd slot so
                                    * no need to change
                                    * COAP_DTLS_PKI_SETUP_VERSION and just
                                    * decrement the reserved[] count.
                                    */

  /** CN check call-back function.
   * If not NULL, is called when the TLS connection has passed the configured
   * TLS options above for the application to verify if the CN is valid.
   */
  coap_dtls_cn_callback_t validate_cn_call_back;
  void *cn_call_back_arg;  /**< Passed in to the CN call-back function */

  /** SNI check call-back function.
   * If not @p NULL, called if the SNI is not previously seen and prior to
   * sending a certificate set back to the client so that the appropriate
   * certificate set can be used based on the requesting SNI.
   */
  coap_dtls_sni_callback_t validate_sni_call_back;
  void *sni_call_back_arg;  /**< Passed in to the sni call-back function */

  /** Additional Security call-back handler that is invoked when libcoap has
   * done the standerd, defined validation checks at the TLS level,
   * If not @p NULL, called from within the TLS Client Hello connection
   * setup.
   */
  coap_dtls_security_setup_t additional_tls_setup_call_back;

  char* client_sni;    /**<  If not NULL, SNI to use in client TLS setup.
                             Owned by the client app and must remain valid
                             during the call to coap_new_client_session_pki() */

  coap_dtls_key_t pki_key;  /**< PKI key definition */
} coap_dtls_pki_t;

/** @} */

/**
 * @defgroup dtls_internal DTLS Support (Internal)
 * Internal API functions for interfacing with DTLS libraries.
 * @{
 */

/**
 * Creates a new DTLS context for the given @p coap_context. This function
 * returns a pointer to a new DTLS context object or @c NULL on error.
 *
 * Internal function.
 *
 * @param coap_context The CoAP context where the DTLS object shall be used.
 *
 * @return A DTLS context object or @c NULL on error.
 */
void *
coap_dtls_new_context(struct coap_context_t *coap_context);

typedef enum coap_dtls_role_t {
  COAP_DTLS_ROLE_CLIENT, /**< Internal function invoked for client */
  COAP_DTLS_ROLE_SERVER  /**< Internal function invoked for server */
} coap_dtls_role_t;

/**
 * Set the DTLS context's default PSK information.
 * This does the PSK specifics following coap_dtls_new_context().
 * If @p COAP_DTLS_ROLE_SERVER, then identity hint will also get set.
 * If @p COAP_DTLS_ROLE_SERVER, then the information will get put into the
 * TLS library's context (from which sessions are derived).
 * If @p COAP_DTLS_ROLE_CLIENT, then the information will get put into the
 * TLS library's session.
 *
 * Internal function.
 *
 * @param coap_context The CoAP context.
 * @param identity_hint The default PSK server identity hint sent to a client.
 *                      Required parameter.  If @p NULL, will be set to "".
 *                      Empty string is a valid hint.
 *                      This parameter is ignored if COAP_DTLS_ROLE_CLIENT
 * @param role  One of @p COAP_DTLS_ROLE_CLIENT or @p COAP_DTLS_ROLE_SERVER
 *
 * @return @c 1 if successful, else @c 0.
 */

int
coap_dtls_context_set_psk(struct coap_context_t *coap_context,
                          const char *identity_hint,
                          coap_dtls_role_t role);

/**
 * Set the DTLS context's default server PKI information.
 * This does the PKI specifics following coap_dtls_new_context().
 * If @p COAP_DTLS_ROLE_SERVER, then the information will get put into the
 * TLS library's context (from which sessions are derived).
 * If @p COAP_DTLS_ROLE_CLIENT, then the information will get put into the
 * TLS library's session.
 *
 * Internal function.
 *
 * @param coap_context The CoAP context.
 * @param setup_data     Setup information defining how PKI is to be setup.
 *                       Required parameter.  If @p NULL, PKI will not be
 *                       set up.
 * @param role  One of @p COAP_DTLS_ROLE_CLIENT or @p COAP_DTLS_ROLE_SERVER
 *
 * @return @c 1 if successful, else @c 0.
 */

int
coap_dtls_context_set_pki(struct coap_context_t *coap_context,
                          coap_dtls_pki_t *setup_data,
                          coap_dtls_role_t role);

/**
 * Set the dtls context's default Root CA information for a client or server.
 *
 * Internal function.
 *
 * @param coap_context   The current coap_context_t object.
 * @param ca_file        If not @p NULL, is the full path name of a PEM encoded
 *                       file containing all the Root CAs to be used.
 * @param ca_dir         If not @p NULL, points to a directory containing PEM
 *                       encoded files containing all the Root CAs to be used.
 *
 * @return @c 1 if successful, else @c 0.
 */

int
coap_dtls_context_set_pki_root_cas(struct coap_context_t *coap_context,
                                   const char *ca_file,
                                   const char *ca_dir);

/**
 * Check whether one of the coap_dtls_context_set_{psk|pki}() functions have
 * been called.
 *
 * Internal function.
 *
 * @param coap_context The current coap_context_t object.
 *
 * @return @c 1 if coap_dtls_context_set_{psk|pki}() called, else @c 0.
 */

int coap_dtls_context_check_keys_enabled(struct coap_context_t *coap_context);

/**
 * Releases the storage allocated for @p dtls_context.
 *
 * Internal function.
 *
 * @param dtls_context The DTLS context as returned by coap_dtls_new_context().
 */
void coap_dtls_free_context(void *dtls_context);

/**
 * Create a new client-side session. This should send a HELLO to the server.
 *
 * Internal function.
 *
 * @param coap_session   The CoAP session.
 *
 * @return Opaque handle to underlying TLS library object containing security
 *         parameters for the session.
*/
void *coap_dtls_new_client_session(struct coap_session_t *coap_session);

/**
 * Create a new DTLS server-side session.
 * Called after coap_dtls_hello() has returned @c 1, signalling that a validated
 * HELLO was received from a client.
 * This should send a HELLO to the server.
 *
 * Internal function.
 *
 * @param coap_session   The CoAP session.
 *
 * @return Opaque handle to underlying TLS library object containing security
 *         parameters for the DTLS session.
 */
void *coap_dtls_new_server_session(struct coap_session_t *coap_session);

/**
 * Terminates the DTLS session (may send an ALERT if necessary) then frees the
 * underlying TLS library object containing security parameters for the session.
 *
 * Internal function.
 *
 * @param coap_session   The CoAP session.
 */
void coap_dtls_free_session(struct coap_session_t *coap_session);

/**
 * Notify of a change in the CoAP session's MTU, for example after
 * a PMTU update.
 *
 * Internal function.
 *
 * @param coap_session   The CoAP session.
 */
void coap_dtls_session_update_mtu(struct coap_session_t *coap_session);

/**
 * Send data to a DTLS peer.
 *
 * Internal function.
 *
 * @param coap_session The CoAP session.
 * @param data      pointer to data.
 * @param data_len  Number of bytes to send.
 *
 * @return @c 0 if this would be blocking, @c -1 if there is an error or the
 *         number of cleartext bytes sent.
 */
int coap_dtls_send(struct coap_session_t *coap_session,
                   const uint8_t *data,
                   size_t data_len);

/**
 * Check if timeout is handled per CoAP session or per CoAP context.
 *
 * Internal function.
 *
 * @return @c 1 of timeout and retransmit is per context, @c 0 if it is
 *         per session.
 */
int coap_dtls_is_context_timeout(void);

/**
 * Do all pending retransmits and get next timeout
 *
 * Internal function.
 *
 * @param dtls_context The DTLS context.
 *
 * @return @c 0 if no event is pending or date of the next retransmit.
 */
coap_tick_t coap_dtls_get_context_timeout(void *dtls_context);

/**
 * Get next timeout for this session.
 *
 * Internal function.
 *
 * @param coap_session The CoAP session.
 *
 * @return @c 0 If no event is pending or date of the next retransmit.
 */
coap_tick_t coap_dtls_get_timeout(struct coap_session_t *coap_session);

/**
 * Handle a DTLS timeout expiration.
 *
 * Internal function.
 *
 * @param coap_session The CoAP session.
 */
void coap_dtls_handle_timeout(struct coap_session_t *coap_session);

/**
 * Handling incoming data from a DTLS peer.
 *
 * Internal function.
 *
 * @param coap_session The CoAP session.
 * @param data      Encrypted datagram.
 * @param data_len  Encrypted datagram size.
 *
 * @return Result of coap_handle_dgram on the decrypted CoAP PDU
 *         or @c -1 for error.
 */
int coap_dtls_receive(struct coap_session_t *coap_session,
                      const uint8_t *data,
                      size_t data_len);

/**
 * Handling client HELLO messages from a new candiate peer.
 * Note that session->tls is empty.
 *
 * Internal function.
 *
 * @param coap_session The CoAP session.
 * @param data      Encrypted datagram.
 * @param data_len  Encrypted datagram size.
 *
 * @return @c 0 if a cookie verification message has been sent, @c 1 if the
 *        HELLO contains a valid cookie and a server session should be created,
 *        @c -1 if the message is invalid.
 */
int coap_dtls_hello(struct coap_session_t *coap_session,
                    const uint8_t *data,
                    size_t data_len);

/**
 * Get DTLS overhead over cleartext PDUs.
 *
 * Internal function.
 *
 * @param coap_session The CoAP session.
 *
 * @return Maximum number of bytes added by DTLS layer.
 */
unsigned int coap_dtls_get_overhead(struct coap_session_t *coap_session);

/**
 * Create a new TLS client-side session.
 *
 * Internal function.
 *
 * @param coap_session The CoAP session.
 * @param connected Updated with whether the connection is connected yet or not.
 *                  @c 0 is not connected, @c 1 is connected.
 *
 * @return Opaque handle to underlying TLS library object containing security
 *         parameters for the session.
*/
void *coap_tls_new_client_session(struct coap_session_t *coap_session, int *connected);

/**
 * Create a TLS new server-side session.
 *
 * Internal function.
 *
 * @param coap_session The CoAP session.
 * @param connected Updated with whether the connection is connected yet or not.
 *                  @c 0 is not connected, @c 1 is connected.
 *
 * @return Opaque handle to underlying TLS library object containing security
 *         parameters for the session.
 */
void *coap_tls_new_server_session(struct coap_session_t *coap_session, int *connected);

/**
 * Terminates the TLS session (may send an ALERT if necessary) then frees the
 * underlying TLS library object containing security parameters for the session.
 *
 * Internal function.
 *
 * @param coap_session The CoAP session.
 */
void coap_tls_free_session( struct coap_session_t *coap_session );

/**
 * Send data to a TLS peer, with implicit flush.
 *
 * Internal function.
 *
 * @param coap_session The CoAP session.
 * @param data      Pointer to data.
 * @param data_len  Number of bytes to send.
 *
 * @return          @c 0 if this should be retried, @c -1 if there is an error
 *                  or the number of cleartext bytes sent.
 */
ssize_t coap_tls_write(struct coap_session_t *coap_session,
                       const uint8_t *data,
                       size_t data_len
                       );

/**
 * Read some data from a TLS peer.
 *
 * Internal function.
 *
 * @param coap_session The CoAP session.
 * @param data      Pointer to data.
 * @param data_len  Maximum number of bytes to read.
 *
 * @return          @c 0 if this should be retried, @c -1 if there is an error
 *                  or the number of cleartext bytes read.
 */
ssize_t coap_tls_read(struct coap_session_t *coap_session,
                      uint8_t *data,
                      size_t data_len
                      );

/**
 * Initialize the underlying (D)TLS Library layer.
 *
 * Internal function.
 *
 */
void coap_dtls_startup(void);

/** @} */

/**
 * @ingroup logging
 * Sets the (D)TLS logging level to the specified @p level.
 * Note: coap_log_level() will influence output if at a specified level.
 *
 * @param level The logging level to use - LOG_*
 */
void coap_dtls_set_log_level(int level);

/**
 * @ingroup logging
 * Get the current (D)TLS logging.
 *
 * @return The current log level (one of LOG_*).
 */
int coap_dtls_get_log_level(void);


#endif /* COAP_DTLS_H */
/*
 * coap_event.h -- libcoap Event API
 *
 * Copyright (C) 2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef COAP_EVENT_H_
#define COAP_EVENT_H_

#include "libcoap.h"

struct coap_context_t;
struct coap_session_t;

/**
 * @defgroup events Event API
 * API functions for event delivery from lower-layer library functions.
 * @{
 */

/**
 * Scalar type to represent different events, e.g. DTLS events or
 * retransmission timeouts.
 */
 typedef unsigned int coap_event_t;

/**
 * (D)TLS events for COAP_PROTO_DTLS and COAP_PROTO_TLS
 */
#define COAP_EVENT_DTLS_CLOSED        0x0000
#define COAP_EVENT_DTLS_CONNECTED     0x01DE
#define COAP_EVENT_DTLS_RENEGOTIATE   0x01DF
#define COAP_EVENT_DTLS_ERROR         0x0200

/**
 * TCP events for COAP_PROTO_TCP and COAP_PROTO_TLS
 */
#define COAP_EVENT_TCP_CONNECTED      0x1001
#define COAP_EVENT_TCP_CLOSED         0x1002
#define COAP_EVENT_TCP_FAILED         0x1003

/**
 * CSM exchange events for reliable protocols only
 */
#define COAP_EVENT_SESSION_CONNECTED  0x2001
#define COAP_EVENT_SESSION_CLOSED     0x2002
#define COAP_EVENT_SESSION_FAILED     0x2003

/**
 * Type for event handler functions that can be registered with a CoAP
 * context using the unction coap_set_event_handler(). When called by
 * the library, the first argument will be the coap_context_t object
 * where the handler function has been registered. The second argument
 * is the event type that may be complemented by event-specific data
 * passed as the third argument.
 */
typedef int (*coap_event_handler_t)(struct coap_context_t *,
                                    coap_event_t event,
                                    struct coap_session_t *session);

/**
 * Registers the function @p hnd as callback for events from the given
 * CoAP context @p context. Any event handler that has previously been
 * registered with @p context will be overwritten by this operation.
 *
 * @param context The CoAP context to register the event handler with.
 * @param hnd     The event handler to be registered.  @c NULL if to be
 *                de-registered.
 */
void coap_register_event_handler(struct coap_context_t *context,
                            coap_event_handler_t hnd);

/**
 * Registers the function @p hnd as callback for events from the given
 * CoAP context @p context. Any event handler that has previously been
 * registered with @p context will be overwritten by this operation.
 *
 * @deprecated Use coap_register_event_handler() instead.
 *
 * @param context The CoAP context to register the event handler with.
 * @param hnd     The event handler to be registered.
 */
COAP_DEPRECATED
void coap_set_event_handler(struct coap_context_t *context,
                            coap_event_handler_t hnd);

/**
 * Clears the event handler registered with @p context.
 *
 * @deprecated Use coap_register_event_handler() instead with NULL for hnd.
 *
 * @param context The CoAP context whose event handler is to be removed.
 */
COAP_DEPRECATED
void coap_clear_event_handler(struct coap_context_t *context);

/** @} */

#endif /* COAP_EVENT_H */
/*
 * coap_hashkey.h -- definition of hash key type and helper functions
 *
 * Copyright (C) 2010-2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_hashkey.h
 * @brief definition of hash key type and helper functions
 */

#ifndef COAP_HASHKEY_H_
#define COAP_HASHKEY_H_

#include "libcoap.h"
#include "uthash.h"
#include "str.h"

typedef unsigned char coap_key_t[4];

#ifndef coap_hash
/**
 * Calculates a fast hash over the given string @p s of length @p len and stores
 * the result into @p h. Depending on the exact implementation, this function
 * cannot be used as one-way function to check message integrity or simlar.
 *
 * @param s   The string used for hash calculation.
 * @param len The length of @p s.
 * @param h   The result buffer to store the calculated hash key.
 */
void coap_hash_impl(const unsigned char *s, unsigned int len, coap_key_t h);

#define coap_hash(String,Length,Result) \
  coap_hash_impl((String),(Length),(Result))

/* This is used to control the pre-set hash-keys for resources. */
#define COAP_DEFAULT_HASH
#else
#undef COAP_DEFAULT_HASH
#endif /* coap_hash */

/**
 * Calls coap_hash() with given @c coap_string_t object as parameter.
 *
 * @param Str Must contain a pointer to a coap string object.
 * @param H   A coap_key_t object to store the result.
 *
 * @hideinitializer
 */
#define coap_str_hash(Str,H) {               \
    assert(Str);                             \
    memset((H), 0, sizeof(coap_key_t));      \
    coap_hash((Str)->s, (Str)->length, (H)); \
  }

#endif /* COAP_HASHKEY_H_ */
/*
 * coap_io.h -- Default network I/O functions for libcoap
 *
 * Copyright (C) 2012-2013 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef COAP_IO_H_
#define COAP_IO_H_

#include <assert.h>
#include <sys/types.h>

#include "address.h"

#ifndef COAP_RXBUFFER_SIZE
#define COAP_RXBUFFER_SIZE 1472
#endif /* COAP_RXBUFFER_SIZE */

#ifdef _WIN32
typedef SOCKET coap_fd_t;
#define coap_closesocket closesocket
#define COAP_SOCKET_ERROR SOCKET_ERROR
#define COAP_INVALID_SOCKET INVALID_SOCKET
#else
typedef int coap_fd_t;
#define coap_closesocket close
#define COAP_SOCKET_ERROR (-1)
#define COAP_INVALID_SOCKET (-1)
#endif

struct coap_packet_t;
struct coap_session_t;
struct coap_pdu_t;

typedef uint16_t coap_socket_flags_t;

typedef struct coap_socket_t {
#if defined(WITH_LWIP)
  struct udp_pcb *pcb;
#elif defined(WITH_CONTIKI)
  void *conn;
#else
  coap_fd_t fd;
#endif /* WITH_LWIP */
  coap_socket_flags_t flags;
} coap_socket_t;

/**
 * coap_socket_flags_t values
 */
#define COAP_SOCKET_EMPTY        0x0000  /**< the socket is not used */
#define COAP_SOCKET_NOT_EMPTY    0x0001  /**< the socket is not empty */
#define COAP_SOCKET_BOUND        0x0002  /**< the socket is bound */
#define COAP_SOCKET_CONNECTED    0x0004  /**< the socket is connected */
#define COAP_SOCKET_WANT_READ    0x0010  /**< non blocking socket is waiting for reading */
#define COAP_SOCKET_WANT_WRITE   0x0020  /**< non blocking socket is waiting for writing */
#define COAP_SOCKET_WANT_ACCEPT  0x0040  /**< non blocking server socket is waiting for accept */
#define COAP_SOCKET_WANT_CONNECT 0x0080  /**< non blocking client socket is waiting for connect */
#define COAP_SOCKET_CAN_READ     0x0100  /**< non blocking socket can now read without blocking */
#define COAP_SOCKET_CAN_WRITE    0x0200  /**< non blocking socket can now write without blocking */
#define COAP_SOCKET_CAN_ACCEPT   0x0400  /**< non blocking server socket can now accept without blocking */
#define COAP_SOCKET_CAN_CONNECT  0x0800  /**< non blocking client socket can now connect without blocking */
#define COAP_SOCKET_MULTICAST    0x1000  /**< socket is used for multicast communication */

struct coap_endpoint_t *coap_malloc_endpoint( void );
void coap_mfree_endpoint( struct coap_endpoint_t *ep );

int
coap_socket_connect_udp(coap_socket_t *sock,
                        const coap_address_t *local_if,
                        const coap_address_t *server,
                        int default_port,
                        coap_address_t *local_addr,
                        coap_address_t *remote_addr);

int
coap_socket_bind_udp(coap_socket_t *sock,
                     const coap_address_t *listen_addr,
                     coap_address_t *bound_addr );

int
coap_socket_connect_tcp1(coap_socket_t *sock,
                         const coap_address_t *local_if,
                         const coap_address_t *server,
                         int default_port,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr);

int
coap_socket_connect_tcp2(coap_socket_t *sock,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr);

int
coap_socket_bind_tcp(coap_socket_t *sock,
                     const coap_address_t *listen_addr,
                     coap_address_t *bound_addr);

int
coap_socket_accept_tcp(coap_socket_t *server,
                       coap_socket_t *new_client,
                       coap_address_t *local_addr,
                       coap_address_t *remote_addr);

void coap_socket_close(coap_socket_t *sock);

ssize_t
coap_socket_send( coap_socket_t *sock, struct coap_session_t *session,
                  const uint8_t *data, size_t data_len );

ssize_t
coap_socket_write(coap_socket_t *sock, const uint8_t *data, size_t data_len);

ssize_t
coap_socket_read(coap_socket_t *sock, uint8_t *data, size_t data_len);

#ifdef WITH_LWIP
ssize_t
coap_socket_send_pdu( coap_socket_t *sock, struct coap_session_t *session,
                      struct coap_pdu_t *pdu );
#endif

const char *coap_socket_strerror( void );

/**
 * Function interface for data transmission. This function returns the number of
 * bytes that have been transmitted, or a value less than zero on error.
 *
 * @param sock             Socket to send data with
 * @param session          Addressing information for unconnected sockets, or NULL
 * @param data             The data to send.
 * @param datalen          The actual length of @p data.
 *
 * @return                 The number of bytes written on success, or a value
 *                         less than zero on error.
 */
ssize_t coap_network_send( coap_socket_t *sock, const struct coap_session_t *session, const uint8_t *data, size_t datalen );

/**
 * Function interface for reading data. This function returns the number of
 * bytes that have been read, or a value less than zero on error. In case of an
 * error, @p *packet is set to NULL.
 *
 * @param sock   Socket to read data from
 * @param packet Received packet metadata and payload. src and dst should be preset.
 *
 * @return       The number of bytes received on success, or a value less than
 *               zero on error.
 */
ssize_t coap_network_read( coap_socket_t *sock, struct coap_packet_t *packet );

#ifndef coap_mcast_interface
# define coap_mcast_interface(Local) 0
#endif

/**
 * Given a packet, set msg and msg_len to an address and length of the packet's
 * data in memory.
 * */
void coap_packet_get_memmapped(struct coap_packet_t *packet,
                               unsigned char **address,
                               size_t *length);

void coap_packet_set_addr( struct coap_packet_t *packet, const coap_address_t *src,
                           const coap_address_t *dst );

#ifdef WITH_LWIP
/**
 * Get the pbuf of a packet. The caller takes over responsibility for freeing
 * the pbuf.
 */
struct pbuf *coap_packet_extract_pbuf(struct coap_packet_t *packet);
#endif

#if defined(WITH_LWIP)
/*
 * This is only included in coap_io.h instead of .c in order to be available for
 * sizeof in lwippools.h.
 * Simple carry-over of the incoming pbuf that is later turned into a node.
 *
 * Source address data is currently side-banded via ip_current_dest_addr & co
 * as the packets have limited lifetime anyway.
 */
struct coap_packet_t {
  struct pbuf *pbuf;
  const struct coap_endpoint_t *local_interface;
  coap_address_t src;              /**< the packet's source address */
  coap_address_t dst;              /**< the packet's destination address */
  int ifindex;                /**< the interface index */
//  uint16_t srcport;
};
#else
struct coap_packet_t {
  coap_address_t src;              /**< the packet's source address */
  coap_address_t dst;              /**< the packet's destination address */
  int ifindex;                /**< the interface index */
  size_t length;              /**< length of payload */
  unsigned char payload[COAP_RXBUFFER_SIZE]; /**< payload */
};
#endif
typedef struct coap_packet_t coap_packet_t;

typedef enum {
  COAP_NACK_TOO_MANY_RETRIES,
  COAP_NACK_NOT_DELIVERABLE,
  COAP_NACK_RST,
  COAP_NACK_TLS_FAILED
} coap_nack_reason_t;

#endif /* COAP_IO_H_ */
/*
 * coap_mutex.h -- mutex utilities
 *
 * Copyright (C) 2019 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_mutex.h
 * @brief COAP mutex mechanism wrapper
 */

#ifndef COAP_MUTEX_H_
#define COAP_MUTEX_H_

#if defined(RIOT_VERSION)

#include <mutex.h>

typedef mutex_t coap_mutex_t;
#define COAP_MUTEX_INITIALIZER MUTEX_INIT
#define coap_mutex_lock(a) mutex_lock(a)
#define coap_mutex_trylock(a) mutex_trylock(a)
#define coap_mutex_unlock(a) mutex_unlock(a)

#elif defined(WITH_CONTIKI)

/* CONTIKI does not support mutex */

typedef int coap_mutex_t;
#define COAP_MUTEX_INITIALIZER 0
#define coap_mutex_lock(a) *(a) = 1
#define coap_mutex_trylock(a) *(a) = 1
#define coap_mutex_unlock(a) *(a) = 0

#else /* ! RIOT_VERSION && ! WITH_CONTIKI */

#include <pthread.h>

typedef pthread_mutex_t coap_mutex_t;
#define COAP_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#define coap_mutex_lock(a) pthread_mutex_lock(a)
#define coap_mutex_trylock(a) pthread_mutex_trylock(a)
#define coap_mutex_unlock(a) pthread_mutex_unlock(a)

#endif /* ! RIOT_VERSION && ! WITH_CONTIKI */

#endif /* COAP_MUTEX_H_ */
/* coap_session.h -- Session management for libcoap
*
* Copyright (C) 2017 Jean-Claue Michelou <jcm@spinetix.com>
*
* This file is part of the CoAP library libcoap. Please see
* README for terms of use.
*/

#ifndef COAP_SESSION_H_
#define COAP_SESSION_H_


#include "coap_io.h"
#include "coap_time.h"
#include "pdu.h"

struct coap_endpoint_t;
struct coap_context_t;
struct coap_queue_t;

/**
* Abstraction of a fixed point number that can be used where necessary instead
* of a float.  1,000 fractional bits equals one integer
*/
typedef struct coap_fixed_point_t {
  uint16_t integer_part;    /**< Integer part of fixed point variable */
  uint16_t fractional_part; /**< Fractional part of fixed point variable
                                1/1000 (3 points) precision */
} coap_fixed_point_t;

#define COAP_DEFAULT_SESSION_TIMEOUT 300
#define COAP_PARTIAL_SESSION_TIMEOUT_TICKS (30 * COAP_TICKS_PER_SECOND)
#define COAP_DEFAULT_MAX_HANDSHAKE_SESSIONS 100

#define COAP_PROTO_NOT_RELIABLE(p) ((p)==COAP_PROTO_UDP || (p)==COAP_PROTO_DTLS)
#define COAP_PROTO_RELIABLE(p) ((p)==COAP_PROTO_TCP || (p)==COAP_PROTO_TLS)

typedef uint8_t coap_session_type_t;
/**
 * coap_session_type_t values
 */
#define COAP_SESSION_TYPE_CLIENT 1  /**< client-side */
#define COAP_SESSION_TYPE_SERVER 2  /**< server-side */
#define COAP_SESSION_TYPE_HELLO  3  /**< server-side ephemeral session for responding to a client hello */

typedef uint8_t coap_session_state_t;
/**
 * coap_session_state_t values
 */
#define COAP_SESSION_STATE_NONE                0
#define COAP_SESSION_STATE_CONNECTING        1
#define COAP_SESSION_STATE_HANDSHAKE        2
#define COAP_SESSION_STATE_CSM                3
#define COAP_SESSION_STATE_ESTABLISHED        4

typedef struct coap_session_t {
  struct coap_session_t *next;
  coap_proto_t proto;               /**< protocol used */
  coap_session_type_t type;         /**< client or server side socket */
  coap_session_state_t state;       /**< current state of relationaship with peer */
  unsigned ref;                     /**< reference count from queues */
  unsigned tls_overhead;            /**< overhead of TLS layer */
  unsigned mtu;                     /**< path or CSM mtu */
  coap_address_t local_if;          /**< optional local interface address */
  coap_address_t remote_addr;       /**< remote address and port */
  coap_address_t local_addr;        /**< local address and port */
  int ifindex;                      /**< interface index */
  coap_socket_t sock;               /**< socket object for the session, if any */
  struct coap_endpoint_t *endpoint; /**< session's endpoint */
  struct coap_context_t *context;   /**< session's context */
  void *tls;                        /**< security parameters */
  uint16_t tx_mid;                  /**< the last message id that was used in this session */
  uint8_t con_active;               /**< Active CON request sent */
  struct coap_queue_t *delayqueue;  /**< list of delayed messages waiting to be sent */
  size_t partial_write;             /**< if > 0 indicates number of bytes already written from the pdu at the head of sendqueue */
  uint8_t read_header[8];           /**< storage space for header of incoming message header */
  size_t partial_read;              /**< if > 0 indicates number of bytes already read for an incoming message */
  coap_pdu_t *partial_pdu;          /**< incomplete incoming pdu */
  coap_tick_t last_rx_tx;
  coap_tick_t last_tx_rst;
  coap_tick_t last_ping;
  coap_tick_t last_pong;
  coap_tick_t csm_tx;
  uint8_t *psk_identity;
  size_t psk_identity_len;
  uint8_t *psk_key;
  size_t psk_key_len;
  void *app;                        /**< application-specific data */
  unsigned int max_retransmit;      /**< maximum re-transmit count (default 4) */
  coap_fixed_point_t ack_timeout;   /**< timeout waiting for ack (default 2 secs) */
  coap_fixed_point_t ack_random_factor; /**< ack random factor backoff (default 1.5) */
  unsigned int dtls_timeout_count;      /**< dtls setup retry counter */
  int dtls_event;                       /**< Tracking any (D)TLS events on this sesison */
} coap_session_t;

/**
* Increment reference counter on a session.
*
* @param session The CoAP session.
* @return same as session
*/
coap_session_t *coap_session_reference(coap_session_t *session);

/**
* Decrement reference counter on a session.
* Note that the session may be deleted as a result and should not be used
* after this call.
*
* @param session The CoAP session.
*/
void coap_session_release(coap_session_t *session);

/**
* Stores @p data with the given session. This function overwrites any value
* that has previously been stored with @p session.
*/
void coap_session_set_app_data(coap_session_t *session, void *data);

/**
* Returns any application-specific data that has been stored with @p
* session using the function coap_session_set_app_data(). This function will
* return @c NULL if no data has been stored.
*/
void *coap_session_get_app_data(const coap_session_t *session);

/**
* Notify session that it has failed.
*
* @param session The CoAP session.
* @param reason The reason why the session was disconnected.
*/
void coap_session_disconnected(coap_session_t *session, coap_nack_reason_t reason);

/**
* Notify session transport has just connected and CSM exchange can now start.
*
* @param session The CoAP session.
*/
void coap_session_send_csm(coap_session_t *session);

/**
* Notify session that it has just connected or reconnected.
*
* @param session The CoAP session.
*/
void coap_session_connected(coap_session_t *session);

/**
* Set the session MTU. This is the maximum message size that can be sent,
* excluding IP and UDP overhead.
*
* @param session The CoAP session.
* @param mtu maximum message size
*/
void coap_session_set_mtu(coap_session_t *session, unsigned mtu);

/**
 * Get maximum acceptable PDU size
 *
 * @param session The CoAP session.
 * @return maximum PDU size, not including header (but including token).
 */
size_t coap_session_max_pdu_size(const coap_session_t *session);

/**
* Creates a new client session to the designated server.
* @param ctx The CoAP context.
* @param local_if Address of local interface. It is recommended to use NULL to let the operating system choose a suitable local interface. If an address is specified, the port number should be zero, which means that a free port is automatically selected.
* @param server The server's address. If the port number is zero, the default port for the protocol will be used.
* @param proto Protocol.
*
* @return A new CoAP session or NULL if failed. Call coap_session_release to free.
*/
coap_session_t *coap_new_client_session(
  struct coap_context_t *ctx,
  const coap_address_t *local_if,
  const coap_address_t *server,
  coap_proto_t proto
);

/**
* Creates a new client session to the designated server with PSK credentials
* @param ctx The CoAP context.
* @param local_if Address of local interface. It is recommended to use NULL to let the operating system choose a suitable local interface. If an address is specified, the port number should be zero, which means that a free port is automatically selected.
* @param server The server's address. If the port number is zero, the default port for the protocol will be used.
* @param proto Protocol.
* @param identity PSK client identity
* @param key PSK shared key
* @param key_len PSK shared key length
*
* @return A new CoAP session or NULL if failed. Call coap_session_release to free.
*/
coap_session_t *coap_new_client_session_psk(
  struct coap_context_t *ctx,
  const coap_address_t *local_if,
  const coap_address_t *server,
  coap_proto_t proto,
  const char *identity,
  const uint8_t *key,
  unsigned key_len
);

struct coap_dtls_pki_t;

/**
* Creates a new client session to the designated server with PKI credentials
* @param ctx The CoAP context.
* @param local_if Address of local interface. It is recommended to use NULL to
*                 let the operating system choose a suitable local interface.
*                 If an address is specified, the port number should be zero,
*                 which means that a free port is automatically selected.
* @param server The server's address. If the port number is zero, the default
*               port for the protocol will be used.
* @param proto CoAP Protocol.
* @param setup_data PKI parameters.
*
* @return A new CoAP session or NULL if failed. Call coap_session_release()
*         to free.
*/
coap_session_t *coap_new_client_session_pki(
  struct coap_context_t *ctx,
  const coap_address_t *local_if,
  const coap_address_t *server,
  coap_proto_t proto,
  struct coap_dtls_pki_t *setup_data
);

/**
* Creates a new server session for the specified endpoint.
* @param ctx The CoAP context.
* @param ep An endpoint where an incoming connection request is pending.
*
* @return A new CoAP session or NULL if failed. Call coap_session_release to free.
*/
coap_session_t *coap_new_server_session(
  struct coap_context_t *ctx,
  struct coap_endpoint_t *ep
);

/**
* Function interface for datagram data transmission. This function returns
* the number of bytes that have been transmitted, or a value less than zero
* on error.
*
* @param session          Session to send data on.
* @param data             The data to send.
* @param datalen          The actual length of @p data.
*
* @return                 The number of bytes written on success, or a value
*                         less than zero on error.
*/
ssize_t coap_session_send(coap_session_t *session,
  const uint8_t *data, size_t datalen);

/**
* Function interface for stream data transmission. This function returns
* the number of bytes that have been transmitted, or a value less than zero
* on error. The number of bytes written may be less than datalen because of
* congestion control.
*
* @param session          Session to send data on.
* @param data             The data to send.
* @param datalen          The actual length of @p data.
*
* @return                 The number of bytes written on success, or a value
*                         less than zero on error.
*/
ssize_t coap_session_write(coap_session_t *session,
  const uint8_t *data, size_t datalen);

/**
* Send a pdu according to the session's protocol. This function returns
* the number of bytes that have been transmitted, or a value less than zero
* on error.
*
* @param session          Session to send pdu on.
* @param pdu              The pdu to send.
*
* @return                 The number of bytes written on success, or a value
*                         less than zero on error.
*/
ssize_t coap_session_send_pdu(coap_session_t *session, coap_pdu_t *pdu);


/**
 * @ingroup logging
 * Get session description.
 *
 * @param session  The CoAP session.
 * @return description string.
 */
const char *coap_session_str(const coap_session_t *session);

ssize_t
coap_session_delay_pdu(coap_session_t *session, coap_pdu_t *pdu,
                       struct coap_queue_t *node);
/**
* Abstraction of virtual endpoint that can be attached to coap_context_t. The
* tuple (handle, addr) must uniquely identify this endpoint.
*/
typedef struct coap_endpoint_t {
  struct coap_endpoint_t *next;
  struct coap_context_t *context; /**< endpoint's context */
  coap_proto_t proto;             /**< protocol used on this interface */
  uint16_t default_mtu;           /**< default mtu for this interface */
  coap_socket_t sock;             /**< socket object for the interface, if any */
  coap_address_t bind_addr;       /**< local interface address */
  coap_session_t *sessions;       /**< list of active sessions */
} coap_endpoint_t;

/**
* Create a new endpoint for communicating with peers.
*
* @param context        The coap context that will own the new endpoint
* @param listen_addr    Address the endpoint will listen for incoming requests on or originate outgoing requests from. Use NULL to specify that no incoming request will be accepted and use a random endpoint.
* @param proto          Protocol used on this endpoint
*/

coap_endpoint_t *coap_new_endpoint(struct coap_context_t *context, const coap_address_t *listen_addr, coap_proto_t proto);

/**
* Set the endpoint's default MTU. This is the maximum message size that can be
* sent, excluding IP and UDP overhead.
*
* @param endpoint The CoAP endpoint.
* @param mtu maximum message size
*/
void coap_endpoint_set_default_mtu(coap_endpoint_t *endpoint, unsigned mtu);

void coap_free_endpoint(coap_endpoint_t *ep);


/**
 * @ingroup logging
* Get endpoint description.
*
* @param endpoint  The CoAP endpoint.
* @return description string.
*/
const char *coap_endpoint_str(const coap_endpoint_t *endpoint);

/**
* Lookup the server session for the packet received on an endpoint, or create
* a new one.
*
* @param endpoint Active endpoint the packet was received on.
* @param packet Received packet.
* @param now The current time in ticks.
* @return The CoAP session or @c NULL if error.
*/
coap_session_t *coap_endpoint_get_session(coap_endpoint_t *endpoint,
  const struct coap_packet_t *packet, coap_tick_t now);

/**
 * Create a new DTLS session for the @p session.
 * Note: the @p session is released if no DTLS server session can be created.
 *
 * @ingroup dtls_internal
 *
 * @param session   Session to add DTLS session to
 * @param now       The current time in ticks.
 *
 * @return CoAP session or @c NULL if error.
 */
coap_session_t *coap_session_new_dtls_session(coap_session_t *session,
  coap_tick_t now);

coap_session_t *coap_session_get_by_peer(struct coap_context_t *ctx,
  const struct coap_address_t *remote_addr, int ifindex);

void coap_session_free(coap_session_t *session);
void coap_session_mfree(coap_session_t *session);

 /**
  * @defgroup cc Rate Control
  * The transmission parameters for CoAP rate control ("Congestion
  * Control" in stream-oriented protocols) are defined in
  * https://tools.ietf.org/html/rfc7252#section-4.8
  * @{
  */

  /**
   * Number of seconds when to expect an ACK or a response to an
   * outstanding CON message.
   * RFC 7252, Section 4.8 Default value of ACK_TIMEOUT is 2
   */
#define COAP_DEFAULT_ACK_TIMEOUT ((coap_fixed_point_t){2,0})

   /**
    * A factor that is used to randomize the wait time before a message
    * is retransmitted to prevent synchronization effects.
    * RFC 7252, Section 4.8 Default value of ACK_RANDOM_FACTOR is 1.5
    */
#define COAP_DEFAULT_ACK_RANDOM_FACTOR ((coap_fixed_point_t){1,500})

    /**
     * Number of message retransmissions before message sending is stopped
     * RFC 7252, Section 4.8 Default value of MAX_RETRANSMIT is 4
     */
#define COAP_DEFAULT_MAX_RETRANSMIT  4

     /**
      * The number of simultaneous outstanding interactions that a client
      * maintains to a given server.
      * RFC 7252, Section 4.8 Default value of NSTART is 1
      */
#define COAP_DEFAULT_NSTART 1

      /** @} */

/**
* Set the CoAP maximum retransmit count before failure
*
* Number of message retransmissions before message sending is stopped
*
* @param session The CoAP session.
* @param value The value to set to. The default is 4 and should not normally
*              get changed.
*/
void coap_session_set_max_retransmit(coap_session_t *session,
                                     unsigned int value);

/**
* Set the CoAP initial ack response timeout before the next re-transmit
*
* Number of seconds when to expect an ACK or a response to an
* outstanding CON message.
*
* @param session The CoAP session.
* @param value The value to set to. The default is 2 and should not normally
*              get changed.
*/
void coap_session_set_ack_timeout(coap_session_t *session,
                                  coap_fixed_point_t value);

/**
* Set the CoAP ack randomize factor
*
* A factor that is used to randomize the wait time before a message
* is retransmitted to prevent synchronization effects.
*
* @param session The CoAP session.
* @param value The value to set to. The default is 1.5 and should not normally
*              get changed.
*/
void coap_session_set_ack_random_factor(coap_session_t *session,
                                        coap_fixed_point_t value);

/**
* Get the CoAP maximum retransmit before failure
*
* Number of message retransmissions before message sending is stopped
*
* @param session The CoAP session.
*
* @return Current maximum retransmit value
*/
unsigned int coap_session_get_max_transmit(coap_session_t *session);

/**
* Get the CoAP initial ack response timeout before the next re-transmit
*
* Number of seconds when to expect an ACK or a response to an
* outstanding CON message.
*
* @param session The CoAP session.
*
* @return Current ack response timeout value
*/
coap_fixed_point_t coap_session_get_ack_timeout(coap_session_t *session);

/**
* Get the CoAP ack randomize factor
*
* A factor that is used to randomize the wait time before a message
* is retransmitted to prevent synchronization effects.
*
* @param session The CoAP session.
*
* @return Current ack randomize value
*/
coap_fixed_point_t coap_session_get_ack_random_factor(coap_session_t *session);

/**
 * Send a ping message for the session.
 * @param session The CoAP session.
 *
 * @return COAP_INVALID_TID if there is an error
 */
coap_tid_t coap_session_send_ping(coap_session_t *session);

#endif  /* COAP_SESSION_H */
/*
 * coap_time.h -- Clock Handling
 *
 * Copyright (C) 2010-2019 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_time.h
 * @brief Clock Handling
 */

#ifndef COAP_TIME_H_
#define COAP_TIME_H_

/**
 * @defgroup clock Clock Handling
 * Default implementation of internal clock.
 * @{
 */

#if defined(WITH_LWIP)

#include <stdint.h>
#include <lwip/sys.h>

/* lwIP provides ms in sys_now */
#define COAP_TICKS_PER_SECOND 1000

typedef uint32_t coap_tick_t;
typedef uint32_t coap_time_t;
typedef int32_t coap_tick_diff_t;

COAP_STATIC_INLINE void coap_ticks_impl(coap_tick_t *t) {
  *t = sys_now();
}

COAP_STATIC_INLINE void coap_clock_init_impl(void) {
}

#define coap_clock_init coap_clock_init_impl
#define coap_ticks coap_ticks_impl

COAP_STATIC_INLINE coap_time_t coap_ticks_to_rt(coap_tick_t t) {
  return t / COAP_TICKS_PER_SECOND;
}

#elif defined(WITH_CONTIKI)

#include "clock.h"

typedef clock_time_t coap_tick_t;
typedef clock_time_t coap_time_t;

/**
 * This data type is used to represent the difference between two clock_tick_t
 * values. This data type must have the same size in memory as coap_tick_t to
 * allow wrapping.
 */
typedef int coap_tick_diff_t;

#define COAP_TICKS_PER_SECOND CLOCK_SECOND

COAP_STATIC_INLINE void coap_clock_init(void) {
  clock_init();
}

COAP_STATIC_INLINE void coap_ticks(coap_tick_t *t) {
  *t = clock_time();
}

COAP_STATIC_INLINE coap_time_t coap_ticks_to_rt(coap_tick_t t) {
  return t / COAP_TICKS_PER_SECOND;
}

#else
#include <stdint.h>

/**
 * This data type represents internal timer ticks with COAP_TICKS_PER_SECOND
 * resolution.
 */
typedef uint64_t coap_tick_t;

/**
 * CoAP time in seconds since epoch.
 */
typedef time_t coap_time_t;

/**
 * This data type is used to represent the difference between two clock_tick_t
 * values. This data type must have the same size in memory as coap_tick_t to
 * allow wrapping.
 */
typedef int64_t coap_tick_diff_t;

/** Use ms resolution on POSIX systems */
#define COAP_TICKS_PER_SECOND ((coap_tick_t)(1000U))

/**
 * Initializes the internal clock.
 */
void coap_clock_init(void);

/**
 * Sets @p t to the internal time with COAP_TICKS_PER_SECOND resolution.
 */
void coap_ticks(coap_tick_t *t);

/**
 * Helper function that converts coap ticks to wallclock time. On POSIX, this
 * function returns the number of seconds since the epoch. On other systems, it
 * may be the calculated number of seconds since last reboot or so.
 *
 * @param t Internal system ticks.
 *
 * @return  The number of seconds that has passed since a specific reference
 *          point (seconds since epoch on POSIX).
 */
coap_time_t coap_ticks_to_rt(coap_tick_t t);

/**
* Helper function that converts coap ticks to POSIX wallclock time in us.
*
* @param t Internal system ticks.
*
* @return  The number of seconds that has passed since a specific reference
*          point (seconds since epoch on POSIX).
*/
uint64_t coap_ticks_to_rt_us(coap_tick_t t);

/**
* Helper function that converts POSIX wallclock time in us to coap ticks.
*
* @param t POSIX time is us
*
* @return  coap ticks
*/
coap_tick_t coap_ticks_from_rt_us(uint64_t t);
#endif

/**
 * Returns @c 1 if and only if @p a is less than @p b where less is defined on a
 * signed data type.
 */
COAP_STATIC_INLINE int coap_time_lt(coap_tick_t a, coap_tick_t b) {
  return ((coap_tick_diff_t)(a - b)) < 0;
}

/**
 * Returns @c 1 if and only if @p a is less than or equal @p b where less is
 * defined on a signed data type.
 */
COAP_STATIC_INLINE int coap_time_le(coap_tick_t a, coap_tick_t b) {
  return a == b || coap_time_lt(a,b);
}

/** @} */

#endif /* COAP_TIME_H_ */
/*
 * encode.h -- encoding and decoding of CoAP data types
 *
 * Copyright (C) 2010-2012 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef COAP_ENCODE_H_
#define COAP_ENCODE_H_

#if (BSD >= 199103) || defined(WITH_CONTIKI) || defined(_WIN32)
# include <string.h>
#else
# include <strings.h>
#endif

#include <stdint.h>

#define Nn 8  /* duplicate definition of N if built on sky motes */
#define ENCODE_HEADER_SIZE 4
#define HIBIT (1 << (Nn - 1))
#define EMASK ((1 << ENCODE_HEADER_SIZE) - 1)
#define MMASK ((1 << Nn) - 1 - EMASK)
#define MAX_VALUE ( (1 << Nn) - (1 << ENCODE_HEADER_SIZE) ) * (1 << ((1 << ENCODE_HEADER_SIZE) - 1))

#define COAP_PSEUDOFP_DECODE_8_4(r) (r < HIBIT ? r : (r & MMASK) << (r & EMASK))

#ifndef HAVE_FLS
/* include this only if fls() is not available */
extern int coap_fls(unsigned int i);
#else
#define coap_fls(i) fls(i)
#endif

#ifndef HAVE_FLSLL
 /* include this only if flsll() is not available */
extern int coap_flsll(long long i);
#else
#define coap_flsll(i) flsll(i)
#endif

/* ls and s must be integer variables */
#define COAP_PSEUDOFP_ENCODE_8_4_DOWN(v,ls) (v < HIBIT ? v : (ls = coap_fls(v) - Nn, (v >> ls) & MMASK) + ls)
#define COAP_PSEUDOFP_ENCODE_8_4_UP(v,ls,s) (v < HIBIT ? v : (ls = coap_fls(v) - Nn, (s = (((v + ((1<<ENCODE_HEADER_SIZE<<ls)-1)) >> ls) & MMASK)), s == 0 ? HIBIT + ls + 1 : s + ls))

/**
 * Decodes multiple-length byte sequences. @p buf points to an input byte
 * sequence of length @p length. Returns the decoded value.
 *
 * @param buf The input byte sequence to decode from
 * @param length The length of the input byte sequence
 *
 * @return      The decoded value
 */
unsigned int coap_decode_var_bytes(const uint8_t *buf, unsigned int length);

/**
 * Encodes multiple-length byte sequences. @p buf points to an output buffer of
 * sufficient length to store the encoded bytes. @p value is the value to
 * encode.
 * Returns the number of bytes used to encode @p value or 0 on error.
 *
 * @param buf    The output buffer to decode into
 * @param length The output buffer size to encode into (must be sufficient)
 * @param value  The value to encode into the buffer
 *
 * @return       The number of bytes used to encode @p value or @c 0 on error.
 */
unsigned int coap_encode_var_safe(uint8_t *buf,
                                  size_t length,
                                  unsigned int value);

/**
 * @deprecated Use coap_encode_var_safe() instead.
 * Provided for backward compatibility.  As @p value has a
 * maximum value of 0xffffffff, and buf is usually defined as an array, it
 * is unsafe to continue to use this variant if buf[] is less than buf[4].
 *
 * For example
 *  char buf[1],oops;
 *  ..
 *  coap_encode_var_bytes(buf, 0xfff);
 * would cause oops to get overwritten.  This error can only be found by code
 * inspection.
 *   coap_encode_var_safe(buf, sizeof(buf), 0xfff);
 * would catch this error at run-time and should be used instead.
 */
COAP_STATIC_INLINE COAP_DEPRECATED int
coap_encode_var_bytes(uint8_t *buf, unsigned int value
) {
  return (int)coap_encode_var_safe(buf, sizeof(value), value);
}

#endif /* COAP_ENCODE_H_ */
/*
 * libcoap.h -- platform specific header file for CoAP stack
 *
 * Copyright (C) 2015 Carsten Schoenert <c.schoenert@t-online.de>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef COAP_LIBCOAP_H_
#define COAP_LIBCOAP_H_

/* The non posix embedded platforms like Contiki, TinyOS, RIOT, ... doesn't have
 * a POSIX compatible header structure so we have to slightly do some platform
 * related things. Currently there is only Contiki available so we check for a
 * CONTIKI environment and do *not* include the POSIX related network stuff. If
 * there are other platforms in future there need to be analogous environments.
 *
 * The CONTIKI variable is within the Contiki build environment! */

#if defined(_WIN32)
#pragma comment(lib,"Ws2_32.lib")
#include <ws2tcpip.h>
typedef SSIZE_T ssize_t;
typedef USHORT in_port_t;
#elif !defined (CONTIKI)
#include <netinet/in.h>
#include <sys/socket.h>
#endif /* CONTIKI */

#ifndef COAP_STATIC_INLINE
#  if defined(__cplusplus)
#    define COAP_STATIC_INLINE inline
#  else
#    if defined(_MSC_VER)
#      define COAP_STATIC_INLINE static __inline
#    else
#      define COAP_STATIC_INLINE static inline
#    endif
#  endif
#endif
#ifndef COAP_DEPRECATED
#  if defined(__cplusplus)
#    define COAP_DEPRECATED __attribute__ ((deprecated))
#  else
#    if defined(_MSC_VER)
#      define COAP_DEPRECATED __declspec(deprecated)
#    else
#      define COAP_DEPRECATED __attribute__ ((deprecated))
#    endif
#  endif
#endif

void coap_startup(void);

void coap_cleanup(void);

#endif /* COAP_LIBCOAP_H_ */
/*
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/* Memory pool definitions for the libcoap when used with lwIP (which has its
 * own mechanism for quickly allocating chunks of data with known sizes). Has
 * to be findable by lwIP (ie. an #include <lwippools.h> must either directly
 * include this or include something more generic which includes this), and
 * MEMP_USE_CUSTOM_POOLS has to be set in lwipopts.h. */

#include "coap_config.h"
#include <net.h>
#include <resource.h>
#include <subscribe.h>

#ifndef MEMP_NUM_COAPCONTEXT
#define MEMP_NUM_COAPCONTEXT 1
#endif

#ifndef MEMP_NUM_COAPENDPOINT
#define MEMP_NUM_COAPENDPOINT 1
#endif

/* 1 is sufficient as this is very short-lived */
#ifndef MEMP_NUM_COAPPACKET
#define MEMP_NUM_COAPPACKET 1
#endif

#ifndef MEMP_NUM_COAPNODE
#define MEMP_NUM_COAPNODE 4
#endif

#ifndef MEMP_NUM_COAPPDU
#define MEMP_NUM_COAPPDU MEMP_NUM_COAPNODE
#endif

#ifndef MEMP_NUM_COAPSESSION
#define MEMP_NUM_COAPSESSION 2
#endif

#ifndef MEMP_NUM_COAP_SUBSCRIPTION
#define MEMP_NUM_COAP_SUBSCRIPTION 4
#endif

#ifndef MEMP_NUM_COAPRESOURCE
#define MEMP_NUM_COAPRESOURCE 10
#endif

#ifndef MEMP_NUM_COAPRESOURCEATTR
#define MEMP_NUM_COAPRESOURCEATTR 20
#endif

#ifndef MEMP_NUM_COAPOPTLIST
#define MEMP_NUM_COAPOPTLIST 1
#endif

#ifndef MEMP_LEN_COAPOPTLIST
#define MEMP_LEN_COAPOPTLIST 12
#endif

#ifndef MEMP_NUM_COAPSTRING
#define MEMP_NUM_COAPSTRING 10
#endif

#ifndef MEMP_LEN_COAPSTRING
#define MEMP_LEN_COAPSTRING 32
#endif

LWIP_MEMPOOL(COAP_CONTEXT, MEMP_NUM_COAPCONTEXT, sizeof(coap_context_t), "COAP_CONTEXT")
LWIP_MEMPOOL(COAP_ENDPOINT, MEMP_NUM_COAPENDPOINT, sizeof(coap_endpoint_t), "COAP_ENDPOINT")
LWIP_MEMPOOL(COAP_PACKET, MEMP_NUM_COAPPACKET, sizeof(coap_packet_t), "COAP_PACKET")
LWIP_MEMPOOL(COAP_NODE, MEMP_NUM_COAPNODE, sizeof(coap_queue_t), "COAP_NODE")
LWIP_MEMPOOL(COAP_PDU, MEMP_NUM_COAPPDU, sizeof(coap_pdu_t), "COAP_PDU")
LWIP_MEMPOOL(COAP_SESSION, MEMP_NUM_COAPSESSION, sizeof(coap_session_t), "COAP_SESSION")
LWIP_MEMPOOL(COAP_subscription, MEMP_NUM_COAP_SUBSCRIPTION, sizeof(coap_subscription_t), "COAP_subscription")
LWIP_MEMPOOL(COAP_RESOURCE, MEMP_NUM_COAPRESOURCE, sizeof(coap_resource_t), "COAP_RESOURCE")
LWIP_MEMPOOL(COAP_RESOURCEATTR, MEMP_NUM_COAPRESOURCEATTR, sizeof(coap_attr_t), "COAP_RESOURCEATTR")
LWIP_MEMPOOL(COAP_OPTLIST, MEMP_NUM_COAPOPTLIST, sizeof(coap_optlist_t)+MEMP_LEN_COAPOPTLIST, "COAP_OPTLIST")
LWIP_MEMPOOL(COAP_STRING, MEMP_NUM_COAPSTRING, sizeof(coap_string_t)+MEMP_LEN_COAPSTRING, "COAP_STRING")

/*
 * mem.h -- CoAP memory handling
 *
 * Copyright (C) 2010-2011,2014-2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef COAP_MEM_H_
#define COAP_MEM_H_

#include <stdlib.h>

#ifndef WITH_LWIP
/**
 * Initializes libcoap's memory management.
 * This function must be called once before coap_malloc() can be used on
 * constrained devices.
 */
void coap_memory_init(void);
#endif /* WITH_LWIP */

/**
 * Type specifiers for coap_malloc_type(). Memory objects can be typed to
 * facilitate arrays of type objects to be used instead of dynamic memory
 * management on constrained devices.
 */
typedef enum {
  COAP_STRING,
  COAP_ATTRIBUTE_NAME,
  COAP_ATTRIBUTE_VALUE,
  COAP_PACKET,
  COAP_NODE,
  COAP_CONTEXT,
  COAP_ENDPOINT,
  COAP_PDU,
  COAP_PDU_BUF,
  COAP_RESOURCE,
  COAP_RESOURCEATTR,
#ifdef HAVE_LIBTINYDTLS
  COAP_DTLS_SESSION,
#endif
  COAP_SESSION,
  COAP_OPTLIST,
} coap_memory_tag_t;

#ifndef WITH_LWIP

/**
 * Allocates a chunk of @p size bytes and returns a pointer to the newly
 * allocated memory. The @p type is used to select the appropriate storage
 * container on constrained devices. The storage allocated by coap_malloc_type()
 * must be released with coap_free_type().
 *
 * @param type The type of object to be stored.
 * @param size The number of bytes requested.
 * @return     A pointer to the allocated storage or @c NULL on error.
 */
void *coap_malloc_type(coap_memory_tag_t type, size_t size);

/**
 * Releases the memory that was allocated by coap_malloc_type(). The type tag @p
 * type must be the same that was used for allocating the object pointed to by
 * @p .
 *
 * @param type The type of the object to release.
 * @param p    A pointer to memory that was allocated by coap_malloc_type().
 */
void coap_free_type(coap_memory_tag_t type, void *p);

/**
 * Wrapper function to coap_malloc_type() for backwards compatibility.
 */
COAP_STATIC_INLINE void *coap_malloc(size_t size) {
  return coap_malloc_type(COAP_STRING, size);
}

/**
 * Wrapper function to coap_free_type() for backwards compatibility.
 */
COAP_STATIC_INLINE void coap_free(void *object) {
  coap_free_type(COAP_STRING, object);
}

#endif /* not WITH_LWIP */

#ifdef WITH_LWIP

#include <lwip/memp.h>

/* no initialization needed with lwip (or, more precisely: lwip must be
 * completely initialized anyway by the time coap gets active)  */
COAP_STATIC_INLINE void coap_memory_init(void) {}

/* It would be nice to check that size equals the size given at the memp
 * declaration, but i currently don't see a standard way to check that without
 * sourcing the custom memp pools and becoming dependent of its syntax
 */
#define coap_malloc_type(type, size) memp_malloc(MEMP_ ## type)
#define coap_free_type(type, p) memp_free(MEMP_ ## type, p)

/* Those are just here to make uri.c happy where string allocation has not been
 * made conditional.
 */
COAP_STATIC_INLINE void *coap_malloc(size_t size) {
  LWIP_ASSERT("coap_malloc must not be used in lwIP", 0);
}

COAP_STATIC_INLINE void coap_free(void *pointer) {
  LWIP_ASSERT("coap_free must not be used in lwIP", 0);
}

#endif /* WITH_LWIP */

#endif /* COAP_MEM_H_ */
/*
 * net.h -- CoAP network interface
 *
 * Copyright (C) 2010-2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef COAP_NET_H_
#define COAP_NET_H_

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <sys/time.h>
#endif
#include <time.h>

#ifdef WITH_LWIP
#include <lwip/ip_addr.h>
#endif

#include "coap_io.h"
#include "coap_dtls.h"
#include "coap_event.h"
#include "coap_time.h"
#include "option.h"
#include "pdu.h"
#include "prng.h"
#include "coap_session.h"

struct coap_queue_t;

/**
 * Queue entry
 */
typedef struct coap_queue_t {
  struct coap_queue_t *next;
  coap_tick_t t;                /**< when to send PDU for the next time */
  unsigned char retransmit_cnt; /**< retransmission counter, will be removed
                                 *    when zero */
  unsigned int timeout;         /**< the randomized timeout value */
  coap_session_t *session;      /**< the CoAP session */
  coap_tid_t id;                /**< CoAP transaction id */
  coap_pdu_t *pdu;              /**< the CoAP PDU to send */
} coap_queue_t;

/**
 * Adds @p node to given @p queue, ordered by variable t in @p node.
 *
 * @param queue Queue to add to.
 * @param node Node entry to add to Queue.
 *
 * @return @c 1 added to queue, @c 0 failure.
 */
int coap_insert_node(coap_queue_t **queue, coap_queue_t *node);

/**
 * Destroys specified @p node.
 *
 * @param node Node entry to remove.
 *
 * @return @c 1 node deleted from queue, @c 0 failure.
 */
int coap_delete_node(coap_queue_t *node);

/**
 * Removes all items from given @p queue and frees the allocated storage.
 *
 * @param queue The queue to delete.
 */
void coap_delete_all(coap_queue_t *queue);

/**
 * Creates a new node suitable for adding to the CoAP sendqueue.
 *
 * @return New node entry, or @c NULL if failure.
 */
coap_queue_t *coap_new_node(void);

struct coap_resource_t;
struct coap_context_t;
#ifndef WITHOUT_ASYNC
struct coap_async_state_t;
#endif

/**
 * Response handler that is used as call-back in coap_context_t.
 *
 * @param context CoAP session.
 * @param session CoAP session.
 * @param sent The PDU that was transmitted.
 * @param received The PDU that was received.
 * @param id CoAP transaction ID.
 */
typedef void (*coap_response_handler_t)(struct coap_context_t *context,
                                        coap_session_t *session,
                                        coap_pdu_t *sent,
                                        coap_pdu_t *received,
                                        const coap_tid_t id);

/**
 * Negative Acknowedge handler that is used as call-back in coap_context_t.
 *
 * @param context CoAP session.
 * @param session CoAP session.
 * @param sent The PDU that was transmitted.
 * @param reason The reason for the NACK.
 * @param id CoAP transaction ID.
 */
typedef void (*coap_nack_handler_t)(struct coap_context_t *context,
                                    coap_session_t *session,
                                    coap_pdu_t *sent,
                                    coap_nack_reason_t reason,
                                    const coap_tid_t id);

/**
 * Recieved Ping handler that is used as call-back in coap_context_t.
 *
 * @param context CoAP session.
 * @param session CoAP session.
 * @param received The PDU that was received.
 * @param id CoAP transaction ID.
 */
typedef void (*coap_ping_handler_t)(struct coap_context_t *context,
                                    coap_session_t *session,
                                    coap_pdu_t *received,
                                    const coap_tid_t id);

/**
 * Recieved Pong handler that is used as call-back in coap_context_t.
 *
 * @param context CoAP session.
 * @param session CoAP session.
 * @param received The PDU that was received.
 * @param id CoAP transaction ID.
 */
typedef void (*coap_pong_handler_t)(struct coap_context_t *context,
                                    coap_session_t *session,
                                    coap_pdu_t *received,
                                    const coap_tid_t id);

/**
 * The CoAP stack's global state is stored in a coap_context_t object.
 */
typedef struct coap_context_t {
  coap_opt_filter_t known_options;
  struct coap_resource_t *resources; /**< hash table or list of known
                                          resources */
  struct coap_resource_t *unknown_resource; /**< can be used for handling
                                                 unknown resources */

#ifndef WITHOUT_ASYNC
  /**
   * list of asynchronous transactions */
  struct coap_async_state_t *async_state;
#endif /* WITHOUT_ASYNC */

  /**
   * The time stamp in the first element of the sendqeue is relative
   * to sendqueue_basetime. */
  coap_tick_t sendqueue_basetime;
  coap_queue_t *sendqueue;
  coap_endpoint_t *endpoint;      /**< the endpoints used for listening  */
  coap_session_t *sessions;       /**< client sessions */

#ifdef WITH_CONTIKI
  struct uip_udp_conn *conn;      /**< uIP connection object */
  struct etimer retransmit_timer; /**< fires when the next packet must be sent */
  struct etimer notify_timer;     /**< used to check resources periodically */
#endif /* WITH_CONTIKI */

#ifdef WITH_LWIP
  uint8_t timer_configured;       /**< Set to 1 when a retransmission is
                                   *   scheduled using lwIP timers for this
                                   *   context, otherwise 0. */
#endif /* WITH_LWIP */

  /**
   * The last message id that was used is stored in this field. The initial
   * value is set by coap_new_context() and is usually a random value. A new
   * message id can be created with coap_new_message_id().
   */
  uint16_t message_id;

  coap_response_handler_t response_handler;
  coap_nack_handler_t nack_handler;
  coap_ping_handler_t ping_handler;
  coap_pong_handler_t pong_handler;

  /**
   * Callback function that is used to signal events to the
   * application.  This field is set by coap_set_event_handler().
   */
  coap_event_handler_t handle_event;

  ssize_t (*network_send)(coap_socket_t *sock, const coap_session_t *session, const uint8_t *data, size_t datalen);

  ssize_t (*network_read)(coap_socket_t *sock, struct coap_packet_t *packet);

  size_t(*get_client_psk)(const coap_session_t *session, const uint8_t *hint, size_t hint_len, uint8_t *identity, size_t *identity_len, size_t max_identity_len, uint8_t *psk, size_t max_psk_len);
  size_t(*get_server_psk)(const coap_session_t *session, const uint8_t *identity, size_t identity_len, uint8_t *psk, size_t max_psk_len);
  size_t(*get_server_hint)(const coap_session_t *session, uint8_t *hint, size_t max_hint_len);

  void *dtls_context;
  uint8_t *psk_hint;
  size_t psk_hint_len;
  uint8_t *psk_key;
  size_t psk_key_len;

  unsigned int session_timeout;    /**< Number of seconds of inactivity after which an unused session will be closed. 0 means use default. */
  unsigned int max_idle_sessions;  /**< Maximum number of simultaneous unused sessions per endpoint. 0 means no maximum. */
  unsigned int max_handshake_sessions; /**< Maximum number of simultaneous negotating sessions per endpoint. 0 means use default. */
  unsigned int ping_timeout;           /**< Minimum inactivity time before sending a ping message. 0 means disabled. */
  unsigned int csm_timeout;           /**< Timeout for waiting for a CSM from the remote side. 0 means disabled. */

  void *app;                       /**< application-specific data */
} coap_context_t;

/**
 * Registers a new message handler that is called whenever a response was
 * received that matches an ongoing transaction.
 *
 * @param context The context to register the handler for.
 * @param handler The response handler to register.
 */
COAP_STATIC_INLINE void
coap_register_response_handler(coap_context_t *context,
                               coap_response_handler_t handler) {
  context->response_handler = handler;
}

/**
 * Registers a new message handler that is called whenever a confirmable
 * message (request or response) is dropped after all retries have been
 * exhausted, or a rst message was received, or a network or TLS level
 * event was received that indicates delivering the message is not possible.
 *
 * @param context The context to register the handler for.
 * @param handler The nack handler to register.
 */
COAP_STATIC_INLINE void
coap_register_nack_handler(coap_context_t *context,
                           coap_nack_handler_t handler) {
  context->nack_handler = handler;
}

/**
 * Registers a new message handler that is called whenever a CoAP Ping
 * message is received.
 *
 * @param context The context to register the handler for.
 * @param handler The ping handler to register.
 */
COAP_STATIC_INLINE void
coap_register_ping_handler(coap_context_t *context,
                           coap_ping_handler_t handler) {
  context->ping_handler = handler;
}

/**
 * Registers a new message handler that is called whenever a CoAP Pong
 * message is received.
 *
 * @param context The context to register the handler for.
 * @param handler The pong handler to register.
 */
COAP_STATIC_INLINE void
coap_register_pong_handler(coap_context_t *context,
                           coap_pong_handler_t handler) {
  context->pong_handler = handler;
}

/**
 * Registers the option type @p type with the given context object @p ctx.
 *
 * @param ctx  The context to use.
 * @param type The option type to register.
 */
COAP_STATIC_INLINE void
coap_register_option(coap_context_t *ctx, uint16_t type) {
  coap_option_setb(ctx->known_options, type);
}

/**
 * Set sendqueue_basetime in the given context object @p ctx to @p now. This
 * function returns the number of elements in the queue head that have timed
 * out.
 */
unsigned int coap_adjust_basetime(coap_context_t *ctx, coap_tick_t now);

/**
 * Returns the next pdu to send without removing from sendqeue.
 */
coap_queue_t *coap_peek_next( coap_context_t *context );

/**
 * Returns the next pdu to send and removes it from the sendqeue.
 */
coap_queue_t *coap_pop_next( coap_context_t *context );

/**
 * Creates a new coap_context_t object that will hold the CoAP stack status.
 */
coap_context_t *coap_new_context(const coap_address_t *listen_addr);

/**
 * Set the context's default PSK hint and/or key for a server.
 *
 * @param context The current coap_context_t object.
 * @param hint    The default PSK server hint sent to a client. If @p NULL, PSK
 *                authentication is disabled. Empty string is a valid hint.
 * @param key     The default PSK key. If @p NULL, PSK authentication will fail.
 * @param key_len The default PSK key's length. If @p 0, PSK authentication will
 *                fail.
 *
 * @return @c 1 if successful, else @c 0.
 */
int coap_context_set_psk( coap_context_t *context, const char *hint,
                           const uint8_t *key, size_t key_len );

/**
 * Set the context's default PKI information for a server.
 *
 * @param context        The current coap_context_t object.
 * @param setup_data     If @p NULL, PKI authentication will fail. Certificate
 *                       information required.
 *
 * @return @c 1 if successful, else @c 0.
 */
int
coap_context_set_pki(coap_context_t *context,
                     coap_dtls_pki_t *setup_data);

/**
 * Set the context's default Root CA information for a client or server.
 *
 * @param context        The current coap_context_t object.
 * @param ca_file        If not @p NULL, is the full path name of a PEM encoded
 *                       file containing all the Root CAs to be used.
 * @param ca_dir         If not @p NULL, points to a directory containing PEM
 *                       encoded files containing all the Root CAs to be used.
 *
 * @return @c 1 if successful, else @c 0.
 */
int
coap_context_set_pki_root_cas(coap_context_t *context,
                              const char *ca_file,
                              const char *ca_dir);

/**
 * Set the context keepalive timer for sessions.
 * A keepalive message will be sent after if a session has been inactive,
 * i.e. no packet sent or received, for the given number of seconds.
 * For reliable protocols, a PING message will be sent. If a PONG has not
 * been received before the next PING is due to be sent, the session will
 * considered as disconnected.
 *
 * @param context        The coap_context_t object.
 * @param seconds                 Number of seconds for the inactivity timer, or zero
 *                       to disable CoAP-level keepalive messages.
 *
 * @return 1 if successful, else 0
 */
void coap_context_set_keepalive(coap_context_t *context, unsigned int seconds);

/**
 * Returns a new message id and updates @p session->tx_mid accordingly. The
 * message id is returned in network byte order to make it easier to read in
 * tracing tools.
 *
 * @param session The current coap_session_t object.
 *
 * @return        Incremented message id in network byte order.
 */
COAP_STATIC_INLINE uint16_t
coap_new_message_id(coap_session_t *session) {
  return ++session->tx_mid;
}

/**
 * CoAP stack context must be released with coap_free_context(). This function
 * clears all entries from the receive queue and send queue and deletes the
 * resources that have been registered with @p context, and frees the attached
 * endpoints.
 *
 * @param context The current coap_context_t object to free off.
 */
void coap_free_context(coap_context_t *context);

/**
 * Stores @p data with the given CoAP context. This function
 * overwrites any value that has previously been stored with @p
 * context.
 *
 * @param context The CoAP context.
 * @param data The data to store with wih the context. Note that this data
 *             must be valid during the lifetime of @p context.
 */
void coap_set_app_data(coap_context_t *context, void *data);

/**
 * Returns any application-specific data that has been stored with @p
 * context using the function coap_set_app_data(). This function will
 * return @c NULL if no data has been stored.
 *
 * @param context The CoAP context.
 *
 * @return The data previously stored or @c NULL if not data stored.
 */
void *coap_get_app_data(const coap_context_t *context);

/**
 * Creates a new ACK PDU with specified error @p code. The options specified by
 * the filter expression @p opts will be copied from the original request
 * contained in @p request. Unless @c SHORT_ERROR_RESPONSE was defined at build
 * time, the textual reason phrase for @p code will be added as payload, with
 * Content-Type @c 0.
 * This function returns a pointer to the new response message, or @c NULL on
 * error. The storage allocated for the new message must be relased with
 * coap_free().
 *
 * @param request Specification of the received (confirmable) request.
 * @param code    The error code to set.
 * @param opts    An option filter that specifies which options to copy from
 *                the original request in @p node.
 *
 * @return        A pointer to the new message or @c NULL on error.
 */
coap_pdu_t *coap_new_error_response(coap_pdu_t *request,
                                    unsigned char code,
                                    coap_opt_filter_t opts);

/**
 * Sends an error response with code @p code for request @p request to @p dst.
 * @p opts will be passed to coap_new_error_response() to copy marked options
 * from the request. This function returns the transaction id if the message was
 * sent, or @c COAP_INVALID_TID otherwise.
 *
 * @param session         The CoAP session.
 * @param request         The original request to respond to.
 * @param code            The response code.
 * @param opts            A filter that specifies the options to copy from the
 *                        @p request.
 *
 * @return                The transaction id if the message was sent, or @c
 *                        COAP_INVALID_TID otherwise.
 */
coap_tid_t coap_send_error(coap_session_t *session,
                           coap_pdu_t *request,
                           unsigned char code,
                           coap_opt_filter_t opts);

/**
 * Helper funktion to create and send a message with @p type (usually ACK or
 * RST). This function returns @c COAP_INVALID_TID when the message was not
 * sent, a valid transaction id otherwise.
 *
 * @param session         The CoAP session.
 * @param request         The request that should be responded to.
 * @param type            Which type to set.
 * @return                transaction id on success or @c COAP_INVALID_TID
 *                        otherwise.
 */
coap_tid_t
coap_send_message_type(coap_session_t *session, coap_pdu_t *request, unsigned char type);

/**
 * Sends an ACK message with code @c 0 for the specified @p request to @p dst.
 * This function returns the corresponding transaction id if the message was
 * sent or @c COAP_INVALID_TID on error.
 *
 * @param session         The CoAP session.
 * @param request         The request to be acknowledged.
 *
 * @return                The transaction id if ACK was sent or @c
 *                        COAP_INVALID_TID on error.
 */
coap_tid_t coap_send_ack(coap_session_t *session, coap_pdu_t *request);

/**
 * Sends an RST message with code @c 0 for the specified @p request to @p dst.
 * This function returns the corresponding transaction id if the message was
 * sent or @c COAP_INVALID_TID on error.
 *
 * @param session         The CoAP session.
 * @param request         The request to be reset.
 *
 * @return                The transaction id if RST was sent or @c
 *                        COAP_INVALID_TID on error.
 */
COAP_STATIC_INLINE coap_tid_t
coap_send_rst(coap_session_t *session, coap_pdu_t *request) {
  return coap_send_message_type(session, request, COAP_MESSAGE_RST);
}

/**
* Sends a CoAP message to given peer. The memory that is
* allocated by pdu will be released by coap_send().
* The caller must not use the pdu after calling coap_send().
*
* @param session         The CoAP session.
* @param pdu             The CoAP PDU to send.
*
* @return                The message id of the sent message or @c
*                        COAP_INVALID_TID on error.
*/
coap_tid_t coap_send( coap_session_t *session, coap_pdu_t *pdu );

/**
 * Handles retransmissions of confirmable messages
 *
 * @param context      The CoAP context.
 * @param node         The node to retransmit.
 *
 * @return             The message id of the sent message or @c
 *                     COAP_INVALID_TID on error.
 */
coap_tid_t coap_retransmit(coap_context_t *context, coap_queue_t *node);

/**
* For applications with their own message loop, send all pending retransmits and
* return the list of sockets with events to wait for and the next timeout
* The application should call coap_read, then coap_write again when any condition below is true:
* - data is available on any of the sockets with the COAP_SOCKET_WANT_READ
* - an incoming connection is pending in the listen queue and the COAP_SOCKET_WANT_ACCEPT flag is set
* - at least some data can be written without blocking on any of the sockets with the COAP_SOCKET_WANT_WRITE flag set
* - a connection event occured (success or failure) and the COAP_SOCKET_WANT_CONNECT flag is set
* - the timeout has expired
* Before calling coap_read or coap_write again, the application should position COAP_SOCKET_CAN_READ and COAP_SOCKET_CAN_WRITE flags as applicable.
*
* @param ctx The CoAP context
* @param sockets array of socket descriptors, filled on output
* @param max_sockets size of socket array.
* @param num_sockets pointer to the number of valid entries in the socket arrays on output
* @param now Current time.
*
* @return timeout as maxmimum number of milliseconds that the application should wait for network events or 0 if the application should wait forever.
*/

unsigned int
coap_write(coap_context_t *ctx,
  coap_socket_t *sockets[],
  unsigned int max_sockets,
  unsigned int *num_sockets,
  coap_tick_t now
);

/**
 * For applications with their own message loop, reads all data from the network.
 *
 * @param ctx The CoAP context
 * @param now Current time
 */
void coap_read(coap_context_t *ctx, coap_tick_t now);

/**
 * The main message processing loop.
 *
 * @param ctx The CoAP context
 * @param timeout_ms Minimum number of milliseconds to wait for new messages before returning. If zero the call will block until at least one packet is sent or received.
 *
 * @return number of milliseconds spent or @c -1 if there was an error
 */

int coap_run_once( coap_context_t *ctx, unsigned int timeout_ms );

/**
 * Parses and interprets a CoAP datagram with context @p ctx. This function
 * returns @c 0 if the datagram was handled, or a value less than zero on
 * error.
 *
 * @param ctx    The current CoAP context.
 * @param session The current CoAP session.
 * @param data The received packet'd data.
 * @param data_len The received packet'd data length.
 *
 * @return       @c 0 if message was handled successfully, or less than zero on
 *               error.
 */
int coap_handle_dgram(coap_context_t *ctx, coap_session_t *session, uint8_t *data, size_t data_len);

/**
 * Invokes the event handler of @p context for the given @p event and
 * @p data.
 *
 * @param context The CoAP context whose event handler is to be called.
 * @param event   The event to deliver.
 * @param session The session related to @p event.
 * @return The result from the associated event handler or 0 if none was
 * registered.
 */
int coap_handle_event(coap_context_t *context,
                      coap_event_t event,
                      coap_session_t *session);
/**
 * This function removes the element with given @p id from the list given list.
 * If @p id was found, @p node is updated to point to the removed element. Note
 * that the storage allocated by @p node is @b not released. The caller must do
 * this manually using coap_delete_node(). This function returns @c 1 if the
 * element with id @p id was found, @c 0 otherwise. For a return value of @c 0,
 * the contents of @p node is undefined.
 *
 * @param queue The queue to search for @p id.
 * @param session The session to look for.
 * @param id    The transaction id to look for.
 * @param node  If found, @p node is updated to point to the removed node. You
 *              must release the storage pointed to by @p node manually.
 *
 * @return      @c 1 if @p id was found, @c 0 otherwise.
 */
int coap_remove_from_queue(coap_queue_t **queue,
                           coap_session_t *session,
                           coap_tid_t id,
                           coap_queue_t **node);

coap_tid_t
coap_wait_ack( coap_context_t *context, coap_session_t *session,
               coap_queue_t *node);

/**
 * Retrieves transaction from the queue.
 *
 * @param queue The transaction queue to be searched.
 * @param session The session to find.
 * @param id    The transaction id to find.
 *
 * @return      A pointer to the transaction object or @c NULL if not found.
 */
coap_queue_t *coap_find_transaction(coap_queue_t *queue, coap_session_t *session, coap_tid_t id);

/**
 * Cancels all outstanding messages for session @p session that have the specified
 * token.
 *
 * @param context      The context in use.
 * @param session      Session of the messages to remove.
 * @param token        Message token.
 * @param token_length Actual length of @p token.
 */
void coap_cancel_all_messages(coap_context_t *context,
                              coap_session_t *session,
                              const uint8_t *token,
                              size_t token_length);

/**
* Cancels all outstanding messages for session @p session.
*
* @param context      The context in use.
* @param session      Session of the messages to remove.
* @param reason       The reasion for the session cancellation
*/
void
coap_cancel_session_messages(coap_context_t *context,
                             coap_session_t *session,
                             coap_nack_reason_t reason);

/**
 * Dispatches the PDUs from the receive queue in given context.
 */
void coap_dispatch(coap_context_t *context, coap_session_t *session,
                   coap_pdu_t *pdu);

/**
 * Returns 1 if there are no messages to send or to dispatch in the context's
 * queues. */
int coap_can_exit(coap_context_t *context);

/**
 * Returns the current value of an internal tick counter. The counter counts \c
 * COAP_TICKS_PER_SECOND ticks every second.
 */
void coap_ticks(coap_tick_t *);

/**
 * Verifies that @p pdu contains no unknown critical options. Options must be
 * registered at @p ctx, using the function coap_register_option(). A basic set
 * of options is registered automatically by coap_new_context(). This function
 * returns @c 1 if @p pdu is ok, @c 0 otherwise. The given filter object @p
 * unknown will be updated with the unknown options. As only @c COAP_MAX_OPT
 * options can be signalled this way, remaining options must be examined
 * manually.
 *
 * @code
  coap_opt_filter_t f = COAP_OPT_NONE;
  coap_opt_iterator_t opt_iter;

  if (coap_option_check_critical(ctx, pdu, f) == 0) {
    coap_option_iterator_init(pdu, &opt_iter, f);

    while (coap_option_next(&opt_iter)) {
      if (opt_iter.type & 0x01) {
        ... handle unknown critical option in opt_iter ...
      }
    }
  }
   @endcode
 *
 * @param ctx      The context where all known options are registered.
 * @param pdu      The PDU to check.
 * @param unknown  The output filter that will be updated to indicate the
 *                 unknown critical options found in @p pdu.
 *
 * @return         @c 1 if everything was ok, @c 0 otherwise.
 */
int coap_option_check_critical(coap_context_t *ctx,
                               coap_pdu_t *pdu,
                               coap_opt_filter_t unknown);

/**
 * Creates a new response for given @p request with the contents of @c
 * .well-known/core. The result is NULL on error or a newly allocated PDU that
 * must be either sent with coap_sent() or released by coap_delete_pdu().
 *
 * @param context The current coap context to use.
 * @param session The CoAP session.
 * @param request The request for @c .well-known/core .
 *
 * @return        A new 2.05 response for @c .well-known/core or NULL on error.
 */
coap_pdu_t *coap_wellknown_response(coap_context_t *context,
                                    coap_session_t *session,
                                    coap_pdu_t *request);

/**
 * Calculates the initial timeout based on the session CoAP transmission
 * parameters 'ack_timeout', 'ack_random_factor', and COAP_TICKS_PER_SECOND.
 * The calculation requires 'ack_timeout' and 'ack_random_factor' to be in
 * Qx.FRAC_BITS fixed point notation, whereas the passed parameter @p r
 * is interpreted as the fractional part of a Q0.MAX_BITS random value.
 *
 * @param session session timeout is associated with
 * @param r  random value as fractional part of a Q0.MAX_BITS fixed point
 *           value
 * @return   COAP_TICKS_PER_SECOND * 'ack_timeout' *
 *           (1 + ('ack_random_factor' - 1) * r)
 */
unsigned int coap_calc_timeout(coap_session_t *session, unsigned char r);

/**
 * Function interface for joining a multicast group for listening
 *
 * @param ctx   The current context
 * @param groupname The name of the group that is to be joined for listening
 *
 * @return       0 on success, -1 on error
 */
int
coap_join_mcast_group(coap_context_t *ctx, const char *groupname);

#endif /* COAP_NET_H_ */
/*
 * option.h -- helpers for handling options in CoAP PDUs
 *
 * Copyright (C) 2010-2013 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file option.h
 * @brief Helpers for handling options in CoAP PDUs
 */

#ifndef COAP_OPTION_H_
#define COAP_OPTION_H_

#include "bits.h"
#include "pdu.h"

/**
 * Use byte-oriented access methods here because sliding a complex struct
 * coap_opt_t over the data buffer may cause bus error on certain platforms.
 */
typedef uint8_t coap_opt_t;
#define PCHAR(p) ((coap_opt_t *)(p))

/**
 * Representation of CoAP options.
 */
typedef struct {
  uint16_t delta;
  size_t length;
  const uint8_t *value;
} coap_option_t;

/**
 * Parses the option pointed to by @p opt into @p result. This function returns
 * the number of bytes that have been parsed, or @c 0 on error. An error is
 * signaled when illegal delta or length values are encountered or when option
 * parsing would result in reading past the option (i.e. beyond opt + length).
 *
 * @param opt    The beginning of the option to parse.
 * @param length The maximum length of @p opt.
 * @param result A pointer to the coap_option_t structure that is filled with
 *               actual values iff coap_opt_parse() > 0.
 * @return       The number of bytes parsed or @c 0 on error.
 */
size_t coap_opt_parse(const coap_opt_t *opt,
                      size_t length,
                      coap_option_t *result);

/**
 * Returns the size of the given option, taking into account a possible option
 * jump.
 *
 * @param opt An option jump or the beginning of the option.
 * @return    The number of bytes between @p opt and the end of the option
 *            starting at @p opt. In case of an error, this function returns
 *            @c 0 as options need at least one byte storage space.
 */
size_t coap_opt_size(const coap_opt_t *opt);

/**
 * @defgroup opt_filter Option Filters
 * API functions for access option filters
 * @{
 */

/**
 * The number of option types below 256 that can be stored in an
 * option filter. COAP_OPT_FILTER_SHORT + COAP_OPT_FILTER_LONG must be
 * at most 16. Each coap_option_filter_t object reserves
 * ((COAP_OPT_FILTER_SHORT + 1) / 2) * 2 bytes for short options.
 */
#define COAP_OPT_FILTER_SHORT 6

/**
 * The number of option types above 255 that can be stored in an
 * option filter. COAP_OPT_FILTER_SHORT + COAP_OPT_FILTER_LONG must be
 * at most 16. Each coap_option_filter_t object reserves
 * COAP_OPT_FILTER_LONG * 2 bytes for short options.
 */
#define COAP_OPT_FILTER_LONG  2

/* Ensure that COAP_OPT_FILTER_SHORT and COAP_OPT_FILTER_LONG are set
 * correctly. */
#if (COAP_OPT_FILTER_SHORT + COAP_OPT_FILTER_LONG > 16)
#error COAP_OPT_FILTER_SHORT + COAP_OPT_FILTER_LONG must be less or equal 16
#endif /* (COAP_OPT_FILTER_SHORT + COAP_OPT_FILTER_LONG > 16) */

/** The number of elements in coap_opt_filter_t. */
#define COAP_OPT_FILTER_SIZE                                        \
  (((COAP_OPT_FILTER_SHORT + 1) >> 1) + COAP_OPT_FILTER_LONG) +1

/**
 * Fixed-size vector we use for option filtering. It is large enough
 * to hold COAP_OPT_FILTER_SHORT entries with an option number between
 * 0 and 255, and COAP_OPT_FILTER_LONG entries with an option number
 * between 256 and 65535. Its internal structure is
 *
 * @code
struct {
  uint16_t mask;
  uint16_t long_opts[COAP_OPT_FILTER_LONG];
  uint8_t short_opts[COAP_OPT_FILTER_SHORT];
}
 * @endcode
 *
 * The first element contains a bit vector that indicates which fields
 * in the remaining array are used. The first COAP_OPT_FILTER_LONG
 * bits correspond to the long option types that are stored in the
 * elements from index 1 to COAP_OPT_FILTER_LONG. The next
 * COAP_OPT_FILTER_SHORT bits correspond to the short option types
 * that are stored in the elements from index COAP_OPT_FILTER_LONG + 1
 * to COAP_OPT_FILTER_LONG + COAP_OPT_FILTER_SHORT. The latter
 * elements are treated as bytes.
 */
typedef uint16_t coap_opt_filter_t[COAP_OPT_FILTER_SIZE];

/** Pre-defined filter that includes all options. */
#define COAP_OPT_ALL NULL

/**
 * Clears filter @p f.
 *
 * @param f The filter to clear.
 */
COAP_STATIC_INLINE void
coap_option_filter_clear(coap_opt_filter_t f) {
  memset(f, 0, sizeof(coap_opt_filter_t));
}

/**
 * Sets the corresponding entry for @p type in @p filter. This
 * function returns @c 1 if bit was set or @c 0 on error (i.e. when
 * the given type does not fit in the filter).
 *
 * @param filter The filter object to change.
 * @param type   The type for which the bit should be set.
 *
 * @return       @c 1 if bit was set, @c 0 otherwise.
 */
int coap_option_filter_set(coap_opt_filter_t filter, uint16_t type);

/**
 * Clears the corresponding entry for @p type in @p filter. This
 * function returns @c 1 if bit was set or @c 0 on error (i.e. when
 * the given type does not fit in the filter).
 *
 * @param filter The filter object to change.
 * @param type   The type that should be cleared from the filter.
 *
 * @return       @c 1 if bit was set, @c 0 otherwise.
 */
int coap_option_filter_unset(coap_opt_filter_t filter, uint16_t type);

/**
 * Checks if @p type is contained in @p filter. This function returns
 * @c 1 if found, @c 0 if not, or @c -1 on error (i.e. when the given
 * type does not fit in the filter).
 *
 * @param filter The filter object to search.
 * @param type   The type to search for.
 *
 * @return       @c 1 if @p type was found, @c 0 otherwise, or @c -1 on error.
 */
int coap_option_filter_get(coap_opt_filter_t filter, uint16_t type);

/**
 * Sets the corresponding bit for @p type in @p filter. This function returns @c
 * 1 if bit was set or @c -1 on error (i.e. when the given type does not fit in
 * the filter).
 *
 * @deprecated Use coap_option_filter_set() instead.
 *
 * @param filter The filter object to change.
 * @param type   The type for which the bit should be set.
 *
 * @return       @c 1 if bit was set, @c -1 otherwise.
 */
COAP_STATIC_INLINE int
coap_option_setb(coap_opt_filter_t filter, uint16_t type) {
  return coap_option_filter_set(filter, type) ? 1 : -1;
}

/**
 * Clears the corresponding bit for @p type in @p filter. This function returns
 * @c 1 if bit was cleared or @c -1 on error (i.e. when the given type does not
 * fit in the filter).
 *
 * @deprecated Use coap_option_filter_unset() instead.
 *
 * @param filter The filter object to change.
 * @param type   The type for which the bit should be cleared.
 *
 * @return       @c 1 if bit was set, @c -1 otherwise.
 */
COAP_STATIC_INLINE int
coap_option_clrb(coap_opt_filter_t filter, uint16_t type) {
  return coap_option_filter_unset(filter, type) ? 1 : -1;
}

/**
 * Gets the corresponding bit for @p type in @p filter. This function returns @c
 * 1 if the bit is set @c 0 if not, or @c -1 on error (i.e. when the given type
 * does not fit in the filter).
 *
 * @deprecated Use coap_option_filter_get() instead.
 *
 * @param filter The filter object to read bit from.
 * @param type   The type for which the bit should be read.
 *
 * @return       @c 1 if bit was set, @c 0 if not, @c -1 on error.
 */
COAP_STATIC_INLINE int
coap_option_getb(coap_opt_filter_t filter, uint16_t type) {
  return coap_option_filter_get(filter, type);
}

/**
 * Iterator to run through PDU options. This object must be
 * initialized with coap_option_iterator_init(). Call
 * coap_option_next() to walk through the list of options until
 * coap_option_next() returns @c NULL.
 *
 * @code
 * coap_opt_t *option;
 * coap_opt_iterator_t opt_iter;
 * coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);
 *
 * while ((option = coap_option_next(&opt_iter))) {
 *   ... do something with option ...
 * }
 * @endcode
 */
typedef struct {
  size_t length;                /**< remaining length of PDU */
  uint16_t type;                /**< decoded option type */
  unsigned int bad:1;           /**< iterator object is ok if not set */
  unsigned int filtered:1;      /**< denotes whether or not filter is used */
  coap_opt_t *next_option;      /**< pointer to the unparsed next option */
  coap_opt_filter_t filter;     /**< option filter */
} coap_opt_iterator_t;

/**
 * Initializes the given option iterator @p oi to point to the beginning of the
 * @p pdu's option list. This function returns @p oi on success, @c NULL
 * otherwise (i.e. when no options exist). Note that a length check on the
 * option list must be performed before coap_option_iterator_init() is called.
 *
 * @param pdu    The PDU the options of which should be walked through.
 * @param oi     An iterator object that will be initilized.
 * @param filter An optional option type filter.
 *               With @p type != @c COAP_OPT_ALL, coap_option_next()
 *               will return only options matching this bitmask.
 *               Fence-post options @c 14, @c 28, @c 42, ... are always
 *               skipped.
 *
 * @return       The iterator object @p oi on success, @c NULL otherwise.
 */
coap_opt_iterator_t *coap_option_iterator_init(const coap_pdu_t *pdu,
                                               coap_opt_iterator_t *oi,
                                               const coap_opt_filter_t filter);

/**
 * Updates the iterator @p oi to point to the next option. This function returns
 * a pointer to that option or @c NULL if no more options exist. The contents of
 * @p oi will be updated. In particular, @c oi->n specifies the current option's
 * ordinal number (counted from @c 1), @c oi->type is the option's type code,
 * and @c oi->option points to the beginning of the current option itself. When
 * advanced past the last option, @c oi->option will be @c NULL.
 *
 * Note that options are skipped whose corresponding bits in the filter
 * specified with coap_option_iterator_init() are @c 0. Options with type codes
 * that do not fit in this filter hence will always be returned.
 *
 * @param oi The option iterator to update.
 *
 * @return   The next option or @c NULL if no more options exist.
 */
coap_opt_t *coap_option_next(coap_opt_iterator_t *oi);

/**
 * Retrieves the first option of type @p type from @p pdu. @p oi must point to a
 * coap_opt_iterator_t object that will be initialized by this function to
 * filter only options with code @p type. This function returns the first option
 * with this type, or @c NULL if not found.
 *
 * @param pdu  The PDU to parse for options.
 * @param type The option type code to search for.
 * @param oi   An iterator object to use.
 *
 * @return     A pointer to the first option of type @p type, or @c NULL if
 *             not found.
 */
coap_opt_t *coap_check_option(coap_pdu_t *pdu,
                              uint16_t type,
                              coap_opt_iterator_t *oi);

/**
 * Encodes the given delta and length values into @p opt. This function returns
 * the number of bytes that were required to encode @p delta and @p length or @c
 * 0 on error. Note that the result indicates by how many bytes @p opt must be
 * advanced to encode the option value.
 *
 * @param opt    The option buffer space where @p delta and @p length are
 *               written.
 * @param maxlen The maximum length of @p opt.
 * @param delta  The actual delta value to encode.
 * @param length The actual length value to encode.
 *
 * @return       The number of bytes used or @c 0 on error.
 */
size_t coap_opt_setheader(coap_opt_t *opt,
                          size_t maxlen,
                          uint16_t delta,
                          size_t length);

/**
 * Compute storage bytes needed for an option with given @p delta and
 * @p length
 *
 * @param delta  The option delta.
 * @param length The option length.
 *
 * @return       The number of bytes required to encode this option.
 */
size_t coap_opt_encode_size(uint16_t delta, size_t length);

/**
 * Encodes option with given @p delta into @p opt. This function returns the
 * number of bytes written to @p opt or @c 0 on error. This happens especially
 * when @p opt does not provide sufficient space to store the option value,
 * delta, and option jumps when required.
 *
 * @param opt    The option buffer space where @p val is written.
 * @param n      Maximum length of @p opt.
 * @param delta  The option delta.
 * @param val    The option value to copy into @p opt.
 * @param length The actual length of @p val.
 *
 * @return       The number of bytes that have been written to @p opt or @c 0 on
 *               error. The return value will always be less than @p n.
 */
size_t coap_opt_encode(coap_opt_t *opt,
                       size_t n,
                       uint16_t delta,
                       const uint8_t *val,
                       size_t length);

/**
 * Decodes the delta value of the next option. This function returns the number
 * of bytes read or @c 0 on error. The caller of this function must ensure that
 * it does not read over the boundaries of @p opt (e.g. by calling
 * coap_opt_check_delta().
 *
 * @param opt The option to examine.
 *
 * @return    The number of bytes read or @c 0 on error.
 */
uint16_t coap_opt_delta(const coap_opt_t *opt);

/**
 * Returns the length of the given option. @p opt must point to an option jump
 * or the beginning of the option. This function returns @c 0 when @p opt is not
 * an option or the actual length of @p opt (which can be @c 0 as well).
 *
 * @note {The rationale for using @c 0 in case of an error is that in most
 * contexts, the result of this function is used to skip the next
 * coap_opt_length() bytes.}
 *
 * @param opt  The option whose length should be returned.
 *
 * @return     The option's length or @c 0 when undefined.
 */
uint16_t coap_opt_length(const coap_opt_t *opt);

/**
 * Returns a pointer to the value of the given option. @p opt must point to an
 * option jump or the beginning of the option. This function returns @c NULL if
 * @p opt is not a valid option.
 *
 * @param opt The option whose value should be returned.
 *
 * @return    A pointer to the option value or @c NULL on error.
 */
const uint8_t *coap_opt_value(const coap_opt_t *opt);

/** @} */

/**
 * Representation of chained list of CoAP options to install.
 *
 * @code
 * coap_optlist_t *optlist_chain = NULL;
 * coap_pdu_t *pdu = coap_new_pdu(session);
 *
 * ... other set up code ...
 * coap_insert_optlist(&optlist_chain, coap_new_optlist(COAP_OPTION_OBSERVE,
 *                    COAP_OBSERVE_ESTABLISH, NULL));
 *
 * coap_add_optlist_pdu(pdu, &optlist_chain);
 * ... other code ...
 * coap_delete_optlist(optlist_chain);
 * @endcode
 */
typedef struct coap_optlist_t {
  struct coap_optlist_t *next;  /**< next entry in the optlist chain */
  uint16_t number;              /**< the option number (no delta coding) */
  size_t length;                /**< the option value length */
  uint8_t *data;                /**< the option data */
} coap_optlist_t;

/**
 * Create a new optlist entry.
 *
 * @param number    The option number (COAP_OPTION_*)
 * @param length    The option length
 * @param data      The option value data
 *
 * @return          A pointer to the new optlist entry, or @c NULL if error
 */
coap_optlist_t *coap_new_optlist(uint16_t number,
                                 size_t length,
                                 const uint8_t *data);

/**
 * The current optlist of @p optlist_chain is first sorted (as per RFC7272
 * ordering requirements) and then added to the @p pdu.
 *
 * @param pdu  The pdu to add the options to from the chain list
 * @param optlist_chain The chained list of optlist to add to the pdu
 *
 * @return     @c 1 if succesful or @c 0 if failure;
 */
int coap_add_optlist_pdu(coap_pdu_t *pdu, coap_optlist_t** optlist_chain);

/**
 * Adds @p optlist to the given @p optlist_chain. The optlist_chain variable
 * be set to NULL before the initial call to coap_insert_optlist().
 * The optlist_chain will need to be deleted using coap_delete_optlist()
 * when no longer required.
 *
 * @param optlist_chain The chain to add optlist to
 * @param optlist  The optlist to add to the queue
 *
 * @return         @c 1 if successful, @c 0 otherwise.
 */
int coap_insert_optlist(coap_optlist_t **optlist_chain,
                        coap_optlist_t *optlist);

/**
 * Removes all entries from the @p optlist_chain, freeing off their
 * memory usage.
 *
 * @param optlist_chain The optlist chain to remove all the entries from
 */
void coap_delete_optlist(coap_optlist_t *optlist_chain);

#endif /* COAP_OPTION_H_ */
/*
 * pdu.h -- CoAP message structure
 *
 * Copyright (C) 2010-2014 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file pdu.h
 * @brief Pre-defined constants that reflect defaults for CoAP
 */

#ifndef COAP_PDU_H_
#define COAP_PDU_H_

#include "uri.h"

struct coap_session_t;

#ifdef WITH_LWIP
#include <lwip/pbuf.h>
#endif

#include <stdint.h>

#define COAP_DEFAULT_PORT      5683 /* CoAP default UDP/TCP port */
#define COAPS_DEFAULT_PORT     5684 /* CoAP default UDP/TCP port for secure transmission */
#define COAP_DEFAULT_MAX_AGE     60 /* default maximum object lifetime in seconds */
#ifndef COAP_DEFAULT_MTU
#define COAP_DEFAULT_MTU       1152
#endif /* COAP_DEFAULT_MTU */

/* TCP Message format constants, do not modify */
#define COAP_MESSAGE_SIZE_OFFSET_TCP8 13
#define COAP_MESSAGE_SIZE_OFFSET_TCP16 269 /* 13 + 256 */
#define COAP_MESSAGE_SIZE_OFFSET_TCP32 65805 /* 269 + 65536 */

/* Derived message size limits */
#define COAP_MAX_MESSAGE_SIZE_TCP0 (COAP_MESSAGE_SIZE_OFFSET_TCP8-1) /* 12 */
#define COAP_MAX_MESSAGE_SIZE_TCP8 (COAP_MESSAGE_SIZE_OFFSET_TCP16-1) /* 268 */
#define COAP_MAX_MESSAGE_SIZE_TCP16 (COAP_MESSAGE_SIZE_OFFSET_TCP32-1) /* 65804 */
#define COAP_MAX_MESSAGE_SIZE_TCP32 (COAP_MESSAGE_SIZE_OFFSET_TCP32+0xFFFFFFFF)

#ifndef COAP_DEFAULT_MAX_PDU_RX_SIZE
#if defined(WITH_CONTIKI) || defined(WITH_LWIP)
#define COAP_DEFAULT_MAX_PDU_RX_SIZE (COAP_MAX_MESSAGE_SIZE_TCP16+4)
#else
/* 8 MiB max-message-size plus some space for options */
#define COAP_DEFAULT_MAX_PDU_RX_SIZE (8*1024*1024+256)
#endif
#endif /* COAP_DEFAULT_MAX_PDU_RX_SIZE */

#ifndef COAP_DEBUG_BUF_SIZE
#if defined(WITH_CONTIKI) || defined(WITH_LWIP)
#define COAP_DEBUG_BUF_SIZE 128
#else /* defined(WITH_CONTIKI) || defined(WITH_LWIP) */
/* 1024 derived from RFC7252 4.6.  Message Size max payload */
#define COAP_DEBUG_BUF_SIZE (8 + 1024 * 2)
#endif /* defined(WITH_CONTIKI) || defined(WITH_LWIP) */
#endif /* COAP_DEBUG_BUF_SIZE */

#define COAP_DEFAULT_VERSION      1 /* version of CoAP supported */
#define COAP_DEFAULT_SCHEME  "coap" /* the default scheme for CoAP URIs */

/** well-known resources URI */
#define COAP_DEFAULT_URI_WELLKNOWN ".well-known/core"

/* CoAP message types */

#define COAP_MESSAGE_CON       0 /* confirmable message (requires ACK/RST) */
#define COAP_MESSAGE_NON       1 /* non-confirmable message (one-shot message) */
#define COAP_MESSAGE_ACK       2 /* used to acknowledge confirmable messages */
#define COAP_MESSAGE_RST       3 /* indicates error in received messages */

/* CoAP request methods */

#define COAP_REQUEST_GET       1
#define COAP_REQUEST_POST      2
#define COAP_REQUEST_PUT       3
#define COAP_REQUEST_DELETE    4
#define COAP_REQUEST_FETCH     5 /* RFC 8132 */
#define COAP_REQUEST_PATCH     6 /* RFC 8132 */
#define COAP_REQUEST_IPATCH    7 /* RFC 8132 */

/*
 * CoAP option types (be sure to update coap_option_check_critical() when
 * adding options
 */

#define COAP_OPTION_IF_MATCH        1 /* C, opaque, 0-8 B, (none) */
#define COAP_OPTION_URI_HOST        3 /* C, String, 1-255 B, destination address */
#define COAP_OPTION_ETAG            4 /* E, opaque, 1-8 B, (none) */
#define COAP_OPTION_IF_NONE_MATCH   5 /* empty, 0 B, (none) */
#define COAP_OPTION_URI_PORT        7 /* C, uint, 0-2 B, destination port */
#define COAP_OPTION_LOCATION_PATH   8 /* E, String, 0-255 B, - */
#define COAP_OPTION_URI_PATH       11 /* C, String, 0-255 B, (none) */
#define COAP_OPTION_CONTENT_FORMAT 12 /* E, uint, 0-2 B, (none) */
#define COAP_OPTION_CONTENT_TYPE COAP_OPTION_CONTENT_FORMAT
#define COAP_OPTION_MAXAGE         14 /* E, uint, 0--4 B, 60 Seconds */
#define COAP_OPTION_URI_QUERY      15 /* C, String, 1-255 B, (none) */
#define COAP_OPTION_ACCEPT         17 /* C, uint,   0-2 B, (none) */
#define COAP_OPTION_LOCATION_QUERY 20 /* E, String,   0-255 B, (none) */
#define COAP_OPTION_SIZE2          28 /* E, uint, 0-4 B, (none) */
#define COAP_OPTION_PROXY_URI      35 /* C, String, 1-1034 B, (none) */
#define COAP_OPTION_PROXY_SCHEME   39 /* C, String, 1-255 B, (none) */
#define COAP_OPTION_SIZE1          60 /* E, uint, 0-4 B, (none) */

/* option types from RFC 7641 */

#define COAP_OPTION_OBSERVE         6 /* E, empty/uint, 0 B/0-3 B, (none) */
#define COAP_OPTION_SUBSCRIPTION  COAP_OPTION_OBSERVE

/* selected option types from RFC 7959 */

#define COAP_OPTION_BLOCK2         23 /* C, uint, 0--3 B, (none) */
#define COAP_OPTION_BLOCK1         27 /* C, uint, 0--3 B, (none) */

/* selected option types from RFC 7967 */

#define COAP_OPTION_NORESPONSE    258 /* N, uint, 0--1 B, 0 */

#define COAP_MAX_OPT            65535 /**< the highest option number we know */

/* CoAP result codes (HTTP-Code / 100 * 40 + HTTP-Code % 100) */

/* As of draft-ietf-core-coap-04, response codes are encoded to base
 * 32, i.e.  the three upper bits determine the response class while
 * the remaining five fine-grained information specific to that class.
 */
#define COAP_RESPONSE_CODE(N) (((N)/100 << 5) | (N)%100)

/* Determines the class of response code C */
#define COAP_RESPONSE_CLASS(C) (((C) >> 5) & 0xFF)

#ifndef SHORT_ERROR_RESPONSE
/**
 * Returns a human-readable response phrase for the specified CoAP response @p
 * code. This function returns @c NULL if not found.
 *
 * @param code The response code for which the literal phrase should be
 *             retrieved.
 *
 * @return     A zero-terminated string describing the error, or @c NULL if not
 *             found.
 */
const char *coap_response_phrase(unsigned char code);

#define COAP_ERROR_PHRASE_LENGTH   32 /**< maximum length of error phrase */

#else
#define coap_response_phrase(x) ((char *)NULL)

#define COAP_ERROR_PHRASE_LENGTH    0 /**< maximum length of error phrase */
#endif /* SHORT_ERROR_RESPONSE */

/* The following definitions exist for backwards compatibility */
#if 0 /* this does not exist any more */
#define COAP_RESPONSE_100      40 /* 100 Continue */
#endif
#define COAP_RESPONSE_200      COAP_RESPONSE_CODE(200)  /* 2.00 OK */
#define COAP_RESPONSE_201      COAP_RESPONSE_CODE(201)  /* 2.01 Created */
#define COAP_RESPONSE_304      COAP_RESPONSE_CODE(203)  /* 2.03 Valid */
#define COAP_RESPONSE_400      COAP_RESPONSE_CODE(400)  /* 4.00 Bad Request */
#define COAP_RESPONSE_404      COAP_RESPONSE_CODE(404)  /* 4.04 Not Found */
#define COAP_RESPONSE_405      COAP_RESPONSE_CODE(405)  /* 4.05 Method Not Allowed */
#define COAP_RESPONSE_415      COAP_RESPONSE_CODE(415)  /* 4.15 Unsupported Media Type */
#define COAP_RESPONSE_500      COAP_RESPONSE_CODE(500)  /* 5.00 Internal Server Error */
#define COAP_RESPONSE_501      COAP_RESPONSE_CODE(501)  /* 5.01 Not Implemented */
#define COAP_RESPONSE_503      COAP_RESPONSE_CODE(503)  /* 5.03 Service Unavailable */
#define COAP_RESPONSE_504      COAP_RESPONSE_CODE(504)  /* 5.04 Gateway Timeout */
#if 0  /* these response codes do not have a valid code any more */
#  define COAP_RESPONSE_X_240    240   /* Token Option required by server */
#  define COAP_RESPONSE_X_241    241   /* Uri-Authority Option required by server */
#endif
#define COAP_RESPONSE_X_242    COAP_RESPONSE_CODE(402)  /* Critical Option not supported */

#define COAP_SIGNALING_CODE(N) (((N)/100 << 5) | (N)%100)
#define COAP_SIGNALING_CSM     COAP_SIGNALING_CODE(701)
#define COAP_SIGNALING_PING    COAP_SIGNALING_CODE(702)
#define COAP_SIGNALING_PONG    COAP_SIGNALING_CODE(703)
#define COAP_SIGNALING_RELEASE COAP_SIGNALING_CODE(704)
#define COAP_SIGNALING_ABORT   COAP_SIGNALING_CODE(705)

/* Applies to COAP_SIGNALING_CSM */
#define COAP_SIGNALING_OPTION_MAX_MESSAGE_SIZE 2
#define COAP_SIGNALING_OPTION_BLOCK_WISE_TRANSFER 4
/* Applies to COAP_SIGNALING_PING / COAP_SIGNALING_PONG */
#define COAP_SIGNALING_OPTION_CUSTODY 2
/* Applies to COAP_SIGNALING_RELEASE */
#define COAP_SIGNALING_OPTION_ALTERNATIVE_ADDRESS 2
#define COAP_SIGNALING_OPTION_HOLD_OFF 4
/* Applies to COAP_SIGNALING_ABORT */
#define COAP_SIGNALING_OPTION_BAD_CSM_OPTION 2

/* CoAP media type encoding */

#define COAP_MEDIATYPE_TEXT_PLAIN                 0 /* text/plain (UTF-8) */
#define COAP_MEDIATYPE_APPLICATION_LINK_FORMAT   40 /* application/link-format */
#define COAP_MEDIATYPE_APPLICATION_XML           41 /* application/xml */
#define COAP_MEDIATYPE_APPLICATION_OCTET_STREAM  42 /* application/octet-stream */
#define COAP_MEDIATYPE_APPLICATION_RDF_XML       43 /* application/rdf+xml */
#define COAP_MEDIATYPE_APPLICATION_EXI           47 /* application/exi  */
#define COAP_MEDIATYPE_APPLICATION_JSON          50 /* application/json  */
#define COAP_MEDIATYPE_APPLICATION_CBOR          60 /* application/cbor  */

/* Content formats from RFC 8152 */
#define COAP_MEDIATYPE_APPLICATION_COSE_SIGN     98 /* application/cose; cose-type="cose-sign"     */
#define COAP_MEDIATYPE_APPLICATION_COSE_SIGN1    18 /* application/cose; cose-type="cose-sign1"    */
#define COAP_MEDIATYPE_APPLICATION_COSE_ENCRYPT  96 /* application/cose; cose-type="cose-encrypt"  */
#define COAP_MEDIATYPE_APPLICATION_COSE_ENCRYPT0 16 /* application/cose; cose-type="cose-encrypt0" */
#define COAP_MEDIATYPE_APPLICATION_COSE_MAC      97 /* application/cose; cose-type="cose-mac"      */
#define COAP_MEDIATYPE_APPLICATION_COSE_MAC0     17 /* application/cose; cose-type="cose-mac0"     */

#define COAP_MEDIATYPE_APPLICATION_COSE_KEY     101 /* application/cose-key  */
#define COAP_MEDIATYPE_APPLICATION_COSE_KEY_SET 102 /* application/cose-key-set  */

/* Content formats from RFC 8428 */
#define COAP_MEDIATYPE_APPLICATION_SENML_JSON   110 /* application/senml+json  */
#define COAP_MEDIATYPE_APPLICATION_SENSML_JSON  111 /* application/sensml+json */
#define COAP_MEDIATYPE_APPLICATION_SENML_CBOR   112 /* application/senml+cbor  */
#define COAP_MEDIATYPE_APPLICATION_SENSML_CBOR  113 /* application/sensml+cbor */
#define COAP_MEDIATYPE_APPLICATION_SENML_EXI    114 /* application/senml-exi   */
#define COAP_MEDIATYPE_APPLICATION_SENSML_EXI   115 /* application/sensml-exi  */
#define COAP_MEDIATYPE_APPLICATION_SENML_XML    310 /* application/senml+xml   */
#define COAP_MEDIATYPE_APPLICATION_SENSML_XML   311 /* application/sensml+xml  */

/* Note that identifiers for registered media types are in the range 0-65535. We
 * use an unallocated type here and hope for the best. */
#define COAP_MEDIATYPE_ANY                         0xff /* any media type */

/**
 * coap_tid_t is used to store CoAP transaction id, i.e. a hash value
 * built from the remote transport address and the message id of a
 * CoAP PDU.  Valid transaction ids are greater or equal zero.
 */
typedef int coap_tid_t;

/** Indicates an invalid transaction id. */
#define COAP_INVALID_TID -1

/**
 * Indicates that a response is suppressed. This will occur for error
 * responses if the request was received via IP multicast.
 */
#define COAP_DROPPED_RESPONSE -2

#define COAP_PDU_DELAYED -3

#define COAP_OPT_LONG 0x0F      /* OC == 0b1111 indicates that the option list
                                 * in a CoAP message is limited by 0b11110000
                                 * marker */

#define COAP_OPT_END 0xF0       /* end marker */

#define COAP_PAYLOAD_START 0xFF /* payload marker */

/**
 * @deprecated Use coap_optlist_t instead.
 *
 * Structures for more convenient handling of options. (To be used with ordered
 * coap_list_t.) The option's data will be added to the end of the coap_option
 * structure (see macro COAP_OPTION_DATA).
 */
COAP_DEPRECATED typedef struct {
  uint16_t key;           /* the option key (no delta coding) */
  unsigned int length;
} coap_option;

#define COAP_OPTION_KEY(option) (option).key
#define COAP_OPTION_LENGTH(option) (option).length
#define COAP_OPTION_DATA(option) ((unsigned char *)&(option) + sizeof(coap_option))

/**
 * structure for CoAP PDUs
 * token, if any, follows the fixed size header, then options until
 * payload marker (0xff), then the payload if stored inline.
 * Memory layout is:
 * <---header--->|<---token---><---options--->0xff<---payload--->
 * header is addressed with a negative offset to token, its maximum size is
 * max_hdr_size.
 * options starts at token + token_length
 * payload starts at data, its length is used_size - (data - token)
 */

typedef struct coap_pdu_t {
  uint8_t type;             /**< message type */
  uint8_t code;             /**< request method (value 1--10) or response code (value 40-255) */
  uint8_t max_hdr_size;     /**< space reserved for protocol-specific header */
  uint8_t hdr_size;         /**< actaul size used for protocol-specific header */
  uint8_t token_length;     /**< length of Token */
  uint16_t tid;             /**< transaction id, if any, in regular host byte order */
  uint16_t max_delta;       /**< highest option number */
  size_t alloc_size;        /**< allocated storage for token, options and payload */
  size_t used_size;         /**< used bytes of storage for token, options and payload */
  size_t max_size;          /**< maximum size for token, options and payload, or zero for variable size pdu */
  uint8_t *token;           /**< first byte of token, if any, or options */
  uint8_t *data;            /**< first byte of payload, if any */
#ifdef WITH_LWIP
  struct pbuf *pbuf;        /**< lwIP PBUF. The package data will always reside
                             *   inside the pbuf's payload, but this pointer
                             *   has to be kept because no exact offset can be
                             *   given. This field must not be accessed from
                             *   outside, because the pbuf's reference count
                             *   is checked to be 1 when the pbuf is assigned
                             *   to the pdu, and the pbuf stays exclusive to
                             *   this pdu. */
#endif
} coap_pdu_t;

#define COAP_PDU_IS_EMPTY(pdu)     ((pdu)->code == 0)
#define COAP_PDU_IS_REQUEST(pdu)   (!COAP_PDU_IS_EMPTY(pdu) && (pdu)->code < 32)
#define COAP_PDU_IS_RESPONSE(pdu)  ((pdu)->code >= 64 && (pdu)->code < 224)
#define COAP_PDU_IS_SIGNALING(pdu) ((pdu)->code >= 224)

#define COAP_PDU_MAX_UDP_HEADER_SIZE 4
#define COAP_PDU_MAX_TCP_HEADER_SIZE 6

#ifdef WITH_LWIP
/**
 * Creates a CoAP PDU from an lwIP @p pbuf, whose reference is passed on to this
 * function.
 *
 * The pbuf is checked for being contiguous, and for having only one reference.
 * The reference is stored in the PDU and will be freed when the PDU is freed.
 *
 * (For now, these are fatal errors; in future, a new pbuf might be allocated,
 * the data copied and the passed pbuf freed).
 *
 * This behaves like coap_pdu_init(0, 0, 0, pbuf->tot_len), and afterwards
 * copying the contents of the pbuf to the pdu.
 *
 * @return A pointer to the new PDU object or @c NULL on error.
 */
coap_pdu_t * coap_pdu_from_pbuf(struct pbuf *pbuf);
#endif

typedef uint8_t coap_proto_t;
/**
* coap_proto_t values
*/
#define COAP_PROTO_NONE         0
#define COAP_PROTO_UDP          1
#define COAP_PROTO_DTLS         2
#define COAP_PROTO_TCP          3
#define COAP_PROTO_TLS          4

/**
 * Creates a new CoAP PDU with at least enough storage space for the given
 * @p size maximum message size. The function returns a pointer to the
 * node coap_pdu_t object on success, or @c NULL on error. The storage allocated
 * for the result must be released with coap_delete_pdu() if coap_send() is not
 * called.
 *
 * @param type The type of the PDU (one of COAP_MESSAGE_CON, COAP_MESSAGE_NON,
 *             COAP_MESSAGE_ACK, COAP_MESSAGE_RST).
 * @param code The message code.
 * @param tid  The transcation id to set or 0 if unknown / not applicable.
 * @param size The maximum allowed number of byte for the message.
 * @return     A pointer to the new PDU object or @c NULL on error.
 */
coap_pdu_t *
coap_pdu_init(uint8_t type, uint8_t code, uint16_t tid, size_t size);

/**
 * Dynamically grows the size of @p pdu to @p new_size. The new size
 * must not exceed the PDU's configure maximum size. On success, this
 * function returns 1, otherwise 0.
 *
 * @param pdu      The PDU to resize.
 * @param new_size The new size in bytes.
 * @return         1 if the operation succeeded, 0 otherwise.
 */
int coap_pdu_resize(coap_pdu_t *pdu, size_t new_size);

/**
 * Clears any contents from @p pdu and resets @c used_size,
 * and @c data pointers. @c max_size is set to @p size, any
 * other field is set to @c 0. Note that @p pdu must be a valid
 * pointer to a coap_pdu_t object created e.g. by coap_pdu_init().
 */
void coap_pdu_clear(coap_pdu_t *pdu, size_t size);

/**
 * Creates a new CoAP PDU.
 */
coap_pdu_t *coap_new_pdu(const struct coap_session_t *session);

/**
 * Dispose of an CoAP PDU and frees associated storage.
 * Not that in general you should not call this function directly.
 * When a PDU is sent with coap_send(), coap_delete_pdu() will be
 * called automatically for you.
 */

void coap_delete_pdu(coap_pdu_t *);

/**
* Interprets @p data to determine the number of bytes in the header.
* This function returns @c 0 on error or a number greater than zero on success.
*
* @param proto  Session's protocol
* @param data   The first byte of raw data to parse as CoAP PDU.
*
* @return       A value greater than zero on success or @c 0 on error.
*/
size_t coap_pdu_parse_header_size(coap_proto_t proto,
                                 const uint8_t *data);

/**
 * Parses @p data to extract the message size.
 * @p length must be at least coap_pdu_parse_header_size(proto, data).
 * This function returns @c 0 on error or a number greater than zero on success.
 *
 * @param proto  Session's protocol
 * @param data   The raw data to parse as CoAP PDU.
 * @param length The actual size of @p data.
 *
 * @return       A value greater than zero on success or @c 0 on error.
 */
size_t coap_pdu_parse_size(coap_proto_t proto,
                           const uint8_t *data,
                           size_t length);

/**
 * Decode the protocol specific header for the specified PDU.
 * @param pdu A newly received PDU.
 * @param proto The target wire protocol.
 * @return 1 for success or 0 on error.
 */

int coap_pdu_parse_header(coap_pdu_t *pdu, coap_proto_t proto);

/**
 * Verify consistency in the given CoAP PDU structure and locate the data.
 * This function returns @c 0 on error or a number greater than zero on
 * success.
 * This function only parses the token and options, up to the payload start
 * marker.
 *
 * @param pdu     The PDU structure to.
 *
 * @return       1 on success or @c 0 on error.
 */
int coap_pdu_parse_opt(coap_pdu_t *pdu);

/**
* Parses @p data into the CoAP PDU structure given in @p result.
* The target pdu must be large enough to
* This function returns @c 0 on error or a number greater than zero on success.
*
* @param proto   Session's protocol
* @param data    The raw data to parse as CoAP PDU.
* @param length  The actual size of @p data.
* @param pdu     The PDU structure to fill. Note that the structure must
*                provide space to hold at least the token and options
*                part of the message.
*
* @return       1 on success or @c 0 on error.
*/
int coap_pdu_parse(coap_proto_t proto,
                   const uint8_t *data,
                   size_t length,
                   coap_pdu_t *pdu);
/**
 * Adds token of length @p len to @p pdu.
 * Adding the token destroys any following contents of the pdu. Hence options
 * and data must be added after coap_add_token() has been called. In @p pdu,
 * length is set to @p len + @c 4, and max_delta is set to @c 0. This function
 * returns @c 0 on error or a value greater than zero on success.
 *
 * @param pdu  The PDU where the token is to be added.
 * @param len  The length of the new token.
 * @param data The token to add.
 *
 * @return     A value greater than zero on success, or @c 0 on error.
 */
int coap_add_token(coap_pdu_t *pdu,
                  size_t len,
                  const uint8_t *data);

/**
 * Adds option of given type to pdu that is passed as first
 * parameter.
 * coap_add_option() destroys the PDU's data, so coap_add_data() must be called
 * after all options have been added. As coap_add_token() destroys the options
 * following the token, the token must be added before coap_add_option() is
 * called. This function returns the number of bytes written or @c 0 on error.
 */
size_t coap_add_option(coap_pdu_t *pdu,
                       uint16_t type,
                       size_t len,
                       const uint8_t *data);

/**
 * Adds option of given type to pdu that is passed as first parameter, but does
 * not write a value. It works like coap_add_option with respect to calling
 * sequence (i.e. after token and before data). This function returns a memory
 * address to which the option data has to be written before the PDU can be
 * sent, or @c NULL on error.
 */
uint8_t *coap_add_option_later(coap_pdu_t *pdu,
                               uint16_t type,
                               size_t len);

/**
 * Adds given data to the pdu that is passed as first parameter. Note that the
 * PDU's data is destroyed by coap_add_option(). coap_add_data() must be called
 * only once per PDU, otherwise the result is undefined.
 */
int coap_add_data(coap_pdu_t *pdu,
                  size_t len,
                  const uint8_t *data);

/**
 * Adds given data to the pdu that is passed as first parameter but does not
 * copyt it. Note that the PDU's data is destroyed by coap_add_option().
 * coap_add_data() must be have been called once for this PDU, otherwise the
 * result is undefined.
 * The actual data must be copied at the returned location.
 */
uint8_t *coap_add_data_after(coap_pdu_t *pdu, size_t len);

/**
 * Retrieves the length and data pointer of specified PDU. Returns 0 on error or
 * 1 if *len and *data have correct values. Note that these values are destroyed
 * with the pdu.
 */
int coap_get_data(const coap_pdu_t *pdu,
                  size_t *len,
                  uint8_t **data);

/**
 * Compose the protocol specific header for the specified PDU.
 * @param pdu A newly composed PDU.
 * @param proto The target wire protocol.
 * @return Number of header bytes prepended before pdu->token or 0 on error.
 */

size_t coap_pdu_encode_header(coap_pdu_t *pdu, coap_proto_t proto);

#endif /* COAP_PDU_H_ */
/*
 * prng.h -- Pseudo Random Numbers
 *
 * Copyright (C) 2010-2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file prng.h
 * @brief Pseudo Random Numbers
 */

#ifndef COAP_PRNG_H_
#define COAP_PRNG_H_

/**
 * @defgroup prng Pseudo Random Numbers
 * API functions for gerating pseudo random numbers
 * @{
 */

#if defined(WITH_CONTIKI)
#include <string.h>

/**
 * Fills \p buf with \p len random bytes. This is the default implementation for
 * prng(). You might want to change prng() to use a better PRNG on your specific
 * platform.
 */
COAP_STATIC_INLINE int
contiki_prng_impl(unsigned char *buf, size_t len) {
  uint16_t v = random_rand();
  while (len > sizeof(v)) {
    memcpy(buf, &v, sizeof(v));
    len -= sizeof(v);
    buf += sizeof(v);
    v = random_rand();
  }

  memcpy(buf, &v, len);
  return 1;
}

#define prng(Buf,Length) contiki_prng_impl((Buf), (Length))
#define prng_init(Value) random_init((uint16_t)(Value))
#elif defined(WITH_LWIP) && defined(LWIP_RAND)
COAP_STATIC_INLINE int
lwip_prng_impl(unsigned char *buf, size_t len) {
  u32_t v = LWIP_RAND();
  while (len > sizeof(v)) {
    memcpy(buf, &v, sizeof(v));
    len -= sizeof(v);
    buf += sizeof(v);
    v = LWIP_RAND();
  }

  memcpy(buf, &v, len);
  return 1;
}

#define prng(Buf,Length) lwip_prng_impl((Buf), (Length))
#define prng_init(Value)
#elif defined(_WIN32)
#define prng_init(Value)
errno_t __cdecl rand_s( _Out_ unsigned int* _RandomValue );
 /**
 * Fills \p buf with \p len random bytes. This is the default implementation for
 * prng(). You might want to change prng() to use a better PRNG on your specific
 * platform.
 */
COAP_STATIC_INLINE int
coap_prng_impl( unsigned char *buf, size_t len ) {
        while ( len != 0 ) {
                uint32_t r = 0;
                size_t i;
                if ( rand_s( &r ) != 0 )
                        return 0;
                for ( i = 0; i < len && i < 4; i++ ) {
                        *buf++ = (uint8_t)r;
                        r >>= 8;
                }
                len -= i;
        }
        return 1;
}

#else
#include <stdlib.h>

 /**
 * Fills \p buf with \p len random bytes. This is the default implementation for
 * prng(). You might want to change prng() to use a better PRNG on your specific
 * platform.
 */
COAP_STATIC_INLINE int
coap_prng_impl( unsigned char *buf, size_t len ) {
        while ( len-- )
                *buf++ = rand() & 0xFF;
        return 1;
}
#endif


#ifndef prng
/**
 * Fills \p Buf with \p Length bytes of random data.
 *
 * @hideinitializer
 */
#define prng(Buf,Length) coap_prng_impl((Buf), (Length))
#endif

#ifndef prng_init
/**
 * Called to set the PRNG seed. You may want to re-define this to allow for a
 * better PRNG.
 *
 * @hideinitializer
 */
#define prng_init(Value) srand((unsigned long)(Value))
#endif

/** @} */

#endif /* COAP_PRNG_H_ */
/*
 * resource.h -- generic resource handling
 *
 * Copyright (C) 2010,2011,2014,2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file resource.h
 * @brief Generic resource handling
 */

#ifndef COAP_RESOURCE_H_
#define COAP_RESOURCE_H_

# include <assert.h>

#ifndef COAP_RESOURCE_CHECK_TIME
/** The interval in seconds to check if resources have changed. */
#define COAP_RESOURCE_CHECK_TIME 2
#endif /* COAP_RESOURCE_CHECK_TIME */

#include "uthash.h"
#include "async.h"
#include "str.h"
#include "pdu.h"
#include "net.h"
#include "subscribe.h"

/**
 * Definition of message handler function (@sa coap_resource_t).
 */
typedef void (*coap_method_handler_t)
  (coap_context_t  *,
   struct coap_resource_t *,
   coap_session_t *,
   coap_pdu_t *,
   coap_binary_t * /* token */,
   coap_string_t * /* query string */,
   coap_pdu_t * /* response */);

#define COAP_ATTR_FLAGS_RELEASE_NAME  0x1
#define COAP_ATTR_FLAGS_RELEASE_VALUE 0x2

typedef struct coap_attr_t {
  struct coap_attr_t *next;
  coap_str_const_t *name;
  coap_str_const_t *value;
  int flags;
} coap_attr_t;

/** The URI passed to coap_resource_init() is free'd by coap_delete_resource(). */
#define COAP_RESOURCE_FLAGS_RELEASE_URI 0x1

/**
 * Notifications will be sent non-confirmable by default. RFC 7641 Section 4.5
 * https://tools.ietf.org/html/rfc7641#section-4.5
 */
#define COAP_RESOURCE_FLAGS_NOTIFY_NON  0x0

/**
 * Notifications will be sent confirmable by default. RFC 7641 Section 4.5
 * https://tools.ietf.org/html/rfc7641#section-4.5
 */
#define COAP_RESOURCE_FLAGS_NOTIFY_CON  0x2

typedef struct coap_resource_t {
  unsigned int dirty:1;          /**< set to 1 if resource has changed */
  unsigned int partiallydirty:1; /**< set to 1 if some subscribers have not yet
                                  *   been notified of the last change */
  unsigned int observable:1;     /**< can be observed */
  unsigned int cacheable:1;      /**< can be cached */
  unsigned int is_unknown:1;     /**< resource created for unknown handler */

  /**
   * Used to store handlers for the seven coap methods @c GET, @c POST, @c PUT,
   * @c DELETE, @c FETCH, @c PATCH and @c IPATCH.
   * coap_dispatch() will pass incoming requests to the handler
   * that corresponds to its request method or generate a 4.05 response if no
   * handler is available.
   */
  coap_method_handler_t handler[7];

  UT_hash_handle hh;

  coap_attr_t *link_attr; /**< attributes to be included with the link format */
  coap_subscription_t *subscribers;  /**< list of observers for this resource */

  /**
   * Request URI Path for this resource. This field will point into static
   * or allocated memory which must remain there for the duration of the
   * resource.
   */
  coap_str_const_t *uri_path;  /**< the key used for hash lookup for this resource */
  int flags;

  /**
  * The next value for the Observe option. This field must be increased each
  * time the resource changes. Only the lower 24 bits are sent.
  */
  unsigned int observe;

  /**
   * This pointer is under user control. It can be used to store context for
   * the coap handler.
   */
  void *user_data;

} coap_resource_t;

/**
 * Creates a new resource object and initializes the link field to the string
 * @p uri_path. This function returns the new coap_resource_t object.
 *
 * If the string is going to be freed off by coap_delete_resource() when
 * COAP_RESOURCE_FLAGS_RELEASE_URI is set in @p flags, then either the 's'
 * variable of coap_str_const_t has to point to constant text, or point to data
 * within the allocated coap_str_const_t parameter.
 *
 * @param uri_path The string URI path of the new resource.
 * @param flags    Flags for memory management (in particular release of
 *                 memory). Possible values:@n
 *
 *                 COAP_RESOURCE_FLAGS_RELEASE_URI
 *                  If this flag is set, the URI passed to
 *                  coap_resource_init() is free'd by
 *                  coap_delete_resource()@n
 *
 *                 COAP_RESOURCE_FLAGS_NOTIFY_CON
 *                  If this flag is set, coap-observe notifications
 *                  will be sent confirmable by default.@n
 *
 *                 COAP_RESOURCE_FLAGS_NOTIFY_NON (default)
 *                  If this flag is set, coap-observe notifications
 *                  will be sent non-confirmable by default.@n
 *
 *                  If flags is set to 0 then the
 *                  COAP_RESOURCE_FLAGS_NOTIFY_NON is considered.
 *
 * @return         A pointer to the new object or @c NULL on error.
 */
coap_resource_t *coap_resource_init(coap_str_const_t *uri_path,
                                    int flags);


/**
 * Creates a new resource object for the unknown resource handler with support
 * for PUT.
 *
 * In the same way that additional handlers can be added to the resource
 * created by coap_resource_init() by using coap_register_handler(), POST,
 * GET, DELETE etc. handlers can be added to this resource. It is the
 * responsibility of the application to manage the unknown resources by either
 * creating new resources with coap_resource_init() (which should have a
 * DELETE handler specified for the resource removal) or by maintaining an
 * active resource list.
 *
 * Note: There can only be one unknown resource handler per context - attaching
 *       a new one overrides the previous definition.
 *
 * Note: It is not possible to observe the unknown resource with a GET request
 *       - a separate resource needs to be reated by the PUT (or POST) handler,
 *       and make that resource observable.
 *
 * This function returns the new coap_resource_t object.
 *
 * @param put_handler The PUT handler to register with @p resource for
 *                    unknown Uri-Path.
 *
 * @return       A pointer to the new object or @c NULL on error.
 */
coap_resource_t *coap_resource_unknown_init(coap_method_handler_t put_handler);

/**
 * Sets the notification message type of resource @p resource to given
 * @p mode

 * @param resource The resource to update.
 * @param mode     Must be one of @c COAP_RESOURCE_FLAGS_NOTIFY_NON
 *                 or @c COAP_RESOURCE_FLAGS_NOTIFY_CON.
 */
COAP_STATIC_INLINE void
coap_resource_set_mode(coap_resource_t *resource, int mode) {
  resource->flags = (resource->flags &
    ~(COAP_RESOURCE_FLAGS_NOTIFY_CON|COAP_RESOURCE_FLAGS_NOTIFY_NON)) |
    (mode & (COAP_RESOURCE_FLAGS_NOTIFY_CON|COAP_RESOURCE_FLAGS_NOTIFY_NON));
}

/**
 * Sets the user_data. The user_data is exclusively used by the library-user
 * and can be used as context in the handler functions.
 *
 * @param r       Resource to attach the data to
 * @param data    Data to attach to the user_data field. This pointer is only used for
 *                storage, the data remains under user control
 */
COAP_STATIC_INLINE void
coap_resource_set_userdata(coap_resource_t *r, void *data) {
  r->user_data = data;
}

/**
 * Gets the user_data. The user_data is exclusively used by the library-user
 * and can be used as context in the handler functions.
 *
 * @param r        Resource to retrieve the user_darta from
 *
 * @return        The user_data pointer
 */
COAP_STATIC_INLINE void *
coap_resource_get_userdata(coap_resource_t *r) {
  return r->user_data;
}

/**
 * Registers the given @p resource for @p context. The resource must have been
 * created by coap_resource_init() or coap_resource_unknown_init(), the
 * storage allocated for the resource will be released by coap_delete_resource().
 *
 * @param context  The context to use.
 * @param resource The resource to store.
 */
void coap_add_resource(coap_context_t *context, coap_resource_t *resource);

/**
 * Deletes a resource identified by @p resource. The storage allocated for that
 * resource is freed, and removed from the context.
 *
 * @param context  The context where the resources are stored.
 * @param resource The resource to delete.
 *
 * @return         @c 1 if the resource was found (and destroyed),
 *                 @c 0 otherwise.
 */
int coap_delete_resource(coap_context_t *context, coap_resource_t *resource);

/**
 * Deletes all resources from given @p context and frees their storage.
 *
 * @param context The CoAP context with the resources to be deleted.
 */
void coap_delete_all_resources(coap_context_t *context);

/**
 * Registers a new attribute with the given @p resource. As the
 * attribute's coap_str_const_ fields will point to @p name and @p value the
 * caller must ensure that these pointers are valid during the
 * attribute's lifetime.

 * If the @p name and/or @p value string is going to be freed off at attribute
 * removal time by the setting of COAP_ATTR_FLAGS_RELEASE_NAME or
 * COAP_ATTR_FLAGS_RELEASE_VALUE in @p flags, then either the 's'
 * variable of coap_str_const_t has to point to constant text, or point to data
 * within the allocated coap_str_const_t parameter.
 *
 * @param resource The resource to register the attribute with.
 * @param name     The attribute's name as a string.
 * @param value    The attribute's value as a string or @c NULL if none.
 * @param flags    Flags for memory management (in particular release of
 *                 memory). Possible values:@n
 *
 *                 COAP_ATTR_FLAGS_RELEASE_NAME
 *                  If this flag is set, the name passed to
 *                  coap_add_attr_release() is free'd
 *                  when the attribute is deleted@n
 *
 *                 COAP_ATTR_FLAGS_RELEASE_VALUE
 *                  If this flag is set, the value passed to
 *                  coap_add_attr_release() is free'd
 *                  when the attribute is deleted@n
 *
 * @return         A pointer to the new attribute or @c NULL on error.
 */
coap_attr_t *coap_add_attr(coap_resource_t *resource,
                           coap_str_const_t *name,
                           coap_str_const_t *value,
                           int flags);

/**
 * Returns @p resource's coap_attr_t object with given @p name if found, @c NULL
 * otherwise.
 *
 * @param resource The resource to search for attribute @p name.
 * @param name     Name of the requested attribute as a string.
 * @return         The first attribute with specified @p name or @c NULL if none
 *                 was found.
 */
coap_attr_t *coap_find_attr(coap_resource_t *resource,
                            coap_str_const_t *name);

/**
 * Deletes an attribute.
 * Note: This is for internal use only, as it is not deleted from its chain.
 *
 * @param attr Pointer to a previously created attribute.
 *
 */
void coap_delete_attr(coap_attr_t *attr);

/**
 * Status word to encode the result of conditional print or copy operations such
 * as coap_print_link(). The lower 28 bits of coap_print_status_t are used to
 * encode the number of characters that has actually been printed, bits 28 to 31
 * encode the status.  When COAP_PRINT_STATUS_ERROR is set, an error occurred
 * during output. In this case, the other bits are undefined.
 * COAP_PRINT_STATUS_TRUNC indicates that the output is truncated, i.e. the
 * printing would have exceeded the current buffer.
 */
typedef unsigned int coap_print_status_t;

#define COAP_PRINT_STATUS_MASK  0xF0000000u
#define COAP_PRINT_OUTPUT_LENGTH(v) ((v) & ~COAP_PRINT_STATUS_MASK)
#define COAP_PRINT_STATUS_ERROR 0x80000000u
#define COAP_PRINT_STATUS_TRUNC 0x40000000u

/**
 * Writes a description of this resource in link-format to given text buffer. @p
 * len must be initialized to the maximum length of @p buf and will be set to
 * the number of characters actually written if successful. This function
 * returns @c 1 on success or @c 0 on error.
 *
 * @param resource The resource to describe.
 * @param buf      The output buffer to write the description to.
 * @param len      Must be initialized to the length of @p buf and
 *                 will be set to the length of the printed link description.
 * @param offset   The offset within the resource description where to
 *                 start writing into @p buf. This is useful for dealing
 *                 with the Block2 option. @p offset is updated during
 *                 output as it is consumed.
 *
 * @return If COAP_PRINT_STATUS_ERROR is set, an error occured. Otherwise,
 *         the lower 28 bits will indicate the number of characters that
 *         have actually been output into @p buffer. The flag
 *         COAP_PRINT_STATUS_TRUNC indicates that the output has been
 *         truncated.
 */
coap_print_status_t coap_print_link(const coap_resource_t *resource,
                                    unsigned char *buf,
                                    size_t *len,
                                    size_t *offset);

/**
 * Registers the specified @p handler as message handler for the request type @p
 * method
 *
 * @param resource The resource for which the handler shall be registered.
 * @param method   The CoAP request method to handle.
 * @param handler  The handler to register with @p resource.
 */
void coap_register_handler(coap_resource_t *resource,
                           unsigned char method,
                           coap_method_handler_t handler);

/**
 * Returns the resource identified by the unique string @p uri_path. If no
 * resource was found, this function returns @c NULL.
 *
 * @param context  The context to look for this resource.
 * @param uri_path  The unique string uri of the resource.
 *
 * @return         A pointer to the resource or @c NULL if not found.
 */
coap_resource_t *coap_get_resource_from_uri_path(coap_context_t *context,
                                                coap_str_const_t *uri_path);

/**
 * @addtogroup observe
 */

/**
 * Adds the specified peer as observer for @p resource. The subscription is
 * identified by the given @p token. This function returns the registered
 * subscription information if the @p observer has been added, or @c NULL on
 * error.
 *
 * @param resource        The observed resource.
 * @param session         The observer's session
 * @param token           The token that identifies this subscription.
 * @param query           The query string, if any. subscription will
                          take ownership of the string.
 * @param has_block2      If Option Block2 defined.
 * @param block2          Contents of Block2 if Block 2 defined.
 * @return                A pointer to the added/updated subscription
 *                        information or @c NULL on error.
 */
coap_subscription_t *coap_add_observer(coap_resource_t *resource,
                                       coap_session_t *session,
                                       const coap_binary_t *token,
                                       coap_string_t *query,
                                       int has_block2,
                                       coap_block_t block2);

/**
 * Returns a subscription object for given @p peer.
 *
 * @param resource The observed resource.
 * @param session  The observer's session
 * @param token    The token that identifies this subscription or @c NULL for
 *                 any token.
 * @return         A valid subscription if exists or @c NULL otherwise.
 */
coap_subscription_t *coap_find_observer(coap_resource_t *resource,
                                        coap_session_t *session,
                                        const coap_binary_t *token);

/**
 * Marks an observer as alive.
 *
 * @param context  The CoAP context to use.
 * @param session  The observer's session
 * @param token    The corresponding token that has been used for the
 *                 subscription.
 */
void coap_touch_observer(coap_context_t *context,
                         coap_session_t *session,
                         const coap_binary_t *token);

/**
 * Removes any subscription for @p observer from @p resource and releases the
 * allocated storage. The result is @c 1 if an observation relationship with @p
 * observer and @p token existed, @c 0 otherwise.
 *
 * @param resource The observed resource.
 * @param session  The observer's session.
 * @param token    The token that identifies this subscription or @c NULL for
 *                 any token.
 * @return         @c 1 if the observer has been deleted, @c 0 otherwise.
 */
int coap_delete_observer(coap_resource_t *resource,
                         coap_session_t *session,
                         const coap_binary_t *token);

/**
 * Removes any subscription for @p session and releases the allocated storage.
 *
 * @param context  The CoAP context to use.
 * @param session  The observer's session.
 */
void coap_delete_observers(coap_context_t *context, coap_session_t *session);

/**
 * Checks for all known resources, if they are dirty and notifies subscribed
 * observers.
 */
void coap_check_notify(coap_context_t *context);

#define RESOURCES_ADD(r, obj) \
  HASH_ADD(hh, (r), uri_path->s[0], (obj)->uri_path->length, (obj))

#define RESOURCES_DELETE(r, obj) \
  HASH_DELETE(hh, (r), (obj))

#define RESOURCES_ITER(r,tmp)  \
  coap_resource_t *tmp, *rtmp; \
  HASH_ITER(hh, (r), tmp, rtmp)

#define RESOURCES_FIND(r, k, res) {                     \
    HASH_FIND(hh, (r), (k)->s, (k)->length, (res)); \
  }

/** @} */

coap_print_status_t coap_print_wellknown(coap_context_t *,
                                         unsigned char *,
                                         size_t *, size_t,
                                         coap_opt_t *);

void
coap_handle_failed_notify(coap_context_t *,
                          coap_session_t *,
                          const coap_binary_t *);

/**
 * Set whether a @p resource is observable.  If the resource is observable
 * and the client has set the COAP_OPTION_OBSERVE in a request packet, then
 * whenever the state of the resource changes (a call to
 * coap_resource_trigger_observe()), an Observer response will get sent.
 *
 * @param resource The CoAP resource to use.
 * @param mode     @c 1 if Observable is to be set, @c 0 otherwise.
 *
 */
COAP_STATIC_INLINE void
coap_resource_set_get_observable(coap_resource_t *resource, int mode) {
  resource->observable = mode ? 1 : 0;
}

/**
 * Initiate the sending of an Observe packet for all observers of @p resource,
 * optionally matching @p query if not NULL
 *
 * @param resource The CoAP resource to use.
 * @param query    The Query to match against or NULL
 *
 * @return         @c 1 if the Observe has been triggered, @c 0 otherwise.
 */
int
coap_resource_notify_observers(coap_resource_t *resource,
                               const coap_string_t *query);

/**
 * Get the UriPath from a @p resource.
 *
 * @param resource The CoAP resource to check.
 *
 * @return         The UriPath if it exists or @c NULL otherwise.
 */
COAP_STATIC_INLINE coap_str_const_t*
coap_resource_get_uri_path(coap_resource_t *resource) {
  if (resource)
    return resource->uri_path;
  return NULL;
}

/**
 * @deprecated use coap_resource_notify_observers() instead.
 */
COAP_DEPRECATED int
coap_resource_set_dirty(coap_resource_t *r,
                        const coap_string_t *query);

#endif /* COAP_RESOURCE_H_ */
/*
 * str.h -- strings to be used in the CoAP library
 *
 * Copyright (C) 2010-2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef COAP_STR_H_
#define COAP_STR_H_

#include <string.h>


/**
 * @defgroup string String handling support
 * API functions for handling strings
 * @{
 */

/**
 * Coap string data definition
 */
typedef struct coap_string_t {
  size_t length;    /**< length of string */
  uint8_t *s;       /**< string data */
} coap_string_t;

/**
 * Coap string data definition with const data
 */
typedef struct coap_str_const_t {
  size_t length;    /**< length of string */
  const uint8_t *s; /**< string data */
} coap_str_const_t;

#define COAP_SET_STR(st,l,v) { (st)->length = (l), (st)->s = (v); }

/**
 * Coap binary data definition
 */
typedef struct coap_binary_t {
  size_t length;    /**< length of binary data */
  uint8_t *s;       /**< binary data */
} coap_binary_t;

/**
 * Returns a new string object with at least size+1 bytes storage allocated.
 * The string must be released using coap_delete_string().
 *
 * @param size The size to allocate for the binary string data.
 *
 * @return       A pointer to the new object or @c NULL on error.
 */
coap_string_t *coap_new_string(size_t size);

/**
 * Deletes the given string and releases any memory allocated.
 *
 * @param string The string to free off.
 */
void coap_delete_string(coap_string_t *string);

/**
 * Returns a new const string object with at least size+1 bytes storage
 * allocated, and the provided data copied into the string object.
 * The string must be released using coap_delete_str_const().
 *
 * @param data The data to put in the new string object.
 * @param size The size to allocate for the binary string data.
 *
 * @return       A pointer to the new object or @c NULL on error.
 */
coap_str_const_t *coap_new_str_const(const uint8_t *data, size_t size);

/**
 * Deletes the given const string and releases any memory allocated.
 *
 * @param string The string to free off.
 */
void coap_delete_str_const(coap_str_const_t *string);

/**
 * Take the specified byte array (text) and create a coap_str_const_t *
 *
 * WARNING: The byte array must be in the local scope and not a
 * parameter in the function call as sizeof() will return the size of the
 * pointer, not the size of the byte array, leading to unxepected results.
 *
 * @param string The const byte array to convert to a coap_str_const_t *
 */
#ifdef __cplusplus
namespace libcoap {
  struct CoAPStrConst : coap_str_const_t {
    operator coap_str_const_t *() { return this; }
  };
}
#define coap_make_str_const(CStr)                                       \
  libcoap::CoAPStrConst{sizeof(CStr)-1, reinterpret_cast<const uint8_t *>(CStr)}
#else /* __cplusplus */
#define coap_make_str_const(string)                                     \
  (&(coap_str_const_t){sizeof(string)-1,(const uint8_t *)(string)})
#endif  /* __cplusplus */

/**
 * Compares the two strings for equality
 *
 * @param string1 The first string.
 * @param string2 The second string.
 *
 * @return         @c 1 if the strings are equal
 *                 @c 0 otherwise.
 */
#define coap_string_equal(string1,string2) \
        ((string1)->length == (string2)->length && ((string1)->length == 0 || \
         memcmp((string1)->s, (string2)->s, (string1)->length) == 0))

/** @} */

#endif /* COAP_STR_H_ */
/*
 * subscribe.h -- subscription handling for CoAP
 *                see RFC7641
 *
 * Copyright (C) 2010-2012,2014-2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */


#ifndef COAP_SUBSCRIBE_H_
#define COAP_SUBSCRIBE_H_

#include "address.h"
#include "coap_io.h"
#include "block.h"

/**
 * @defgroup observe Resource observation
 * API functions for interfacing with the observe handling (RFC7641)
 * @{
 */

/**
 * The value COAP_OBSERVE_ESTABLISH in a GET request indicates a new observe
 * relationship for (sender address, token) is requested.
 */
#define COAP_OBSERVE_ESTABLISH 0

/**
 * The value COAP_OBSERVE_CANCEL in a GET request indicates that the observe
 * relationship for (sender address, token) must be cancelled.
 */
#define COAP_OBSERVE_CANCEL 1

#ifndef COAP_OBS_MAX_NON
/**
 * Number of notifications that may be sent non-confirmable before a confirmable
 * message is sent to detect if observers are alive. The maximum allowed value
 * here is @c 15.
 */
#define COAP_OBS_MAX_NON   5
#endif /* COAP_OBS_MAX_NON */

#ifndef COAP_OBS_MAX_FAIL
/**
 * Number of confirmable notifications that may fail (i.e. time out without
 * being ACKed) before an observer is removed. The maximum value for
 * COAP_OBS_MAX_FAIL is @c 3.
 */
#define COAP_OBS_MAX_FAIL  3
#endif /* COAP_OBS_MAX_FAIL */

/** Subscriber information */
typedef struct coap_subscription_t {
  struct coap_subscription_t *next; /**< next element in linked list */
  coap_session_t *session;          /**< subscriber session */

  unsigned int non_cnt:4;  /**< up to 15 non-confirmable notifies allowed */
  unsigned int fail_cnt:2; /**< up to 3 confirmable notifies can fail */
  unsigned int dirty:1;    /**< set if the notification temporarily could not be
                            *   sent (in that case, the resource's partially
                            *   dirty flag is set too) */
  unsigned int has_block2:1; /**< GET request had Block2 definition */
  coap_block_t block2;     /**< GET request Block2 definition */
  size_t token_length;     /**< actual length of token */
  unsigned char token[8];  /**< token used for subscription */
  coap_string_t *query;    /**< query string used for subscription, if any */
} coap_subscription_t;

void coap_subscription_init(coap_subscription_t *);

/** @} */

#endif /* COAP_SUBSCRIBE_H_ */
/*
 * uri.h -- helper functions for URI treatment
 *
 * Copyright (C) 2010-2011,2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef COAP_URI_H_
#define COAP_URI_H_

#include <stdint.h>

#include "str.h"
struct coap_pdu_t;

/**
 * The scheme specifiers. Secure schemes have an odd numeric value,
 * others are even.
 */
enum coap_uri_scheme_t {
  COAP_URI_SCHEME_COAP=0,
  COAP_URI_SCHEME_COAPS=1,
  COAP_URI_SCHEME_COAP_TCP=2,
  COAP_URI_SCHEME_COAPS_TCP=3
};

/** This mask can be used to check if a parsed URI scheme is secure. */
#define COAP_URI_SCHEME_SECURE_MASK 0x01

/**
 * Representation of parsed URI. Components may be filled from a string with
 * coap_split_uri() and can be used as input for option-creation functions.
 */
typedef struct {
  coap_str_const_t host;  /**< host part of the URI */
  uint16_t port;          /**< The port in host byte order */
  coap_str_const_t path;  /**< Beginning of the first path segment.
                           Use coap_split_path() to create Uri-Path options */
  coap_str_const_t query; /**<  The query part if present */

  /** The parsed scheme specifier. */
  enum coap_uri_scheme_t scheme;
} coap_uri_t;

static inline int
coap_uri_scheme_is_secure(const coap_uri_t *uri) {
  return uri && ((uri->scheme & COAP_URI_SCHEME_SECURE_MASK) != 0);
}

/**
 * Creates a new coap_uri_t object from the specified URI. Returns the new
 * object or NULL on error. The memory allocated by the new coap_uri_t
 * must be released using coap_free().
 *
 * @param uri The URI path to copy.
 * @param length The length of uri.
 *
 * @return New URI object or NULL on error.
 */
coap_uri_t *coap_new_uri(const uint8_t *uri, unsigned int length);

/**
 * Clones the specified coap_uri_t object. Thie function allocates sufficient
 * memory to hold the coap_uri_t structure and its contents. The object must
 * be released with coap_free(). */
coap_uri_t *coap_clone_uri(const coap_uri_t *uri);

/**
 * @defgroup uri_parse URI Parsing Functions
 *
 * CoAP PDUs contain normalized URIs with their path and query split into
 * multiple segments. The functions in this module help splitting strings.
 * @{
 */

/**
 * Parses a given string into URI components. The identified syntactic
 * components are stored in the result parameter @p uri. Optional URI
 * components that are not specified will be set to { 0, 0 }, except for the
 * port which is set to @c COAP_DEFAULT_PORT. This function returns @p 0 if
 * parsing succeeded, a value less than zero otherwise.
 *
 * @param str_var The string to split up.
 * @param len     The actual length of @p str_var
 * @param uri     The coap_uri_t object to store the result.
 * @return        @c 0 on success, or < 0 on error.
 *
 */
int coap_split_uri(const uint8_t *str_var, size_t len, coap_uri_t *uri);

/**
 * Splits the given URI path into segments. Each segment is preceded
 * by an option pseudo-header with delta-value 0 and the actual length
 * of the respective segment after percent-decoding.
 *
 * @param s      The path string to split.
 * @param length The actual length of @p s.
 * @param buf    Result buffer for parsed segments.
 * @param buflen Maximum length of @p buf. Will be set to the actual number
 *               of bytes written into buf on success.
 *
 * @return       The number of segments created or @c -1 on error.
 */
int coap_split_path(const uint8_t *s,
                    size_t length,
                    unsigned char *buf,
                    size_t *buflen);

/**
 * Splits the given URI query into segments. Each segment is preceded
 * by an option pseudo-header with delta-value 0 and the actual length
 * of the respective query term.
 *
 * @param s      The query string to split.
 * @param length The actual length of @p s.
 * @param buf    Result buffer for parsed segments.
 * @param buflen Maximum length of @p buf. Will be set to the actual number
 *               of bytes written into buf on success.
 *
 * @return       The number of segments created or @c -1 on error.
 *
 * @bug This function does not reserve additional space for delta > 12.
 */
int coap_split_query(const uint8_t *s,
                     size_t length,
                     unsigned char *buf,
                     size_t *buflen);

/**
 * Extract query string from request PDU according to escape rules in 6.5.8.
 * @param request Request PDU.
 * @return        Reconstructed and escaped query string part.
 */
coap_string_t *coap_get_query(const struct coap_pdu_t *request);

/**
 * Extract uri_path string from request PDU
 * @param request Request PDU.
 * @return        Reconstructed and escaped uri path string part.
 */
coap_string_t *coap_get_uri_path(const struct coap_pdu_t *request);

/** @} */

#endif /* COAP_URI_H_ */
/*
Copyright (c) 2003-2017, Troy D. Hanson     http://troydhanson.github.com/uthash/
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef UTHASH_H
#define UTHASH_H

#define UTHASH_VERSION 2.0.2

#include <string.h>   /* memcmp, memset, strlen */
#include <stddef.h>   /* ptrdiff_t */
#include <stdlib.h>   /* exit */

/* These macros use decltype or the earlier __typeof GNU extension.
   As decltype is only available in newer compilers (VS2010 or gcc 4.3+
   when compiling c++ source) this code uses whatever method is needed
   or, for VS2008 where neither is available, uses casting workarounds. */
#if !defined(DECLTYPE) && !defined(NO_DECLTYPE)
#if defined(_MSC_VER)   /* MS compiler */
#if _MSC_VER >= 1600 && defined(__cplusplus)  /* VS2010 or newer in C++ mode */
#define DECLTYPE(x) (decltype(x))
#else                   /* VS2008 or older (or VS2010 in C mode) */
#define NO_DECLTYPE
#endif
#elif defined(__BORLANDC__) || defined(__ICCARM__) || defined(__LCC__) || defined(__WATCOMC__)
#define NO_DECLTYPE
#else                   /* GNU, Sun and other compilers */
#define DECLTYPE(x) (__typeof(x))
#endif
#endif

#ifdef NO_DECLTYPE
#define DECLTYPE(x)
#define DECLTYPE_ASSIGN(dst,src)                                                 \
do {                                                                             \
  char **_da_dst = (char**)(&(dst));                                             \
  *_da_dst = (char*)(src);                                                       \
} while (0)
#else
#define DECLTYPE_ASSIGN(dst,src)                                                 \
do {                                                                             \
  (dst) = DECLTYPE(dst)(src);                                                    \
} while (0)
#endif

/* a number of the hash function use uint32_t which isn't defined on Pre VS2010 */
#if defined(_WIN32)
#if defined(_MSC_VER) && _MSC_VER >= 1600
#include <stdint.h>
#elif defined(__WATCOMC__) || defined(__MINGW32__) || defined(__CYGWIN__)
#include <stdint.h>
#else
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
#endif
#elif defined(__GNUC__) && !defined(__VXWORKS__)
#include <stdint.h>
#else
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
#endif

#ifndef uthash_fatal
#define uthash_fatal(msg) exit(-1)        /* fatal error (out of memory,etc) */
#endif
#ifndef uthash_malloc
#define uthash_malloc(sz) malloc(sz)      /* malloc fcn                      */
#endif
#ifndef uthash_free
#define uthash_free(ptr,sz) free(ptr)     /* free fcn                        */
#endif
#ifndef uthash_bzero
#define uthash_bzero(a,n) memset(a,'\0',n)
#endif
#ifndef uthash_memcmp
#define uthash_memcmp(a,b,n) memcmp(a,b,n)
#endif
#ifndef uthash_strlen
#define uthash_strlen(s) strlen(s)
#endif

#ifndef uthash_noexpand_fyi
#define uthash_noexpand_fyi(tbl)          /* can be defined to log noexpand  */
#endif
#ifndef uthash_expand_fyi
#define uthash_expand_fyi(tbl)            /* can be defined to log expands   */
#endif

/* initial number of buckets */
#define HASH_INITIAL_NUM_BUCKETS 32U     /* initial number of buckets        */
#define HASH_INITIAL_NUM_BUCKETS_LOG2 5U /* lg2 of initial number of buckets */
#define HASH_BKT_CAPACITY_THRESH 10U     /* expand when bucket count reaches */

/* calculate the element whose hash handle address is hhp */
#define ELMT_FROM_HH(tbl,hhp) ((void*)(((char*)(hhp)) - ((tbl)->hho)))
/* calculate the hash handle from element address elp */
#define HH_FROM_ELMT(tbl,elp) ((UT_hash_handle *)(((char*)(elp)) + ((tbl)->hho)))

#define HASH_VALUE(keyptr,keylen,hashv)                                          \
do {                                                                             \
  HASH_FCN(keyptr, keylen, hashv);                                               \
} while (0)

#define HASH_FIND_BYHASHVALUE(hh,head,keyptr,keylen,hashval,out)                 \
do {                                                                             \
  (out) = NULL;                                                                  \
  if (head) {                                                                    \
    unsigned _hf_bkt;                                                            \
    HASH_TO_BKT(hashval, (head)->hh.tbl->num_buckets, _hf_bkt);                  \
    if (HASH_BLOOM_TEST((head)->hh.tbl, hashval) != 0) {                         \
      HASH_FIND_IN_BKT((head)->hh.tbl, hh, (head)->hh.tbl->buckets[ _hf_bkt ], keyptr, keylen, hashval, out); \
    }                                                                            \
  }                                                                              \
} while (0)

#define HASH_FIND(hh,head,keyptr,keylen,out)                                     \
do {                                                                             \
  unsigned _hf_hashv;                                                            \
  HASH_VALUE(keyptr, keylen, _hf_hashv);                                         \
  HASH_FIND_BYHASHVALUE(hh, head, keyptr, keylen, _hf_hashv, out);               \
} while (0)

#ifdef HASH_BLOOM
#define HASH_BLOOM_BITLEN (1UL << HASH_BLOOM)
#define HASH_BLOOM_BYTELEN (HASH_BLOOM_BITLEN/8UL) + (((HASH_BLOOM_BITLEN%8UL)!=0UL) ? 1UL : 0UL)
#define HASH_BLOOM_MAKE(tbl)                                                     \
do {                                                                             \
  (tbl)->bloom_nbits = HASH_BLOOM;                                               \
  (tbl)->bloom_bv = (uint8_t*)uthash_malloc(HASH_BLOOM_BYTELEN);                 \
  if (!(tbl)->bloom_bv) {                                                        \
    uthash_fatal("out of memory");                                               \
  }                                                                              \
  uthash_bzero((tbl)->bloom_bv, HASH_BLOOM_BYTELEN);                             \
  (tbl)->bloom_sig = HASH_BLOOM_SIGNATURE;                                       \
} while (0)

#define HASH_BLOOM_FREE(tbl)                                                     \
do {                                                                             \
  uthash_free((tbl)->bloom_bv, HASH_BLOOM_BYTELEN);                              \
} while (0)

#define HASH_BLOOM_BITSET(bv,idx) (bv[(idx)/8U] |= (1U << ((idx)%8U)))
#define HASH_BLOOM_BITTEST(bv,idx) (bv[(idx)/8U] & (1U << ((idx)%8U)))

#define HASH_BLOOM_ADD(tbl,hashv)                                                \
  HASH_BLOOM_BITSET((tbl)->bloom_bv, (hashv & (uint32_t)((1UL << (tbl)->bloom_nbits) - 1U)))

#define HASH_BLOOM_TEST(tbl,hashv)                                               \
  HASH_BLOOM_BITTEST((tbl)->bloom_bv, (hashv & (uint32_t)((1UL << (tbl)->bloom_nbits) - 1U)))

#else
#define HASH_BLOOM_MAKE(tbl)
#define HASH_BLOOM_FREE(tbl)
#define HASH_BLOOM_ADD(tbl,hashv)
#define HASH_BLOOM_TEST(tbl,hashv) (1)
#define HASH_BLOOM_BYTELEN 0U
#endif

#define HASH_MAKE_TABLE(hh,head)                                                 \
do {                                                                             \
  (head)->hh.tbl = (UT_hash_table*)uthash_malloc(sizeof(UT_hash_table));         \
  if (!(head)->hh.tbl) {                                                         \
    uthash_fatal("out of memory");                                               \
  }                                                                              \
  uthash_bzero((head)->hh.tbl, sizeof(UT_hash_table));                           \
  (head)->hh.tbl->tail = &((head)->hh);                                          \
  (head)->hh.tbl->num_buckets = HASH_INITIAL_NUM_BUCKETS;                        \
  (head)->hh.tbl->log2_num_buckets = HASH_INITIAL_NUM_BUCKETS_LOG2;              \
  (head)->hh.tbl->hho = (char*)(&(head)->hh) - (char*)(head);                    \
  (head)->hh.tbl->buckets = (UT_hash_bucket*)uthash_malloc(                      \
      HASH_INITIAL_NUM_BUCKETS * sizeof(struct UT_hash_bucket));                 \
  if (!(head)->hh.tbl->buckets) {                                                \
    uthash_fatal("out of memory");                                               \
  }                                                                              \
  uthash_bzero((head)->hh.tbl->buckets,                                          \
      HASH_INITIAL_NUM_BUCKETS * sizeof(struct UT_hash_bucket));                 \
  HASH_BLOOM_MAKE((head)->hh.tbl);                                               \
  (head)->hh.tbl->signature = HASH_SIGNATURE;                                    \
} while (0)

#define HASH_REPLACE_BYHASHVALUE_INORDER(hh,head,fieldname,keylen_in,hashval,add,replaced,cmpfcn) \
do {                                                                             \
  (replaced) = NULL;                                                             \
  HASH_FIND_BYHASHVALUE(hh, head, &((add)->fieldname), keylen_in, hashval, replaced); \
  if (replaced) {                                                                \
    HASH_DELETE(hh, head, replaced);                                             \
  }                                                                              \
  HASH_ADD_KEYPTR_BYHASHVALUE_INORDER(hh, head, &((add)->fieldname), keylen_in, hashval, add, cmpfcn); \
} while (0)

#define HASH_REPLACE_BYHASHVALUE(hh,head,fieldname,keylen_in,hashval,add,replaced) \
do {                                                                             \
  (replaced) = NULL;                                                             \
  HASH_FIND_BYHASHVALUE(hh, head, &((add)->fieldname), keylen_in, hashval, replaced); \
  if (replaced) {                                                                \
    HASH_DELETE(hh, head, replaced);                                             \
  }                                                                              \
  HASH_ADD_KEYPTR_BYHASHVALUE(hh, head, &((add)->fieldname), keylen_in, hashval, add); \
} while (0)

#define HASH_REPLACE(hh,head,fieldname,keylen_in,add,replaced)                   \
do {                                                                             \
  unsigned _hr_hashv;                                                            \
  HASH_VALUE(&((add)->fieldname), keylen_in, _hr_hashv);                         \
  HASH_REPLACE_BYHASHVALUE(hh, head, fieldname, keylen_in, _hr_hashv, add, replaced); \
} while (0)

#define HASH_REPLACE_INORDER(hh,head,fieldname,keylen_in,add,replaced,cmpfcn)    \
do {                                                                             \
  unsigned _hr_hashv;                                                            \
  HASH_VALUE(&((add)->fieldname), keylen_in, _hr_hashv);                         \
  HASH_REPLACE_BYHASHVALUE_INORDER(hh, head, fieldname, keylen_in, _hr_hashv, add, replaced, cmpfcn); \
} while (0)

#define HASH_APPEND_LIST(hh, head, add)                                          \
do {                                                                             \
  (add)->hh.next = NULL;                                                         \
  (add)->hh.prev = ELMT_FROM_HH((head)->hh.tbl, (head)->hh.tbl->tail);           \
  (head)->hh.tbl->tail->next = (add);                                            \
  (head)->hh.tbl->tail = &((add)->hh);                                           \
} while (0)

#define HASH_AKBI_INNER_LOOP(hh,head,add,cmpfcn)                                 \
do {                                                                             \
  do {                                                                           \
    if (cmpfcn(DECLTYPE(head)(_hs_iter), add) > 0) {                             \
      break;                                                                     \
    }                                                                            \
  } while ((_hs_iter = HH_FROM_ELMT((head)->hh.tbl, _hs_iter)->next));           \
} while (0)

#ifdef NO_DECLTYPE
#undef HASH_AKBI_INNER_LOOP
#define HASH_AKBI_INNER_LOOP(hh,head,add,cmpfcn)                                 \
do {                                                                             \
  char *_hs_saved_head = (char*)(head);                                          \
  do {                                                                           \
    DECLTYPE_ASSIGN(head, _hs_iter);                                             \
    if (cmpfcn(head, add) > 0) {                                                 \
      DECLTYPE_ASSIGN(head, _hs_saved_head);                                     \
      break;                                                                     \
    }                                                                            \
    DECLTYPE_ASSIGN(head, _hs_saved_head);                                       \
  } while ((_hs_iter = HH_FROM_ELMT((head)->hh.tbl, _hs_iter)->next));           \
} while (0)
#endif

#define HASH_ADD_KEYPTR_BYHASHVALUE_INORDER(hh,head,keyptr,keylen_in,hashval,add,cmpfcn) \
do {                                                                             \
  unsigned _ha_bkt;                                                              \
  (add)->hh.hashv = (hashval);                                                   \
  (add)->hh.key = (char*) (keyptr);                                              \
  (add)->hh.keylen = (unsigned) (keylen_in);                                     \
  if (!(head)) {                                                                 \
    (add)->hh.next = NULL;                                                       \
    (add)->hh.prev = NULL;                                                       \
    (head) = (add);                                                              \
    HASH_MAKE_TABLE(hh, head);                                                   \
  } else {                                                                       \
    void *_hs_iter = (head);                                                     \
    (add)->hh.tbl = (head)->hh.tbl;                                              \
    HASH_AKBI_INNER_LOOP(hh, head, add, cmpfcn);                                 \
    if (_hs_iter) {                                                              \
      (add)->hh.next = _hs_iter;                                                 \
      if (((add)->hh.prev = HH_FROM_ELMT((head)->hh.tbl, _hs_iter)->prev)) {     \
        HH_FROM_ELMT((head)->hh.tbl, (add)->hh.prev)->next = (add);              \
      } else {                                                                   \
        (head) = (add);                                                          \
      }                                                                          \
      HH_FROM_ELMT((head)->hh.tbl, _hs_iter)->prev = (add);                      \
    } else {                                                                     \
      HASH_APPEND_LIST(hh, head, add);                                           \
    }                                                                            \
  }                                                                              \
  (head)->hh.tbl->num_items++;                                                   \
  HASH_TO_BKT(hashval, (head)->hh.tbl->num_buckets, _ha_bkt);                    \
  HASH_ADD_TO_BKT((head)->hh.tbl->buckets[_ha_bkt], &(add)->hh);                 \
  HASH_BLOOM_ADD((head)->hh.tbl, hashval);                                       \
  HASH_EMIT_KEY(hh, head, keyptr, keylen_in);                                    \
  HASH_FSCK(hh, head, "HASH_ADD_KEYPTR_BYHASHVALUE_INORDER");                    \
} while (0)

#define HASH_ADD_KEYPTR_INORDER(hh,head,keyptr,keylen_in,add,cmpfcn)             \
do {                                                                             \
  unsigned _hs_hashv;                                                            \
  HASH_VALUE(keyptr, keylen_in, _hs_hashv);                                      \
  HASH_ADD_KEYPTR_BYHASHVALUE_INORDER(hh, head, keyptr, keylen_in, _hs_hashv, add, cmpfcn); \
} while (0)

#define HASH_ADD_BYHASHVALUE_INORDER(hh,head,fieldname,keylen_in,hashval,add,cmpfcn) \
  HASH_ADD_KEYPTR_BYHASHVALUE_INORDER(hh, head, &((add)->fieldname), keylen_in, hashval, add, cmpfcn)

#define HASH_ADD_INORDER(hh,head,fieldname,keylen_in,add,cmpfcn)                 \
  HASH_ADD_KEYPTR_INORDER(hh, head, &((add)->fieldname), keylen_in, add, cmpfcn)

#define HASH_ADD_KEYPTR_BYHASHVALUE(hh,head,keyptr,keylen_in,hashval,add)        \
do {                                                                             \
  unsigned _ha_bkt;                                                              \
  (add)->hh.hashv = (hashval);                                                   \
  (add)->hh.key = (const void *) (keyptr);                                       \
  (add)->hh.keylen = (unsigned) (keylen_in);                                     \
  if (!(head)) {                                                                 \
    (add)->hh.next = NULL;                                                       \
    (add)->hh.prev = NULL;                                                       \
    (head) = (add);                                                              \
    HASH_MAKE_TABLE(hh, head);                                                   \
  } else {                                                                       \
    (add)->hh.tbl = (head)->hh.tbl;                                              \
    HASH_APPEND_LIST(hh, head, add);                                             \
  }                                                                              \
  (head)->hh.tbl->num_items++;                                                   \
  HASH_TO_BKT(hashval, (head)->hh.tbl->num_buckets, _ha_bkt);                    \
  HASH_ADD_TO_BKT((head)->hh.tbl->buckets[_ha_bkt], &(add)->hh);                 \
  HASH_BLOOM_ADD((head)->hh.tbl, hashval);                                       \
  HASH_EMIT_KEY(hh, head, keyptr, keylen_in);                                    \
  HASH_FSCK(hh, head, "HASH_ADD_KEYPTR_BYHASHVALUE");                            \
} while (0)

#define HASH_ADD_KEYPTR(hh,head,keyptr,keylen_in,add)                            \
do {                                                                             \
  unsigned _ha_hashv;                                                            \
  HASH_VALUE(keyptr, keylen_in, _ha_hashv);                                      \
  HASH_ADD_KEYPTR_BYHASHVALUE(hh, head, keyptr, keylen_in, _ha_hashv, add);      \
} while (0)

#define HASH_ADD_BYHASHVALUE(hh,head,fieldname,keylen_in,hashval,add)            \
  HASH_ADD_KEYPTR_BYHASHVALUE(hh, head, &((add)->fieldname), keylen_in, hashval, add)

#define HASH_ADD(hh,head,fieldname,keylen_in,add)                                \
  HASH_ADD_KEYPTR(hh, head, &((add)->fieldname), keylen_in, add)

#define HASH_TO_BKT(hashv,num_bkts,bkt)                                          \
do {                                                                             \
  bkt = ((hashv) & ((num_bkts) - 1U));                                           \
} while (0)

/* delete "delptr" from the hash table.
 * "the usual" patch-up process for the app-order doubly-linked-list.
 * The use of _hd_hh_del below deserves special explanation.
 * These used to be expressed using (delptr) but that led to a bug
 * if someone used the same symbol for the head and deletee, like
 *  HASH_DELETE(hh,users,users);
 * We want that to work, but by changing the head (users) below
 * we were forfeiting our ability to further refer to the deletee (users)
 * in the patch-up process. Solution: use scratch space to
 * copy the deletee pointer, then the latter references are via that
 * scratch pointer rather than through the repointed (users) symbol.
 */
#define HASH_DELETE(hh,head,delptr)                                              \
    HASH_DELETE_HH(hh, head, &(delptr)->hh)

#define HASH_DELETE_HH(hh,head,delptrhh)                                         \
do {                                                                             \
  struct UT_hash_handle *_hd_hh_del = (delptrhh);                                \
  if ((_hd_hh_del->prev == NULL) && (_hd_hh_del->next == NULL)) {                \
    HASH_BLOOM_FREE((head)->hh.tbl);                                             \
    uthash_free((head)->hh.tbl->buckets,                                         \
                (head)->hh.tbl->num_buckets * sizeof(struct UT_hash_bucket));    \
    uthash_free((head)->hh.tbl, sizeof(UT_hash_table));                          \
    (head) = NULL;                                                               \
  } else {                                                                       \
    unsigned _hd_bkt;                                                            \
    if (_hd_hh_del == (head)->hh.tbl->tail) {                                    \
      (head)->hh.tbl->tail = HH_FROM_ELMT((head)->hh.tbl, _hd_hh_del->prev);     \
    }                                                                            \
    if (_hd_hh_del->prev != NULL) {                                              \
      HH_FROM_ELMT((head)->hh.tbl, _hd_hh_del->prev)->next = _hd_hh_del->next;   \
    } else {                                                                     \
      DECLTYPE_ASSIGN(head, _hd_hh_del->next);                                   \
    }                                                                            \
    if (_hd_hh_del->next != NULL) {                                              \
      HH_FROM_ELMT((head)->hh.tbl, _hd_hh_del->next)->prev = _hd_hh_del->prev;   \
    }                                                                            \
    HASH_TO_BKT(_hd_hh_del->hashv, (head)->hh.tbl->num_buckets, _hd_bkt);        \
    HASH_DEL_IN_BKT((head)->hh.tbl->buckets[_hd_bkt], _hd_hh_del);               \
    (head)->hh.tbl->num_items--;                                                 \
  }                                                                              \
  HASH_FSCK(hh, head, "HASH_DELETE");                                            \
} while (0)


/* convenience forms of HASH_FIND/HASH_ADD/HASH_DEL */
#define HASH_FIND_STR(head,findstr,out)                                          \
    HASH_FIND(hh,head,findstr,(unsigned)uthash_strlen(findstr),out)
#define HASH_ADD_STR(head,strfield,add)                                          \
    HASH_ADD(hh,head,strfield[0],(unsigned)uthash_strlen(add->strfield),add)
#define HASH_REPLACE_STR(head,strfield,add,replaced)                             \
    HASH_REPLACE(hh,head,strfield[0],(unsigned)uthash_strlen(add->strfield),add,replaced)
#define HASH_FIND_INT(head,findint,out)                                          \
    HASH_FIND(hh,head,findint,sizeof(int),out)
#define HASH_ADD_INT(head,intfield,add)                                          \
    HASH_ADD(hh,head,intfield,sizeof(int),add)
#define HASH_REPLACE_INT(head,intfield,add,replaced)                             \
    HASH_REPLACE(hh,head,intfield,sizeof(int),add,replaced)
#define HASH_FIND_PTR(head,findptr,out)                                          \
    HASH_FIND(hh,head,findptr,sizeof(void *),out)
#define HASH_ADD_PTR(head,ptrfield,add)                                          \
    HASH_ADD(hh,head,ptrfield,sizeof(void *),add)
#define HASH_REPLACE_PTR(head,ptrfield,add,replaced)                             \
    HASH_REPLACE(hh,head,ptrfield,sizeof(void *),add,replaced)
#define HASH_DEL(head,delptr)                                                    \
    HASH_DELETE(hh,head,delptr)

/* HASH_FSCK checks hash integrity on every add/delete when HASH_DEBUG is defined.
 * This is for uthash developer only; it compiles away if HASH_DEBUG isn't defined.
 */
#ifdef HASH_DEBUG
#define HASH_OOPS(...) do { fprintf(stderr,__VA_ARGS__); exit(-1); } while (0)
#define HASH_FSCK(hh,head,where)                                                 \
do {                                                                             \
  struct UT_hash_handle *_thh;                                                   \
  if (head) {                                                                    \
    unsigned _bkt_i;                                                             \
    unsigned _count = 0;                                                         \
    char *_prev;                                                                 \
    for (_bkt_i = 0; _bkt_i < (head)->hh.tbl->num_buckets; ++_bkt_i) {           \
      unsigned _bkt_count = 0;                                                   \
      _thh = (head)->hh.tbl->buckets[_bkt_i].hh_head;                            \
      _prev = NULL;                                                              \
      while (_thh) {                                                             \
        if (_prev != (char*)(_thh->hh_prev)) {                                   \
          HASH_OOPS("%s: invalid hh_prev %p, actual %p\n",                       \
              (where), (void*)_thh->hh_prev, (void*)_prev);                      \
        }                                                                        \
        _bkt_count++;                                                            \
        _prev = (char*)(_thh);                                                   \
        _thh = _thh->hh_next;                                                    \
      }                                                                          \
      _count += _bkt_count;                                                      \
      if ((head)->hh.tbl->buckets[_bkt_i].count !=  _bkt_count) {                \
        HASH_OOPS("%s: invalid bucket count %u, actual %u\n",                    \
            (where), (head)->hh.tbl->buckets[_bkt_i].count, _bkt_count);         \
      }                                                                          \
    }                                                                            \
    if (_count != (head)->hh.tbl->num_items) {                                   \
      HASH_OOPS("%s: invalid hh item count %u, actual %u\n",                     \
          (where), (head)->hh.tbl->num_items, _count);                           \
    }                                                                            \
    _count = 0;                                                                  \
    _prev = NULL;                                                                \
    _thh =  &(head)->hh;                                                         \
    while (_thh) {                                                               \
      _count++;                                                                  \
      if (_prev != (char*)_thh->prev) {                                          \
        HASH_OOPS("%s: invalid prev %p, actual %p\n",                            \
            (where), (void*)_thh->prev, (void*)_prev);                           \
      }                                                                          \
      _prev = (char*)ELMT_FROM_HH((head)->hh.tbl, _thh);                         \
      _thh = (_thh->next ? HH_FROM_ELMT((head)->hh.tbl, _thh->next) : NULL);     \
    }                                                                            \
    if (_count != (head)->hh.tbl->num_items) {                                   \
      HASH_OOPS("%s: invalid app item count %u, actual %u\n",                    \
          (where), (head)->hh.tbl->num_items, _count);                           \
    }                                                                            \
  }                                                                              \
} while (0)
#else
#define HASH_FSCK(hh,head,where)
#endif

/* When compiled with -DHASH_EMIT_KEYS, length-prefixed keys are emitted to
 * the descriptor to which this macro is defined for tuning the hash function.
 * The app can #include <unistd.h> to get the prototype for write(2). */
#ifdef HASH_EMIT_KEYS
#define HASH_EMIT_KEY(hh,head,keyptr,fieldlen)                                   \
do {                                                                             \
  unsigned _klen = fieldlen;                                                     \
  write(HASH_EMIT_KEYS, &_klen, sizeof(_klen));                                  \
  write(HASH_EMIT_KEYS, keyptr, (unsigned long)fieldlen);                        \
} while (0)
#else
#define HASH_EMIT_KEY(hh,head,keyptr,fieldlen)
#endif

/* default to Jenkin's hash unless overridden e.g. DHASH_FUNCTION=HASH_SAX */
#ifdef HASH_FUNCTION
#define HASH_FCN HASH_FUNCTION
#else
#define HASH_FCN HASH_JEN
#endif

/* The Bernstein hash function, used in Perl prior to v5.6. Note (x<<5+x)=x*33. */
#define HASH_BER(key,keylen,hashv)                                               \
do {                                                                             \
  unsigned _hb_keylen = (unsigned)keylen;                                        \
  const unsigned char *_hb_key = (const unsigned char*)(key);                    \
  (hashv) = 0;                                                                   \
  while (_hb_keylen-- != 0U) {                                                   \
    (hashv) = (((hashv) << 5) + (hashv)) + *_hb_key++;                           \
  }                                                                              \
} while (0)


/* SAX/FNV/OAT/JEN hash functions are macro variants of those listed at
 * http://eternallyconfuzzled.com/tuts/algorithms/jsw_tut_hashing.aspx */
#define HASH_SAX(key,keylen,hashv)                                               \
do {                                                                             \
  unsigned _sx_i;                                                                \
  const unsigned char *_hs_key = (const unsigned char*)(key);                    \
  hashv = 0;                                                                     \
  for (_sx_i=0; _sx_i < keylen; _sx_i++) {                                       \
    hashv ^= (hashv << 5) + (hashv >> 2) + _hs_key[_sx_i];                       \
  }                                                                              \
} while (0)
/* FNV-1a variation */
#define HASH_FNV(key,keylen,hashv)                                               \
do {                                                                             \
  unsigned _fn_i;                                                                \
  const unsigned char *_hf_key = (const unsigned char*)(key);                    \
  (hashv) = 2166136261U;                                                         \
  for (_fn_i=0; _fn_i < keylen; _fn_i++) {                                       \
    hashv = hashv ^ _hf_key[_fn_i];                                              \
    hashv = hashv * 16777619U;                                                   \
  }                                                                              \
} while (0)

#define HASH_OAT(key,keylen,hashv)                                               \
do {                                                                             \
  unsigned _ho_i;                                                                \
  const unsigned char *_ho_key=(const unsigned char*)(key);                      \
  hashv = 0;                                                                     \
  for(_ho_i=0; _ho_i < keylen; _ho_i++) {                                        \
      hashv += _ho_key[_ho_i];                                                   \
      hashv += (hashv << 10);                                                    \
      hashv ^= (hashv >> 6);                                                     \
  }                                                                              \
  hashv += (hashv << 3);                                                         \
  hashv ^= (hashv >> 11);                                                        \
  hashv += (hashv << 15);                                                        \
} while (0)

#define HASH_JEN_MIX(a,b,c)                                                      \
do {                                                                             \
  a -= b; a -= c; a ^= ( c >> 13 );                                              \
  b -= c; b -= a; b ^= ( a << 8 );                                               \
  c -= a; c -= b; c ^= ( b >> 13 );                                              \
  a -= b; a -= c; a ^= ( c >> 12 );                                              \
  b -= c; b -= a; b ^= ( a << 16 );                                              \
  c -= a; c -= b; c ^= ( b >> 5 );                                               \
  a -= b; a -= c; a ^= ( c >> 3 );                                               \
  b -= c; b -= a; b ^= ( a << 10 );                                              \
  c -= a; c -= b; c ^= ( b >> 15 );                                              \
} while (0)

#define HASH_JEN(key,keylen,hashv)                                               \
do {                                                                             \
  unsigned _hj_i,_hj_j,_hj_k;                                                    \
  unsigned const char *_hj_key=(unsigned const char*)(key);                      \
  hashv = 0xfeedbeefu;                                                           \
  _hj_i = _hj_j = 0x9e3779b9u;                                                   \
  _hj_k = (unsigned)(keylen);                                                    \
  while (_hj_k >= 12U) {                                                         \
    _hj_i +=    (_hj_key[0] + ( (unsigned)_hj_key[1] << 8 )                      \
        + ( (unsigned)_hj_key[2] << 16 )                                         \
        + ( (unsigned)_hj_key[3] << 24 ) );                                      \
    _hj_j +=    (_hj_key[4] + ( (unsigned)_hj_key[5] << 8 )                      \
        + ( (unsigned)_hj_key[6] << 16 )                                         \
        + ( (unsigned)_hj_key[7] << 24 ) );                                      \
    hashv += (_hj_key[8] + ( (unsigned)_hj_key[9] << 8 )                         \
        + ( (unsigned)_hj_key[10] << 16 )                                        \
        + ( (unsigned)_hj_key[11] << 24 ) );                                     \
                                                                                 \
     HASH_JEN_MIX(_hj_i, _hj_j, hashv);                                          \
                                                                                 \
     _hj_key += 12;                                                              \
     _hj_k -= 12U;                                                               \
  }                                                                              \
  hashv += (unsigned)(keylen);                                                   \
  switch ( _hj_k ) {                                                             \
    case 11: hashv += ( (unsigned)_hj_key[10] << 24 ); /* FALLTHROUGH */         \
    case 10: hashv += ( (unsigned)_hj_key[9] << 16 );  /* FALLTHROUGH */         \
    case 9:  hashv += ( (unsigned)_hj_key[8] << 8 );   /* FALLTHROUGH */         \
    case 8:  _hj_j += ( (unsigned)_hj_key[7] << 24 );  /* FALLTHROUGH */         \
    case 7:  _hj_j += ( (unsigned)_hj_key[6] << 16 );  /* FALLTHROUGH */         \
    case 6:  _hj_j += ( (unsigned)_hj_key[5] << 8 );   /* FALLTHROUGH */         \
    case 5:  _hj_j += _hj_key[4];                      /* FALLTHROUGH */         \
    case 4:  _hj_i += ( (unsigned)_hj_key[3] << 24 );  /* FALLTHROUGH */         \
    case 3:  _hj_i += ( (unsigned)_hj_key[2] << 16 );  /* FALLTHROUGH */         \
    case 2:  _hj_i += ( (unsigned)_hj_key[1] << 8 );   /* FALLTHROUGH */         \
    case 1:  _hj_i += _hj_key[0];                                                \
    default: ;                                         /* does not happen */     \
  }                                                                              \
  HASH_JEN_MIX(_hj_i, _hj_j, hashv);                                             \
} while (0)

/* The Paul Hsieh hash function */
#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__)             \
  || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)             \
                       +(uint32_t)(((const uint8_t *)(d))[0]) )
#endif
#define HASH_SFH(key,keylen,hashv)                                               \
do {                                                                             \
  unsigned const char *_sfh_key=(unsigned const char*)(key);                     \
  uint32_t _sfh_tmp, _sfh_len = (uint32_t)keylen;                                \
                                                                                 \
  unsigned _sfh_rem = _sfh_len & 3U;                                             \
  _sfh_len >>= 2;                                                                \
  hashv = 0xcafebabeu;                                                           \
                                                                                 \
  /* Main loop */                                                                \
  for (;_sfh_len > 0U; _sfh_len--) {                                             \
    hashv    += get16bits (_sfh_key);                                            \
    _sfh_tmp  = ((uint32_t)(get16bits (_sfh_key+2)) << 11) ^ hashv;              \
    hashv     = (hashv << 16) ^ _sfh_tmp;                                        \
    _sfh_key += 2U*sizeof (uint16_t);                                            \
    hashv    += hashv >> 11;                                                     \
  }                                                                              \
                                                                                 \
  /* Handle end cases */                                                         \
  switch (_sfh_rem) {                                                            \
    case 3: hashv += get16bits (_sfh_key);                                       \
            hashv ^= hashv << 16;                                                \
            hashv ^= (uint32_t)(_sfh_key[sizeof (uint16_t)]) << 18;              \
            hashv += hashv >> 11;                                                \
            break;                                                               \
    case 2: hashv += get16bits (_sfh_key);                                       \
            hashv ^= hashv << 11;                                                \
            hashv += hashv >> 17;                                                \
            break;                                                               \
    case 1: hashv += *_sfh_key;                                                  \
            hashv ^= hashv << 10;                                                \
            hashv += hashv >> 1;                                                 \
  }                                                                              \
                                                                                 \
  /* Force "avalanching" of final 127 bits */                                    \
  hashv ^= hashv << 3;                                                           \
  hashv += hashv >> 5;                                                           \
  hashv ^= hashv << 4;                                                           \
  hashv += hashv >> 17;                                                          \
  hashv ^= hashv << 25;                                                          \
  hashv += hashv >> 6;                                                           \
} while (0)

#ifdef HASH_USING_NO_STRICT_ALIASING
/* The MurmurHash exploits some CPU's (x86,x86_64) tolerance for unaligned reads.
 * For other types of CPU's (e.g. Sparc) an unaligned read causes a bus error.
 * MurmurHash uses the faster approach only on CPU's where we know it's safe.
 *
 * Note the preprocessor built-in defines can be emitted using:
 *
 *   gcc -m64 -dM -E - < /dev/null                  (on gcc)
 *   cc -## a.c (where a.c is a simple test file)   (Sun Studio)
 */
#if (defined(__i386__) || defined(__x86_64__)  || defined(_M_IX86))
#define MUR_GETBLOCK(p,i) p[i]
#else /* non intel */
#define MUR_PLUS0_ALIGNED(p) (((unsigned long)p & 3UL) == 0UL)
#define MUR_PLUS1_ALIGNED(p) (((unsigned long)p & 3UL) == 1UL)
#define MUR_PLUS2_ALIGNED(p) (((unsigned long)p & 3UL) == 2UL)
#define MUR_PLUS3_ALIGNED(p) (((unsigned long)p & 3UL) == 3UL)
#define WP(p) ((uint32_t*)((unsigned long)(p) & ~3UL))
#if (defined(__BIG_ENDIAN__) || defined(SPARC) || defined(__ppc__) || defined(__ppc64__))
#define MUR_THREE_ONE(p) ((((*WP(p))&0x00ffffff) << 8) | (((*(WP(p)+1))&0xff000000) >> 24))
#define MUR_TWO_TWO(p)   ((((*WP(p))&0x0000ffff) <<16) | (((*(WP(p)+1))&0xffff0000) >> 16))
#define MUR_ONE_THREE(p) ((((*WP(p))&0x000000ff) <<24) | (((*(WP(p)+1))&0xffffff00) >>  8))
#else /* assume little endian non-intel */
#define MUR_THREE_ONE(p) ((((*WP(p))&0xffffff00) >> 8) | (((*(WP(p)+1))&0x000000ff) << 24))
#define MUR_TWO_TWO(p)   ((((*WP(p))&0xffff0000) >>16) | (((*(WP(p)+1))&0x0000ffff) << 16))
#define MUR_ONE_THREE(p) ((((*WP(p))&0xff000000) >>24) | (((*(WP(p)+1))&0x00ffffff) <<  8))
#endif
#define MUR_GETBLOCK(p,i) (MUR_PLUS0_ALIGNED(p) ? ((p)[i]) :           \
                            (MUR_PLUS1_ALIGNED(p) ? MUR_THREE_ONE(p) : \
                             (MUR_PLUS2_ALIGNED(p) ? MUR_TWO_TWO(p) :  \
                                                      MUR_ONE_THREE(p))))
#endif
#define MUR_ROTL32(x,r) (((x) << (r)) | ((x) >> (32 - (r))))
#define MUR_FMIX(_h) \
do {                 \
  _h ^= _h >> 16;    \
  _h *= 0x85ebca6bu; \
  _h ^= _h >> 13;    \
  _h *= 0xc2b2ae35u; \
  _h ^= _h >> 16;    \
} while (0)

#define HASH_MUR(key,keylen,hashv)                                     \
do {                                                                   \
  const uint8_t *_mur_data = (const uint8_t*)(key);                    \
  const int _mur_nblocks = (int)(keylen) / 4;                          \
  uint32_t _mur_h1 = 0xf88D5353u;                                      \
  uint32_t _mur_c1 = 0xcc9e2d51u;                                      \
  uint32_t _mur_c2 = 0x1b873593u;                                      \
  uint32_t _mur_k1 = 0;                                                \
  const uint8_t *_mur_tail;                                            \
  const uint32_t *_mur_blocks = (const uint32_t*)(_mur_data+(_mur_nblocks*4)); \
  int _mur_i;                                                          \
  for (_mur_i = -_mur_nblocks; _mur_i != 0; _mur_i++) {                \
    _mur_k1 = MUR_GETBLOCK(_mur_blocks,_mur_i);                        \
    _mur_k1 *= _mur_c1;                                                \
    _mur_k1 = MUR_ROTL32(_mur_k1,15);                                  \
    _mur_k1 *= _mur_c2;                                                \
                                                                       \
    _mur_h1 ^= _mur_k1;                                                \
    _mur_h1 = MUR_ROTL32(_mur_h1,13);                                  \
    _mur_h1 = (_mur_h1*5U) + 0xe6546b64u;                              \
  }                                                                    \
  _mur_tail = (const uint8_t*)(_mur_data + (_mur_nblocks*4));          \
  _mur_k1=0;                                                           \
  switch ((keylen) & 3U) {                                             \
    case 0: break;                                                     \
    case 3: _mur_k1 ^= (uint32_t)_mur_tail[2] << 16; /* FALLTHROUGH */ \
    case 2: _mur_k1 ^= (uint32_t)_mur_tail[1] << 8;  /* FALLTHROUGH */ \
    case 1: _mur_k1 ^= (uint32_t)_mur_tail[0];                         \
    _mur_k1 *= _mur_c1;                                                \
    _mur_k1 = MUR_ROTL32(_mur_k1,15);                                  \
    _mur_k1 *= _mur_c2;                                                \
    _mur_h1 ^= _mur_k1;                                                \
  }                                                                    \
  _mur_h1 ^= (uint32_t)(keylen);                                       \
  MUR_FMIX(_mur_h1);                                                   \
  hashv = _mur_h1;                                                     \
} while (0)
#endif  /* HASH_USING_NO_STRICT_ALIASING */

/* iterate over items in a known bucket to find desired item */
#define HASH_FIND_IN_BKT(tbl,hh,head,keyptr,keylen_in,hashval,out)               \
do {                                                                             \
  if ((head).hh_head != NULL) {                                                  \
    DECLTYPE_ASSIGN(out, ELMT_FROM_HH(tbl, (head).hh_head));                     \
  } else {                                                                       \
    (out) = NULL;                                                                \
  }                                                                              \
  while ((out) != NULL) {                                                        \
    if ((out)->hh.hashv == (hashval) && (out)->hh.keylen == (keylen_in)) {       \
      if (uthash_memcmp((out)->hh.key, keyptr, keylen_in) == 0) {                \
        break;                                                                   \
      }                                                                          \
    }                                                                            \
    if ((out)->hh.hh_next != NULL) {                                             \
      DECLTYPE_ASSIGN(out, ELMT_FROM_HH(tbl, (out)->hh.hh_next));                \
    } else {                                                                     \
      (out) = NULL;                                                              \
    }                                                                            \
  }                                                                              \
} while (0)

/* add an item to a bucket  */
#define HASH_ADD_TO_BKT(head,addhh)                                              \
do {                                                                             \
  UT_hash_bucket *_ha_head = &(head);                                            \
  _ha_head->count++;                                                             \
  (addhh)->hh_next = _ha_head->hh_head;                                          \
  (addhh)->hh_prev = NULL;                                                       \
  if (_ha_head->hh_head != NULL) {                                               \
    _ha_head->hh_head->hh_prev = (addhh);                                        \
  }                                                                              \
  _ha_head->hh_head = (addhh);                                                   \
  if ((_ha_head->count >= ((_ha_head->expand_mult + 1U) * HASH_BKT_CAPACITY_THRESH)) \
      && !(addhh)->tbl->noexpand) {                                              \
    HASH_EXPAND_BUCKETS((addhh)->tbl);                                           \
  }                                                                              \
} while (0)

/* remove an item from a given bucket */
#define HASH_DEL_IN_BKT(head,delhh)                                              \
do {                                                                             \
  UT_hash_bucket *_hd_head = &(head);                                            \
  _hd_head->count--;                                                             \
  if (_hd_head->hh_head == (delhh)) {                                            \
    _hd_head->hh_head = (delhh)->hh_next;                                        \
  }                                                                              \
  if ((delhh)->hh_prev) {                                                        \
    (delhh)->hh_prev->hh_next = (delhh)->hh_next;                                \
  }                                                                              \
  if ((delhh)->hh_next) {                                                        \
    (delhh)->hh_next->hh_prev = (delhh)->hh_prev;                                \
  }                                                                              \
} while (0)

/* Bucket expansion has the effect of doubling the number of buckets
 * and redistributing the items into the new buckets. Ideally the
 * items will distribute more or less evenly into the new buckets
 * (the extent to which this is true is a measure of the quality of
 * the hash function as it applies to the key domain).
 *
 * With the items distributed into more buckets, the chain length
 * (item count) in each bucket is reduced. Thus by expanding buckets
 * the hash keeps a bound on the chain length. This bounded chain
 * length is the essence of how a hash provides constant time lookup.
 *
 * The calculation of tbl->ideal_chain_maxlen below deserves some
 * explanation. First, keep in mind that we're calculating the ideal
 * maximum chain length based on the *new* (doubled) bucket count.
 * In fractions this is just n/b (n=number of items,b=new num buckets).
 * Since the ideal chain length is an integer, we want to calculate
 * ceil(n/b). We don't depend on floating point arithmetic in this
 * hash, so to calculate ceil(n/b) with integers we could write
 *
 *      ceil(n/b) = (n/b) + ((n%b)?1:0)
 *
 * and in fact a previous version of this hash did just that.
 * But now we have improved things a bit by recognizing that b is
 * always a power of two. We keep its base 2 log handy (call it lb),
 * so now we can write this with a bit shift and logical AND:
 *
 *      ceil(n/b) = (n>>lb) + ( (n & (b-1)) ? 1:0)
 *
 */
#define HASH_EXPAND_BUCKETS(tbl)                                                 \
do {                                                                             \
  unsigned _he_bkt;                                                              \
  unsigned _he_bkt_i;                                                            \
  struct UT_hash_handle *_he_thh, *_he_hh_nxt;                                   \
  UT_hash_bucket *_he_new_buckets, *_he_newbkt;                                  \
  _he_new_buckets = (UT_hash_bucket*)uthash_malloc(                              \
           2UL * (tbl)->num_buckets * sizeof(struct UT_hash_bucket));            \
  if (!_he_new_buckets) {                                                        \
    uthash_fatal("out of memory");                                               \
  }                                                                              \
  uthash_bzero(_he_new_buckets,                                                  \
          2UL * (tbl)->num_buckets * sizeof(struct UT_hash_bucket));             \
  (tbl)->ideal_chain_maxlen =                                                    \
     ((tbl)->num_items >> ((tbl)->log2_num_buckets+1U)) +                        \
     ((((tbl)->num_items & (((tbl)->num_buckets*2U)-1U)) != 0U) ? 1U : 0U);      \
  (tbl)->nonideal_items = 0;                                                     \
  for (_he_bkt_i = 0; _he_bkt_i < (tbl)->num_buckets; _he_bkt_i++) {             \
    _he_thh = (tbl)->buckets[ _he_bkt_i ].hh_head;                               \
    while (_he_thh != NULL) {                                                    \
      _he_hh_nxt = _he_thh->hh_next;                                             \
      HASH_TO_BKT(_he_thh->hashv, (tbl)->num_buckets * 2U, _he_bkt);             \
      _he_newbkt = &(_he_new_buckets[_he_bkt]);                                  \
      if (++(_he_newbkt->count) > (tbl)->ideal_chain_maxlen) {                   \
        (tbl)->nonideal_items++;                                                 \
        _he_newbkt->expand_mult = _he_newbkt->count / (tbl)->ideal_chain_maxlen; \
      }                                                                          \
      _he_thh->hh_prev = NULL;                                                   \
      _he_thh->hh_next = _he_newbkt->hh_head;                                    \
      if (_he_newbkt->hh_head != NULL) {                                         \
        _he_newbkt->hh_head->hh_prev = _he_thh;                                  \
      }                                                                          \
      _he_newbkt->hh_head = _he_thh;                                             \
      _he_thh = _he_hh_nxt;                                                      \
    }                                                                            \
  }                                                                              \
  uthash_free((tbl)->buckets, (tbl)->num_buckets * sizeof(struct UT_hash_bucket)); \
  (tbl)->num_buckets *= 2U;                                                      \
  (tbl)->log2_num_buckets++;                                                     \
  (tbl)->buckets = _he_new_buckets;                                              \
  (tbl)->ineff_expands = ((tbl)->nonideal_items > ((tbl)->num_items >> 1)) ?     \
      ((tbl)->ineff_expands+1U) : 0U;                                            \
  if ((tbl)->ineff_expands > 1U) {                                               \
    (tbl)->noexpand = 1;                                                         \
    uthash_noexpand_fyi(tbl);                                                    \
  }                                                                              \
  uthash_expand_fyi(tbl);                                                        \
} while (0)


/* This is an adaptation of Simon Tatham's O(n log(n)) mergesort */
/* Note that HASH_SORT assumes the hash handle name to be hh.
 * HASH_SRT was added to allow the hash handle name to be passed in. */
#define HASH_SORT(head,cmpfcn) HASH_SRT(hh,head,cmpfcn)
#define HASH_SRT(hh,head,cmpfcn)                                                 \
do {                                                                             \
  unsigned _hs_i;                                                                \
  unsigned _hs_looping,_hs_nmerges,_hs_insize,_hs_psize,_hs_qsize;               \
  struct UT_hash_handle *_hs_p, *_hs_q, *_hs_e, *_hs_list, *_hs_tail;            \
  if (head != NULL) {                                                            \
    _hs_insize = 1;                                                              \
    _hs_looping = 1;                                                             \
    _hs_list = &((head)->hh);                                                    \
    while (_hs_looping != 0U) {                                                  \
      _hs_p = _hs_list;                                                          \
      _hs_list = NULL;                                                           \
      _hs_tail = NULL;                                                           \
      _hs_nmerges = 0;                                                           \
      while (_hs_p != NULL) {                                                    \
        _hs_nmerges++;                                                           \
        _hs_q = _hs_p;                                                           \
        _hs_psize = 0;                                                           \
        for (_hs_i = 0; _hs_i < _hs_insize; ++_hs_i) {                           \
          _hs_psize++;                                                           \
          _hs_q = ((_hs_q->next != NULL) ?                                       \
            HH_FROM_ELMT((head)->hh.tbl, _hs_q->next) : NULL);                   \
          if (_hs_q == NULL) {                                                   \
            break;                                                               \
          }                                                                      \
        }                                                                        \
        _hs_qsize = _hs_insize;                                                  \
        while ((_hs_psize != 0U) || ((_hs_qsize != 0U) && (_hs_q != NULL))) {    \
          if (_hs_psize == 0U) {                                                 \
            _hs_e = _hs_q;                                                       \
            _hs_q = ((_hs_q->next != NULL) ?                                     \
              HH_FROM_ELMT((head)->hh.tbl, _hs_q->next) : NULL);                 \
            _hs_qsize--;                                                         \
          } else if ((_hs_qsize == 0U) || (_hs_q == NULL)) {                     \
            _hs_e = _hs_p;                                                       \
            if (_hs_p != NULL) {                                                 \
              _hs_p = ((_hs_p->next != NULL) ?                                   \
                HH_FROM_ELMT((head)->hh.tbl, _hs_p->next) : NULL);               \
            }                                                                    \
            _hs_psize--;                                                         \
          } else if ((cmpfcn(                                                    \
                DECLTYPE(head)(ELMT_FROM_HH((head)->hh.tbl, _hs_p)),             \
                DECLTYPE(head)(ELMT_FROM_HH((head)->hh.tbl, _hs_q))              \
                )) <= 0) {                                                       \
            _hs_e = _hs_p;                                                       \
            if (_hs_p != NULL) {                                                 \
              _hs_p = ((_hs_p->next != NULL) ?                                   \
                HH_FROM_ELMT((head)->hh.tbl, _hs_p->next) : NULL);               \
            }                                                                    \
            _hs_psize--;                                                         \
          } else {                                                               \
            _hs_e = _hs_q;                                                       \
            _hs_q = ((_hs_q->next != NULL) ?                                     \
              HH_FROM_ELMT((head)->hh.tbl, _hs_q->next) : NULL);                 \
            _hs_qsize--;                                                         \
          }                                                                      \
          if ( _hs_tail != NULL ) {                                              \
            _hs_tail->next = ((_hs_e != NULL) ?                                  \
              ELMT_FROM_HH((head)->hh.tbl, _hs_e) : NULL);                       \
          } else {                                                               \
            _hs_list = _hs_e;                                                    \
          }                                                                      \
          if (_hs_e != NULL) {                                                   \
            _hs_e->prev = ((_hs_tail != NULL) ?                                  \
              ELMT_FROM_HH((head)->hh.tbl, _hs_tail) : NULL);                    \
          }                                                                      \
          _hs_tail = _hs_e;                                                      \
        }                                                                        \
        _hs_p = _hs_q;                                                           \
      }                                                                          \
      if (_hs_tail != NULL) {                                                    \
        _hs_tail->next = NULL;                                                   \
      }                                                                          \
      if (_hs_nmerges <= 1U) {                                                   \
        _hs_looping = 0;                                                         \
        (head)->hh.tbl->tail = _hs_tail;                                         \
        DECLTYPE_ASSIGN(head, ELMT_FROM_HH((head)->hh.tbl, _hs_list));           \
      }                                                                          \
      _hs_insize *= 2U;                                                          \
    }                                                                            \
    HASH_FSCK(hh, head, "HASH_SRT");                                             \
  }                                                                              \
} while (0)

/* This function selects items from one hash into another hash.
 * The end result is that the selected items have dual presence
 * in both hashes. There is no copy of the items made; rather
 * they are added into the new hash through a secondary hash
 * hash handle that must be present in the structure. */
#define HASH_SELECT(hh_dst, dst, hh_src, src, cond)                              \
do {                                                                             \
  unsigned _src_bkt, _dst_bkt;                                                   \
  void *_last_elt = NULL, *_elt;                                                 \
  UT_hash_handle *_src_hh, *_dst_hh, *_last_elt_hh=NULL;                         \
  ptrdiff_t _dst_hho = ((char*)(&(dst)->hh_dst) - (char*)(dst));                 \
  if ((src) != NULL) {                                                           \
    for (_src_bkt=0; _src_bkt < (src)->hh_src.tbl->num_buckets; _src_bkt++) {    \
      for (_src_hh = (src)->hh_src.tbl->buckets[_src_bkt].hh_head;               \
        _src_hh != NULL;                                                         \
        _src_hh = _src_hh->hh_next) {                                            \
        _elt = ELMT_FROM_HH((src)->hh_src.tbl, _src_hh);                         \
        if (cond(_elt)) {                                                        \
          _dst_hh = (UT_hash_handle*)(((char*)_elt) + _dst_hho);                 \
          _dst_hh->key = _src_hh->key;                                           \
          _dst_hh->keylen = _src_hh->keylen;                                     \
          _dst_hh->hashv = _src_hh->hashv;                                       \
          _dst_hh->prev = _last_elt;                                             \
          _dst_hh->next = NULL;                                                  \
          if (_last_elt_hh != NULL) {                                            \
            _last_elt_hh->next = _elt;                                           \
          }                                                                      \
          if ((dst) == NULL) {                                                   \
            DECLTYPE_ASSIGN(dst, _elt);                                          \
            HASH_MAKE_TABLE(hh_dst, dst);                                        \
          } else {                                                               \
            _dst_hh->tbl = (dst)->hh_dst.tbl;                                    \
          }                                                                      \
          HASH_TO_BKT(_dst_hh->hashv, _dst_hh->tbl->num_buckets, _dst_bkt);      \
          HASH_ADD_TO_BKT(_dst_hh->tbl->buckets[_dst_bkt], _dst_hh);             \
          HASH_BLOOM_ADD(_dst_hh->tbl, _dst_hh->hashv);                          \
          (dst)->hh_dst.tbl->num_items++;                                        \
          _last_elt = _elt;                                                      \
          _last_elt_hh = _dst_hh;                                                \
        }                                                                        \
      }                                                                          \
    }                                                                            \
  }                                                                              \
  HASH_FSCK(hh_dst, dst, "HASH_SELECT");                                         \
} while (0)

#define HASH_CLEAR(hh,head)                                                      \
do {                                                                             \
  if ((head) != NULL) {                                                          \
    HASH_BLOOM_FREE((head)->hh.tbl);                                             \
    uthash_free((head)->hh.tbl->buckets,                                         \
                (head)->hh.tbl->num_buckets*sizeof(struct UT_hash_bucket));      \
    uthash_free((head)->hh.tbl, sizeof(UT_hash_table));                          \
    (head) = NULL;                                                               \
  }                                                                              \
} while (0)

#define HASH_OVERHEAD(hh,head)                                                   \
 (((head) != NULL) ? (                                                           \
 (size_t)(((head)->hh.tbl->num_items   * sizeof(UT_hash_handle))   +             \
          ((head)->hh.tbl->num_buckets * sizeof(UT_hash_bucket))   +             \
           sizeof(UT_hash_table)                                   +             \
           (HASH_BLOOM_BYTELEN))) : 0U)

#ifdef NO_DECLTYPE
#define HASH_ITER(hh,head,el,tmp)                                                \
for(((el)=(head)), ((*(char**)(&(tmp)))=(char*)((head!=NULL)?(head)->hh.next:NULL)); \
  (el) != NULL; ((el)=(tmp)), ((*(char**)(&(tmp)))=(char*)((tmp!=NULL)?(tmp)->hh.next:NULL)))
#else
#define HASH_ITER(hh,head,el,tmp)                                                \
for(((el)=(head)), ((tmp)=DECLTYPE(el)((head!=NULL)?(head)->hh.next:NULL));      \
  (el) != NULL; ((el)=(tmp)), ((tmp)=DECLTYPE(el)((tmp!=NULL)?(tmp)->hh.next:NULL)))
#endif

/* obtain a count of items in the hash */
#define HASH_COUNT(head) HASH_CNT(hh,head)
#define HASH_CNT(hh,head) ((head != NULL)?((head)->hh.tbl->num_items):0U)

typedef struct UT_hash_bucket {
   struct UT_hash_handle *hh_head;
   unsigned count;

   /* expand_mult is normally set to 0. In this situation, the max chain length
    * threshold is enforced at its default value, HASH_BKT_CAPACITY_THRESH. (If
    * the bucket's chain exceeds this length, bucket expansion is triggered).
    * However, setting expand_mult to a non-zero value delays bucket expansion
    * (that would be triggered by additions to this particular bucket)
    * until its chain length reaches a *multiple* of HASH_BKT_CAPACITY_THRESH.
    * (The multiplier is simply expand_mult+1). The whole idea of this
    * multiplier is to reduce bucket expansions, since they are expensive, in
    * situations where we know that a particular bucket tends to be overused.
    * It is better to let its chain length grow to a longer yet-still-bounded
    * value, than to do an O(n) bucket expansion too often.
    */
   unsigned expand_mult;

} UT_hash_bucket;

/* random signature used only to find hash tables in external analysis */
#define HASH_SIGNATURE 0xa0111fe1u
#define HASH_BLOOM_SIGNATURE 0xb12220f2u

typedef struct UT_hash_table {
   UT_hash_bucket *buckets;
   unsigned num_buckets, log2_num_buckets;
   unsigned num_items;
   struct UT_hash_handle *tail; /* tail hh in app order, for fast append    */
   ptrdiff_t hho; /* hash handle offset (byte pos of hash handle in element */

   /* in an ideal situation (all buckets used equally), no bucket would have
    * more than ceil(#items/#buckets) items. that's the ideal chain length. */
   unsigned ideal_chain_maxlen;

   /* nonideal_items is the number of items in the hash whose chain position
    * exceeds the ideal chain maxlen. these items pay the penalty for an uneven
    * hash distribution; reaching them in a chain traversal takes >ideal steps */
   unsigned nonideal_items;

   /* ineffective expands occur when a bucket doubling was performed, but
    * afterward, more than half the items in the hash had nonideal chain
    * positions. If this happens on two consecutive expansions we inhibit any
    * further expansion, as it's not helping; this happens when the hash
    * function isn't a good fit for the key domain. When expansion is inhibited
    * the hash will still work, albeit no longer in constant time. */
   unsigned ineff_expands, noexpand;

   uint32_t signature; /* used only to find hash tables in external analysis */
#ifdef HASH_BLOOM
   uint32_t bloom_sig; /* used only to test bloom exists in external analysis */
   uint8_t *bloom_bv;
   uint8_t bloom_nbits;
#endif

} UT_hash_table;

typedef struct UT_hash_handle {
   struct UT_hash_table *tbl;
   void *prev;                       /* prev element in app order      */
   void *next;                       /* next element in app order      */
   struct UT_hash_handle *hh_prev;   /* previous hh in bucket order    */
   struct UT_hash_handle *hh_next;   /* next hh in bucket order        */
   const void *key;                  /* ptr to enclosing struct's key  */
   unsigned keylen;                  /* enclosing struct's key len     */
   unsigned hashv;                   /* result of hash-fcn(key)        */
} UT_hash_handle;

#endif /* UTHASH_H */
/*
Copyright (c) 2007-2017, Troy D. Hanson   http://troydhanson.github.com/uthash/
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef UTLIST_H
#define UTLIST_H

#define UTLIST_VERSION 2.0.2

#include <assert.h>

/*
 * This file contains macros to manipulate singly and doubly-linked lists.
 *
 * 1. LL_ macros:  singly-linked lists.
 * 2. DL_ macros:  doubly-linked lists.
 * 3. CDL_ macros: circular doubly-linked lists.
 *
 * To use singly-linked lists, your structure must have a "next" pointer.
 * To use doubly-linked lists, your structure must "prev" and "next" pointers.
 * Either way, the pointer to the head of the list must be initialized to NULL.
 *
 * ----------------.EXAMPLE -------------------------
 * struct item {
 *      int id;
 *      struct item *prev, *next;
 * }
 *
 * struct item *list = NULL:
 *
 * int main() {
 *      struct item *item;
 *      ... allocate and populate item ...
 *      DL_APPEND(list, item);
 * }
 * --------------------------------------------------
 *
 * For doubly-linked lists, the append and delete macros are O(1)
 * For singly-linked lists, append and delete are O(n) but prepend is O(1)
 * The sort macro is O(n log(n)) for all types of single/double/circular lists.
 */

/* These macros use decltype or the earlier __typeof GNU extension.
   As decltype is only available in newer compilers (VS2010 or gcc 4.3+
   when compiling c++ source) this code uses whatever method is needed
   or, for VS2008 where neither is available, uses casting workarounds. */
#if !defined(LDECLTYPE) && !defined(NO_DECLTYPE)
#if defined(_MSC_VER)   /* MS compiler */
#if _MSC_VER >= 1600 && defined(__cplusplus)  /* VS2010 or newer in C++ mode */
#define LDECLTYPE(x) decltype(x)
#else                   /* VS2008 or older (or VS2010 in C mode) */
#define NO_DECLTYPE
#endif
#elif defined(__BORLANDC__) || defined(__ICCARM__) || defined(__LCC__) || defined(__WATCOMC__)
#define NO_DECLTYPE
#else                   /* GNU, Sun and other compilers */
#define LDECLTYPE(x) __typeof(x)
#endif
#endif

/* for VS2008 we use some workarounds to get around the lack of decltype,
 * namely, we always reassign our tmp variable to the list head if we need
 * to dereference its prev/next pointers, and save/restore the real head.*/
#ifdef NO_DECLTYPE
#define IF_NO_DECLTYPE(x) x
#define LDECLTYPE(x) char*
#define UTLIST_SV(elt,list) _tmp = (char*)(list); {char **_alias = (char**)&(list); *_alias = (elt); }
#define UTLIST_NEXT(elt,list,next) ((char*)((list)->next))
#define UTLIST_NEXTASGN(elt,list,to,next) { char **_alias = (char**)&((list)->next); *_alias=(char*)(to); }
/* #define UTLIST_PREV(elt,list,prev) ((char*)((list)->prev)) */
#define UTLIST_PREVASGN(elt,list,to,prev) { char **_alias = (char**)&((list)->prev); *_alias=(char*)(to); }
#define UTLIST_RS(list) { char **_alias = (char**)&(list); *_alias=_tmp; }
#define UTLIST_CASTASGN(a,b) { char **_alias = (char**)&(a); *_alias=(char*)(b); }
#else
#define IF_NO_DECLTYPE(x)
#define UTLIST_SV(elt,list)
#define UTLIST_NEXT(elt,list,next) ((elt)->next)
#define UTLIST_NEXTASGN(elt,list,to,next) ((elt)->next)=(to)
/* #define UTLIST_PREV(elt,list,prev) ((elt)->prev) */
#define UTLIST_PREVASGN(elt,list,to,prev) ((elt)->prev)=(to)
#define UTLIST_RS(list)
#define UTLIST_CASTASGN(a,b) (a)=(b)
#endif

/******************************************************************************
 * The sort macro is an adaptation of Simon Tatham's O(n log(n)) mergesort    *
 * Unwieldy variable names used here to avoid shadowing passed-in variables.  *
 *****************************************************************************/
#define LL_SORT(list, cmp)                                                                     \
    LL_SORT2(list, cmp, next)

#define LL_SORT2(list, cmp, next)                                                              \
do {                                                                                           \
  LDECLTYPE(list) _ls_p;                                                                       \
  LDECLTYPE(list) _ls_q;                                                                       \
  LDECLTYPE(list) _ls_e;                                                                       \
  LDECLTYPE(list) _ls_tail;                                                                    \
  IF_NO_DECLTYPE(LDECLTYPE(list) _tmp;)                                                        \
  int _ls_insize, _ls_nmerges, _ls_psize, _ls_qsize, _ls_i, _ls_looping;                       \
  if (list) {                                                                                  \
    _ls_insize = 1;                                                                            \
    _ls_looping = 1;                                                                           \
    while (_ls_looping) {                                                                      \
      UTLIST_CASTASGN(_ls_p,list);                                                             \
      (list) = NULL;                                                                           \
      _ls_tail = NULL;                                                                         \
      _ls_nmerges = 0;                                                                         \
      while (_ls_p) {                                                                          \
        _ls_nmerges++;                                                                         \
        _ls_q = _ls_p;                                                                         \
        _ls_psize = 0;                                                                         \
        for (_ls_i = 0; _ls_i < _ls_insize; _ls_i++) {                                         \
          _ls_psize++;                                                                         \
          UTLIST_SV(_ls_q,list); _ls_q = UTLIST_NEXT(_ls_q,list,next); UTLIST_RS(list);        \
          if (!_ls_q) break;                                                                   \
        }                                                                                      \
        _ls_qsize = _ls_insize;                                                                \
        while (_ls_psize > 0 || (_ls_qsize > 0 && _ls_q)) {                                    \
          if (_ls_psize == 0) {                                                                \
            _ls_e = _ls_q; UTLIST_SV(_ls_q,list); _ls_q =                                      \
              UTLIST_NEXT(_ls_q,list,next); UTLIST_RS(list); _ls_qsize--;                      \
          } else if (_ls_qsize == 0 || !_ls_q) {                                               \
            _ls_e = _ls_p; UTLIST_SV(_ls_p,list); _ls_p =                                      \
              UTLIST_NEXT(_ls_p,list,next); UTLIST_RS(list); _ls_psize--;                      \
          } else if (cmp(_ls_p,_ls_q) <= 0) {                                                  \
            _ls_e = _ls_p; UTLIST_SV(_ls_p,list); _ls_p =                                      \
              UTLIST_NEXT(_ls_p,list,next); UTLIST_RS(list); _ls_psize--;                      \
          } else {                                                                             \
            _ls_e = _ls_q; UTLIST_SV(_ls_q,list); _ls_q =                                      \
              UTLIST_NEXT(_ls_q,list,next); UTLIST_RS(list); _ls_qsize--;                      \
          }                                                                                    \
          if (_ls_tail) {                                                                      \
            UTLIST_SV(_ls_tail,list); UTLIST_NEXTASGN(_ls_tail,list,_ls_e,next); UTLIST_RS(list); \
          } else {                                                                             \
            UTLIST_CASTASGN(list,_ls_e);                                                       \
          }                                                                                    \
          _ls_tail = _ls_e;                                                                    \
        }                                                                                      \
        _ls_p = _ls_q;                                                                         \
      }                                                                                        \
      if (_ls_tail) {                                                                          \
        UTLIST_SV(_ls_tail,list); UTLIST_NEXTASGN(_ls_tail,list,NULL,next); UTLIST_RS(list);   \
      }                                                                                        \
      if (_ls_nmerges <= 1) {                                                                  \
        _ls_looping=0;                                                                         \
      }                                                                                        \
      _ls_insize *= 2;                                                                         \
    }                                                                                          \
  }                                                                                            \
} while (0)


#define DL_SORT(list, cmp)                                                                     \
    DL_SORT2(list, cmp, prev, next)

#define DL_SORT2(list, cmp, prev, next)                                                        \
do {                                                                                           \
  LDECLTYPE(list) _ls_p;                                                                       \
  LDECLTYPE(list) _ls_q;                                                                       \
  LDECLTYPE(list) _ls_e;                                                                       \
  LDECLTYPE(list) _ls_tail;                                                                    \
  IF_NO_DECLTYPE(LDECLTYPE(list) _tmp;)                                                        \
  int _ls_insize, _ls_nmerges, _ls_psize, _ls_qsize, _ls_i, _ls_looping;                       \
  if (list) {                                                                                  \
    _ls_insize = 1;                                                                            \
    _ls_looping = 1;                                                                           \
    while (_ls_looping) {                                                                      \
      UTLIST_CASTASGN(_ls_p,list);                                                             \
      (list) = NULL;                                                                           \
      _ls_tail = NULL;                                                                         \
      _ls_nmerges = 0;                                                                         \
      while (_ls_p) {                                                                          \
        _ls_nmerges++;                                                                         \
        _ls_q = _ls_p;                                                                         \
        _ls_psize = 0;                                                                         \
        for (_ls_i = 0; _ls_i < _ls_insize; _ls_i++) {                                         \
          _ls_psize++;                                                                         \
          UTLIST_SV(_ls_q,list); _ls_q = UTLIST_NEXT(_ls_q,list,next); UTLIST_RS(list);        \
          if (!_ls_q) break;                                                                   \
        }                                                                                      \
        _ls_qsize = _ls_insize;                                                                \
        while ((_ls_psize > 0) || ((_ls_qsize > 0) && _ls_q)) {                                \
          if (_ls_psize == 0) {                                                                \
            _ls_e = _ls_q; UTLIST_SV(_ls_q,list); _ls_q =                                      \
              UTLIST_NEXT(_ls_q,list,next); UTLIST_RS(list); _ls_qsize--;                      \
          } else if ((_ls_qsize == 0) || (!_ls_q)) {                                           \
            _ls_e = _ls_p; UTLIST_SV(_ls_p,list); _ls_p =                                      \
              UTLIST_NEXT(_ls_p,list,next); UTLIST_RS(list); _ls_psize--;                      \
          } else if (cmp(_ls_p,_ls_q) <= 0) {                                                  \
            _ls_e = _ls_p; UTLIST_SV(_ls_p,list); _ls_p =                                      \
              UTLIST_NEXT(_ls_p,list,next); UTLIST_RS(list); _ls_psize--;                      \
          } else {                                                                             \
            _ls_e = _ls_q; UTLIST_SV(_ls_q,list); _ls_q =                                      \
              UTLIST_NEXT(_ls_q,list,next); UTLIST_RS(list); _ls_qsize--;                      \
          }                                                                                    \
          if (_ls_tail) {                                                                      \
            UTLIST_SV(_ls_tail,list); UTLIST_NEXTASGN(_ls_tail,list,_ls_e,next); UTLIST_RS(list); \
          } else {                                                                             \
            UTLIST_CASTASGN(list,_ls_e);                                                       \
          }                                                                                    \
          UTLIST_SV(_ls_e,list); UTLIST_PREVASGN(_ls_e,list,_ls_tail,prev); UTLIST_RS(list);   \
          _ls_tail = _ls_e;                                                                    \
        }                                                                                      \
        _ls_p = _ls_q;                                                                         \
      }                                                                                        \
      UTLIST_CASTASGN((list)->prev, _ls_tail);                                                 \
      UTLIST_SV(_ls_tail,list); UTLIST_NEXTASGN(_ls_tail,list,NULL,next); UTLIST_RS(list);     \
      if (_ls_nmerges <= 1) {                                                                  \
        _ls_looping=0;                                                                         \
      }                                                                                        \
      _ls_insize *= 2;                                                                         \
    }                                                                                          \
  }                                                                                            \
} while (0)

#define CDL_SORT(list, cmp)                                                                    \
    CDL_SORT2(list, cmp, prev, next)

#define CDL_SORT2(list, cmp, prev, next)                                                       \
do {                                                                                           \
  LDECLTYPE(list) _ls_p;                                                                       \
  LDECLTYPE(list) _ls_q;                                                                       \
  LDECLTYPE(list) _ls_e;                                                                       \
  LDECLTYPE(list) _ls_tail;                                                                    \
  LDECLTYPE(list) _ls_oldhead;                                                                 \
  LDECLTYPE(list) _tmp;                                                                        \
  int _ls_insize, _ls_nmerges, _ls_psize, _ls_qsize, _ls_i, _ls_looping;                       \
  if (list) {                                                                                  \
    _ls_insize = 1;                                                                            \
    _ls_looping = 1;                                                                           \
    while (_ls_looping) {                                                                      \
      UTLIST_CASTASGN(_ls_p,list);                                                             \
      UTLIST_CASTASGN(_ls_oldhead,list);                                                       \
      (list) = NULL;                                                                           \
      _ls_tail = NULL;                                                                         \
      _ls_nmerges = 0;                                                                         \
      while (_ls_p) {                                                                          \
        _ls_nmerges++;                                                                         \
        _ls_q = _ls_p;                                                                         \
        _ls_psize = 0;                                                                         \
        for (_ls_i = 0; _ls_i < _ls_insize; _ls_i++) {                                         \
          _ls_psize++;                                                                         \
          UTLIST_SV(_ls_q,list);                                                               \
          if (UTLIST_NEXT(_ls_q,list,next) == _ls_oldhead) {                                   \
            _ls_q = NULL;                                                                      \
          } else {                                                                             \
            _ls_q = UTLIST_NEXT(_ls_q,list,next);                                              \
          }                                                                                    \
          UTLIST_RS(list);                                                                     \
          if (!_ls_q) break;                                                                   \
        }                                                                                      \
        _ls_qsize = _ls_insize;                                                                \
        while (_ls_psize > 0 || (_ls_qsize > 0 && _ls_q)) {                                    \
          if (_ls_psize == 0) {                                                                \
            _ls_e = _ls_q; UTLIST_SV(_ls_q,list); _ls_q =                                      \
              UTLIST_NEXT(_ls_q,list,next); UTLIST_RS(list); _ls_qsize--;                      \
            if (_ls_q == _ls_oldhead) { _ls_q = NULL; }                                        \
          } else if (_ls_qsize == 0 || !_ls_q) {                                               \
            _ls_e = _ls_p; UTLIST_SV(_ls_p,list); _ls_p =                                      \
              UTLIST_NEXT(_ls_p,list,next); UTLIST_RS(list); _ls_psize--;                      \
            if (_ls_p == _ls_oldhead) { _ls_p = NULL; }                                        \
          } else if (cmp(_ls_p,_ls_q) <= 0) {                                                  \
            _ls_e = _ls_p; UTLIST_SV(_ls_p,list); _ls_p =                                      \
              UTLIST_NEXT(_ls_p,list,next); UTLIST_RS(list); _ls_psize--;                      \
            if (_ls_p == _ls_oldhead) { _ls_p = NULL; }                                        \
          } else {                                                                             \
            _ls_e = _ls_q; UTLIST_SV(_ls_q,list); _ls_q =                                      \
              UTLIST_NEXT(_ls_q,list,next); UTLIST_RS(list); _ls_qsize--;                      \
            if (_ls_q == _ls_oldhead) { _ls_q = NULL; }                                        \
          }                                                                                    \
          if (_ls_tail) {                                                                      \
            UTLIST_SV(_ls_tail,list); UTLIST_NEXTASGN(_ls_tail,list,_ls_e,next); UTLIST_RS(list); \
          } else {                                                                             \
            UTLIST_CASTASGN(list,_ls_e);                                                       \
          }                                                                                    \
          UTLIST_SV(_ls_e,list); UTLIST_PREVASGN(_ls_e,list,_ls_tail,prev); UTLIST_RS(list);   \
          _ls_tail = _ls_e;                                                                    \
        }                                                                                      \
        _ls_p = _ls_q;                                                                         \
      }                                                                                        \
      UTLIST_CASTASGN((list)->prev,_ls_tail);                                                  \
      UTLIST_CASTASGN(_tmp,list);                                                              \
      UTLIST_SV(_ls_tail,list); UTLIST_NEXTASGN(_ls_tail,list,_tmp,next); UTLIST_RS(list);     \
      if (_ls_nmerges <= 1) {                                                                  \
        _ls_looping=0;                                                                         \
      }                                                                                        \
      _ls_insize *= 2;                                                                         \
    }                                                                                          \
  }                                                                                            \
} while (0)

/******************************************************************************
 * singly linked list macros (non-circular)                                   *
 *****************************************************************************/
#define LL_PREPEND(head,add)                                                                   \
    LL_PREPEND2(head,add,next)

#define LL_PREPEND2(head,add,next)                                                             \
do {                                                                                           \
  (add)->next = (head);                                                                        \
  (head) = (add);                                                                              \
} while (0)

#define LL_CONCAT(head1,head2)                                                                 \
    LL_CONCAT2(head1,head2,next)

#define LL_CONCAT2(head1,head2,next)                                                           \
do {                                                                                           \
  LDECLTYPE(head1) _tmp;                                                                       \
  if (head1) {                                                                                 \
    _tmp = (head1);                                                                            \
    while (_tmp->next) { _tmp = _tmp->next; }                                                  \
    _tmp->next=(head2);                                                                        \
  } else {                                                                                     \
    (head1)=(head2);                                                                           \
  }                                                                                            \
} while (0)

#define LL_APPEND(head,add)                                                                    \
    LL_APPEND2(head,add,next)

#define LL_APPEND2(head,add,next)                                                              \
do {                                                                                           \
  LDECLTYPE(head) _tmp;                                                                        \
  (add)->next=NULL;                                                                            \
  if (head) {                                                                                  \
    _tmp = (head);                                                                             \
    while (_tmp->next) { _tmp = _tmp->next; }                                                  \
    _tmp->next=(add);                                                                          \
  } else {                                                                                     \
    (head)=(add);                                                                              \
  }                                                                                            \
} while (0)

#define LL_INSERT_INORDER(head,add,cmp)                                                        \
    LL_INSERT_INORDER2(head,add,cmp,next)

#define LL_INSERT_INORDER2(head,add,cmp,next)                                                  \
do {                                                                                           \
  LDECLTYPE(head) _tmp;                                                                        \
  if (head) {                                                                                  \
    LL_LOWER_BOUND(head, _tmp, add, cmp);                                                      \
    LL_APPEND_ELEM(head, _tmp, add);                                                           \
  } else {                                                                                     \
    (head) = (add);                                                                            \
    (head)->next = NULL;                                                                       \
  }                                                                                            \
} while (0)

#define LL_LOWER_BOUND(head,elt,like,cmp)                                                      \
    LL_LOWER_BOUND2(head,elt,like,cmp,next)

#define LL_LOWER_BOUND2(head,elt,like,cmp,next)                                                \
  do {                                                                                         \
    if ((head) == NULL || (cmp(head, like)) >= 0) {                                            \
      (elt) = NULL;                                                                            \
    } else {                                                                                   \
      for ((elt) = (head); (elt)->next != NULL; (elt) = (elt)->next) {                         \
        if (cmp((elt)->next, like) >= 0) {                                                     \
          break;                                                                               \
        }                                                                                      \
      }                                                                                        \
    }                                                                                          \
  } while (0)

#define LL_DELETE(head,del)                                                                    \
    LL_DELETE2(head,del,next)

#define LL_DELETE2(head,del,next)                                                              \
do {                                                                                           \
  LDECLTYPE(head) _tmp;                                                                        \
  if ((head) == (del)) {                                                                       \
    (head)=(head)->next;                                                                       \
  } else {                                                                                     \
    _tmp = (head);                                                                             \
    while (_tmp->next && (_tmp->next != (del))) {                                              \
      _tmp = _tmp->next;                                                                       \
    }                                                                                          \
    if (_tmp->next) {                                                                          \
      _tmp->next = (del)->next;                                                                \
    }                                                                                          \
  }                                                                                            \
} while (0)

#define LL_COUNT(head,el,counter)                                                              \
    LL_COUNT2(head,el,counter,next)                                                            \

#define LL_COUNT2(head,el,counter,next)                                                        \
do {                                                                                           \
  (counter) = 0;                                                                               \
  LL_FOREACH2(head,el,next) { ++(counter); }                                                   \
} while (0)

#define LL_FOREACH(head,el)                                                                    \
    LL_FOREACH2(head,el,next)

#define LL_FOREACH2(head,el,next)                                                              \
    for ((el) = (head); el; (el) = (el)->next)

#define LL_FOREACH_SAFE(head,el,tmp)                                                           \
    LL_FOREACH_SAFE2(head,el,tmp,next)

#define LL_FOREACH_SAFE2(head,el,tmp,next)                                                     \
  for ((el) = (head); (el) && ((tmp) = (el)->next, 1); (el) = (tmp))

#define LL_SEARCH_SCALAR(head,out,field,val)                                                   \
    LL_SEARCH_SCALAR2(head,out,field,val,next)

#define LL_SEARCH_SCALAR2(head,out,field,val,next)                                             \
do {                                                                                           \
    LL_FOREACH2(head,out,next) {                                                               \
      if ((out)->field == (val)) break;                                                        \
    }                                                                                          \
} while (0)

#define LL_SEARCH(head,out,elt,cmp)                                                            \
    LL_SEARCH2(head,out,elt,cmp,next)

#define LL_SEARCH2(head,out,elt,cmp,next)                                                      \
do {                                                                                           \
    LL_FOREACH2(head,out,next) {                                                               \
      if ((cmp(out,elt))==0) break;                                                            \
    }                                                                                          \
} while (0)

#define LL_REPLACE_ELEM2(head, el, add, next)                                                  \
do {                                                                                           \
 LDECLTYPE(head) _tmp;                                                                         \
 assert((head) != NULL);                                                                       \
 assert((el) != NULL);                                                                         \
 assert((add) != NULL);                                                                        \
 (add)->next = (el)->next;                                                                     \
 if ((head) == (el)) {                                                                         \
  (head) = (add);                                                                              \
 } else {                                                                                      \
  _tmp = (head);                                                                               \
  while (_tmp->next && (_tmp->next != (el))) {                                                 \
   _tmp = _tmp->next;                                                                          \
  }                                                                                            \
  if (_tmp->next) {                                                                            \
    _tmp->next = (add);                                                                        \
  }                                                                                            \
 }                                                                                             \
} while (0)

#define LL_REPLACE_ELEM(head, el, add)                                                         \
    LL_REPLACE_ELEM2(head, el, add, next)

#define LL_PREPEND_ELEM2(head, el, add, next)                                                  \
do {                                                                                           \
 if (el) {                                                                                     \
  LDECLTYPE(head) _tmp;                                                                        \
  assert((head) != NULL);                                                                      \
  assert((add) != NULL);                                                                       \
  (add)->next = (el);                                                                          \
  if ((head) == (el)) {                                                                        \
   (head) = (add);                                                                             \
  } else {                                                                                     \
   _tmp = (head);                                                                              \
   while (_tmp->next && (_tmp->next != (el))) {                                                \
    _tmp = _tmp->next;                                                                         \
   }                                                                                           \
   if (_tmp->next) {                                                                           \
     _tmp->next = (add);                                                                       \
   }                                                                                           \
  }                                                                                            \
 } else {                                                                                      \
  LL_APPEND2(head, add, next);                                                                 \
 }                                                                                             \
} while (0)                                                                                    \

#define LL_PREPEND_ELEM(head, el, add)                                                         \
    LL_PREPEND_ELEM2(head, el, add, next)

#define LL_APPEND_ELEM2(head, el, add, next)                                                   \
do {                                                                                           \
 if (el) {                                                                                     \
  assert((head) != NULL);                                                                      \
  assert((add) != NULL);                                                                       \
  (add)->next = (el)->next;                                                                    \
  (el)->next = (add);                                                                          \
 } else {                                                                                      \
  LL_PREPEND2(head, add, next);                                                                \
 }                                                                                             \
} while (0)                                                                                    \

#define LL_APPEND_ELEM(head, el, add)                                                          \
    LL_APPEND_ELEM2(head, el, add, next)

#ifdef NO_DECLTYPE
/* Here are VS2008 / NO_DECLTYPE replacements for a few functions */

#undef LL_CONCAT2
#define LL_CONCAT2(head1,head2,next)                                                           \
do {                                                                                           \
  char *_tmp;                                                                                  \
  if (head1) {                                                                                 \
    _tmp = (char*)(head1);                                                                     \
    while ((head1)->next) { (head1) = (head1)->next; }                                         \
    (head1)->next = (head2);                                                                   \
    UTLIST_RS(head1);                                                                          \
  } else {                                                                                     \
    (head1)=(head2);                                                                           \
  }                                                                                            \
} while (0)

#undef LL_APPEND2
#define LL_APPEND2(head,add,next)                                                              \
do {                                                                                           \
  if (head) {                                                                                  \
    (add)->next = head;     /* use add->next as a temp variable */                             \
    while ((add)->next->next) { (add)->next = (add)->next->next; }                             \
    (add)->next->next=(add);                                                                   \
  } else {                                                                                     \
    (head)=(add);                                                                              \
  }                                                                                            \
  (add)->next=NULL;                                                                            \
} while (0)

#undef LL_INSERT_INORDER2
#define LL_INSERT_INORDER2(head,add,cmp,next)                                                  \
do {                                                                                           \
  if ((head) == NULL || (cmp(head, add)) >= 0) {                                               \
    (add)->next = (head);                                                                      \
    (head) = (add);                                                                            \
  } else {                                                                                     \
    char *_tmp = (char*)(head);                                                                \
    while ((head)->next != NULL && (cmp((head)->next, add)) < 0) {                             \
      (head) = (head)->next;                                                                   \
    }                                                                                          \
    (add)->next = (head)->next;                                                                \
    (head)->next = (add);                                                                      \
    UTLIST_RS(head);                                                                           \
  }                                                                                            \
} while (0)

#undef LL_DELETE2
#define LL_DELETE2(head,del,next)                                                              \
do {                                                                                           \
  if ((head) == (del)) {                                                                       \
    (head)=(head)->next;                                                                       \
  } else {                                                                                     \
    char *_tmp = (char*)(head);                                                                \
    while ((head)->next && ((head)->next != (del))) {                                          \
      (head) = (head)->next;                                                                   \
    }                                                                                          \
    if ((head)->next) {                                                                        \
      (head)->next = ((del)->next);                                                            \
    }                                                                                          \
    UTLIST_RS(head);                                                                           \
  }                                                                                            \
} while (0)

#undef LL_REPLACE_ELEM2
#define LL_REPLACE_ELEM2(head, el, add, next)                                                  \
do {                                                                                           \
  assert((head) != NULL);                                                                      \
  assert((el) != NULL);                                                                        \
  assert((add) != NULL);                                                                       \
  if ((head) == (el)) {                                                                        \
    (head) = (add);                                                                            \
  } else {                                                                                     \
    (add)->next = head;                                                                        \
    while ((add)->next->next && ((add)->next->next != (el))) {                                 \
      (add)->next = (add)->next->next;                                                         \
    }                                                                                          \
    if ((add)->next->next) {                                                                   \
      (add)->next->next = (add);                                                               \
    }                                                                                          \
  }                                                                                            \
  (add)->next = (el)->next;                                                                    \
} while (0)

#undef LL_PREPEND_ELEM2
#define LL_PREPEND_ELEM2(head, el, add, next)                                                  \
do {                                                                                           \
  if (el) {                                                                                    \
    assert((head) != NULL);                                                                    \
    assert((add) != NULL);                                                                     \
    if ((head) == (el)) {                                                                      \
      (head) = (add);                                                                          \
    } else {                                                                                   \
      (add)->next = (head);                                                                    \
      while ((add)->next->next && ((add)->next->next != (el))) {                               \
        (add)->next = (add)->next->next;                                                       \
      }                                                                                        \
      if ((add)->next->next) {                                                                 \
        (add)->next->next = (add);                                                             \
      }                                                                                        \
    }                                                                                          \
    (add)->next = (el);                                                                        \
  } else {                                                                                     \
    LL_APPEND2(head, add, next);                                                               \
  }                                                                                            \
} while (0)                                                                                    \

#endif /* NO_DECLTYPE */

/******************************************************************************
 * doubly linked list macros (non-circular)                                   *
 *****************************************************************************/
#define DL_PREPEND(head,add)                                                                   \
    DL_PREPEND2(head,add,prev,next)

#define DL_PREPEND2(head,add,prev,next)                                                        \
do {                                                                                           \
 (add)->next = (head);                                                                         \
 if (head) {                                                                                   \
   (add)->prev = (head)->prev;                                                                 \
   (head)->prev = (add);                                                                       \
 } else {                                                                                      \
   (add)->prev = (add);                                                                        \
 }                                                                                             \
 (head) = (add);                                                                               \
} while (0)

#define DL_APPEND(head,add)                                                                    \
    DL_APPEND2(head,add,prev,next)

#define DL_APPEND2(head,add,prev,next)                                                         \
do {                                                                                           \
  if (head) {                                                                                  \
      (add)->prev = (head)->prev;                                                              \
      (head)->prev->next = (add);                                                              \
      (head)->prev = (add);                                                                    \
      (add)->next = NULL;                                                                      \
  } else {                                                                                     \
      (head)=(add);                                                                            \
      (head)->prev = (head);                                                                   \
      (head)->next = NULL;                                                                     \
  }                                                                                            \
} while (0)

#define DL_INSERT_INORDER(head,add,cmp)                                                        \
    DL_INSERT_INORDER2(head,add,cmp,next)

#define DL_INSERT_INORDER2(head,add,cmp,next)                                                  \
do {                                                                                           \
  LDECLTYPE(head) _tmp;                                                                        \
  if (head) {                                                                                  \
    DL_LOWER_BOUND(head, _tmp, add, cmp);                                                      \
    DL_APPEND_ELEM(head, _tmp, add);                                                           \
  } else {                                                                                     \
    (head) = (add);                                                                            \
    (head)->prev = (head);                                                                     \
    (head)->next = NULL;                                                                       \
  }                                                                                            \
} while (0)

#define DL_LOWER_BOUND(head,elt,like,cmp)                                                      \
    DL_LOWER_BOUND2(head,elt,like,cmp,next)

#define DL_LOWER_BOUND2(head,elt,like,cmp,next)                                                \
do {                                                                                           \
  if ((head) == NULL || (cmp(head, like)) >= 0) {                                              \
    (elt) = NULL;                                                                              \
  } else {                                                                                     \
    for ((elt) = (head); (elt)->next != NULL; (elt) = (elt)->next) {                           \
      if ((cmp((elt)->next, like)) >= 0) {                                                     \
        break;                                                                                 \
      }                                                                                        \
    }                                                                                          \
  }                                                                                            \
} while (0)

#define DL_CONCAT(head1,head2)                                                                 \
    DL_CONCAT2(head1,head2,prev,next)

#define DL_CONCAT2(head1,head2,prev,next)                                                      \
do {                                                                                           \
  LDECLTYPE(head1) _tmp;                                                                       \
  if (head2) {                                                                                 \
    if (head1) {                                                                               \
        UTLIST_CASTASGN(_tmp, (head2)->prev);                                                  \
        (head2)->prev = (head1)->prev;                                                         \
        (head1)->prev->next = (head2);                                                         \
        UTLIST_CASTASGN((head1)->prev, _tmp);                                                  \
    } else {                                                                                   \
        (head1)=(head2);                                                                       \
    }                                                                                          \
  }                                                                                            \
} while (0)

#define DL_DELETE(head,del)                                                                    \
    DL_DELETE2(head,del,prev,next)

#define DL_DELETE2(head,del,prev,next)                                                         \
do {                                                                                           \
  assert((head) != NULL);                                                                      \
  assert((del)->prev != NULL);                                                                 \
  if ((del)->prev == (del)) {                                                                  \
      (head)=NULL;                                                                             \
  } else if ((del)==(head)) {                                                                  \
      (del)->next->prev = (del)->prev;                                                         \
      (head) = (del)->next;                                                                    \
  } else {                                                                                     \
      (del)->prev->next = (del)->next;                                                         \
      if ((del)->next) {                                                                       \
          (del)->next->prev = (del)->prev;                                                     \
      } else {                                                                                 \
          (head)->prev = (del)->prev;                                                          \
      }                                                                                        \
  }                                                                                            \
} while (0)

#define DL_COUNT(head,el,counter)                                                              \
    DL_COUNT2(head,el,counter,next)                                                            \

#define DL_COUNT2(head,el,counter,next)                                                        \
do {                                                                                           \
  (counter) = 0;                                                                               \
  DL_FOREACH2(head,el,next) { ++(counter); }                                                   \
} while (0)

#define DL_FOREACH(head,el)                                                                    \
    DL_FOREACH2(head,el,next)

#define DL_FOREACH2(head,el,next)                                                              \
    for ((el) = (head); el; (el) = (el)->next)

/* this version is safe for deleting the elements during iteration */
#define DL_FOREACH_SAFE(head,el,tmp)                                                           \
    DL_FOREACH_SAFE2(head,el,tmp,next)

#define DL_FOREACH_SAFE2(head,el,tmp,next)                                                     \
  for ((el) = (head); (el) && ((tmp) = (el)->next, 1); (el) = (tmp))

/* these are identical to their singly-linked list counterparts */
#define DL_SEARCH_SCALAR LL_SEARCH_SCALAR
#define DL_SEARCH LL_SEARCH
#define DL_SEARCH_SCALAR2 LL_SEARCH_SCALAR2
#define DL_SEARCH2 LL_SEARCH2

#define DL_REPLACE_ELEM2(head, el, add, prev, next)                                            \
do {                                                                                           \
 assert((head) != NULL);                                                                       \
 assert((el) != NULL);                                                                         \
 assert((add) != NULL);                                                                        \
 if ((head) == (el)) {                                                                         \
  (head) = (add);                                                                              \
  (add)->next = (el)->next;                                                                    \
  if ((el)->next == NULL) {                                                                    \
   (add)->prev = (add);                                                                        \
  } else {                                                                                     \
   (add)->prev = (el)->prev;                                                                   \
   (add)->next->prev = (add);                                                                  \
  }                                                                                            \
 } else {                                                                                      \
  (add)->next = (el)->next;                                                                    \
  (add)->prev = (el)->prev;                                                                    \
  (add)->prev->next = (add);                                                                   \
  if ((el)->next == NULL) {                                                                    \
   (head)->prev = (add);                                                                       \
  } else {                                                                                     \
   (add)->next->prev = (add);                                                                  \
  }                                                                                            \
 }                                                                                             \
} while (0)

#define DL_REPLACE_ELEM(head, el, add)                                                         \
    DL_REPLACE_ELEM2(head, el, add, prev, next)

#define DL_PREPEND_ELEM2(head, el, add, prev, next)                                            \
do {                                                                                           \
 if (el) {                                                                                     \
  assert((head) != NULL);                                                                      \
  assert((add) != NULL);                                                                       \
  (add)->next = (el);                                                                          \
  (add)->prev = (el)->prev;                                                                    \
  (el)->prev = (add);                                                                          \
  if ((head) == (el)) {                                                                        \
   (head) = (add);                                                                             \
  } else {                                                                                     \
   (add)->prev->next = (add);                                                                  \
  }                                                                                            \
 } else {                                                                                      \
  DL_APPEND2(head, add, prev, next);                                                           \
 }                                                                                             \
} while (0)                                                                                    \

#define DL_PREPEND_ELEM(head, el, add)                                                         \
    DL_PREPEND_ELEM2(head, el, add, prev, next)

#define DL_APPEND_ELEM2(head, el, add, prev, next)                                             \
do {                                                                                           \
 if (el) {                                                                                     \
  assert((head) != NULL);                                                                      \
  assert((add) != NULL);                                                                       \
  (add)->next = (el)->next;                                                                    \
  (add)->prev = (el);                                                                          \
  (el)->next = (add);                                                                          \
  if ((add)->next) {                                                                           \
   (add)->next->prev = (add);                                                                  \
  } else {                                                                                     \
   (head)->prev = (add);                                                                       \
  }                                                                                            \
 } else {                                                                                      \
  DL_PREPEND2(head, add, prev, next);                                                          \
 }                                                                                             \
} while (0)                                                                                    \

#define DL_APPEND_ELEM(head, el, add)                                                          \
   DL_APPEND_ELEM2(head, el, add, prev, next)

#ifdef NO_DECLTYPE
/* Here are VS2008 / NO_DECLTYPE replacements for a few functions */

#undef DL_INSERT_INORDER2
#define DL_INSERT_INORDER2(head,add,cmp,next)                                                  \
do {                                                                                           \
  if ((head) == NULL) {                                                                        \
    (add)->prev = (add);                                                                       \
    (add)->next = NULL;                                                                        \
    (head) = (add);                                                                            \
  } else if ((cmp(head, add)) >= 0) {                                                          \
    (add)->prev = (head)->prev;                                                                \
    (add)->next = (head);                                                                      \
    (head)->prev = (add);                                                                      \
    (head) = (add);                                                                            \
  } else {                                                                                     \
    char *_tmp = (char*)(head);                                                                \
    while ((char*)(head)->next != _tmp && (cmp((head)->next, add)) < 0) {                      \
      (head) = (head)->next;                                                                   \
    }                                                                                          \
    (add)->prev = (head);                                                                      \
    (add)->next = (head)->next;                                                                \
    (head)->next = (add);                                                                      \
    UTLIST_RS(head);                                                                           \
    if ((add)->next) {                                                                         \
      (add)->next->prev = (add);                                                               \
    } else {                                                                                   \
      (head)->prev = (add);                                                                    \
    }                                                                                          \
  }                                                                                            \
} while (0)
#endif /* NO_DECLTYPE */

/******************************************************************************
 * circular doubly linked list macros                                         *
 *****************************************************************************/
#define CDL_APPEND(head,add)                                                                   \
    CDL_APPEND2(head,add,prev,next)

#define CDL_APPEND2(head,add,prev,next)                                                        \
do {                                                                                           \
 if (head) {                                                                                   \
   (add)->prev = (head)->prev;                                                                 \
   (add)->next = (head);                                                                       \
   (head)->prev = (add);                                                                       \
   (add)->prev->next = (add);                                                                  \
 } else {                                                                                      \
   (add)->prev = (add);                                                                        \
   (add)->next = (add);                                                                        \
   (head) = (add);                                                                             \
 }                                                                                             \
} while (0)

#define CDL_PREPEND(head,add)                                                                  \
    CDL_PREPEND2(head,add,prev,next)

#define CDL_PREPEND2(head,add,prev,next)                                                       \
do {                                                                                           \
 if (head) {                                                                                   \
   (add)->prev = (head)->prev;                                                                 \
   (add)->next = (head);                                                                       \
   (head)->prev = (add);                                                                       \
   (add)->prev->next = (add);                                                                  \
 } else {                                                                                      \
   (add)->prev = (add);                                                                        \
   (add)->next = (add);                                                                        \
 }                                                                                             \
 (head) = (add);                                                                               \
} while (0)

#define CDL_INSERT_INORDER(head,add,cmp)                                                       \
    CDL_INSERT_INORDER2(head,add,cmp,next)

#define CDL_INSERT_INORDER2(head,add,cmp,next)                                                 \
do {                                                                                           \
  LDECLTYPE(head) _tmp;                                                                        \
  if (head) {                                                                                  \
    CDL_LOWER_BOUND(head, _tmp, add, cmp);                                                     \
    CDL_APPEND_ELEM(head, _tmp, add);                                                          \
  } else {                                                                                     \
    (head) = (add);                                                                            \
    (head)->next = (head);                                                                     \
    (head)->prev = (head);                                                                     \
  }                                                                                            \
} while (0)

#define CDL_LOWER_BOUND(head,elt,like,cmp)                                                     \
    CDL_LOWER_BOUND2(head,elt,like,cmp,next)

#define CDL_LOWER_BOUND2(head,elt,like,cmp,next)                                               \
do {                                                                                           \
  if ((head) == NULL || (cmp(head, like)) >= 0) {                                              \
    (elt) = NULL;                                                                              \
  } else {                                                                                     \
    for ((elt) = (head); (elt)->next != (head); (elt) = (elt)->next) {                         \
      if ((cmp((elt)->next, like)) >= 0) {                                                     \
        break;                                                                                 \
      }                                                                                        \
    }                                                                                          \
  }                                                                                            \
} while (0)

#define CDL_DELETE(head,del)                                                                   \
    CDL_DELETE2(head,del,prev,next)

#define CDL_DELETE2(head,del,prev,next)                                                        \
do {                                                                                           \
  if (((head)==(del)) && ((head)->next == (head))) {                                           \
      (head) = NULL;                                                                           \
  } else {                                                                                     \
     (del)->next->prev = (del)->prev;                                                          \
     (del)->prev->next = (del)->next;                                                          \
     if ((del) == (head)) (head)=(del)->next;                                                  \
  }                                                                                            \
} while (0)

#define CDL_COUNT(head,el,counter)                                                             \
    CDL_COUNT2(head,el,counter,next)                                                           \

#define CDL_COUNT2(head, el, counter,next)                                                     \
do {                                                                                           \
  (counter) = 0;                                                                               \
  CDL_FOREACH2(head,el,next) { ++(counter); }                                                  \
} while (0)

#define CDL_FOREACH(head,el)                                                                   \
    CDL_FOREACH2(head,el,next)

#define CDL_FOREACH2(head,el,next)                                                             \
    for ((el)=(head);el;(el)=(((el)->next==(head)) ? NULL : (el)->next))

#define CDL_FOREACH_SAFE(head,el,tmp1,tmp2)                                                    \
    CDL_FOREACH_SAFE2(head,el,tmp1,tmp2,prev,next)

#define CDL_FOREACH_SAFE2(head,el,tmp1,tmp2,prev,next)                                         \
  for ((el) = (head), (tmp1) = (head) ? (head)->prev : NULL;                                   \
       (el) && ((tmp2) = (el)->next, 1);                                                       \
       (el) = ((el) == (tmp1) ? NULL : (tmp2)))

#define CDL_SEARCH_SCALAR(head,out,field,val)                                                  \
    CDL_SEARCH_SCALAR2(head,out,field,val,next)

#define CDL_SEARCH_SCALAR2(head,out,field,val,next)                                            \
do {                                                                                           \
    CDL_FOREACH2(head,out,next) {                                                              \
      if ((out)->field == (val)) break;                                                        \
    }                                                                                          \
} while (0)

#define CDL_SEARCH(head,out,elt,cmp)                                                           \
    CDL_SEARCH2(head,out,elt,cmp,next)

#define CDL_SEARCH2(head,out,elt,cmp,next)                                                     \
do {                                                                                           \
    CDL_FOREACH2(head,out,next) {                                                              \
      if ((cmp(out,elt))==0) break;                                                            \
    }                                                                                          \
} while (0)

#define CDL_REPLACE_ELEM2(head, el, add, prev, next)                                           \
do {                                                                                           \
 assert((head) != NULL);                                                                       \
 assert((el) != NULL);                                                                         \
 assert((add) != NULL);                                                                        \
 if ((el)->next == (el)) {                                                                     \
  (add)->next = (add);                                                                         \
  (add)->prev = (add);                                                                         \
  (head) = (add);                                                                              \
 } else {                                                                                      \
  (add)->next = (el)->next;                                                                    \
  (add)->prev = (el)->prev;                                                                    \
  (add)->next->prev = (add);                                                                   \
  (add)->prev->next = (add);                                                                   \
  if ((head) == (el)) {                                                                        \
   (head) = (add);                                                                             \
  }                                                                                            \
 }                                                                                             \
} while (0)

#define CDL_REPLACE_ELEM(head, el, add)                                                        \
    CDL_REPLACE_ELEM2(head, el, add, prev, next)

#define CDL_PREPEND_ELEM2(head, el, add, prev, next)                                           \
do {                                                                                           \
  if (el) {                                                                                    \
    assert((head) != NULL);                                                                    \
    assert((add) != NULL);                                                                     \
    (add)->next = (el);                                                                        \
    (add)->prev = (el)->prev;                                                                  \
    (el)->prev = (add);                                                                        \
    (add)->prev->next = (add);                                                                 \
    if ((head) == (el)) {                                                                      \
      (head) = (add);                                                                          \
    }                                                                                          \
  } else {                                                                                     \
    CDL_APPEND2(head, add, prev, next);                                                        \
  }                                                                                            \
} while (0)

#define CDL_PREPEND_ELEM(head, el, add)                                                        \
    CDL_PREPEND_ELEM2(head, el, add, prev, next)

#define CDL_APPEND_ELEM2(head, el, add, prev, next)                                            \
do {                                                                                           \
 if (el) {                                                                                     \
  assert((head) != NULL);                                                                      \
  assert((add) != NULL);                                                                       \
  (add)->next = (el)->next;                                                                    \
  (add)->prev = (el);                                                                          \
  (el)->next = (add);                                                                          \
  (add)->next->prev = (add);                                                                   \
 } else {                                                                                      \
  CDL_PREPEND2(head, add, prev, next);                                                         \
 }                                                                                             \
} while (0)

#define CDL_APPEND_ELEM(head, el, add)                                                         \
    CDL_APPEND_ELEM2(head, el, add, prev, next)

#ifdef NO_DECLTYPE
/* Here are VS2008 / NO_DECLTYPE replacements for a few functions */

#undef CDL_INSERT_INORDER2
#define CDL_INSERT_INORDER2(head,add,cmp,next)                                                 \
do {                                                                                           \
  if ((head) == NULL) {                                                                        \
    (add)->prev = (add);                                                                       \
    (add)->next = (add);                                                                       \
    (head) = (add);                                                                            \
  } else if ((cmp(head, add)) >= 0) {                                                          \
    (add)->prev = (head)->prev;                                                                \
    (add)->next = (head);                                                                      \
    (add)->prev->next = (add);                                                                 \
    (head)->prev = (add);                                                                      \
    (head) = (add);                                                                            \
  } else {                                                                                     \
    char *_tmp = (char*)(head);                                                                \
    while ((char*)(head)->next != _tmp && (cmp((head)->next, add)) < 0) {                      \
      (head) = (head)->next;                                                                   \
    }                                                                                          \
    (add)->prev = (head);                                                                      \
    (add)->next = (head)->next;                                                                \
    (add)->next->prev = (add);                                                                 \
    (head)->next = (add);                                                                      \
    UTLIST_RS(head);                                                                           \
  }                                                                                            \
} while (0)
#endif /* NO_DECLTYPE */

#endif /* UTLIST_H */

/* address.c -- representation of network addresses
 *
 * Copyright (C) 2015-2016,2019 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_config.h"

#if !defined(WITH_CONTIKI) && !defined(WITH_LWIP)
#ifdef HAVE_ASSERT_H
#include <assert.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif

#include "address.h"

#ifdef RIOT_VERSION
/* FIXME */
#define IN_MULTICAST(Address) (0)
#endif /* RIOT_VERSION */

int
coap_address_equals(const coap_address_t *a, const coap_address_t *b) {
  assert(a); assert(b);

  if (a->size != b->size || a->addr.sa.sa_family != b->addr.sa.sa_family)
    return 0;

  /* need to compare only relevant parts of sockaddr_in6 */
 switch (a->addr.sa.sa_family) {
 case AF_INET:
   return
     a->addr.sin.sin_port == b->addr.sin.sin_port &&
     memcmp(&a->addr.sin.sin_addr, &b->addr.sin.sin_addr,
            sizeof(struct in_addr)) == 0;
 case AF_INET6:
   return a->addr.sin6.sin6_port == b->addr.sin6.sin6_port &&
     memcmp(&a->addr.sin6.sin6_addr, &b->addr.sin6.sin6_addr,
            sizeof(struct in6_addr)) == 0;
 default: /* fall through and signal error */
   ;
 }
 return 0;
}

int coap_is_mcast(const coap_address_t *a) {
  if (!a)
    return 0;

 switch (a->addr.sa.sa_family) {
 case AF_INET:
   return IN_MULTICAST(ntohl(a->addr.sin.sin_addr.s_addr));
 case  AF_INET6:
   return IN6_IS_ADDR_MULTICAST(&a->addr.sin6.sin6_addr);
 default:  /* fall through and signal error */
   ;
  }
 return 0;
}
#else /* !defined(WITH_CONTIKI) && !defined(WITH_LWIP) */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void dummy(void) {
}

#endif /* !defined(WITH_CONTIKI) && !defined(WITH_LWIP) */
/* async.c -- state management for asynchronous messages
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file async.c
 * @brief state management for asynchronous messages
 */

#ifndef WITHOUT_ASYNC

#include "coap_config.h"
#include "coap.h"
#include "async.h"
#include "coap_debug.h"
#include "mem.h"
#include "utlist.h"

/* utlist-style macros for searching pairs in linked lists */
#define SEARCH_PAIR(head,out,field1,val1,field2,val2)   \
  SEARCH_PAIR2(head,out,field1,val1,field2,val2,next)

#define SEARCH_PAIR2(head,out,field1,val1,field2,val2,next)             \
  do {                                                                  \
    LL_FOREACH2(head,out,next) {                                        \
      if ((out)->field1 == (val1) && (out)->field2 == (val2)) break;    \
    }                                                                   \
} while(0)

coap_async_state_t *
coap_register_async(coap_context_t *context, coap_session_t *session,
                    coap_pdu_t *request, unsigned char flags, void *data) {
  coap_async_state_t *s;
  coap_tid_t id = request->tid;

  SEARCH_PAIR(context->async_state,s,session,session,id,id);

  if (s != NULL) {
    /* We must return NULL here as the caller must know that he is
     * responsible for releasing @p data. */
    coap_log(LOG_DEBUG,
         "asynchronous state for transaction %d already registered\n", id);
    return NULL;
  }

  /* store information for handling the asynchronous task */
  s = (coap_async_state_t *)coap_malloc(sizeof(coap_async_state_t));
  if (!s) {
    coap_log(LOG_CRIT, "coap_register_async: insufficient memory\n");
    return NULL;
  }

  memset(s, 0, sizeof(coap_async_state_t));

  /* set COAP_ASYNC_CONFIRM according to request's type */
  s->flags = flags & ~COAP_ASYNC_CONFIRM;
  if (request->type == COAP_MESSAGE_CON)
    s->flags |= COAP_ASYNC_CONFIRM;

  s->appdata = data;
  s->session = coap_session_reference( session );
  s->id = id;

  if (request->token_length) {
    /* A token can be up to 8 bytes */
    s->tokenlen = (request->token_length > 8) ? 8 : request->token_length;
    memcpy(s->token, request->token, s->tokenlen);
  }

  coap_touch_async(s);

  LL_PREPEND(context->async_state, s);

  return s;
}

coap_async_state_t *
coap_find_async(coap_context_t *context, coap_session_t *session, coap_tid_t id) {
  coap_async_state_t *tmp;
  SEARCH_PAIR(context->async_state,tmp,session,session,id,id);
  return tmp;
}

int
coap_remove_async(coap_context_t *context, coap_session_t *session,
                  coap_tid_t id, coap_async_state_t **s) {
  coap_async_state_t *tmp = coap_find_async(context, session, id);

  if (tmp)
    LL_DELETE(context->async_state,tmp);

  *s = tmp;
  return tmp != NULL;
}

void
coap_free_async(coap_async_state_t *s) {
  if (s) {
    if (s->session) {
      coap_session_release(s->session);
    }
    if ((s->flags & COAP_ASYNC_RELEASE_DATA) != 0) {
      coap_free(s->appdata);
    }
    coap_free(s);
  }
}

#else
void does_not_exist(void);        /* make some compilers happy */
#endif /* WITHOUT_ASYNC */
/* block.c -- block transfer
 *
 * Copyright (C) 2010--2012,2015-2019 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_config.h"

#if defined(HAVE_ASSERT_H) && !defined(assert)
# include <assert.h>
#endif

#include "libcoap.h"
#include "coap_debug.h"
#include "block.h"
#include "resource.h"
#include "coap_hashkey.h"

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef WITHOUT_BLOCK
unsigned int
coap_opt_block_num(const coap_opt_t *block_opt) {
  unsigned int num = 0;
  uint16_t len;

  len = coap_opt_length(block_opt);

  if (len == 0) {
    return 0;
  }

  if (len > 1) {
    num = coap_decode_var_bytes(coap_opt_value(block_opt),
                                coap_opt_length(block_opt) - 1);
  }

  return (num << 4) | ((*COAP_OPT_BLOCK_LAST(block_opt) & 0xF0) >> 4);
}

int
coap_get_block(coap_pdu_t *pdu, uint16_t type, coap_block_t *block) {
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;

  assert(block);
  memset(block, 0, sizeof(coap_block_t));

  if (pdu && (option = coap_check_option(pdu, type, &opt_iter)) != NULL) {
    unsigned int num;

    block->szx = COAP_OPT_BLOCK_SZX(option);
    if (COAP_OPT_BLOCK_MORE(option))
      block->m = 1;

    /* The block number is at most 20 bits, so values above 2^20 - 1
     * are illegal. */
    num = coap_opt_block_num(option);
    if (num > 0xFFFFF) {
      return 0;
    }
    block->num = num;
    return 1;
  }

  return 0;
}

int
coap_write_block_opt(coap_block_t *block, uint16_t type,
                     coap_pdu_t *pdu, size_t data_length) {
  size_t start, want, avail;
  unsigned char buf[4];

  assert(pdu);

  start = block->num << (block->szx + 4);
  if (data_length <= start) {
    coap_log(LOG_DEBUG, "illegal block requested\n");
    return -2;
  }

  assert(pdu->max_size > 0);
  avail = pdu->max_size - pdu->used_size - 4;
  want = (size_t)1 << (block->szx + 4);

  /* check if entire block fits in message */
  if (want <= avail) {
    block->m = want < data_length - start;
  } else {
    /* Sender has requested a block that is larger than the remaining
     * space in pdu. This is ok if the remaining data fits into the pdu
     * anyway. The block size needs to be adjusted only if there is more
     * data left that cannot be delivered in this message. */

    if (data_length - start <= avail) {

      /* it's the final block and everything fits in the message */
      block->m = 0;
    } else {
      unsigned int szx;
      int newBlockSize;

      /* we need to decrease the block size */
      if (avail < 16) {         /* bad luck, this is the smallest block size */
        coap_log(LOG_DEBUG,
                 "not enough space, even the smallest block does not fit");
        return -3;
      }
      newBlockSize = coap_flsll((long long)avail) - 5;
      coap_log(LOG_DEBUG,
               "decrease block size for %zu to %d\n", avail, newBlockSize);
      szx = block->szx;
      block->szx = newBlockSize;
      block->m = 1;
      block->num <<= szx - block->szx;
    }
  }

  /* to re-encode the block option */
  coap_add_option(pdu, type, coap_encode_var_safe(buf, sizeof(buf),
                                                  ((block->num << 4) |
                                                   (block->m << 3) |
                                                   block->szx)),
                  buf);

  return 1;
}

int
coap_add_block(coap_pdu_t *pdu, unsigned int len, const uint8_t *data,
               unsigned int block_num, unsigned char block_szx) {
  unsigned int start;
  start = block_num << (block_szx + 4);

  if (len <= start)
    return 0;

  return coap_add_data(pdu,
                       min(len - start, (1U << (block_szx + 4))),
                       data + start);
}

/*
 * Note that the COAP_OPTION_ have to be added in the correct order
 */
void
coap_add_data_blocked_response(coap_resource_t *resource,
                       coap_session_t *session,
                       coap_pdu_t *request,
                       coap_pdu_t *response,
                       const coap_binary_t *token,
                       uint16_t media_type,
                       int maxage,
                       size_t length,
                       const uint8_t* data
) {
  coap_key_t etag;
  unsigned char buf[4];
  coap_block_t block2 = { 0, 0, 0 };
  int block2_requested = 0;
  coap_subscription_t *subscription = coap_find_observer(resource, session, token);

  /*
   * Need to check that a valid block is getting asked for so that the
   * correct options are put into the PDU.
   */
  if (request) {
    if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)) {
      block2_requested = 1;
      if (length <= (block2.num << (block2.szx + 4))) {
        coap_log(LOG_DEBUG, "Illegal block requested (%d > last = %zu)\n",
                 block2.num,
                 length >> (block2.szx + 4));
        response->code = COAP_RESPONSE_CODE(400);
        goto error;
      }
    }
  }
  else if (subscription && subscription->has_block2) {
    block2 = subscription->block2;
    block2.num = 0;
    block2_requested = 1;
  }
  response->code = COAP_RESPONSE_CODE(205);

  /* add etag for the resource */
  memset(etag, 0, sizeof(etag));
  coap_hash(data, length, etag);
  coap_add_option(response, COAP_OPTION_ETAG, sizeof(etag), etag);

  if ((block2.num == 0) && subscription) {
    coap_add_option(response, COAP_OPTION_OBSERVE,
                    coap_encode_var_safe(buf, sizeof (buf),
                                         resource->observe),
                    buf);
  }

  coap_add_option(response, COAP_OPTION_CONTENT_TYPE,
                  coap_encode_var_safe(buf, sizeof(buf),
                                       media_type),
                  buf);

  if (maxage >= 0) {
    coap_add_option(response,
                    COAP_OPTION_MAXAGE,
                    coap_encode_var_safe(buf, sizeof(buf), maxage), buf);
  }

  if (block2_requested) {
    int res;

    res = coap_write_block_opt(&block2, COAP_OPTION_BLOCK2, response,
                               length);

    switch (res) {
    case -2:                        /* illegal block (caught above) */
        response->code = COAP_RESPONSE_CODE(400);
        goto error;
    case -1:                        /* should really not happen */
        assert(0);
        /* fall through if assert is a no-op */
    case -3:                        /* cannot handle request */
        response->code = COAP_RESPONSE_CODE(500);
        goto error;
    default:                        /* everything is good */
        ;
    }

    coap_add_option(response,
                    COAP_OPTION_SIZE2,
                    coap_encode_var_safe(buf, sizeof(buf), length),
                    buf);

    coap_add_block(response, length, data,
                   block2.num, block2.szx);
    return;
  }

  /*
   * BLOCK2 not requested
   */
  if (!coap_add_data(response, length, data)) {
    /* set initial block size, will be lowered by
     * coap_write_block_opt) automatically */
    block2.num = 0;
    block2.szx = 6;
    coap_write_block_opt(&block2, COAP_OPTION_BLOCK2, response,
                         length);

    coap_add_option(response,
                    COAP_OPTION_SIZE2,
                    coap_encode_var_safe(buf, sizeof(buf), length),
                    buf);

    coap_add_block(response, length, data,
                   block2.num, block2.szx);
  }
  return;

error:
  coap_add_data(response,
                strlen(coap_response_phrase(response->code)),
                (const unsigned char *)coap_response_phrase(response->code));
}

#endif /* WITHOUT_BLOCK  */
/* debug.c -- debug utilities
 *
 * Copyright (C) 2010--2012,2014--2019 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_config.h"

#if defined(HAVE_STRNLEN) && defined(__GNUC__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif

#if defined(HAVE_ASSERT_H) && !defined(assert)
# include <assert.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#include "libcoap.h"
#include "block.h"
#include "coap_debug.h"
#include "encode.h"
#include "net.h"
#include "coap_mutex.h"

#ifdef WITH_LWIP
# define fprintf(fd, ...) LWIP_PLATFORM_DIAG((__VA_ARGS__))
# define fflush(...)
#endif

#ifdef WITH_CONTIKI
# ifndef DEBUG
#  define DEBUG DEBUG_PRINT
# endif /* DEBUG */
#include "net/ip/uip-debug.h"
#endif

static coap_log_t maxlog = LOG_WARNING;        /* default maximum log level */

static int use_fprintf_for_show_pdu = 1; /* non zero to output with fprintf */

const char *coap_package_name(void) {
  return PACKAGE_NAME;
}

const char *coap_package_version(void) {
  return PACKAGE_STRING;
}

void
coap_set_show_pdu_output(int use_fprintf) {
  use_fprintf_for_show_pdu = use_fprintf;
}

coap_log_t
coap_get_log_level(void) {
  return maxlog;
}

void
coap_set_log_level(coap_log_t level) {
  maxlog = level;
}

/* this array has the same order as the type log_t */
static const char *loglevels[] = {
  "EMRG", "ALRT", "CRIT", "ERR ", "WARN", "NOTE", "INFO", "DEBG"
};

#ifdef HAVE_TIME_H

COAP_STATIC_INLINE size_t
print_timestamp(char *s, size_t len, coap_tick_t t) {
  struct tm *tmp;
  time_t now = coap_ticks_to_rt(t);
  tmp = localtime(&now);
  return strftime(s, len, "%b %d %H:%M:%S", tmp);
}

#else /* alternative implementation: just print the timestamp */

COAP_STATIC_INLINE size_t
print_timestamp(char *s, size_t len, coap_tick_t t) {
#ifdef HAVE_SNPRINTF
  return snprintf(s, len, "%u.%03u",
                  (unsigned int)coap_ticks_to_rt(t),
                  (unsigned int)(t % COAP_TICKS_PER_SECOND));
#else /* HAVE_SNPRINTF */
  /* @todo do manual conversion of timestamp */
  return 0;
#endif /* HAVE_SNPRINTF */
}

#endif /* HAVE_TIME_H */

#ifndef HAVE_STRNLEN
/**
 * A length-safe strlen() fake.
 *
 * @param s      The string to count characters != 0.
 * @param maxlen The maximum length of @p s.
 *
 * @return The length of @p s.
 */
static inline size_t
strnlen(const char *s, size_t maxlen) {
  size_t n = 0;
  while(*s++ && n < maxlen)
    ++n;
  return n;
}
#endif /* HAVE_STRNLEN */

static size_t
print_readable( const uint8_t *data, size_t len,
                unsigned char *result, size_t buflen, int encode_always ) {
  const uint8_t hex[] = "0123456789ABCDEF";
  size_t cnt = 0;
  assert(data || len == 0);

  if (buflen == 0) { /* there is nothing we can do here but return */
    return 0;
  }

  while (len) {
    if (!encode_always && isprint(*data)) {
      if (cnt+1 < buflen) { /* keep one byte for terminating zero */
      *result++ = *data;
      ++cnt;
      } else {
        break;
      }
    } else {
      if (cnt+4 < buflen) { /* keep one byte for terminating zero */
        *result++ = '\\';
        *result++ = 'x';
        *result++ = hex[(*data & 0xf0) >> 4];
        *result++ = hex[*data & 0x0f];
        cnt += 4;
      } else
        break;
    }

    ++data; --len;
  }

  *result = '\0'; /* add a terminating zero */
  return cnt;
}

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

size_t
coap_print_addr(const struct coap_address_t *addr, unsigned char *buf, size_t len) {
#if defined( HAVE_ARPA_INET_H ) || defined( HAVE_WS2TCPIP_H )
  const void *addrptr = NULL;
  in_port_t port;
  unsigned char *p = buf;

  switch (addr->addr.sa.sa_family) {
  case AF_INET:
    addrptr = &addr->addr.sin.sin_addr;
    port = ntohs(addr->addr.sin.sin_port);
    break;
  case AF_INET6:
    if (len < 7) /* do not proceed if buffer is even too short for [::]:0 */
      return 0;

    *p++ = '[';

    addrptr = &addr->addr.sin6.sin6_addr;
    port = ntohs(addr->addr.sin6.sin6_port);

    break;
  default:
    memcpy(buf, "(unknown address type)", min(22, len));
    return min(22, len);
  }

  /* Cast needed for Windows, since it doesn't have the correct API signature. */
  if (inet_ntop(addr->addr.sa.sa_family, addrptr, (char *)p,
                min(len, addr->size)) == 0) {
    perror("coap_print_addr");
    return 0;
  }

  p += strnlen((char *)p, len);

  if (addr->addr.sa.sa_family == AF_INET6) {
    if (p < buf + len) {
      *p++ = ']';
    } else
      return 0;
  }

  p += snprintf((char *)p, buf + len - p + 1, ":%d", port);

  return buf + len - p;
#else /* HAVE_ARPA_INET_H */
# if WITH_CONTIKI
  unsigned char *p = buf;
  uint8_t i;
#  if NETSTACK_CONF_WITH_IPV6
  const uint8_t hex[] = "0123456789ABCDEF";

  if (len < 41)
    return 0;

  *p++ = '[';

  for (i=0; i < 16; i += 2) {
    if (i) {
      *p++ = ':';
    }
    *p++ = hex[(addr->addr.u8[i] & 0xf0) >> 4];
    *p++ = hex[(addr->addr.u8[i] & 0x0f)];
    *p++ = hex[(addr->addr.u8[i+1] & 0xf0) >> 4];
    *p++ = hex[(addr->addr.u8[i+1] & 0x0f)];
  }
  *p++ = ']';
#  else /* WITH_UIP6 */
#   warning "IPv4 network addresses will not be included in debug output"

  if (len < 21)
    return 0;
#  endif /* WITH_UIP6 */
  if (buf + len - p < 6)
    return 0;

#ifdef HAVE_SNPRINTF
  p += snprintf((char *)p, buf + len - p + 1, ":%d", uip_htons(addr->port));
#else /* HAVE_SNPRINTF */
  /* @todo manual conversion of port number */
#endif /* HAVE_SNPRINTF */

  return p - buf;
# else /* WITH_CONTIKI */
  /* TODO: output addresses manually */
#   warning "inet_ntop() not available, network addresses will not be included in debug output"
# endif /* WITH_CONTIKI */
  return 0;
#endif
}

#ifdef WITH_CONTIKI
# define fprintf(fd, ...) PRINTF(__VA_ARGS__)
# define fflush(...)

# ifdef HAVE_VPRINTF
#  define vfprintf(fd, ...) vprintf(__VA_ARGS__)
# else /* HAVE_VPRINTF */
#  define vfprintf(fd, ...) PRINTF(__VA_ARGS__)
# endif /* HAVE_VPRINTF */
#endif /* WITH_CONTIKI */

/** Returns a textual description of the message type @p t. */
static const char *
msg_type_string(uint16_t t) {
  static const char *types[] = { "CON", "NON", "ACK", "RST", "???" };

  return types[min(t, sizeof(types)/sizeof(char *) - 1)];
}

/** Returns a textual description of the method or response code. */
static const char *
msg_code_string(uint16_t c) {
  static const char *methods[] = { "0.00", "GET", "POST", "PUT", "DELETE",
                                   "FETCH", "PATCH", "iPATCH" };
  static const char *signals[] = { "7.00", "CSM", "Ping", "Pong", "Release",
                                   "Abort" };
  static char buf[5];

  if (c < sizeof(methods)/sizeof(const char *)) {
    return methods[c];
  } else if (c >= 224 && c - 224 < (int)(sizeof(signals)/sizeof(const char *))) {
    return signals[c-224];
  } else {
    snprintf(buf, sizeof(buf), "%u.%02u", (c >> 5) & 0x7, c & 0x1f);
    return buf;
  }
}

/** Returns a textual description of the option name. */
static const char *
msg_option_string(uint8_t code, uint16_t option_type) {
  struct option_desc_t {
    uint16_t type;
    const char *name;
  };

  static struct option_desc_t options[] = {
    { COAP_OPTION_IF_MATCH, "If-Match" },
    { COAP_OPTION_URI_HOST, "Uri-Host" },
    { COAP_OPTION_ETAG, "ETag" },
    { COAP_OPTION_IF_NONE_MATCH, "If-None-Match" },
    { COAP_OPTION_OBSERVE, "Observe" },
    { COAP_OPTION_URI_PORT, "Uri-Port" },
    { COAP_OPTION_LOCATION_PATH, "Location-Path" },
    { COAP_OPTION_URI_PATH, "Uri-Path" },
    { COAP_OPTION_CONTENT_FORMAT, "Content-Format" },
    { COAP_OPTION_MAXAGE, "Max-Age" },
    { COAP_OPTION_URI_QUERY, "Uri-Query" },
    { COAP_OPTION_ACCEPT, "Accept" },
    { COAP_OPTION_LOCATION_QUERY, "Location-Query" },
    { COAP_OPTION_BLOCK2, "Block2" },
    { COAP_OPTION_BLOCK1, "Block1" },
    { COAP_OPTION_PROXY_URI, "Proxy-Uri" },
    { COAP_OPTION_PROXY_SCHEME, "Proxy-Scheme" },
    { COAP_OPTION_SIZE1, "Size1" },
    { COAP_OPTION_SIZE2, "Size2" },
    { COAP_OPTION_NORESPONSE, "No-Response" }
  };

  static struct option_desc_t options_csm[] = {
    { COAP_SIGNALING_OPTION_MAX_MESSAGE_SIZE, "Max-Message-Size" },
    { COAP_SIGNALING_OPTION_BLOCK_WISE_TRANSFER, "Block-wise-Transfer" }
  };

  static struct option_desc_t options_pingpong[] = {
    { COAP_SIGNALING_OPTION_CUSTODY, "Custody" }
  };

  static struct option_desc_t options_release[] = {
    { COAP_SIGNALING_OPTION_ALTERNATIVE_ADDRESS, "Alternative-Address" },
    { COAP_SIGNALING_OPTION_HOLD_OFF, "Hold-Off" }
  };

  static struct option_desc_t options_abort[] = {
    { COAP_SIGNALING_OPTION_BAD_CSM_OPTION, "Bad-CSM-Option" }
  };

  static char buf[6];
  size_t i;

  if (code == COAP_SIGNALING_CSM) {
    for (i = 0; i < sizeof(options_csm)/sizeof(struct option_desc_t); i++) {
      if (option_type == options_csm[i].type) {
        return options_csm[i].name;
      }
    }
  } else if (code == COAP_SIGNALING_PING || code == COAP_SIGNALING_PONG) {
    for (i = 0; i < sizeof(options_pingpong)/sizeof(struct option_desc_t); i++) {
      if (option_type == options_pingpong[i].type) {
        return options_pingpong[i].name;
      }
    }
  } else if (code == COAP_SIGNALING_RELEASE) {
    for (i = 0; i < sizeof(options_release)/sizeof(struct option_desc_t); i++) {
      if (option_type == options_release[i].type) {
        return options_release[i].name;
      }
    }
  } else if (code == COAP_SIGNALING_ABORT) {
    for (i = 0; i < sizeof(options_abort)/sizeof(struct option_desc_t); i++) {
      if (option_type == options_abort[i].type) {
        return options_abort[i].name;
      }
    }
  } else {
    /* search option_type in list of known options */
    for (i = 0; i < sizeof(options)/sizeof(struct option_desc_t); i++) {
      if (option_type == options[i].type) {
        return options[i].name;
      }
    }
  }
  /* unknown option type, just print to buf */
  snprintf(buf, sizeof(buf), "%u", option_type);
  return buf;
}

static unsigned int
print_content_format(unsigned int format_type,
                     unsigned char *result, unsigned int buflen) {
  struct desc_t {
    unsigned int type;
    const char *name;
  };

  static struct desc_t formats[] = {
    { COAP_MEDIATYPE_TEXT_PLAIN, "text/plain" },
    { COAP_MEDIATYPE_APPLICATION_LINK_FORMAT, "application/link-format" },
    { COAP_MEDIATYPE_APPLICATION_XML, "application/xml" },
    { COAP_MEDIATYPE_APPLICATION_OCTET_STREAM, "application/octet-stream" },
    { COAP_MEDIATYPE_APPLICATION_EXI, "application/exi" },
    { COAP_MEDIATYPE_APPLICATION_JSON, "application/json" },
    { COAP_MEDIATYPE_APPLICATION_CBOR, "application/cbor" },
    { COAP_MEDIATYPE_APPLICATION_COSE_SIGN, "application/cose; cose-type=\"cose-sign\"" },
    { COAP_MEDIATYPE_APPLICATION_COSE_SIGN1, "application/cose; cose-type=\"cose-sign1\"" },
    { COAP_MEDIATYPE_APPLICATION_COSE_ENCRYPT, "application/cose; cose-type=\"cose-encrypt\"" },
    { COAP_MEDIATYPE_APPLICATION_COSE_ENCRYPT0, "application/cose; cose-type=\"cose-encrypt0\"" },
    { COAP_MEDIATYPE_APPLICATION_COSE_MAC, "application/cose; cose-type=\"cose-mac\"" },
    { COAP_MEDIATYPE_APPLICATION_COSE_MAC0, "application/cose; cose-type=\"cose-mac0\"" },
    { COAP_MEDIATYPE_APPLICATION_COSE_KEY, "application/cose-key" },
    { COAP_MEDIATYPE_APPLICATION_COSE_KEY_SET, "application/cose-key-set" },
    { COAP_MEDIATYPE_APPLICATION_SENML_JSON, "application/senml+json" },
    { COAP_MEDIATYPE_APPLICATION_SENSML_JSON, "application/sensml+json" },
    { COAP_MEDIATYPE_APPLICATION_SENML_CBOR, "application/senml+cbor" },
    { COAP_MEDIATYPE_APPLICATION_SENSML_CBOR, "application/sensml+cbor" },
    { COAP_MEDIATYPE_APPLICATION_SENML_EXI, "application/senml-exi" },
    { COAP_MEDIATYPE_APPLICATION_SENSML_EXI, "application/sensml-exi" },
    { COAP_MEDIATYPE_APPLICATION_SENML_XML, "application/senml+xml" },
    { COAP_MEDIATYPE_APPLICATION_SENSML_XML, "application/sensml+xml" },
    { 75, "application/dcaf+cbor" }
  };

  size_t i;

  /* search format_type in list of known content formats */
  for (i = 0; i < sizeof(formats)/sizeof(struct desc_t); i++) {
    if (format_type == formats[i].type) {
      return snprintf((char *)result, buflen, "%s", formats[i].name);
    }
  }

  /* unknown content format, just print numeric value to buf */
  return snprintf((char *)result, buflen, "%d", format_type);
}

/**
 * Returns 1 if the given @p content_format is either unknown or known
 * to carry binary data. The return value @c 0 hence indicates
 * printable data which is also assumed if @p content_format is @c 01.
 */
COAP_STATIC_INLINE int
is_binary(int content_format) {
  return !(content_format == -1 ||
           content_format == COAP_MEDIATYPE_TEXT_PLAIN ||
           content_format == COAP_MEDIATYPE_APPLICATION_LINK_FORMAT ||
           content_format == COAP_MEDIATYPE_APPLICATION_XML ||
           content_format == COAP_MEDIATYPE_APPLICATION_JSON);
}

#define COAP_DO_SHOW_OUTPUT_LINE           \
 do {                                      \
   if (use_fprintf_for_show_pdu) {         \
     fprintf(COAP_DEBUG_FD, "%s", outbuf); \
   }                                       \
   else {                                  \
     coap_log(level, "%s", outbuf);        \
   }                                       \
 } while (0)

void
coap_show_pdu(coap_log_t level, const coap_pdu_t *pdu) {
#if COAP_CONSTRAINED_STACK
  static coap_mutex_t static_show_pdu_mutex = COAP_MUTEX_INITIALIZER;
  static unsigned char buf[1024]; /* need some space for output creation */
  static char outbuf[COAP_DEBUG_BUF_SIZE];
#else /* ! COAP_CONSTRAINED_STACK */
  unsigned char buf[1024]; /* need some space for output creation */
  char outbuf[COAP_DEBUG_BUF_SIZE];
#endif /* ! COAP_CONSTRAINED_STACK */
  size_t buf_len = 0; /* takes the number of bytes written to buf */
  int encode = 0, have_options = 0, i;
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;
  int content_format = -1;
  size_t data_len;
  unsigned char *data;
  int outbuflen = 0;

  /* Save time if not needed */
  if (level > coap_get_log_level())
    return;

#if COAP_CONSTRAINED_STACK
  coap_mutex_lock(&static_show_pdu_mutex);
#endif /* COAP_CONSTRAINED_STACK */

  snprintf(outbuf, sizeof(outbuf), "v:%d t:%s c:%s i:%04x {",
          COAP_DEFAULT_VERSION, msg_type_string(pdu->type),
          msg_code_string(pdu->code), pdu->tid);

  for (i = 0; i < pdu->token_length; i++) {
    outbuflen = strlen(outbuf);
    snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,
              "%02x", pdu->token[i]);
  }
  outbuflen = strlen(outbuf);
  snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  "}");

  /* show options, if any */
  coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);

  outbuflen = strlen(outbuf);
  snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  " [");
  while ((option = coap_option_next(&opt_iter))) {
    if (!have_options) {
      have_options = 1;
    } else {
      outbuflen = strlen(outbuf);
      snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  ",");
    }

    if (pdu->code == COAP_SIGNALING_CSM) switch(opt_iter.type) {
    case COAP_SIGNALING_OPTION_MAX_MESSAGE_SIZE:
      buf_len = snprintf((char *)buf, sizeof(buf), "%u",
                         coap_decode_var_bytes(coap_opt_value(option),
                                               coap_opt_length(option)));
      break;
    default:
      buf_len = 0;
      break;
    } else if (pdu->code == COAP_SIGNALING_PING
            || pdu->code == COAP_SIGNALING_PONG) {
      buf_len = 0;
    } else if (pdu->code == COAP_SIGNALING_RELEASE) switch(opt_iter.type) {
    case COAP_SIGNALING_OPTION_ALTERNATIVE_ADDRESS:
      buf_len = print_readable(coap_opt_value(option),
                               coap_opt_length(option),
                               buf, sizeof(buf), 0);
      break;
    case COAP_SIGNALING_OPTION_HOLD_OFF:
      buf_len = snprintf((char *)buf, sizeof(buf), "%u",
                         coap_decode_var_bytes(coap_opt_value(option),
                                               coap_opt_length(option)));
      break;
    default:
      buf_len = 0;
      break;
    } else if (pdu->code == COAP_SIGNALING_ABORT) switch(opt_iter.type) {
    case COAP_SIGNALING_OPTION_BAD_CSM_OPTION:
      buf_len = snprintf((char *)buf, sizeof(buf), "%u",
                         coap_decode_var_bytes(coap_opt_value(option),
                                               coap_opt_length(option)));
      break;
    default:
      buf_len = 0;
      break;
    } else switch (opt_iter.type) {
    case COAP_OPTION_CONTENT_FORMAT:
      content_format = (int)coap_decode_var_bytes(coap_opt_value(option),
                                                  coap_opt_length(option));

      buf_len = print_content_format(content_format, buf, sizeof(buf));
      break;

    case COAP_OPTION_BLOCK1:
    case COAP_OPTION_BLOCK2:
      /* split block option into number/more/size where more is the
       * letter M if set, the _ otherwise */
      buf_len = snprintf((char *)buf, sizeof(buf), "%u/%c/%u",
                         coap_opt_block_num(option), /* block number */
                         COAP_OPT_BLOCK_MORE(option) ? 'M' : '_', /* M bit */
                         (1 << (COAP_OPT_BLOCK_SZX(option) + 4))); /* block size */

      break;

    case COAP_OPTION_URI_PORT:
    case COAP_OPTION_MAXAGE:
    case COAP_OPTION_OBSERVE:
    case COAP_OPTION_SIZE1:
    case COAP_OPTION_SIZE2:
      /* show values as unsigned decimal value */
      buf_len = snprintf((char *)buf, sizeof(buf), "%u",
                         coap_decode_var_bytes(coap_opt_value(option),
                                               coap_opt_length(option)));
      break;

    default:
      /* generic output function for all other option types */
      if (opt_iter.type == COAP_OPTION_URI_PATH ||
          opt_iter.type == COAP_OPTION_PROXY_URI ||
          opt_iter.type == COAP_OPTION_URI_HOST ||
          opt_iter.type == COAP_OPTION_LOCATION_PATH ||
          opt_iter.type == COAP_OPTION_LOCATION_QUERY ||
          opt_iter.type == COAP_OPTION_URI_QUERY) {
        encode = 0;
      } else {
        encode = 1;
      }

      buf_len = print_readable(coap_opt_value(option),
                               coap_opt_length(option),
                               buf, sizeof(buf), encode);
    }

    outbuflen = strlen(outbuf);
    snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,
              " %s:%.*s", msg_option_string(pdu->code, opt_iter.type),
              (int)buf_len, buf);
  }

  outbuflen = strlen(outbuf);
  snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  " ]");

  if (coap_get_data(pdu, &data_len, &data)) {

    outbuflen = strlen(outbuf);
    snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  " :: ");

    if (is_binary(content_format)) {
      int keep_data_len = data_len;
      uint8_t *keep_data = data;

      outbuflen = strlen(outbuf);
      snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,
               "binary data length %zu\n", data_len);
      COAP_DO_SHOW_OUTPUT_LINE;
      /*
       * Output hex dump of binary data as a continuous entry
       */
      outbuf[0] = '\000';
      snprintf(outbuf, sizeof(outbuf),  "<<");
      while (data_len--) {
        outbuflen = strlen(outbuf);
        snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,
                 "%02x", *data++);
      }
      outbuflen = strlen(outbuf);
      snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  ">>");
      data_len = keep_data_len;
      data = keep_data;
      outbuflen = strlen(outbuf);
      snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  "\n");
      COAP_DO_SHOW_OUTPUT_LINE;
      /*
       * Output ascii readable (if possible), immediately under the
       * hex value of the character output above to help binary debugging
       */
      outbuf[0] = '\000';
      snprintf(outbuf, sizeof(outbuf),  "<<");
      while (data_len--) {
        outbuflen = strlen(outbuf);
        snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,
                 "%c ", isprint (*data) ? *data : '.');
        data++;
      }
      outbuflen = strlen(outbuf);
      snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  ">>");
    } else {
      if (print_readable(data, data_len, buf, sizeof(buf), 0)) {
        outbuflen = strlen(outbuf);
        snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  "'%s'", buf);
      }
    }
  }

  outbuflen = strlen(outbuf);
  snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  "\n");
  COAP_DO_SHOW_OUTPUT_LINE;

#if COAP_CONSTRAINED_STACK
  coap_mutex_unlock(&static_show_pdu_mutex);
#endif /* COAP_CONSTRAINED_STACK */
}

void coap_show_tls_version(coap_log_t level)
{
  char buffer[64];
  coap_string_tls_version(buffer, sizeof(buffer));
  coap_log(level, "%s\n", buffer);
}

char *coap_string_tls_version(char *buffer, size_t bufsize)
{
  coap_tls_version_t *tls_version = coap_get_tls_library_version();
  char beta[8];
  char sub[2];
  char b_beta[8];
  char b_sub[2];

  switch (tls_version->type) {
  case COAP_TLS_LIBRARY_NOTLS:
    snprintf(buffer, bufsize, "TLS Library: None");
    break;
  case COAP_TLS_LIBRARY_TINYDTLS:
    snprintf(buffer, bufsize, "TLS Library: TinyDTLS - runtime %lu.%lu.%lu, "
             "libcoap built for %lu.%lu.%lu",
             (unsigned long)(tls_version->version >> 16),
             (unsigned long)((tls_version->version >> 8) & 0xff),
             (unsigned long)(tls_version->version & 0xff),
             (unsigned long)(tls_version->built_version >> 16),
             (unsigned long)((tls_version->built_version >> 8) & 0xff),
             (unsigned long)(tls_version->built_version & 0xff));
    break;
  case COAP_TLS_LIBRARY_OPENSSL:
    switch (tls_version->version &0xf) {
    case 0:
      strcpy(beta, "-dev");
      break;
    case 0xf:
      strcpy(beta, "");
      break;
    default:
      strcpy(beta, "-beta");
      beta[5] = (tls_version->version &0xf) + '0';
      beta[6] = '\000';
      break;
    }
    sub[0] = ((tls_version->version >> 4) & 0xff) ?
                    ((tls_version->version >> 4) & 0xff) + 'a' -1 : '\000';
    sub[1] = '\000';
    switch (tls_version->built_version &0xf) {
    case 0:
      strcpy(b_beta, "-dev");
      break;
    case 0xf:
      strcpy(b_beta, "");
      break;
    default:
      strcpy(b_beta, "-beta");
      b_beta[5] = (tls_version->built_version &0xf) + '0';
      b_beta[6] = '\000';
      break;
    }
    b_sub[0] = ((tls_version->built_version >> 4) & 0xff) ?
               ((tls_version->built_version >> 4) & 0xff) + 'a' -1 : '\000';
    b_sub[1] = '\000';
    snprintf(buffer, bufsize, "TLS Library: OpenSSL - runtime "
             "%lu.%lu.%lu%s%s, libcoap built for %lu.%lu.%lu%s%s",
             (unsigned long)(tls_version->version >> 28),
             (unsigned long)((tls_version->version >> 20) & 0xff),
             (unsigned long)((tls_version->version >> 12) & 0xff), sub, beta,
             (unsigned long)(tls_version->built_version >> 28),
             (unsigned long)((tls_version->built_version >> 20) & 0xff),
             (unsigned long)((tls_version->built_version >> 12) & 0xff),
             b_sub, b_beta);
    break;
  case COAP_TLS_LIBRARY_GNUTLS:
    snprintf(buffer, bufsize, "TLS Library: GnuTLS - runtime %lu.%lu.%lu, "
             "libcoap built for %lu.%lu.%lu",
             (unsigned long)(tls_version->version >> 16),
             (unsigned long)((tls_version->version >> 8) & 0xff),
             (unsigned long)(tls_version->version & 0xff),
             (unsigned long)(tls_version->built_version >> 16),
             (unsigned long)((tls_version->built_version >> 8) & 0xff),
             (unsigned long)(tls_version->built_version & 0xff));
    break;
  default:
    snprintf(buffer, bufsize, "Library type %d unknown", tls_version->type);
    break;
  }
  return buffer;
}

static coap_log_handler_t log_handler = NULL;

void coap_set_log_handler(coap_log_handler_t handler) {
  log_handler = handler;
}

void
coap_log_impl(coap_log_t level, const char *format, ...) {

  if (maxlog < level)
    return;

  if (log_handler) {
#if COAP_CONSTRAINED_STACK
    static coap_mutex_t static_log_mutex = COAP_MUTEX_INITIALIZER;
    static char message[COAP_DEBUG_BUF_SIZE];
#else /* ! COAP_CONSTRAINED_STACK */
    char message[COAP_DEBUG_BUF_SIZE];
#endif /* ! COAP_CONSTRAINED_STACK */
    va_list ap;
    va_start(ap, format);
#if COAP_CONSTRAINED_STACK
  coap_mutex_lock(&static_log_mutex);
#endif /* COAP_CONSTRAINED_STACK */

    vsnprintf( message, sizeof(message), format, ap);
    va_end(ap);
    log_handler(level, message);
#if COAP_CONSTRAINED_STACK
    coap_mutex_unlock(&static_log_mutex);
#endif /* COAP_CONSTRAINED_STACK */
  } else {
    char timebuf[32];
    coap_tick_t now;
    va_list ap;
    FILE *log_fd;

    log_fd = level <= LOG_CRIT ? COAP_ERR_FD : COAP_DEBUG_FD;

    coap_ticks(&now);
    if (print_timestamp(timebuf,sizeof(timebuf), now))
      fprintf(log_fd, "%s ", timebuf);

    if (level <= LOG_DEBUG)
      fprintf(log_fd, "%s ", loglevels[level]);

    va_start(ap, format);
    vfprintf(log_fd, format, ap);
    va_end(ap);
    fflush(log_fd);
  }
}

static struct packet_num_interval {
  int start;
  int end;
} packet_loss_intervals[10];
static int num_packet_loss_intervals = 0;
static int packet_loss_level = 0;
static int send_packet_count = 0;

int coap_debug_set_packet_loss(const char *loss_level) {
  const char *p = loss_level;
  char *end = NULL;
  int n = (int)strtol(p, &end, 10), i = 0;
  if (end == p || n < 0)
    return 0;
  if (*end == '%') {
    if (n > 100)
      n = 100;
    packet_loss_level = n * 65536 / 100;
    coap_log(LOG_DEBUG, "packet loss level set to %d%%\n", n);
  } else {
    if (n <= 0)
      return 0;
    while (i < 10) {
      packet_loss_intervals[i].start = n;
      if (*end == '-') {
        p = end + 1;
        n = (int)strtol(p, &end, 10);
        if (end == p || n <= 0)
          return 0;
      }
      packet_loss_intervals[i++].end = n;
      if (*end == 0)
        break;
      if (*end != ',')
        return 0;
      p = end + 1;
      n = (int)strtol(p, &end, 10);
      if (end == p || n <= 0)
        return 0;
    }
    if (i == 10)
      return 0;
    num_packet_loss_intervals = i;
  }
  send_packet_count = 0;
  return 1;
}

int coap_debug_send_packet(void) {
  ++send_packet_count;
  if (num_packet_loss_intervals > 0) {
    int i;
    for (i = 0; i < num_packet_loss_intervals; i++) {
      if (send_packet_count >= packet_loss_intervals[i].start
        && send_packet_count <= packet_loss_intervals[i].end)
        return 0;
    }
  }
  if ( packet_loss_level > 0 ) {
    uint16_t r = 0;
    prng( (uint8_t*)&r, 2 );
    if ( r < packet_loss_level )
      return 0;
  }
  return 1;
}
/*
 * coap_event.c -- libcoap Event API
 *
 * Copyright (C) 2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#include "coap_event.h"
#include "net.h"

/*
 * This replaces coap_set_event_handler() so that handler registration is
 * consistent in the naming.
 */
void
coap_register_event_handler(struct coap_context_t *context,
                            coap_event_handler_t hnd) {
  context->handle_event = hnd;
}

void
coap_set_event_handler(struct coap_context_t *context,
                       coap_event_handler_t hnd) {
  context->handle_event = hnd;
}

void
coap_clear_event_handler(struct coap_context_t *context) {
  context->handle_event = NULL;
}
/*
 * coap_gnutls.c -- GnuTLS Datagram Transport Layer Support for libcoap
 *
 * Copyright (C) 2017 Dag Bjorklund <dag.bjorklund@comsel.fi>
 * Copyright (C) 2018-2019 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/*
 * Naming used to prevent confusion between coap sessions, gnutls sessions etc.
 * when reading the code.
 *
 * c_context  A coap_context_t *
 * c_session  A coap_session_t *
 * g_context  A coap_gnutls_context_t * (held in c_context->dtls_context)
 * g_session  A gnutls_session_t (which has the * in the typedef)
 * g_env      A coap_gnutls_env_t * (held in c_session->tls)
 */

#include "coap_config.h"

#ifdef HAVE_LIBGNUTLS

#define MIN_GNUTLS_VERSION "3.3.0"

#include "net.h"
#include "mem.h"
#include "coap_debug.h"
#include "prng.h"
#include <inttypes.h>
#include <stdio.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/dtls.h>
#include <unistd.h>

#ifdef __GNUC__
#define UNUSED __attribute__((unused))
#else /* __GNUC__ */
#define UNUSED
#endif /* __GNUC__ */

typedef struct coap_ssl_t {
  const uint8_t *pdu;
  unsigned pdu_len;
  unsigned peekmode;
  coap_tick_t timeout;
} coap_ssl_t;

/*
 * This structure encapsulates the GnuTLS session object.
 * It handles both TLS and DTLS.
 * c_session->tls points to this.
 */
typedef struct coap_gnutls_env_t {
  gnutls_session_t g_session;
  gnutls_psk_client_credentials_t psk_cl_credentials;
  gnutls_psk_server_credentials_t psk_sv_credentials;
  gnutls_certificate_credentials_t pki_credentials;
  coap_ssl_t coap_ssl_data;
  /* If not set, need to do gnutls_handshake */
  int established;
  int seen_client_hello;
} coap_gnutls_env_t;

#define IS_PSK (1 << 0)
#define IS_PKI (1 << 1)
#define IS_CLIENT (1 << 6)
#define IS_SERVER (1 << 7)

typedef struct sni_entry {
  char *sni;
  coap_dtls_key_t pki_key;
  gnutls_certificate_credentials_t pki_credentials;
} sni_entry;

typedef struct coap_gnutls_context_t {
  coap_dtls_pki_t setup_data;
  int psk_pki_enabled;
  size_t sni_count;
  sni_entry *sni_entry_list;
  gnutls_datum_t alpn_proto;    /* Will be "coap", but that is a const */
  char *root_ca_file;
  char *root_ca_path;
  gnutls_priority_t priority_cache;
} coap_gnutls_context_t;

typedef enum coap_free_bye_t {
  COAP_FREE_BYE_AS_TCP,  /**< call gnutls_bye() with GNUTLS_SHUT_RDWR */
  COAP_FREE_BYE_AS_UDP,  /**< call gnutls_bye() with GNUTLS_SHUT_WR */
  COAP_FREE_BYE_NONE     /**< do not call gnutls_bye() */
} coap_free_bye_t;

#if (GNUTLS_VERSION_NUMBER >= 0x030505)
#define VARIANTS "NORMAL:+ECDHE-PSK:+PSK:+ECDHE-ECDSA:+AES-128-CCM-8"
#else
#define VARIANTS "NORMAL:+ECDHE-PSK:+PSK"
#endif

#define G_ACTION(xx) do { \
  ret = (xx); \
} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)

#define G_CHECK(xx,func) do { \
  if ((ret = (xx)) < 0) { \
    coap_log(LOG_WARNING, "%s: '%s'\n", func, gnutls_strerror(ret)); \
    goto fail; \
  } \
} while (0)

#define G_ACTION_CHECK(xx,func) do { \
  G_ACTION(xx); \
  G_CHECK(xx, func); \
} while 0

static int dtls_log_level = 0;

static int post_client_hello_gnutls_pki(gnutls_session_t g_session);
static int post_client_hello_gnutls_psk(gnutls_session_t g_session);

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_is_supported(void) {
  if (gnutls_check_version(MIN_GNUTLS_VERSION) == NULL) {
    coap_log(LOG_ERR, "GnuTLS " MIN_GNUTLS_VERSION " or later is required\n");
    return 0;
  }
  return 1;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_tls_is_supported(void) {
  if (gnutls_check_version(MIN_GNUTLS_VERSION) == NULL) {
    coap_log(LOG_ERR, "GnuTLS " MIN_GNUTLS_VERSION " or later is required\n");
    return 0;
  }
  return 1;
}

coap_tls_version_t *
coap_get_tls_library_version(void) {
  static coap_tls_version_t version;
  const char *vers = gnutls_check_version(NULL);

  version.version = 0;
  if (vers) {
    int p1, p2, p3;

    sscanf (vers, "%d.%d.%d", &p1, &p2, &p3);
    version.version = (p1 << 16) | (p2 << 8) | p3;
  }
  version.built_version = GNUTLS_VERSION_NUMBER;
  version.type = COAP_TLS_LIBRARY_GNUTLS;
  return &version;
}

static void
coap_gnutls_audit_log_func(gnutls_session_t g_session, const char* text)
{
  if (g_session) {
    coap_session_t *c_session =
      (coap_session_t *)gnutls_transport_get_ptr(g_session);
    coap_log(LOG_WARNING, "** %s: %s",
             coap_session_str(c_session), text);
  } else {
    coap_log(LOG_WARNING, "** (null): %s", text);
  }
}

static void
coap_gnutls_log_func(int level, const char* text)
{
  /* debug logging in gnutls starts at 2 */
  if (level > 2)
    level = 2;
  coap_log(LOG_DEBUG + level - 2, "%s", text);
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_context_set_pki(coap_context_t *c_context,
                          coap_dtls_pki_t* setup_data,
                          coap_dtls_role_t role UNUSED)
{
  coap_gnutls_context_t *g_context =
                         ((coap_gnutls_context_t *)c_context->dtls_context);

  if (!g_context || !setup_data)
    return 0;

  g_context->setup_data = *setup_data;
  g_context->psk_pki_enabled |= IS_PKI;
  return 1;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_context_set_pki_root_cas(struct coap_context_t *c_context,
                                   const char *ca_file,
                                   const char *ca_path)
{
  coap_gnutls_context_t *g_context =
                         ((coap_gnutls_context_t *)c_context->dtls_context);
  if (!g_context) {
    coap_log(LOG_WARNING,
             "coap_context_set_pki_root_cas: (D)TLS environment "
             "not set up\n");
    return 0;
  }

  if (ca_file == NULL && ca_path == NULL) {
    coap_log(LOG_WARNING,
             "coap_context_set_pki_root_cas: ca_file and/or ca_path "
             "not defined\n");
    return 0;
  }
  if (g_context->root_ca_file) {
    gnutls_free(g_context->root_ca_file);
    g_context->root_ca_file = NULL;
  }
  if (ca_file) {
    g_context->root_ca_file = gnutls_strdup(ca_file);
  }
  if (g_context->root_ca_path) {
    gnutls_free(g_context->root_ca_path);
    g_context->root_ca_path = NULL;
  }
  if (ca_path) {
#if (GNUTLS_VERSION_NUMBER >= 0x030306)
    g_context->root_ca_path = gnutls_strdup(ca_path);
#else
    coap_log(LOG_ERR, "ca_path not supported in GnuTLS < 3.3.6\n");
#endif
  }
  return 1;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_context_set_psk(coap_context_t *c_context,
                          const char *identity_hint UNUSED,
                          coap_dtls_role_t role UNUSED
) {
  coap_gnutls_context_t *g_context =
                         ((coap_gnutls_context_t *)c_context->dtls_context);

  g_context->psk_pki_enabled |= IS_PSK;
  return 1;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_context_check_keys_enabled(coap_context_t *c_context)
{
  coap_gnutls_context_t *g_context =
                         ((coap_gnutls_context_t *)c_context->dtls_context);
  return g_context->psk_pki_enabled ? 1 : 0;
}

void coap_dtls_startup(void) {
  gnutls_global_set_audit_log_function(coap_gnutls_audit_log_func);
  gnutls_global_set_log_function(coap_gnutls_log_func);
}

void
coap_dtls_set_log_level(int level) {
  dtls_log_level = level;
  if (level - LOG_DEBUG >= -2) {
    /* debug logging in gnutls starts at 2 */
    gnutls_global_set_log_level(2 + level - LOG_DEBUG);
  }
  else {
    gnutls_global_set_log_level(0);
  }
}

/*
 * return current logging level
 */
int
coap_dtls_get_log_level(void) {
  return dtls_log_level;
}

/*
 * return +ve  new g_context
 *        NULL failure
 */
void *
coap_dtls_new_context(struct coap_context_t *c_context UNUSED) {
  const char *err;
  int ret;
  struct coap_gnutls_context_t *g_context =
                                (struct coap_gnutls_context_t *)
                                gnutls_malloc(sizeof(coap_gnutls_context_t));

  if (g_context) {
    G_CHECK(gnutls_global_init(), "gnutls_global_init");
    memset(g_context, 0, sizeof(struct coap_gnutls_context_t));
    g_context->alpn_proto.data = gnutls_malloc(4);
    if (g_context->alpn_proto.data) {
      memcpy(g_context->alpn_proto.data, "coap", 4);
      g_context->alpn_proto.size = 4;
    }
    G_CHECK(gnutls_priority_init(&g_context->priority_cache, VARIANTS, &err),
            "gnutls_priority_init");
  }
  return g_context;

fail:
  if (g_context)
    coap_dtls_free_context(g_context);
  return NULL;
}

void
coap_dtls_free_context(void *handle) {
  size_t i;
  coap_gnutls_context_t *g_context = (coap_gnutls_context_t *)handle;

  gnutls_free(g_context->alpn_proto.data);
  gnutls_free(g_context->root_ca_file);
  gnutls_free(g_context->root_ca_path);
  for (i = 0; i < g_context->sni_count; i++) {
    gnutls_free(g_context->sni_entry_list[i].sni);
    if (g_context->psk_pki_enabled & IS_PKI) {
      gnutls_certificate_free_credentials(
          g_context->sni_entry_list[i].pki_credentials);
    }
  }
  if (g_context->sni_count)
    gnutls_free(g_context->sni_entry_list);

  gnutls_priority_deinit(g_context->priority_cache);

  gnutls_global_deinit();
  gnutls_free(g_context);
}

/*
 * gnutls_psk_client_credentials_function return values
 * (see gnutls_psk_set_client_credentials_function())
 *
 * return -1 failed
 *         0 passed
 */
static int
psk_client_callback(gnutls_session_t g_session,
                    char **username, gnutls_datum_t *key) {
  coap_session_t *c_session =
                  (coap_session_t *)gnutls_transport_get_ptr(g_session);
  uint8_t identity[64];
  size_t identity_len;
  uint8_t psk_key[64];
  size_t psk_len;

  /* Constant passed to get_client_psk callback. The final byte is
   * reserved for a terminating 0. */
  const size_t max_identity_len = sizeof(identity) - 1;

  /* Initialize result parameters. */
  *username = NULL;
  key->data = NULL;

  if (c_session == NULL || c_session->context == NULL ||
      c_session->context->get_client_psk == NULL) {
    return -1;
  }

  psk_len = c_session->context->get_client_psk(c_session,
                                               NULL,
                                               0,
                                               identity,
                                               &identity_len,
                                               max_identity_len,
                                               psk_key,
                                               sizeof(psk_key));
  assert(identity_len < sizeof(identity));

  /* Reserve dynamic memory to hold the identity and a terminating
   * zero. */
  *username = gnutls_malloc(identity_len+1);
  if (*username) {
    memcpy(*username, identity, identity_len);
    (*username)[identity_len] = '\0';
  }

  key->data = gnutls_malloc(psk_len);
  if (key->data) {
    memcpy(key->data, psk_key, psk_len);
    key->size = psk_len;
  }

  return (*username && key->data) ? 0 : -1;
}

/*
 * return +ve  SAN or CN derived from certificate
 *        NULL failed
 */
static char* get_san_or_cn(gnutls_session_t g_session)
{
  unsigned int cert_list_size = 0;
  const gnutls_datum_t *cert_list;
  gnutls_x509_crt_t cert;
  char dn[256];
  size_t size;
  int n;
  char *cn;
  int ret;

  if (gnutls_certificate_type_get(g_session) != GNUTLS_CRT_X509)
    return NULL;

  cert_list = gnutls_certificate_get_peers(g_session, &cert_list_size);
  if (cert_list_size == 0) {
    return NULL;
  }

  G_CHECK(gnutls_x509_crt_init(&cert), "gnutls_x509_crt_init");

  /* Interested only in first cert in chain */
  G_CHECK(gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER),
          "gnutls_x509_crt_import");

  size = sizeof(dn) -1;
  /* See if there is a Subject Alt Name first */
  ret = gnutls_x509_crt_get_subject_alt_name(cert, 0, dn, &size, NULL);
  if (ret >= 0) {
    dn[size] = '\000';
    gnutls_x509_crt_deinit(cert);
    return gnutls_strdup(dn);
  }

  size = sizeof(dn);
  G_CHECK(gnutls_x509_crt_get_dn(cert, dn, &size), "gnutls_x509_crt_get_dn");

  gnutls_x509_crt_deinit(cert);

  /* Need to emulate strcasestr() here.  Looking for CN= */
  n = strlen(dn) - 3;
  cn = dn;
  while (n > 0) {
    if (((cn[0] == 'C') || (cn[0] == 'c')) &&
        ((cn[1] == 'N') || (cn[1] == 'n')) &&
        (cn[2] == '=')) {
      cn += 3;
      break;
    }
    cn++;
    n--;
  }
  if (n > 0) {
    char *ecn = strchr(cn, ',');
    if (ecn) {
      cn[ecn-cn] = '\000';
    }
    return gnutls_strdup(cn);
  }
  return NULL;

fail:
  return NULL;
}

/*
 * return 0 failed
 *        1 passed
 */
static int cert_verify_gnutls(gnutls_session_t g_session)
{
  unsigned int status = 0;
  coap_session_t *c_session =
                (coap_session_t *)gnutls_transport_get_ptr(g_session);
  coap_gnutls_context_t *g_context =
             (coap_gnutls_context_t *)c_session->context->dtls_context;
  char *cn = NULL;
  int alert = GNUTLS_A_BAD_CERTIFICATE;
  int ret;

  G_CHECK(gnutls_certificate_verify_peers(g_session, NULL, 0, &status),
          "gnutls_certificate_verify_peers");

  cn = get_san_or_cn(g_session);

  if (status) {
    status &= ~(GNUTLS_CERT_INVALID);
    if (status & (GNUTLS_CERT_NOT_ACTIVATED|GNUTLS_CERT_EXPIRED)) {
      if (g_context->setup_data.allow_expired_certs) {
        status &= ~(GNUTLS_CERT_NOT_ACTIVATED|GNUTLS_CERT_EXPIRED);
        coap_log(LOG_WARNING,
                 "   %s: %s: overridden: '%s'\n",
                 coap_session_str(c_session),
                 "The certificate has an invalid usage date", cn ? cn : "?");
      }
    }
    if (status & (GNUTLS_CERT_REVOCATION_DATA_SUPERSEDED|
                  GNUTLS_CERT_REVOCATION_DATA_ISSUED_IN_FUTURE)) {
      if (g_context->setup_data.allow_expired_crl) {
        status &= ~(GNUTLS_CERT_REVOCATION_DATA_SUPERSEDED|
                    GNUTLS_CERT_REVOCATION_DATA_ISSUED_IN_FUTURE);
        coap_log(LOG_WARNING,
                 "   %s: %s: overridden: '%s'\n",
                 coap_session_str(c_session),
                 "The certificate's CRL entry has an invalid usage date",
                 cn ? cn : "?");
      }
    }

    if (status) {
        coap_log(LOG_WARNING,
                 "   %s: status 0x%x: '%s'\n",
                 coap_session_str(c_session),
                 status, cn ? cn : "?");
    }
  }

  if (status)
    goto fail;

  if (g_context->setup_data.validate_cn_call_back) {
    unsigned int cert_list_size = 0;
    const gnutls_datum_t *cert_list;
    gnutls_x509_crt_t cert;
    uint8_t der[2048];
    size_t size;
    /* status == 0 indicates that the certificate passed to
     *  setup_data.validate_cn_call_back has been validated. */
    const int cert_is_trusted = !status;

    cert_list = gnutls_certificate_get_peers(g_session, &cert_list_size);
    if (cert_list_size == 0) {
      /* get_san_or_cn() should have caught this */
      goto fail;
    }

    G_CHECK(gnutls_x509_crt_init(&cert), "gnutls_x509_crt_init");

    /* Interested only in first cert in chain */
    G_CHECK(gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER),
            "gnutls_x509_crt_import");

    size = sizeof(der);
    G_CHECK(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, der, &size),
            "gnutls_x509_crt_export");
    gnutls_x509_crt_deinit(cert);
    if (!g_context->setup_data.validate_cn_call_back(cn,
           der,
           size,
           c_session,
           0,
           cert_is_trusted,
           g_context->setup_data.cn_call_back_arg)) {
      alert = GNUTLS_A_ACCESS_DENIED;
      goto fail;
    }
  }

  if (g_context->setup_data.additional_tls_setup_call_back) {
    /* Additional application setup wanted */
    if (!g_context->setup_data.additional_tls_setup_call_back(g_session,
            &g_context->setup_data)) {
      goto fail;
    }
  }

  if (cn)
    gnutls_free(cn);

  return 1;

fail:
  if (cn)
    gnutls_free(cn);

  G_ACTION(gnutls_alert_send(g_session, GNUTLS_AL_FATAL, alert));
  return 0;
}

/*
 * gnutls_certificate_verify_function return values
 * (see gnutls_certificate_set_verify_function())
 *
 * return -1 failed
 *         0 passed
 */
static int cert_verify_callback_gnutls(gnutls_session_t g_session)
{
  int ret;

  if (gnutls_auth_get_type(g_session) == GNUTLS_CRD_CERTIFICATE) {
    if (cert_verify_gnutls(g_session) == 0) {
      G_ACTION(gnutls_alert_send(g_session,
                                 GNUTLS_AL_FATAL,
                                 GNUTLS_A_ACCESS_DENIED));
      return -1;
    }
  }
  return 0;
}

/*
 * return 0   Success (GNUTLS_E_SUCCESS)
 *        neg GNUTLS_E_* error code
 */
static int
setup_pki_credentials(gnutls_certificate_credentials_t *pki_credentials,
                      coap_gnutls_context_t *g_context,
                      coap_dtls_pki_t *setup_data, coap_dtls_role_t role)
{
  int ret;

  G_CHECK(gnutls_certificate_allocate_credentials(pki_credentials),
          "gnutls_certificate_allocate_credentials");

  switch (setup_data->pki_key.key_type) {
  case COAP_PKI_KEY_PEM:
    if (setup_data->pki_key.key.pem.public_cert &&
        setup_data->pki_key.key.pem.public_cert[0] &&
        setup_data->pki_key.key.pem.private_key &&
        setup_data->pki_key.key.pem.private_key[0]) {
      G_CHECK(gnutls_certificate_set_x509_key_file(*pki_credentials,
                                   setup_data->pki_key.key.pem.public_cert,
                                   setup_data->pki_key.key.pem.private_key,
                                   GNUTLS_X509_FMT_PEM),
                 "gnutls_certificate_set_x509_key_file");
    }
    else if (role == COAP_DTLS_ROLE_SERVER) {
      coap_log(LOG_ERR,
               "***setup_pki: (D)TLS: No %s Certificate + Private "
               "Key defined\n",
               role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }
    if (setup_data->pki_key.key.pem.ca_file &&
        setup_data->pki_key.key.pem.ca_file[0]) {
      G_CHECK(gnutls_certificate_set_x509_trust_file(*pki_credentials,
                           setup_data->pki_key.key.pem.ca_file,
                           GNUTLS_X509_FMT_PEM),
              "gnutls_certificate_set_x509_trust_file");
    }
    break;

  case COAP_PKI_KEY_ASN1:
    if (setup_data->pki_key.key.asn1.public_cert &&
        setup_data->pki_key.key.asn1.public_cert_len &&
        setup_data->pki_key.key.asn1.private_key &&
        setup_data->pki_key.key.asn1.private_key_len > 0) {
      gnutls_datum_t cert;
      gnutls_datum_t key;

      /* Kludge to get around const parameters */
      memcpy(&cert.data, &setup_data->pki_key.key.asn1.public_cert,
                         sizeof(cert.data));
      cert.size = setup_data->pki_key.key.asn1.public_cert_len;
      memcpy(&key.data, &setup_data->pki_key.key.asn1.private_key,
                        sizeof(key.data));
      key.size = setup_data->pki_key.key.asn1.private_key_len;
      G_CHECK(gnutls_certificate_set_x509_key_mem(*pki_credentials,
                           &cert,
                           &key,
                           GNUTLS_X509_FMT_DER),
              "gnutls_certificate_set_x509_key_mem");
    }
    else if (role == COAP_DTLS_ROLE_SERVER) {
      coap_log(LOG_ERR,
               "***setup_pki: (D)TLS: No %s Certificate + Private "
               "Key defined\n",
               role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }
    if (setup_data->pki_key.key.asn1.ca_cert &&
        setup_data->pki_key.key.asn1.ca_cert_len > 0) {
      gnutls_datum_t ca_cert;

      /* Kludge to get around const parameters */
      memcpy(&ca_cert.data, &setup_data->pki_key.key.asn1.ca_cert,
                            sizeof(ca_cert.data));
      ca_cert.size = setup_data->pki_key.key.asn1.ca_cert_len;
      G_CHECK(gnutls_certificate_set_x509_trust_mem(*pki_credentials,
                           &ca_cert,
                           GNUTLS_X509_FMT_DER),
              "gnutls_certificate_set_x509_trust_mem");
    }
    break;
  default:
    coap_log(LOG_ERR,
             "***setup_pki: (D)TLS: Unknown key type %d\n",
             setup_data->pki_key.key_type);
    return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
  }

  if (g_context->root_ca_file) {
    G_CHECK(gnutls_certificate_set_x509_trust_file(*pki_credentials,
                         g_context->root_ca_file,
                         GNUTLS_X509_FMT_PEM),
            "gnutls_certificate_set_x509_trust_file");
  }
  if (g_context->root_ca_path) {
#if (GNUTLS_VERSION_NUMBER >= 0x030306)
    G_CHECK(gnutls_certificate_set_x509_trust_dir(*pki_credentials,
                         g_context->root_ca_path,
                         GNUTLS_X509_FMT_PEM),
            "gnutls_certificate_set_x509_trust_dir");
#endif
  }
  if (!(g_context->psk_pki_enabled & IS_PKI)) {
    /* No PKI defined at all - still need a trust set up for 3.6.0 or later */
    G_CHECK(gnutls_certificate_set_x509_system_trust(*pki_credentials),
            "gnutls_certificate_set_x509_system_trust");
  }

  /* Verify Peer */
  if (setup_data->verify_peer_cert) {
    gnutls_certificate_set_verify_function(*pki_credentials,
                                           cert_verify_callback_gnutls);
  }

  /* Cert chain checking (can raise GNUTLS_E_CONSTRAINT_ERROR) */
  if (setup_data->cert_chain_validation) {
    gnutls_certificate_set_verify_limits(*pki_credentials,
                                         0,
                                         setup_data->cert_chain_verify_depth);
  }

  /* Check for self signed */
  gnutls_certificate_set_verify_flags(*pki_credentials,
                                      GNUTLS_VERIFY_DO_NOT_ALLOW_SAME);

  /* CRL checking (can raise GNUTLS_CERT_MISSING_OCSP_STATUS) */
  if (setup_data->check_cert_revocation == 0) {
    gnutls_certificate_set_verify_flags(*pki_credentials,
                                        GNUTLS_VERIFY_DO_NOT_ALLOW_SAME |
                                        GNUTLS_VERIFY_DISABLE_CRL_CHECKS);
  }

  return GNUTLS_E_SUCCESS;

fail:
  return ret;
}

/*
 * return 0   Success (GNUTLS_E_SUCCESS)
 *        neg GNUTLS_E_* error code
 */
static int
post_client_hello_gnutls_pki(gnutls_session_t g_session)
{
  coap_session_t *c_session =
                (coap_session_t *)gnutls_transport_get_ptr(g_session);
  coap_gnutls_context_t *g_context =
             (coap_gnutls_context_t *)c_session->context->dtls_context;
  coap_gnutls_env_t *g_env = (coap_gnutls_env_t *)c_session->tls;
  int ret = GNUTLS_E_SUCCESS;
  char *name = NULL;

  g_env->seen_client_hello = 1;

  if (g_context->setup_data.validate_sni_call_back) {
    /* DNS names (only type supported) may be at most 256 byte long */
    size_t len = 256;
    unsigned int type;
    unsigned int i;
    coap_dtls_pki_t sni_setup_data;

    name = gnutls_malloc(len);
    if (name == NULL)
      return GNUTLS_E_MEMORY_ERROR;

    for (i=0; ; ) {
      ret = gnutls_server_name_get(g_session, name, &len, &type, i);
      if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER) {
        char *new_name;
        new_name = gnutls_realloc(name, len);
        if (new_name == NULL) {
          ret = GNUTLS_E_MEMORY_ERROR;
          goto end;
        }
        name = new_name;
        continue; /* retry call with same index */
      }

      /* check if it is the last entry in list */
      if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
        break;
      i++;
      if (ret != GNUTLS_E_SUCCESS)
        goto end;
      /* unknown types need to be ignored */
      if (type != GNUTLS_NAME_DNS)
        continue;

    }
    /* If no extension provided, make it a dummy entry */
    if (i == 0) {
      name[0] = '\000';
      len = 0;
    }

    /* Is this a cached entry? */
    for (i = 0; i < g_context->sni_count; i++) {
      if (strcmp(name, g_context->sni_entry_list[i].sni) == 0) {
        break;
      }
    }
    if (i == g_context->sni_count) {
      /*
       * New SNI request
       */
      coap_dtls_key_t *new_entry =
        g_context->setup_data.validate_sni_call_back(name,
                                   g_context->setup_data.sni_call_back_arg);
      if (!new_entry) {
        G_ACTION(gnutls_alert_send(g_session, GNUTLS_AL_FATAL,
                                   GNUTLS_A_UNRECOGNIZED_NAME));
        ret = GNUTLS_E_NO_CERTIFICATE_FOUND;
        goto end;
      }

      g_context->sni_entry_list = gnutls_realloc(g_context->sni_entry_list,
                                     (i+1)*sizeof(sni_entry));
      g_context->sni_entry_list[i].sni = gnutls_strdup(name);
      g_context->sni_entry_list[i].pki_key = *new_entry;
      sni_setup_data = g_context->setup_data;
      sni_setup_data.pki_key = *new_entry;
      if ((ret = setup_pki_credentials(
                           &g_context->sni_entry_list[i].pki_credentials,
                           g_context,
                           &sni_setup_data, COAP_DTLS_ROLE_CLIENT)) < 0) {
        int keep_ret = ret;
        G_ACTION(gnutls_alert_send(g_session, GNUTLS_AL_FATAL,
                                   GNUTLS_A_BAD_CERTIFICATE));
        ret = keep_ret;
        goto end;
      }
      g_context->sni_count++;
    }
    G_CHECK(gnutls_credentials_set(g_env->g_session, GNUTLS_CRD_CERTIFICATE,
                               g_context->sni_entry_list[i].pki_credentials),
            "gnutls_credentials_set");
  }

end:
  free(name);
  return ret;

fail:
  return ret;
}

/*
 * return 0   Success (GNUTLS_E_SUCCESS)
 *        neg GNUTLS_E_* error code
 */
static int
post_client_hello_gnutls_psk(gnutls_session_t g_session)
{
  coap_session_t *c_session =
                (coap_session_t *)gnutls_transport_get_ptr(g_session);
  coap_gnutls_env_t *g_env = (coap_gnutls_env_t *)c_session->tls;

  g_env->seen_client_hello = 1;
  return GNUTLS_E_SUCCESS;
}

/*
 * return 0   Success (GNUTLS_E_SUCCESS)
 *        neg GNUTLS_E_* error code
 */
static int
setup_client_ssl_session(coap_session_t *c_session, coap_gnutls_env_t *g_env)
{
  coap_gnutls_context_t *g_context =
             (coap_gnutls_context_t *)c_session->context->dtls_context;
  int ret;

  g_context->psk_pki_enabled |= IS_CLIENT;
  if (g_context->psk_pki_enabled & IS_PSK) {
    char *identity = NULL;
    gnutls_datum_t psk_key;

    G_CHECK(gnutls_psk_allocate_client_credentials(&g_env->psk_cl_credentials),
            "gnutls_psk_allocate_client_credentials");
    psk_client_callback(g_env->g_session, &identity, &psk_key);
    G_CHECK(gnutls_psk_set_client_credentials(g_env->psk_cl_credentials,
                                              identity,
                                              &psk_key,
                                              GNUTLS_PSK_KEY_RAW),
            "gnutls_psk_set_client_credentials");
    G_CHECK(gnutls_credentials_set(g_env->g_session, GNUTLS_CRD_PSK,
                                   g_env->psk_cl_credentials),
            "gnutls_credentials_set");
    gnutls_free(identity);
    gnutls_free(psk_key.data);
  }

  if ((g_context->psk_pki_enabled & IS_PKI) ||
      (g_context->psk_pki_enabled & (IS_PSK | IS_PKI)) == 0) {
    /*
     * If neither PSK or PKI have been set up, use PKI basics.
     * This works providing COAP_PKI_KEY_PEM has a value of 0.
     */
    coap_dtls_pki_t *setup_data = &g_context->setup_data;
    G_CHECK(setup_pki_credentials(&g_env->pki_credentials, g_context,
                                  setup_data, COAP_DTLS_ROLE_CLIENT),
            "setup_pki_credentials");

    G_CHECK(gnutls_credentials_set(g_env->g_session, GNUTLS_CRD_CERTIFICATE,
                                   g_env->pki_credentials),
            "gnutls_credentials_set");

    if (c_session->proto == COAP_PROTO_TLS)
      G_CHECK(gnutls_alpn_set_protocols(g_env->g_session,
                                        &g_context->alpn_proto, 1, 0),
              "gnutls_alpn_set_protocols");

    /* Issue SNI if requested (only happens if PKI defined) */
    if (setup_data->client_sni) {
      G_CHECK(gnutls_server_name_set(g_env->g_session, GNUTLS_NAME_DNS,
                                     setup_data->client_sni,
                                     strlen(setup_data->client_sni)),
              "gnutls_server_name_set");
    }
  }
  return GNUTLS_E_SUCCESS;

fail:
  return ret;
}

/*
 * gnutls_psk_server_credentials_function return values
 * (see gnutls_psk_set_server_credentials_function())
 *
 * return -1 failed
 *         0 passed
 */
static int
psk_server_callback(gnutls_session_t g_session,
                    const char *identity,
                    gnutls_datum_t *key)
{
  coap_session_t *c_session =
                (coap_session_t *)gnutls_transport_get_ptr(g_session);
  size_t identity_len = 0;
  uint8_t buf[64];
  size_t psk_len;

  if (identity)
    identity_len = strlen(identity);
  else
    identity = "";

  coap_log(LOG_DEBUG, "got psk_identity: '%.*s'\n",
                      (int)identity_len, identity);

  if (c_session == NULL || c_session->context == NULL ||
      c_session->context->get_server_psk == NULL)
    return -1;

  psk_len = c_session->context->get_server_psk(c_session,
                               (const uint8_t*)identity,
                               identity_len,
                               (uint8_t*)buf, sizeof(buf));
  key->data = gnutls_malloc(psk_len);
  memcpy(key->data, buf, psk_len);
  key->size = psk_len;
  return 0;
}

/*
 * return 0   Success (GNUTLS_E_SUCCESS)
 *        neg GNUTLS_E_* error code
 */
static int
setup_server_ssl_session(coap_session_t *c_session, coap_gnutls_env_t *g_env)
{
  coap_gnutls_context_t *g_context =
             (coap_gnutls_context_t *)c_session->context->dtls_context;
  int ret = GNUTLS_E_SUCCESS;

  g_context->psk_pki_enabled |= IS_SERVER;
  if (g_context->psk_pki_enabled & IS_PSK) {
    G_CHECK(gnutls_psk_allocate_server_credentials(&g_env->psk_sv_credentials),
            "gnutls_psk_allocate_server_credentials");
    gnutls_psk_set_server_credentials_function(g_env->psk_sv_credentials,
                                                      psk_server_callback);

    gnutls_handshake_set_post_client_hello_function(g_env->g_session,
                                                 post_client_hello_gnutls_psk);

    G_CHECK(gnutls_credentials_set(g_env->g_session,
                                   GNUTLS_CRD_PSK,
                                   g_env->psk_sv_credentials),
            "gnutls_credentials_set\n");
  }

  if (g_context->psk_pki_enabled & IS_PKI) {
    coap_dtls_pki_t *setup_data = &g_context->setup_data;
    G_CHECK(setup_pki_credentials(&g_env->pki_credentials, g_context,
                                  setup_data, COAP_DTLS_ROLE_SERVER),
            "setup_pki_credentials");

    if (setup_data->require_peer_cert) {
      gnutls_certificate_server_set_request(g_env->g_session,
                                            GNUTLS_CERT_REQUIRE);
    }
    else {
      gnutls_certificate_server_set_request(g_env->g_session, GNUTLS_CERT_IGNORE);
    }

    gnutls_handshake_set_post_client_hello_function(g_env->g_session,
                                                 post_client_hello_gnutls_pki);

    G_CHECK(gnutls_credentials_set(g_env->g_session, GNUTLS_CRD_CERTIFICATE,
                                   g_env->pki_credentials),
            "gnutls_credentials_set\n");
  }
  return GNUTLS_E_SUCCESS;

fail:
  return ret;
}

/*
 * return +ve data amount
 *        0   no more
 *        -1  error (error in errno)
 */
static ssize_t
coap_dgram_read(gnutls_transport_ptr_t context, void *out, size_t outl)
{
  ssize_t ret = 0;
  coap_session_t *c_session = (struct coap_session_t *)context;
  coap_ssl_t *data = &((coap_gnutls_env_t *)c_session->tls)->coap_ssl_data;

  if (!c_session->tls) {
    errno = EAGAIN;
    return -1;
  }

  if (out != NULL) {
    if (data != NULL && data->pdu_len > 0) {
      if (outl < data->pdu_len) {
        memcpy(out, data->pdu, outl);
        ret = outl;
        data->pdu += outl;
        data->pdu_len -= outl;
      } else {
        memcpy(out, data->pdu, data->pdu_len);
        ret = data->pdu_len;
        if (!data->peekmode) {
          data->pdu_len = 0;
          data->pdu = NULL;
        }
      }
    }
    else {
      errno = EAGAIN;
      ret = -1;
    }
  }
  return ret;
}

/*
 * return +ve data amount
 *        0   no more
 *        -1  error (error in errno)
 */
/* callback function given to gnutls for sending data over socket */
static ssize_t
coap_dgram_write(gnutls_transport_ptr_t context, const void *send_buffer,
                  size_t send_buffer_length) {
  ssize_t result = -1;
  coap_session_t *c_session = (struct coap_session_t *)context;

  if (c_session) {
    result = coap_session_send(c_session, send_buffer, send_buffer_length);
    if (result != (int)send_buffer_length) {
      coap_log(LOG_WARNING, "coap_network_send failed\n");
      result = 0;
    }
  } else {
    result = 0;
  }
  return result;
}

/*
 * return 1  fd has activity
 *        0  timeout
 *        -1 error (error in errno)
 */
static int
receive_timeout(gnutls_transport_ptr_t context, unsigned int ms UNUSED) {
  coap_session_t *c_session = (struct coap_session_t *)context;

  if (c_session) {
    fd_set readfds, writefds, exceptfds;
    struct timeval tv;
    int nfds = c_session->sock.fd +1;

    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);
    FD_SET (c_session->sock.fd, &readfds);
    FD_SET (c_session->sock.fd, &writefds);
    FD_SET (c_session->sock.fd, &exceptfds);
    /* Polling */
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    return select(nfds, &readfds, &writefds, &exceptfds, &tv);
  }
  return 1;
}

static coap_gnutls_env_t *
coap_dtls_new_gnutls_env(coap_session_t *c_session, int type)
{
  coap_gnutls_context_t *g_context =
          ((coap_gnutls_context_t *)c_session->context->dtls_context);
  coap_gnutls_env_t *g_env = (coap_gnutls_env_t *)c_session->tls;
  int flags = type | GNUTLS_DATAGRAM | GNUTLS_NONBLOCK;
  int ret;

  if (g_env)
    return g_env;

  g_env = gnutls_malloc(sizeof(coap_gnutls_env_t));
  if (!g_env)
    return NULL;

  memset(g_env, 0, sizeof(struct coap_gnutls_env_t));

  G_CHECK(gnutls_init(&g_env->g_session, flags), "gnutls_init");

  gnutls_transport_set_pull_function(g_env->g_session, coap_dgram_read);
  gnutls_transport_set_push_function(g_env->g_session, coap_dgram_write);
  gnutls_transport_set_pull_timeout_function(g_env->g_session, receive_timeout);
  /* So we can track the coap_session_t in callbacks */
  gnutls_transport_set_ptr(g_env->g_session, c_session);

  if (type == GNUTLS_SERVER) {
    G_CHECK(setup_server_ssl_session(c_session, g_env),
            "setup_server_ssl_session");
  }
  else {
    G_CHECK(setup_client_ssl_session(c_session, g_env),
            "setup_client_ssl_session");
  }

  G_CHECK(gnutls_priority_set(g_env->g_session, g_context->priority_cache),
          "gnutls_priority_set");
  gnutls_handshake_set_timeout(g_env->g_session,
                               GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

  return g_env;

fail:
  if (g_env)
    gnutls_free(g_env);
  return NULL;
}

static void
coap_dtls_free_gnutls_env(coap_gnutls_context_t *g_context,
                          coap_gnutls_env_t *g_env,
                          coap_free_bye_t free_bye)
{
  if (g_env) {
    /* It is suggested not to use GNUTLS_SHUT_RDWR in DTLS
     * connections because the peer's closure message might
     * be lost */
    if (free_bye != COAP_FREE_BYE_NONE) {
      /* Only do this if appropriate */
      gnutls_bye(g_env->g_session, free_bye == COAP_FREE_BYE_AS_UDP ?
                                       GNUTLS_SHUT_WR : GNUTLS_SHUT_RDWR);
    }
    gnutls_deinit(g_env->g_session);
    g_env->g_session = NULL;
    if (g_context->psk_pki_enabled & IS_PSK) {
      if (g_context->psk_pki_enabled & IS_CLIENT) {
        gnutls_psk_free_client_credentials(g_env->psk_cl_credentials);
        g_env->psk_cl_credentials = NULL;
      }
      else {
        gnutls_psk_free_server_credentials(g_env->psk_sv_credentials);
        g_env->psk_sv_credentials = NULL;
      }
    }
    if (g_context->psk_pki_enabled & IS_PKI) {
      gnutls_certificate_free_credentials(g_env->pki_credentials);
      g_env->pki_credentials = NULL;
    }
    gnutls_free(g_env);
  }
}

void *coap_dtls_new_server_session(coap_session_t *c_session) {
  coap_gnutls_env_t *g_env =
         (coap_gnutls_env_t *)c_session->tls;

  gnutls_transport_set_ptr(g_env->g_session, c_session);

  return g_env;
}

static void log_last_alert(gnutls_session_t g_session) {
  int last_alert = gnutls_alert_get(g_session);

  coap_log(LOG_WARNING, "Received alert '%d': '%s'\n",
                        last_alert, gnutls_alert_get_name(last_alert));
}

/*
 * return -1  failure
 *         0  not completed
 *         1  established
 */
static int
do_gnutls_handshake(coap_session_t *c_session, coap_gnutls_env_t *g_env) {
  int ret;

  ret = gnutls_handshake(g_env->g_session);
  switch (ret) {
  case GNUTLS_E_SUCCESS:
    g_env->established = 1;
    coap_log(LOG_DEBUG, "*  %s: GnuTLS established\n",
                                            coap_session_str(c_session));
    ret = 1;
    break;
  case GNUTLS_E_INTERRUPTED:
    errno = EINTR;
    ret = 0;
    break;
  case GNUTLS_E_AGAIN:
    errno = EAGAIN;
    ret = 0;
    break;
  case GNUTLS_E_INSUFFICIENT_CREDENTIALS:
    coap_log(LOG_WARNING,
             "Insufficient credentials provided.\n");
    ret = -1;
    break;
  case GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET:
  case GNUTLS_E_FATAL_ALERT_RECEIVED:
    log_last_alert(g_env->g_session);
    c_session->dtls_event = COAP_EVENT_DTLS_CLOSED;
    ret = -1;
    break;
  case GNUTLS_E_WARNING_ALERT_RECEIVED:
    log_last_alert(g_env->g_session);
    c_session->dtls_event = COAP_EVENT_DTLS_ERROR;
    ret = 0;
    break;
  case GNUTLS_E_NO_CERTIFICATE_FOUND:
    coap_log(LOG_WARNING,
             "Client Certificate requested and required, but not provided\n"
             );
    G_ACTION(gnutls_alert_send(g_env->g_session, GNUTLS_AL_FATAL,
                                                 GNUTLS_A_BAD_CERTIFICATE));
    c_session->dtls_event = COAP_EVENT_DTLS_CLOSED;
    ret = -1;
    break;
  case GNUTLS_E_DECRYPTION_FAILED:
    coap_log(LOG_WARNING,
             "do_gnutls_handshake: session establish "
             "returned %d: '%s'\n",
             ret, gnutls_strerror(ret));
    G_ACTION(gnutls_alert_send(g_env->g_session, GNUTLS_AL_FATAL,
                                                 GNUTLS_A_DECRYPT_ERROR));
    c_session->dtls_event = COAP_EVENT_DTLS_CLOSED;
    ret = -1;
    break;
  case GNUTLS_E_UNKNOWN_CIPHER_SUITE:
  /* fall through */
  case GNUTLS_E_TIMEDOUT:
    c_session->dtls_event = COAP_EVENT_DTLS_CLOSED;
    ret = -1;
    break;
  default:
    coap_log(LOG_WARNING,
             "do_gnutls_handshake: session establish "
             "returned %d: '%s'\n",
             ret, gnutls_strerror(ret));
    ret = -1;
    break;
  }
  return ret;
}

void *coap_dtls_new_client_session(coap_session_t *c_session) {
  coap_gnutls_env_t *g_env = coap_dtls_new_gnutls_env(c_session, GNUTLS_CLIENT);
  int ret;

  if (g_env) {
    ret = do_gnutls_handshake(c_session, g_env);
    if (ret == -1) {
      coap_dtls_free_gnutls_env(c_session->context->dtls_context,
                                g_env,
                                COAP_PROTO_NOT_RELIABLE(c_session->proto) ?
                                 COAP_FREE_BYE_AS_UDP : COAP_FREE_BYE_AS_TCP);
      return NULL;
    }
  }
  return g_env;
}

void coap_dtls_free_session(coap_session_t *c_session) {
  if (c_session && c_session->context) {
    coap_dtls_free_gnutls_env(c_session->context->dtls_context,
                c_session->tls,
                COAP_PROTO_NOT_RELIABLE(c_session->proto) ?
                 COAP_FREE_BYE_AS_UDP : COAP_FREE_BYE_AS_TCP);
    c_session->tls = NULL;
  }
}

void coap_dtls_session_update_mtu(coap_session_t *c_session) {
  coap_gnutls_env_t *g_env = (coap_gnutls_env_t *)c_session->tls;
  int ret;

  if (g_env)
    G_CHECK(gnutls_dtls_set_data_mtu(g_env->g_session, c_session->mtu),
            "gnutls_dtls_set_data_mtu");
fail:
  ;;
}

/*
 * return +ve data amount
 *        0   no more
 *        -1  error
 */
int coap_dtls_send(coap_session_t *c_session,
  const uint8_t *data, size_t data_len) {
  int ret;
  coap_gnutls_env_t *g_env = (coap_gnutls_env_t *)c_session->tls;

  assert(g_env != NULL);

  c_session->dtls_event = -1;
  if (g_env->established) {
    ret = gnutls_record_send(g_env->g_session, data, data_len);

    if (ret <= 0) {
      switch (ret) {
      case GNUTLS_E_AGAIN:
        ret = 0;
        break;
      case GNUTLS_E_FATAL_ALERT_RECEIVED:
        log_last_alert(g_env->g_session);
        c_session->dtls_event = COAP_EVENT_DTLS_ERROR;
        ret = -1;
        break;
      default:
        ret = -1;
        break;
      }
      if (ret == -1) {
        coap_log(LOG_WARNING, "coap_dtls_send: cannot send PDU\n");
      }
    }
  }
  else {
    ret = do_gnutls_handshake(c_session, g_env);
    if (ret == 1) {
      /* Just connected, so send the data */
      return coap_dtls_send(c_session, data, data_len);
    }
    ret = -1;
  }

  if (c_session->dtls_event >= 0) {
    coap_handle_event(c_session->context, c_session->dtls_event, c_session);
    if (c_session->dtls_event == COAP_EVENT_DTLS_ERROR ||
        c_session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected(c_session, COAP_NACK_TLS_FAILED);
      ret = -1;
    }
  }

  return ret;
}

int coap_dtls_is_context_timeout(void) {
  return 1;
}

coap_tick_t coap_dtls_get_context_timeout(void *dtls_context UNUSED) {
  return 0;
}

coap_tick_t coap_dtls_get_timeout(coap_session_t *c_session UNUSED) {
  return 0;
}

void coap_dtls_handle_timeout(coap_session_t *c_session UNUSED) {
}

/*
 * return +ve data amount
 *        0   no more
 *        -1  error
 */
int
coap_dtls_receive(coap_session_t *c_session,
  const uint8_t *data,
  size_t data_len
) {
  coap_gnutls_env_t *g_env = (coap_gnutls_env_t *)c_session->tls;
  int ret = 0;
  coap_ssl_t *ssl_data = &g_env->coap_ssl_data;

  uint8_t pdu[COAP_RXBUFFER_SIZE];

  assert(g_env != NULL);

  if (ssl_data->pdu_len)
    coap_log(LOG_INFO, "** %s: Previous data not read %u bytes\n",
             coap_session_str(c_session), ssl_data->pdu_len);
  ssl_data->pdu = data;
  ssl_data->pdu_len = (unsigned)data_len;

  c_session->dtls_event = -1;
  if (g_env->established) {
    if (c_session->state == COAP_SESSION_STATE_HANDSHAKE) {
      coap_handle_event(c_session->context, COAP_EVENT_DTLS_CONNECTED,
                        c_session);
      gnutls_transport_set_ptr(g_env->g_session, c_session);
      coap_session_connected(c_session);
    }
    ret = gnutls_record_recv(g_env->g_session, pdu, (int)sizeof(pdu));
    if (ret > 0) {
      return coap_handle_dgram(c_session->context, c_session, pdu, (size_t)ret);
    }
    else if (ret == 0) {
      c_session->dtls_event = COAP_EVENT_DTLS_CLOSED;
    }
    else {
      coap_log(LOG_WARNING,
               "coap_dtls_receive: gnutls_record_recv returned %d\n", ret);
      ret = -1;
    }
  }
  else {
    ret = do_gnutls_handshake(c_session, g_env);
    if (ret == 1) {
      coap_session_connected(c_session);
    }
    else {
      ret = -1;
    }
  }

  if (c_session->dtls_event >= 0) {
    coap_handle_event(c_session->context, c_session->dtls_event, c_session);
    if (c_session->dtls_event == COAP_EVENT_DTLS_ERROR ||
        c_session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected(c_session, COAP_NACK_TLS_FAILED);
      ret = -1;
    }
  }

  return ret;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_hello(coap_session_t *c_session,
  const uint8_t *data,
  size_t data_len
) {
  coap_gnutls_env_t *g_env = (coap_gnutls_env_t *)c_session->tls;
  coap_ssl_t *ssl_data = g_env ? &g_env->coap_ssl_data : NULL;
  int ret;

  if (!g_env) {
    g_env = coap_dtls_new_gnutls_env(c_session, GNUTLS_SERVER);
    if (g_env) {
      c_session->tls = g_env;
      ssl_data = &g_env->coap_ssl_data;
      ssl_data->pdu = data;
      ssl_data->pdu_len = (unsigned)data_len;
      gnutls_dtls_set_data_mtu(g_env->g_session, c_session->mtu);
      ret = do_gnutls_handshake(c_session, g_env);
      if (ret == 1 || g_env->seen_client_hello) {
        /* The test for seen_client_hello gives the ability to setup a new
           coap_session to continue the gnutls_handshake past the client hello
           and safely allow updating of the g_env & g_session and separately
           letting a new session cleanly start up using endpoint->hello.
         */
        g_env->seen_client_hello = 0;
        return 1;
      }
      /*
       * as the above failed, need to remove g_env to clean up any
       * pollution of the information
       */
      coap_dtls_free_gnutls_env(
              ((coap_gnutls_context_t *)c_session->context->dtls_context),
              g_env, COAP_FREE_BYE_NONE);
      c_session->tls = NULL;
    }
    return 0;
  }

  ssl_data->pdu = data;
  ssl_data->pdu_len = (unsigned)data_len;

  ret = do_gnutls_handshake(c_session, g_env);
  if (ret == 1 || g_env->seen_client_hello) {
    /* The test for seen_client_hello gives the ability to setup a new
       coap_session to continue the gnutls_handshake past the client hello
       and safely allow updating of the g_env & g_session and separately
       letting a new session cleanly start up using endpoint->hello.
     */
    g_env->seen_client_hello = 0;
    return 1;
  }
  return 0;
}

unsigned int coap_dtls_get_overhead(coap_session_t *c_session UNUSED) {
  return 37;
}

/*
 * return +ve data amount
 *        0   no more
 *        -1  error (error in errno)
 */
static ssize_t
coap_sock_read(gnutls_transport_ptr_t context, void *out, size_t outl) {
  int ret = 0;
  coap_session_t *c_session = (struct coap_session_t *)context;

  if (out != NULL) {
#ifdef _WIN32
    ret = recv(c_session->sock.fd, (char *)out, (int)outl, 0);
#else
    ret = recv(c_session->sock.fd, out, outl, 0);
#endif
    if (ret == 0) {
      /* graceful shutdown */
      c_session->sock.flags &= ~COAP_SOCKET_CAN_READ;
      return 0;
    } else if (ret == COAP_SOCKET_ERROR)
      c_session->sock.flags &= ~COAP_SOCKET_CAN_READ;
    else if (ret < (ssize_t)outl)
      c_session->sock.flags &= ~COAP_SOCKET_CAN_READ;
    return ret;
  }
  return ret;
}

/*
 * return +ve data amount
 *        0   no more
 *        -1  error (error in errno)
 */
static ssize_t
coap_sock_write(gnutls_transport_ptr_t context, const void *in, size_t inl) {
  int ret = 0;
  coap_session_t *c_session = (struct coap_session_t *)context;

  ret = (int)coap_socket_write(&c_session->sock, in, inl);
  if (ret == 0) {
    errno = EAGAIN;
    ret = -1;
  }
  return ret;
}

void *coap_tls_new_client_session(coap_session_t *c_session, int *connected) {
  coap_gnutls_env_t *g_env = gnutls_malloc(sizeof(coap_gnutls_env_t));
  coap_gnutls_context_t *g_context =
                ((coap_gnutls_context_t *)c_session->context->dtls_context);
  int flags = GNUTLS_CLIENT;
  int ret;

  if (!g_env) {
    return NULL;
  }
  memset(g_env, 0, sizeof(struct coap_gnutls_env_t));

  *connected = 0;
  G_CHECK(gnutls_init(&g_env->g_session, flags), "gnutls_init");

  gnutls_transport_set_pull_function(g_env->g_session, coap_sock_read);
  gnutls_transport_set_push_function(g_env->g_session, coap_sock_write);
  gnutls_transport_set_pull_timeout_function(g_env->g_session, receive_timeout);
  /* So we can track the coap_session_t in callbacks */
  gnutls_transport_set_ptr(g_env->g_session, c_session);

  setup_client_ssl_session(c_session, g_env);

  gnutls_priority_set(g_env->g_session, g_context->priority_cache);
  gnutls_handshake_set_timeout(g_env->g_session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

  ret = do_gnutls_handshake(c_session, g_env);
  if (ret == 1) {
    *connected = 1;
    coap_handle_event(c_session->context, COAP_EVENT_DTLS_CONNECTED, c_session);
    coap_session_connected(c_session);
  }
  return g_env;

fail:
  if (g_env)
    gnutls_free(g_env);
  return NULL;
}

void *coap_tls_new_server_session(coap_session_t *c_session, int *connected) {
  coap_gnutls_env_t *g_env = gnutls_malloc(sizeof(coap_gnutls_env_t));
  coap_gnutls_context_t *g_context =
             ((coap_gnutls_context_t *)c_session->context->dtls_context);
  int flags = GNUTLS_SERVER;
  int ret;

  if (!g_env)
    return NULL;
  memset(g_env, 0, sizeof(struct coap_gnutls_env_t));

  *connected = 0;
  G_CHECK(gnutls_init(&g_env->g_session, flags), "gnutls_init");

  gnutls_transport_set_pull_function(g_env->g_session, coap_sock_read);
  gnutls_transport_set_push_function(g_env->g_session, coap_sock_write);
  gnutls_transport_set_pull_timeout_function(g_env->g_session, receive_timeout);
  /* So we can track the coap_session_t in callbacks */
  gnutls_transport_set_ptr(g_env->g_session, c_session);

  setup_server_ssl_session(c_session, g_env);

  gnutls_priority_set(g_env->g_session, g_context->priority_cache);
  gnutls_handshake_set_timeout(g_env->g_session,
                                     GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

  c_session->tls = g_env;
  ret = do_gnutls_handshake(c_session, g_env);
  if (ret == 1) {
    *connected = 1;
  }
  return g_env;

fail:
  return NULL;
}

void coap_tls_free_session(coap_session_t *c_session) {
  coap_dtls_free_session(c_session);
  return;
}

/*
 * return +ve data amount
 *        0   no more
 *        -1  error (error in errno)
 */
ssize_t coap_tls_write(coap_session_t *c_session,
                       const uint8_t *data,
                       size_t data_len
) {
  int ret;
  coap_gnutls_env_t *g_env = (coap_gnutls_env_t *)c_session->tls;

  assert(g_env != NULL);

  c_session->dtls_event = -1;
  if (g_env->established) {
    ret = gnutls_record_send(g_env->g_session, data, data_len);

    if (ret <= 0) {
      switch (ret) {
      case GNUTLS_E_AGAIN:
        ret = 0;
        break;
      case GNUTLS_E_FATAL_ALERT_RECEIVED:
        log_last_alert(g_env->g_session);
        c_session->dtls_event = COAP_EVENT_DTLS_ERROR;
        ret = -1;
        break;
      default:
        coap_log(LOG_WARNING,
                 "coap_tls_write: gnutls_record_send "
                 "returned %d: '%s'\n",
                 ret, gnutls_strerror(ret));
        ret = -1;
        break;
      }
      if (ret == -1) {
        coap_log(LOG_WARNING, "coap_dtls_send: cannot send PDU\n");
      }
    }
  }
  else {
    ret = do_gnutls_handshake(c_session, g_env);
    if (ret == 1) {
      coap_handle_event(c_session->context, COAP_EVENT_DTLS_CONNECTED,
                                     c_session);
      coap_session_send_csm(c_session);
    }
    else {
      ret = -1;
    }
  }

  if (c_session->dtls_event >= 0) {
    coap_handle_event(c_session->context, c_session->dtls_event, c_session);
    if (c_session->dtls_event == COAP_EVENT_DTLS_ERROR ||
        c_session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected(c_session, COAP_NACK_TLS_FAILED);
      ret = -1;
    }
  }

  return ret;
}

/*
 * return +ve data amount
 *        0   no more
 *        -1  error (error in errno)
 */
ssize_t coap_tls_read(coap_session_t *c_session,
                      uint8_t *data,
                      size_t data_len
) {
  coap_gnutls_env_t *g_env = (coap_gnutls_env_t *)c_session->tls;
  int ret;

  if (!g_env)
    return -1;

  c_session->dtls_event = -1;
  if (!g_env->established) {
    ret = do_gnutls_handshake(c_session, g_env);
    if (ret == 1) {
      coap_handle_event(c_session->context, COAP_EVENT_DTLS_CONNECTED,
                                                               c_session);
      coap_session_send_csm(c_session);
    }
  }
  if (g_env->established) {
    ret = gnutls_record_recv(g_env->g_session, data, (int)data_len);
    if (ret <= 0) {
      switch (ret) {
      case 0:
        c_session->dtls_event = COAP_EVENT_DTLS_CLOSED;
        break;
      case GNUTLS_E_AGAIN:
        errno = EAGAIN;
        ret = 0;
        break;
      case GNUTLS_E_PULL_ERROR:
        c_session->dtls_event = COAP_EVENT_DTLS_ERROR;
        break;
      default:
        coap_log(LOG_WARNING,
                 "coap_tls_read: gnutls_record_recv "
                 "returned %d: '%s'\n",
                 ret, gnutls_strerror(ret));
        ret = -1;
        break;
      }
    }
  }

  if (c_session->dtls_event >= 0) {
    coap_handle_event(c_session->context, c_session->dtls_event, c_session);
    if (c_session->dtls_event == COAP_EVENT_DTLS_ERROR ||
        c_session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected(c_session, COAP_NACK_TLS_FAILED);
      ret = -1;
    }
  }
  return ret;
}

#else /* !HAVE_LIBGNUTLS */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void dummy(void) {
}

#endif /* !HAVE_LIBGNUTLS */
/* coap_hashkey.c -- definition of hash key type and helper functions
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_hashkey.h"

void
coap_hash_impl(const unsigned char *s, unsigned int len, coap_key_t h) {
  size_t j;

  while (len--) {
    j = sizeof(coap_key_t)-1;

    while (j) {
      h[j] = ((h[j] << 7) | (h[j-1] >> 1)) + h[j];
      --j;
    }

    h[0] = (h[0] << 7) + h[0] + *s++;
  }
}

/* coap_io.c -- Default network I/O functions for libcoap
 *
 * Copyright (C) 2012,2014,2016-2019 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_config.h"

#ifdef HAVE_STDIO_H
#  include <stdio.h>
#endif

#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
# define OPTVAL_T(t)         (t)
# define OPTVAL_GT(t)        (t)
#endif
#ifdef HAVE_SYS_IOCTL_H
 #include <sys/ioctl.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
# define OPTVAL_T(t)         (const char*)(t)
# define OPTVAL_GT(t)        (char*)(t)
# undef CMSG_DATA
# define CMSG_DATA WSA_CMSG_DATA
#endif
#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <errno.h>

#ifdef WITH_CONTIKI
# include "uip.h"
#endif

#include "libcoap.h"
#include "coap_debug.h"
#include "mem.h"
#include "net.h"
#include "coap_io.h"
#include "pdu.h"
#include "utlist.h"
#include "resource.h"
#include "coap_mutex.h"

#if !defined(WITH_CONTIKI)
 /* define generic PKTINFO for IPv4 */
#if defined(IP_PKTINFO)
#  define GEN_IP_PKTINFO IP_PKTINFO
#elif defined(IP_RECVDSTADDR)
#  define GEN_IP_PKTINFO IP_RECVDSTADDR
#else
#  error "Need IP_PKTINFO or IP_RECVDSTADDR to request ancillary data from OS."
#endif /* IP_PKTINFO */

/* define generic KTINFO for IPv6 */
#ifdef IPV6_RECVPKTINFO
#  define GEN_IPV6_PKTINFO IPV6_RECVPKTINFO
#elif defined(IPV6_PKTINFO)
#  define GEN_IPV6_PKTINFO IPV6_PKTINFO
#else
#  error "Need IPV6_PKTINFO or IPV6_RECVPKTINFO to request ancillary data from OS."
#endif /* IPV6_RECVPKTINFO */
#endif

void coap_free_endpoint(coap_endpoint_t *ep);

#ifdef WITH_CONTIKI
static int ep_initialized = 0;

struct coap_endpoint_t *
  coap_malloc_endpoint() {
  static struct coap_endpoint_t ep;

  if (ep_initialized) {
    return NULL;
  } else {
    ep_initialized = 1;
    return &ep;
  }
}

void
coap_mfree_endpoint(struct coap_endpoint_t *ep) {
  ep_initialized = 0;
}

int
coap_socket_bind_udp(coap_socket_t *sock,
  const coap_address_t *listen_addr,
  coap_address_t *bound_addr) {
  sock->conn = udp_new(NULL, 0, NULL);

  if (!sock->conn) {
    coap_log(LOG_WARNING, "coap_socket_bind_udp");
    return 0;
  }

  coap_address_init(bound_addr);
  uip_ipaddr_copy(&bound_addr->addr, &listen_addr->addr);
  bound_addr->port = listen_addr->port;
  udp_bind((struct uip_udp_conn *)sock->conn, bound_addr->port);
  return 1;
}

int
coap_socket_connect_udp(coap_socket_t *sock,
  const coap_address_t *local_if,
  const coap_address_t *server,
  int default_port,
  coap_address_t *local_addr,
  coap_address_t *remote_addr) {
  return 0;
}

int
coap_socket_connect_tcp1(coap_socket_t *sock,
                         const coap_address_t *local_if,
                         const coap_address_t *server,
                         int default_port,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr) {
  return 0;
}

int
coap_socket_connect_tcp2(coap_socket_t *sock,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr) {
  return 0;
}

int
coap_socket_bind_tcp(coap_socket_t *sock,
                     const coap_address_t *listen_addr,
                     coap_address_t *bound_addr) {
  return 0;
}

int
coap_socket_accept_tcp(coap_socket_t *server,
                        coap_socket_t *new_client,
                        coap_address_t *local_addr,
                        coap_address_t *remote_addr) {
  return 0;
}

ssize_t
coap_socket_write(coap_socket_t *sock, const uint8_t *data, size_t data_len) {
  return -1;
}

ssize_t
coap_socket_read(coap_socket_t *sock, uint8_t *data, size_t data_len) {
  return -1;
}

void coap_socket_close(coap_socket_t *sock) {
  if (sock->conn)
    uip_udp_remove((struct uip_udp_conn *)sock->conn);
  sock->flags = COAP_SOCKET_EMPTY;
}

#else

static const char *coap_socket_format_errno( int error );

struct coap_endpoint_t *
  coap_malloc_endpoint(void) {
  return (struct coap_endpoint_t *)coap_malloc_type(COAP_ENDPOINT, sizeof(struct coap_endpoint_t));
}

void
coap_mfree_endpoint(struct coap_endpoint_t *ep) {
  coap_free_type(COAP_ENDPOINT, ep);
}

int
coap_socket_bind_udp(coap_socket_t *sock,
  const coap_address_t *listen_addr,
  coap_address_t *bound_addr) {
  int on = 1, off = 0;
#ifdef _WIN32
  u_long u_on = 1;
#endif

  sock->fd = socket(listen_addr->addr.sa.sa_family, SOCK_DGRAM, 0);

  if (sock->fd == COAP_INVALID_SOCKET) {
    coap_log(LOG_WARNING,
             "coap_socket_bind_udp: socket: %s\n", coap_socket_strerror());
    goto error;
  }

#ifdef _WIN32
  if (ioctlsocket(sock->fd, FIONBIO, &u_on) == COAP_SOCKET_ERROR) {
#else
  if (ioctl(sock->fd, FIONBIO, &on) == COAP_SOCKET_ERROR) {
#endif
    coap_log(LOG_WARNING,
         "coap_socket_bind_udp: ioctl FIONBIO: %s\n", coap_socket_strerror());
  }

  if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
    coap_log(LOG_WARNING,
             "coap_socket_bind_udp: setsockopt SO_REUSEADDR: %s\n",
              coap_socket_strerror());

  switch (listen_addr->addr.sa.sa_family) {
  case AF_INET:
    if (setsockopt(sock->fd, IPPROTO_IP, GEN_IP_PKTINFO, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
      coap_log(LOG_ALERT,
               "coap_socket_bind_udp: setsockopt IP_PKTINFO: %s\n",
                coap_socket_strerror());
    break;
  case AF_INET6:
    /* Configure the socket as dual-stacked */
    if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_V6ONLY, OPTVAL_T(&off), sizeof(off)) == COAP_SOCKET_ERROR)
      coap_log(LOG_ALERT,
               "coap_socket_bind_udp: setsockopt IPV6_V6ONLY: %s\n",
                coap_socket_strerror());
    if (setsockopt(sock->fd, IPPROTO_IPV6, GEN_IPV6_PKTINFO, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
      coap_log(LOG_ALERT,
               "coap_socket_bind_udp: setsockopt IPV6_PKTINFO: %s\n",
                coap_socket_strerror());
    setsockopt(sock->fd, IPPROTO_IP, GEN_IP_PKTINFO, OPTVAL_T(&on), sizeof(on)); /* ignore error, because the likely cause is that IPv4 is disabled at the os level */
    break;
  default:
    coap_log(LOG_ALERT, "coap_socket_bind_udp: unsupported sa_family\n");
    break;
  }

  if (bind(sock->fd, &listen_addr->addr.sa, listen_addr->size) == COAP_SOCKET_ERROR) {
    coap_log(LOG_WARNING, "coap_socket_bind_udp: bind: %s\n",
             coap_socket_strerror());
    goto error;
  }

  bound_addr->size = (socklen_t)sizeof(*bound_addr);
  if (getsockname(sock->fd, &bound_addr->addr.sa, &bound_addr->size) < 0) {
    coap_log(LOG_WARNING,
             "coap_socket_bind_udp: getsockname: %s\n",
              coap_socket_strerror());
    goto error;
  }

  return 1;

error:
  coap_socket_close(sock);
  return 0;
}

int
coap_socket_connect_tcp1(coap_socket_t *sock,
                         const coap_address_t *local_if,
                         const coap_address_t *server,
                         int default_port,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr) {
  int on = 1, off = 0;
#ifdef _WIN32
  u_long u_on = 1;
#endif
  coap_address_t connect_addr;
  coap_address_copy( &connect_addr, server );

  sock->flags &= ~COAP_SOCKET_CONNECTED;
  sock->fd = socket(server->addr.sa.sa_family, SOCK_STREAM, 0);

  if (sock->fd == COAP_INVALID_SOCKET) {
    coap_log(LOG_WARNING,
             "coap_socket_connect_tcp1: socket: %s\n",
             coap_socket_strerror());
    goto error;
  }

#ifdef _WIN32
  if (ioctlsocket(sock->fd, FIONBIO, &u_on) == COAP_SOCKET_ERROR) {
#else
  if (ioctl(sock->fd, FIONBIO, &on) == COAP_SOCKET_ERROR) {
#endif
    coap_log(LOG_WARNING,
             "coap_socket_connect_tcp1: ioctl FIONBIO: %s\n",
             coap_socket_strerror());
  }

  switch (server->addr.sa.sa_family) {
  case AF_INET:
    if (connect_addr.addr.sin.sin_port == 0)
      connect_addr.addr.sin.sin_port = htons(default_port);
    break;
  case AF_INET6:
    if (connect_addr.addr.sin6.sin6_port == 0)
      connect_addr.addr.sin6.sin6_port = htons(default_port);
    /* Configure the socket as dual-stacked */
    if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_V6ONLY, OPTVAL_T(&off), sizeof(off)) == COAP_SOCKET_ERROR)
      coap_log(LOG_WARNING,
               "coap_socket_connect_tcp1: setsockopt IPV6_V6ONLY: %s\n",
               coap_socket_strerror());
    break;
  default:
    coap_log(LOG_ALERT, "coap_socket_connect_tcp1: unsupported sa_family\n");
    break;
  }

  if (local_if && local_if->addr.sa.sa_family) {
    coap_address_copy(local_addr, local_if);
    if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
      coap_log(LOG_WARNING,
               "coap_socket_connect_tcp1: setsockopt SO_REUSEADDR: %s\n",
               coap_socket_strerror());
    if (bind(sock->fd, &local_if->addr.sa, local_if->size) == COAP_SOCKET_ERROR) {
      coap_log(LOG_WARNING, "coap_socket_connect_tcp1: bind: %s\n",
               coap_socket_strerror());
      goto error;
    }
  } else {
    local_addr->addr.sa.sa_family = server->addr.sa.sa_family;
  }

  if (connect(sock->fd, &connect_addr.addr.sa, connect_addr.size) == COAP_SOCKET_ERROR) {
#ifdef _WIN32
    if (WSAGetLastError() == WSAEWOULDBLOCK) {
#else
    if (errno == EINPROGRESS) {
#endif
      /*
       * COAP_SOCKET_CONNECTED needs to be set here as there will be reads/writes
       * by underlying TLS libraries during connect() and we do not want to
       * assert() in coap_read_session() or coap_write_session() when called by coap_read()
       */
      sock->flags |= COAP_SOCKET_WANT_CONNECT | COAP_SOCKET_CONNECTED;
      return 1;
    }
    coap_log(LOG_WARNING, "coap_socket_connect_tcp1: connect: %s\n",
             coap_socket_strerror());
    goto error;
  }

  if (getsockname(sock->fd, &local_addr->addr.sa, &local_addr->size) == COAP_SOCKET_ERROR) {
    coap_log(LOG_WARNING, "coap_socket_connect_tcp1: getsockname: %s\n",
             coap_socket_strerror());
  }

  if (getpeername(sock->fd, &remote_addr->addr.sa, &remote_addr->size) == COAP_SOCKET_ERROR) {
    coap_log(LOG_WARNING, "coap_socket_connect_tcp1: getpeername: %s\n",
             coap_socket_strerror());
  }

  sock->flags |= COAP_SOCKET_CONNECTED;
  return 1;

error:
  coap_socket_close(sock);
  return 0;
}

int
coap_socket_connect_tcp2(coap_socket_t *sock,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr) {
  int error = 0;
#ifdef _WIN32
  int optlen = (int)sizeof( error );
#else
  socklen_t optlen = (socklen_t)sizeof( error );
#endif

  sock->flags &= ~(COAP_SOCKET_WANT_CONNECT | COAP_SOCKET_CAN_CONNECT);

  if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, OPTVAL_GT(&error),
    &optlen) == COAP_SOCKET_ERROR) {
    coap_log(LOG_WARNING, "coap_socket_finish_connect_tcp: getsockopt: %s\n",
      coap_socket_strerror());
  }

  if (error) {
    coap_log(LOG_WARNING,
             "coap_socket_finish_connect_tcp: connect failed: %s\n",
             coap_socket_format_errno(error));
    coap_socket_close(sock);
    return 0;
  }

  if (getsockname(sock->fd, &local_addr->addr.sa, &local_addr->size) == COAP_SOCKET_ERROR) {
    coap_log(LOG_WARNING, "coap_socket_connect_tcp: getsockname: %s\n",
             coap_socket_strerror());
  }

  if (getpeername(sock->fd, &remote_addr->addr.sa, &remote_addr->size) == COAP_SOCKET_ERROR) {
    coap_log(LOG_WARNING, "coap_socket_connect_tcp: getpeername: %s\n",
             coap_socket_strerror());
  }

  return 1;
}

int
coap_socket_bind_tcp(coap_socket_t *sock,
                     const coap_address_t *listen_addr,
                     coap_address_t *bound_addr) {
  int on = 1, off = 0;
#ifdef _WIN32
  u_long u_on = 1;
#endif

  sock->fd = socket(listen_addr->addr.sa.sa_family, SOCK_STREAM, 0);

  if (sock->fd == COAP_INVALID_SOCKET) {
    coap_log(LOG_WARNING, "coap_socket_bind_tcp: socket: %s\n",
             coap_socket_strerror());
    goto error;
  }

#ifdef _WIN32
  if (ioctlsocket(sock->fd, FIONBIO, &u_on) == COAP_SOCKET_ERROR) {
#else
  if (ioctl(sock->fd, FIONBIO, &on) == COAP_SOCKET_ERROR) {
#endif
    coap_log(LOG_WARNING, "coap_socket_bind_tcp: ioctl FIONBIO: %s\n",
                           coap_socket_strerror());
  }
  if (setsockopt (sock->fd, SOL_SOCKET, SO_KEEPALIVE, OPTVAL_T(&on),
                  sizeof (on)) == COAP_SOCKET_ERROR)
    coap_log(LOG_WARNING,
             "coap_socket_bind_tcp: setsockopt SO_KEEPALIVE: %s\n",
             coap_socket_strerror());

  if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, OPTVAL_T(&on),
                 sizeof(on)) == COAP_SOCKET_ERROR)
    coap_log(LOG_WARNING,
             "coap_socket_bind_tcp: setsockopt SO_REUSEADDR: %s\n",
             coap_socket_strerror());

  switch (listen_addr->addr.sa.sa_family) {
  case AF_INET:
    break;
  case AF_INET6:
    /* Configure the socket as dual-stacked */
    if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_V6ONLY, OPTVAL_T(&off), sizeof(off)) == COAP_SOCKET_ERROR)
      coap_log(LOG_ALERT,
               "coap_socket_bind_tcp: setsockopt IPV6_V6ONLY: %s\n",
               coap_socket_strerror());
    break;
  default:
    coap_log(LOG_ALERT, "coap_socket_bind_tcp: unsupported sa_family\n");
  }

  if (bind(sock->fd, &listen_addr->addr.sa, listen_addr->size) == COAP_SOCKET_ERROR) {
    coap_log(LOG_ALERT, "coap_socket_bind_tcp: bind: %s\n",
             coap_socket_strerror());
    goto error;
  }

  bound_addr->size = (socklen_t)sizeof(*bound_addr);
  if (getsockname(sock->fd, &bound_addr->addr.sa, &bound_addr->size) < 0) {
    coap_log(LOG_WARNING, "coap_socket_bind_tcp: getsockname: %s\n",
             coap_socket_strerror());
    goto error;
  }

  if (listen(sock->fd, 5) == COAP_SOCKET_ERROR) {
    coap_log(LOG_ALERT, "coap_socket_bind_tcp: listen: %s\n",
             coap_socket_strerror());
    goto  error;
  }

  return 1;

error:
  coap_socket_close(sock);
  return 0;
}

int
coap_socket_accept_tcp(coap_socket_t *server,
                       coap_socket_t *new_client,
                       coap_address_t *local_addr,
                       coap_address_t *remote_addr) {
#ifdef _WIN32
  u_long u_on = 1;
#else
  int on = 1;
#endif

  server->flags &= ~COAP_SOCKET_CAN_ACCEPT;

  new_client->fd = accept(server->fd, &remote_addr->addr.sa,
                          &remote_addr->size);
  if (new_client->fd == COAP_INVALID_SOCKET) {
    coap_log(LOG_WARNING, "coap_socket_accept_tcp: accept: %s\n",
             coap_socket_strerror());
    return 0;
  }

  if (getsockname( new_client->fd, &local_addr->addr.sa, &local_addr->size) < 0)
    coap_log(LOG_WARNING, "coap_socket_accept_tcp: getsockname: %s\n",
             coap_socket_strerror());

  #ifdef _WIN32
  if (ioctlsocket(new_client->fd, FIONBIO, &u_on) == COAP_SOCKET_ERROR) {
#else
  if (ioctl(new_client->fd, FIONBIO, &on) == COAP_SOCKET_ERROR) {
#endif
    coap_log(LOG_WARNING, "coap_socket_accept_tcp: ioctl FIONBIO: %s\n",
             coap_socket_strerror());
  }

  return 1;
}

int
coap_socket_connect_udp(coap_socket_t *sock,
  const coap_address_t *local_if,
  const coap_address_t *server,
  int default_port,
  coap_address_t *local_addr,
  coap_address_t *remote_addr) {
  int on = 1, off = 0;
#ifdef _WIN32
  u_long u_on = 1;
#endif
  coap_address_t connect_addr;
  int is_mcast = coap_is_mcast(server);
  coap_address_copy(&connect_addr, server);

  sock->flags &= ~(COAP_SOCKET_CONNECTED | COAP_SOCKET_MULTICAST);
  sock->fd = socket(connect_addr.addr.sa.sa_family, SOCK_DGRAM, 0);

  if (sock->fd == COAP_INVALID_SOCKET) {
    coap_log(LOG_WARNING, "coap_socket_connect_udp: socket: %s\n",
             coap_socket_strerror());
    goto error;
  }

#ifdef _WIN32
  if (ioctlsocket(sock->fd, FIONBIO, &u_on) == COAP_SOCKET_ERROR) {
#else
  if (ioctl(sock->fd, FIONBIO, &on) == COAP_SOCKET_ERROR) {
#endif
    coap_log(LOG_WARNING, "coap_socket_connect_udp: ioctl FIONBIO: %s\n",
             coap_socket_strerror());
  }

  switch (connect_addr.addr.sa.sa_family) {
  case AF_INET:
    if (connect_addr.addr.sin.sin_port == 0)
      connect_addr.addr.sin.sin_port = htons(default_port);
    break;
  case AF_INET6:
    if (connect_addr.addr.sin6.sin6_port == 0)
      connect_addr.addr.sin6.sin6_port = htons(default_port);
    /* Configure the socket as dual-stacked */
    if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_V6ONLY, OPTVAL_T(&off), sizeof(off)) == COAP_SOCKET_ERROR)
      coap_log(LOG_WARNING,
               "coap_socket_connect_udp: setsockopt IPV6_V6ONLY: %s\n",
               coap_socket_strerror());
    break;
  default:
    coap_log(LOG_ALERT, "coap_socket_connect_udp: unsupported sa_family\n");
    break;
  }

  if (local_if && local_if->addr.sa.sa_family) {
    if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
      coap_log(LOG_WARNING,
               "coap_socket_connect_udp: setsockopt SO_REUSEADDR: %s\n",
               coap_socket_strerror());
    if (bind(sock->fd, &local_if->addr.sa, local_if->size) == COAP_SOCKET_ERROR) {
      coap_log(LOG_WARNING, "coap_socket_connect_udp: bind: %s\n",
               coap_socket_strerror());
      goto error;
    }
  }

  /* special treatment for sockets that are used for multicast communication */
  if (is_mcast) {
    if (getsockname(sock->fd, &local_addr->addr.sa, &local_addr->size) == COAP_SOCKET_ERROR) {
      coap_log(LOG_WARNING,
              "coap_socket_connect_udp: getsockname for multicast socket: %s\n",
              coap_socket_strerror());
    }
    coap_address_copy(remote_addr, &connect_addr);
    sock->flags |= COAP_SOCKET_MULTICAST;
    return 1;
  }

  if (connect(sock->fd, &connect_addr.addr.sa, connect_addr.size) == COAP_SOCKET_ERROR) {
    coap_log(LOG_WARNING, "coap_socket_connect_udp: connect: %s\n",
             coap_socket_strerror());
    goto error;
  }

  if (getsockname(sock->fd, &local_addr->addr.sa, &local_addr->size) == COAP_SOCKET_ERROR) {
    coap_log(LOG_WARNING, "coap_socket_connect_udp: getsockname: %s\n",
             coap_socket_strerror());
  }

  if (getpeername(sock->fd, &remote_addr->addr.sa, &remote_addr->size) == COAP_SOCKET_ERROR) {
    coap_log(LOG_WARNING, "coap_socket_connect_udp: getpeername: %s\n",
             coap_socket_strerror());
  }

  sock->flags |= COAP_SOCKET_CONNECTED;
  return 1;

error:
  coap_socket_close(sock);
  return 0;
}

void coap_socket_close(coap_socket_t *sock) {
  if (sock->fd != COAP_INVALID_SOCKET) {
    coap_closesocket(sock->fd);
    sock->fd = COAP_INVALID_SOCKET;
  }
  sock->flags = COAP_SOCKET_EMPTY;
}

ssize_t
coap_socket_write(coap_socket_t *sock, const uint8_t *data, size_t data_len) {
  ssize_t r;

  sock->flags &= ~(COAP_SOCKET_WANT_WRITE | COAP_SOCKET_CAN_WRITE);
#ifdef _WIN32
  r = send(sock->fd, (const char *)data, (int)data_len, 0);
#else
  r = send(sock->fd, data, data_len, 0);
#endif
  if (r == COAP_SOCKET_ERROR) {
#ifdef _WIN32
    if (WSAGetLastError() == WSAEWOULDBLOCK) {
#elif EAGAIN != EWOULDBLOCK
    if (errno==EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
#else
    if (errno==EAGAIN || errno == EINTR) {
#endif
      sock->flags |= COAP_SOCKET_WANT_WRITE;
      return 0;
    }
    coap_log(LOG_WARNING, "coap_socket_write: send: %s\n",
             coap_socket_strerror());
    return -1;
  }
  if (r < (ssize_t)data_len)
    sock->flags |= COAP_SOCKET_WANT_WRITE;
  return r;
}

ssize_t
coap_socket_read(coap_socket_t *sock, uint8_t *data, size_t data_len) {
  ssize_t r;
#ifdef _WIN32
  int error;
#endif

#ifdef _WIN32
  r = recv(sock->fd, (char *)data, (int)data_len, 0);
#else
  r = recv(sock->fd, data, data_len, 0);
#endif
  if (r == 0) {
    /* graceful shutdown */
    sock->flags &= ~COAP_SOCKET_CAN_READ;
    return -1;
  } else if (r == COAP_SOCKET_ERROR) {
    sock->flags &= ~COAP_SOCKET_CAN_READ;
#ifdef _WIN32
    error = WSAGetLastError();
    if (error == WSAEWOULDBLOCK) {
#elif EAGAIN != EWOULDBLOCK
    if (errno==EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
#else
    if (errno==EAGAIN || errno == EINTR) {
#endif
      return 0;
    }
#ifdef _WIN32
    if (error != WSAECONNRESET)
#else
    if (errno != ECONNRESET)
#endif
      coap_log(LOG_WARNING, "coap_socket_read: recv: %s\n",
               coap_socket_strerror());
    return -1;
  }
  if (r < (ssize_t)data_len)
    sock->flags &= ~COAP_SOCKET_CAN_READ;
  return r;
}

#endif  /* WITH_CONTIKI */

#if (!defined(WITH_CONTIKI)) != ( defined(HAVE_NETINET_IN_H) || defined(HAVE_WS2TCPIP_H) )
/* define struct in6_pktinfo and struct in_pktinfo if not available
   FIXME: check with configure
*/
struct in6_pktinfo {
  struct in6_addr ipi6_addr;        /* src/dst IPv6 address */
  unsigned int ipi6_ifindex;        /* send/recv interface index */
};

struct in_pktinfo {
  int ipi_ifindex;
  struct in_addr ipi_spec_dst;
  struct in_addr ipi_addr;
};
#endif

#if !defined(WITH_CONTIKI) && !defined(SOL_IP)
/* Solaris expects level IPPROTO_IP for ancillary data. */
#define SOL_IP IPPROTO_IP
#endif

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

#if defined(_WIN32)
#include <mswsock.h>
static __declspec(thread) LPFN_WSARECVMSG lpWSARecvMsg = NULL;
/* Map struct WSABUF fields to their posix counterpart */
#define msghdr _WSAMSG
#define msg_name name
#define msg_namelen namelen
#define msg_iov lpBuffers
#define msg_iovlen dwBufferCount
#define msg_control Control.buf
#define msg_controllen Control.len
#define iovec _WSABUF
#define iov_base buf
#define iov_len len
#define iov_len_t u_long
#undef CMSG_DATA
#define CMSG_DATA WSA_CMSG_DATA
#define ipi_spec_dst ipi_addr
#else
#define iov_len_t size_t
#endif

ssize_t
coap_network_send(coap_socket_t *sock, const coap_session_t *session, const uint8_t *data, size_t datalen) {
  ssize_t bytes_written = 0;

  if (!coap_debug_send_packet()) {
    bytes_written = (ssize_t)datalen;
#ifndef WITH_CONTIKI
  } else if (sock->flags & COAP_SOCKET_CONNECTED) {
#ifdef _WIN32
    bytes_written = send(sock->fd, (const char *)data, (int)datalen, 0);
#else
    bytes_written = send(sock->fd, data, datalen, 0);
#endif
#endif
  } else {
#ifndef WITH_CONTIKI
#ifdef _WIN32
    DWORD dwNumberOfBytesSent = 0;
    int r;
#endif
#ifdef HAVE_STRUCT_CMSGHDR
    /* a buffer large enough to hold all packet info types, ipv6 is the largest */
    char buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    struct msghdr mhdr;
    struct iovec iov[1];
    const void *addr = &session->remote_addr.addr;

    assert(session);

    memcpy (&iov[0].iov_base, &data, sizeof (iov[0].iov_base));
    iov[0].iov_len = (iov_len_t)datalen;

    memset(buf, 0, sizeof (buf));

    memset(&mhdr, 0, sizeof(struct msghdr));
    memcpy (&mhdr.msg_name, &addr, sizeof (mhdr.msg_name));
    mhdr.msg_namelen = session->remote_addr.size;

    mhdr.msg_iov = iov;
    mhdr.msg_iovlen = 1;

    if (!coap_address_isany(&session->local_addr) && !coap_is_mcast(&session->local_addr)) switch (session->local_addr.addr.sa.sa_family) {
    case AF_INET6:
    {
      struct cmsghdr *cmsg;

      if (IN6_IS_ADDR_V4MAPPED(&session->local_addr.addr.sin6.sin6_addr)) {
#if defined(IP_PKTINFO)
        struct in_pktinfo *pktinfo;
        mhdr.msg_control = buf;
        mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

        cmsg = CMSG_FIRSTHDR(&mhdr);
        cmsg->cmsg_level = SOL_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

        pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);

        pktinfo->ipi_ifindex = session->ifindex;
        memcpy(&pktinfo->ipi_spec_dst, session->local_addr.addr.sin6.sin6_addr.s6_addr + 12, sizeof(pktinfo->ipi_spec_dst));
#elif defined(IP_SENDSRCADDR)
        mhdr.msg_control = buf;
        mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in_addr));

        cmsg = CMSG_FIRSTHDR(&mhdr);
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_SENDSRCADDR;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_addr));

        memcpy(CMSG_DATA(cmsg), session->local_addr.addr.sin6.sin6_addr.s6_addr + 12, sizeof(struct in_addr));
#endif /* IP_PKTINFO */
      } else {
        struct in6_pktinfo *pktinfo;
        mhdr.msg_control = buf;
        mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

        cmsg = CMSG_FIRSTHDR(&mhdr);
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

        pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);

        pktinfo->ipi6_ifindex = session->ifindex;
        memcpy(&pktinfo->ipi6_addr, &session->local_addr.addr.sin6.sin6_addr, sizeof(pktinfo->ipi6_addr));
      }
      break;
    }
    case AF_INET:
    {
#if defined(IP_PKTINFO)
      struct cmsghdr *cmsg;
      struct in_pktinfo *pktinfo;

      mhdr.msg_control = buf;
      mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

      cmsg = CMSG_FIRSTHDR(&mhdr);
      cmsg->cmsg_level = SOL_IP;
      cmsg->cmsg_type = IP_PKTINFO;
      cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

      pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);

      pktinfo->ipi_ifindex = session->ifindex;
      memcpy(&pktinfo->ipi_spec_dst, &session->local_addr.addr.sin.sin_addr, sizeof(pktinfo->ipi_spec_dst));
#elif defined(IP_SENDSRCADDR)
      struct cmsghdr *cmsg;
      mhdr.msg_control = buf;
      mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in_addr));

      cmsg = CMSG_FIRSTHDR(&mhdr);
      cmsg->cmsg_level = IPPROTO_IP;
      cmsg->cmsg_type = IP_SENDSRCADDR;
      cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_addr));

      memcpy(CMSG_DATA(cmsg), &session->local_addr.addr.sin.sin_addr, sizeof(struct in_addr));
#endif /* IP_PKTINFO */
      break;
    }
    default:
      /* error */
      coap_log(LOG_WARNING, "protocol not supported\n");
      bytes_written = -1;
    }
#endif /* HAVE_STRUCT_CMSGHDR */

#ifdef _WIN32
    r = WSASendMsg(sock->fd, &mhdr, 0 /*dwFlags*/, &dwNumberOfBytesSent, NULL /*lpOverlapped*/, NULL /*lpCompletionRoutine*/);
    if (r == 0)
      bytes_written = (ssize_t)dwNumberOfBytesSent;
    else
      bytes_written = -1;
#else
#ifdef HAVE_STRUCT_CMSGHDR
    bytes_written = sendmsg(sock->fd, &mhdr, 0);
#else /* ! HAVE_STRUCT_CMSGHDR */
    bytes_written = sendto(sock->fd, data, datalen, 0, &session->remote_addr.addr.sa, session->remote_addr.size);
#endif /* ! HAVE_STRUCT_CMSGHDR */
#endif
#else /* WITH_CONTIKI */
    /* FIXME: untested */
    /* FIXME: is there a way to check if send was successful? */
    (void)datalen;
    (void)data;
    uip_udp_packet_sendto((struct uip_udp_conn *)sock->conn, data, datalen,
      &session->remote_addr.addr, session->remote_addr.port);
    bytes_written = datalen;
#endif /* WITH_CONTIKI */
  }

  if (bytes_written < 0)
    coap_log(LOG_CRIT, "coap_network_send: %s\n", coap_socket_strerror());

  return bytes_written;
}

#define SIN6(A) ((struct sockaddr_in6 *)(A))

void
coap_packet_get_memmapped(coap_packet_t *packet, unsigned char **address, size_t *length) {
  *address = packet->payload;
  *length = packet->length;
}

void coap_packet_set_addr(coap_packet_t *packet, const coap_address_t *src, const coap_address_t *dst) {
  coap_address_copy(&packet->src, src);
  coap_address_copy(&packet->dst, dst);
}

ssize_t
coap_network_read(coap_socket_t *sock, coap_packet_t *packet) {
  ssize_t len = -1;

  assert(sock);
  assert(packet);

  if ((sock->flags & COAP_SOCKET_CAN_READ) == 0) {
    return -1;
  } else {
    /* clear has-data flag */
    sock->flags &= ~COAP_SOCKET_CAN_READ;
  }

#ifndef WITH_CONTIKI
  if (sock->flags & COAP_SOCKET_CONNECTED) {
#ifdef _WIN32
    len = recv(sock->fd, (char *)packet->payload, COAP_RXBUFFER_SIZE, 0);
#else
    len = recv(sock->fd, packet->payload, COAP_RXBUFFER_SIZE, 0);
#endif
    if (len < 0) {
#ifdef _WIN32
      if (WSAGetLastError() == WSAECONNRESET) {
#else
      if (errno == ECONNREFUSED) {
#endif
        /* client-side ICMP destination unreachable, ignore it */
        coap_log(LOG_WARNING, "coap_network_read: unreachable\n");
        return -2;
      }
      coap_log(LOG_WARNING, "coap_network_read: %s\n", coap_socket_strerror());
      goto error;
    } else if (len > 0) {
      packet->length = (size_t)len;
    }
  } else {
#endif /* WITH_CONTIKI */
#if defined(_WIN32)
    DWORD dwNumberOfBytesRecvd = 0;
    int r;
#endif
#if !defined(WITH_CONTIKI)
#ifdef HAVE_STRUCT_CMSGHDR
    /* a buffer large enough to hold all packet info types, ipv6 is the largest */
    char buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    struct cmsghdr *cmsg;
    struct msghdr mhdr;
    struct iovec iov[1];

    iov[0].iov_base = packet->payload;
    iov[0].iov_len = (iov_len_t)COAP_RXBUFFER_SIZE;

    memset(&mhdr, 0, sizeof(struct msghdr));

    mhdr.msg_name = (struct sockaddr*)&packet->src.addr;
    mhdr.msg_namelen = sizeof(packet->src.addr);

    mhdr.msg_iov = iov;
    mhdr.msg_iovlen = 1;

    mhdr.msg_control = buf;
    mhdr.msg_controllen = sizeof(buf);
    /* set a big first length incase recvmsg() does not implement updating
       msg_control as well as preset the first cmsg with bad data */
    cmsg = (struct cmsghdr *)buf;
    cmsg->cmsg_len = CMSG_LEN(sizeof(buf));
    cmsg->cmsg_level = -1;
    cmsg->cmsg_type = -1;

#if defined(_WIN32)
    if (!lpWSARecvMsg) {
      GUID wsaid = WSAID_WSARECVMSG;
      DWORD cbBytesReturned = 0;
      if (WSAIoctl(sock->fd, SIO_GET_EXTENSION_FUNCTION_POINTER, &wsaid, sizeof(wsaid), &lpWSARecvMsg, sizeof(lpWSARecvMsg), &cbBytesReturned, NULL, NULL) != 0) {
        coap_log(LOG_WARNING, "coap_network_read: no WSARecvMsg\n");
        return -1;
      }
    }
    r = lpWSARecvMsg(sock->fd, &mhdr, &dwNumberOfBytesRecvd, NULL /* LPWSAOVERLAPPED */, NULL /* LPWSAOVERLAPPED_COMPLETION_ROUTINE */);
    if (r == 0)
      len = (ssize_t)dwNumberOfBytesRecvd;
#else
    len = recvmsg(sock->fd, &mhdr, 0);
#endif

#else /* ! HAVE_STRUCT_CMSGHDR */
    packet->src.size = packet->src.size;
    len = recvfrom(sock->fd, packet->payload, COAP_RXBUFFER_SIZE, 0, &packet->src.addr.sa, &packet->src.size);
#endif /* ! HAVE_STRUCT_CMSGHDR */

    if (len < 0) {
#ifdef _WIN32
      if (WSAGetLastError() == WSAECONNRESET) {
#else
      if (errno == ECONNREFUSED) {
#endif
        /* server-side ICMP destination unreachable, ignore it. The destination address is in msg_name. */
        return 0;
      }
      coap_log(LOG_WARNING, "coap_network_read: %s\n", coap_socket_strerror());
      goto error;
    } else {
#ifdef HAVE_STRUCT_CMSGHDR
      int dst_found = 0;

      packet->src.size = mhdr.msg_namelen;
      packet->length = (size_t)len;

      /* Walk through ancillary data records until the local interface
       * is found where the data was received. */
      for (cmsg = CMSG_FIRSTHDR(&mhdr); cmsg; cmsg = CMSG_NXTHDR(&mhdr, cmsg)) {

        /* get the local interface for IPv6 */
        if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
          union {
            uint8_t *c;
            struct in6_pktinfo *p;
          } u;
          u.c = CMSG_DATA(cmsg);
          packet->ifindex = (int)(u.p->ipi6_ifindex);
          memcpy(&packet->dst.addr.sin6.sin6_addr, &u.p->ipi6_addr, sizeof(struct in6_addr));
          dst_found = 1;
          break;
        }

        /* local interface for IPv4 */
#if defined(IP_PKTINFO)
        if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_PKTINFO) {
          union {
            uint8_t *c;
            struct in_pktinfo *p;
          } u;
          u.c = CMSG_DATA(cmsg);
          packet->ifindex = u.p->ipi_ifindex;
          if (packet->dst.addr.sa.sa_family == AF_INET6) {
            memset(packet->dst.addr.sin6.sin6_addr.s6_addr, 0, 10);
            packet->dst.addr.sin6.sin6_addr.s6_addr[10] = 0xff;
            packet->dst.addr.sin6.sin6_addr.s6_addr[11] = 0xff;
            memcpy(packet->dst.addr.sin6.sin6_addr.s6_addr + 12, &u.p->ipi_addr, sizeof(struct in_addr));
          } else {
            memcpy(&packet->dst.addr.sin.sin_addr, &u.p->ipi_addr, sizeof(struct in_addr));
          }
          dst_found = 1;
          break;
        }
#elif defined(IP_RECVDSTADDR)
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVDSTADDR) {
          packet->ifindex = sock->fd;
          memcpy(&packet->dst.addr.sin.sin_addr, CMSG_DATA(cmsg), sizeof(struct in_addr));
          dst_found = 1;
          break;
        }
#endif /* IP_PKTINFO */
        if (!dst_found) {
          /* cmsg_level / cmsg_type combination we do not understand
             (ignore preset case for bad recvmsg() not updating cmsg) */
          if (cmsg->cmsg_level != -1 && cmsg->cmsg_type != -1) {
            coap_log(LOG_DEBUG,
                     "cmsg_level = %d and cmsg_type = %d not supported - fix\n",
                     cmsg->cmsg_level, cmsg->cmsg_type);
          }
        }
      }
      if (!dst_found) {
        /* Not expected, but cmsg_level and cmsg_type don't match above and
           may need a new case */
        packet->ifindex = sock->fd;
        if (getsockname(sock->fd, &packet->dst.addr.sa, &packet->dst.size) < 0) {
          coap_log(LOG_DEBUG, "Cannot determine local port\n");
        }
      }
#else /* ! HAVE_STRUCT_CMSGHDR */
      packet->length = (size_t)len;
      packet->ifindex = 0;
      if (getsockname(sock->fd, &packet->dst.addr.sa, &packet->dst.size) < 0) {
         coap_log(LOG_DEBUG, "Cannot determine local port\n");
         goto error;
      }
#endif /* ! HAVE_STRUCT_CMSGHDR */
    }
#endif /* !defined(WITH_CONTIKI) */
#ifdef WITH_CONTIKI
    /* FIXME: untested, make this work */
#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])

    if (uip_newdata()) {
      uip_ipaddr_copy(&packet->src.addr, &UIP_IP_BUF->srcipaddr);
      packet->src.port = UIP_UDP_BUF->srcport;
      uip_ipaddr_copy(&(packet)->dst.addr, &UIP_IP_BUF->destipaddr);
      packet->dst.port = UIP_UDP_BUF->destport;

      len = uip_datalen();

      if (len > COAP_RXBUFFER_SIZE) {
        /* FIXME: we might want to send back a response */
        coap_log(LOG_WARNING, "discarded oversized packet\n");
        return -1;
      }

      ((char *)uip_appdata)[len] = 0;
#ifndef NDEBUG
      if (LOG_DEBUG <= coap_get_log_level()) {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif
        unsigned char addr_str[INET6_ADDRSTRLEN + 8];

        if (coap_print_addr(&packet->src, addr_str, INET6_ADDRSTRLEN + 8)) {
          coap_log(LOG_DEBUG, "received %zd bytes from %s\n", len, addr_str);
        }
      }
#endif /* NDEBUG */

      packet->length = len;
      memcpy(&packet->payload, uip_appdata, len);
    }

#undef UIP_IP_BUF
#undef UIP_UDP_BUF
#endif /* WITH_CONTIKI */
#ifndef WITH_CONTIKI
  }
#endif /* WITH_CONTIKI */

  if (len >= 0)
    return len;
#if !defined(WITH_CONTIKI)
error:
#endif
  return -1;
}

#if !defined(WITH_CONTIKI)

unsigned int
coap_write(coap_context_t *ctx,
           coap_socket_t *sockets[],
           unsigned int max_sockets,
           unsigned int *num_sockets,
           coap_tick_t now)
{
  coap_queue_t *nextpdu;
  coap_endpoint_t *ep;
  coap_session_t *s;
  coap_tick_t session_timeout;
  coap_tick_t timeout = 0;
  coap_session_t *tmp;

  *num_sockets = 0;

  /* Check to see if we need to send off any Observe requests */
  coap_check_notify(ctx);

  if (ctx->session_timeout > 0)
    session_timeout = ctx->session_timeout * COAP_TICKS_PER_SECOND;
  else
    session_timeout = COAP_DEFAULT_SESSION_TIMEOUT * COAP_TICKS_PER_SECOND;

  LL_FOREACH(ctx->endpoint, ep) {
    if (ep->sock.flags & (COAP_SOCKET_WANT_READ | COAP_SOCKET_WANT_WRITE | COAP_SOCKET_WANT_ACCEPT)) {
      if (*num_sockets < max_sockets)
        sockets[(*num_sockets)++] = &ep->sock;
    }
    LL_FOREACH_SAFE(ep->sessions, s, tmp) {
      if (s->type == COAP_SESSION_TYPE_SERVER && s->ref == 0 &&
          s->delayqueue == NULL &&
          (s->last_rx_tx + session_timeout <= now ||
           s->state == COAP_SESSION_STATE_NONE)) {
        coap_session_free(s);
      } else {
        if (s->type == COAP_SESSION_TYPE_SERVER && s->ref == 0 && s->delayqueue == NULL) {
          coap_tick_t s_timeout = (s->last_rx_tx + session_timeout) - now;
          if (timeout == 0 || s_timeout < timeout)
            timeout = s_timeout;
        }
        if (s->sock.flags & (COAP_SOCKET_WANT_READ | COAP_SOCKET_WANT_WRITE)) {
          if (*num_sockets < max_sockets)
            sockets[(*num_sockets)++] = &s->sock;
        }
      }
    }
  }
  LL_FOREACH_SAFE(ctx->sessions, s, tmp) {
    if (
        s->type == COAP_SESSION_TYPE_CLIENT
     && COAP_PROTO_RELIABLE(s->proto)
     && s->state == COAP_SESSION_STATE_ESTABLISHED
     && ctx->ping_timeout > 0
    ) {
      coap_tick_t s_timeout;
      if (s->last_rx_tx + ctx->ping_timeout * COAP_TICKS_PER_SECOND <= now) {
        if ((s->last_ping > 0 && s->last_pong < s->last_ping)
          || coap_session_send_ping(s) == COAP_INVALID_TID)
        {
          /* Make sure the session object is not deleted in the callback */
          coap_session_reference(s);
          coap_session_disconnected(s, COAP_NACK_NOT_DELIVERABLE);
          coap_session_release(s);
          continue;
        }
        s->last_rx_tx = now;
        s->last_ping = now;
      }
      s_timeout = (s->last_rx_tx + ctx->ping_timeout * COAP_TICKS_PER_SECOND) - now;
      if (timeout == 0 || s_timeout < timeout)
        timeout = s_timeout;
    }

    if (
        s->type == COAP_SESSION_TYPE_CLIENT
     && COAP_PROTO_RELIABLE(s->proto)
     && s->state == COAP_SESSION_STATE_CSM
     && ctx->csm_timeout > 0
    ) {
      coap_tick_t s_timeout;
      if (s->csm_tx == 0) {
        s->csm_tx = now;
      } else if (s->csm_tx + ctx->csm_timeout * COAP_TICKS_PER_SECOND <= now) {
        /* Make sure the session object is not deleted in the callback */
        coap_session_reference(s);
        coap_session_disconnected(s, COAP_NACK_NOT_DELIVERABLE);
        coap_session_release(s);
        continue;
      }
      s_timeout = (s->csm_tx + ctx->csm_timeout * COAP_TICKS_PER_SECOND) - now;
      if (timeout == 0 || s_timeout < timeout)
        timeout = s_timeout;
    }

    if (s->sock.flags & (COAP_SOCKET_WANT_READ | COAP_SOCKET_WANT_WRITE | COAP_SOCKET_WANT_CONNECT)) {
      if (*num_sockets < max_sockets)
        sockets[(*num_sockets)++] = &s->sock;
    }
  }

  nextpdu = coap_peek_next(ctx);

  while (nextpdu && now >= ctx->sendqueue_basetime && nextpdu->t <= now - ctx->sendqueue_basetime) {
    coap_retransmit(ctx, coap_pop_next(ctx));
    nextpdu = coap_peek_next(ctx);
  }

  if (nextpdu && (timeout == 0 || nextpdu->t - ( now - ctx->sendqueue_basetime ) < timeout))
    timeout = nextpdu->t - (now - ctx->sendqueue_basetime);

  if (ctx->dtls_context) {
    if (coap_dtls_is_context_timeout()) {
      coap_tick_t tls_timeout = coap_dtls_get_context_timeout(ctx->dtls_context);
      if (tls_timeout > 0) {
        if (tls_timeout < now + COAP_TICKS_PER_SECOND / 10)
          tls_timeout = now + COAP_TICKS_PER_SECOND / 10;
        coap_log(LOG_DEBUG, "** DTLS global timeout set to %dms\n",
                 (int)((tls_timeout - now) * 1000 / COAP_TICKS_PER_SECOND));
        if (timeout == 0 || tls_timeout - now < timeout)
          timeout = tls_timeout - now;
      }
    } else {
      LL_FOREACH(ctx->endpoint, ep) {
        if (ep->proto == COAP_PROTO_DTLS) {
          LL_FOREACH(ep->sessions, s) {
            if (s->proto == COAP_PROTO_DTLS && s->tls) {
              coap_tick_t tls_timeout = coap_dtls_get_timeout(s);
              while (tls_timeout > 0 && tls_timeout <= now) {
                coap_log(LOG_DEBUG, "** %s: DTLS retransmit timeout\n",
                         coap_session_str(s));
                coap_dtls_handle_timeout(s);
                if (s->tls)
                  tls_timeout = coap_dtls_get_timeout(s);
                else {
                  tls_timeout = 0;
                  timeout = 1;
                }
              }
              if (tls_timeout > 0 && (timeout == 0 || tls_timeout - now < timeout))
                timeout = tls_timeout - now;
            }
          }
        }
      }
      LL_FOREACH(ctx->sessions, s) {
        if (s->proto == COAP_PROTO_DTLS && s->tls) {
          coap_tick_t tls_timeout = coap_dtls_get_timeout(s);
          while (tls_timeout > 0 && tls_timeout <= now) {
            coap_log(LOG_DEBUG, "** %s: DTLS retransmit timeout\n", coap_session_str(s));
            coap_dtls_handle_timeout(s);
            if (s->tls)
              tls_timeout = coap_dtls_get_timeout(s);
            else {
              tls_timeout = 0;
              timeout = 1;
            }
          }
          if (tls_timeout > 0 && (timeout == 0 || tls_timeout - now < timeout))
            timeout = tls_timeout - now;
        }
      }
    }
  }

  return (unsigned int)((timeout * 1000 + COAP_TICKS_PER_SECOND - 1) / COAP_TICKS_PER_SECOND);
}

int
coap_run_once(coap_context_t *ctx, unsigned timeout_ms) {
#if COAP_CONSTRAINED_STACK
  static coap_mutex_t static_mutex = COAP_MUTEX_INITIALIZER;
  static fd_set readfds, writefds, exceptfds;
  static coap_socket_t *sockets[64];
#else /* ! COAP_CONSTRAINED_STACK */
  fd_set readfds, writefds, exceptfds;
  coap_socket_t *sockets[64];
#endif /* ! COAP_CONSTRAINED_STACK */
  coap_fd_t nfds = 0;
  struct timeval tv;
  coap_tick_t before, now;
  int result;
  unsigned int num_sockets = 0, i, timeout;

#if COAP_CONSTRAINED_STACK
  coap_mutex_lock(&static_mutex);
#endif /* COAP_CONSTRAINED_STACK */

  coap_ticks(&before);

  timeout = coap_write(ctx, sockets, (unsigned int)(sizeof(sockets) / sizeof(sockets[0])), &num_sockets, before);
  if (timeout == 0 || timeout_ms < timeout)
    timeout = timeout_ms;

  FD_ZERO(&readfds);
  FD_ZERO(&writefds);
  FD_ZERO(&exceptfds);
  for (i = 0; i < num_sockets; i++) {
    if (sockets[i]->fd + 1 > nfds)
      nfds = sockets[i]->fd + 1;
    if (sockets[i]->flags & COAP_SOCKET_WANT_READ)
      FD_SET(sockets[i]->fd, &readfds);
    if (sockets[i]->flags & COAP_SOCKET_WANT_WRITE)
      FD_SET(sockets[i]->fd, &writefds);
    if (sockets[i]->flags & COAP_SOCKET_WANT_ACCEPT)
      FD_SET(sockets[i]->fd, &readfds);
    if (sockets[i]->flags & COAP_SOCKET_WANT_CONNECT) {
      FD_SET(sockets[i]->fd, &writefds);
      FD_SET(sockets[i]->fd, &exceptfds);
    }
  }

  if ( timeout > 0 ) {
    tv.tv_usec = (timeout % 1000) * 1000;
    tv.tv_sec = (long)(timeout / 1000);
  }

  result = select(nfds, &readfds, &writefds, &exceptfds, timeout > 0 ? &tv : NULL);

  if (result < 0) {   /* error */
#ifdef _WIN32
    if (WSAGetLastError() != WSAEINVAL) { /* May happen because of ICMP */
#else
    if (errno != EINTR) {
#endif
      coap_log(LOG_DEBUG, "%s", coap_socket_strerror());
#if COAP_CONSTRAINED_STACK
      coap_mutex_unlock(&static_mutex);
#endif /* COAP_CONSTRAINED_STACK */
      return -1;
    }
  }

  if (result > 0) {
    for (i = 0; i < num_sockets; i++) {
      if ((sockets[i]->flags & COAP_SOCKET_WANT_READ) && FD_ISSET(sockets[i]->fd, &readfds))
        sockets[i]->flags |= COAP_SOCKET_CAN_READ;
      if ((sockets[i]->flags & COAP_SOCKET_WANT_ACCEPT) && FD_ISSET(sockets[i]->fd, &readfds))
        sockets[i]->flags |= COAP_SOCKET_CAN_ACCEPT;
      if ((sockets[i]->flags & COAP_SOCKET_WANT_WRITE) && FD_ISSET(sockets[i]->fd, &writefds))
        sockets[i]->flags |= COAP_SOCKET_CAN_WRITE;
      if ((sockets[i]->flags & COAP_SOCKET_WANT_CONNECT) && (FD_ISSET(sockets[i]->fd, &writefds) || FD_ISSET(sockets[i]->fd, &exceptfds)))
        sockets[i]->flags |= COAP_SOCKET_CAN_CONNECT;
    }
  }

  coap_ticks(&now);
  coap_read(ctx, now);

#if COAP_CONSTRAINED_STACK
  coap_mutex_unlock(&static_mutex);
#endif /* COAP_CONSTRAINED_STACK */

  return (int)(((now - before) * 1000) / COAP_TICKS_PER_SECOND);
}

#else
int coap_run_once(coap_context_t *ctx, unsigned int timeout_ms) {
  return -1;
}

unsigned int
coap_write(coap_context_t *ctx,
           coap_socket_t *sockets[],
           unsigned int max_sockets,
           unsigned int *num_sockets,
           coap_tick_t now)
{
  *num_sockets = 0;
  return 0;
}
#endif

#ifdef _WIN32
static const char *coap_socket_format_errno(int error) {
  static char szError[256];
  if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, (DWORD)error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)szError, (DWORD)sizeof(szError), NULL) == 0)
    strcpy(szError, "Unknown error");
  return szError;
}

const char *coap_socket_strerror(void) {
  return coap_socket_format_errno(WSAGetLastError());
}
#else
#ifndef WITH_CONTIKI
static const char *coap_socket_format_errno(int error) {
  return strerror(error);
}
#endif /* WITH_CONTIKI */

const char *coap_socket_strerror(void) {
  return strerror(errno);
}
#endif

ssize_t
coap_socket_send(coap_socket_t *sock, coap_session_t *session,
  const uint8_t *data, size_t data_len) {
  return session->context->network_send(sock, session, data, data_len);
}

#undef SIN6
/* coap_io_lwip.h -- Network I/O functions for libcoap on lwIP
 *
 * Copyright (C) 2012,2014 Olaf Bergmann <bergmann@tzi.org>
 *               2014 chrysn <chrysn@fsfe.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_config.h"
#include "mem.h"
#include "coap_io.h"
#include <lwip/udp.h>

#if NO_SYS
pthread_mutex_t lwprot_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t lwprot_thread = (pthread_t)0xDEAD;
int lwprot_count = 0;
#endif

#if 0
void coap_packet_copy_source(coap_packet_t *packet, coap_address_t *target)
{
        target->port = packet->srcport;
        memcpy(&target->addr, ip_current_src_addr(), sizeof(ip_addr_t));
}
#endif
void coap_packet_get_memmapped(coap_packet_t *packet, unsigned char **address, size_t *length)
{
        LWIP_ASSERT("Can only deal with contiguous PBUFs to read the initial details", packet->pbuf->tot_len == packet->pbuf->len);
        *address = packet->pbuf->payload;
        *length = packet->pbuf->tot_len;
}
void coap_free_packet(coap_packet_t *packet)
{
        if (packet->pbuf)
                pbuf_free(packet->pbuf);
        coap_free_type(COAP_PACKET, packet);
}

struct pbuf *coap_packet_extract_pbuf(coap_packet_t *packet)
{
        struct pbuf *ret = packet->pbuf;
        packet->pbuf = NULL;
        return ret;
}


/** Callback from lwIP when a package was received.
 *
 * The current implementation deals this to coap_dispatch immediately, but
 * other mechanisms (as storing the package in a queue and later fetching it
 * when coap_read is called) can be envisioned.
 *
 * It handles everything coap_read does on other implementations.
 */
static void coap_recv(void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
  coap_endpoint_t *ep = (coap_endpoint_t*)arg;
  coap_pdu_t *pdu = NULL;
  coap_session_t *session;
  coap_tick_t now;
  coap_packet_t *packet = coap_malloc_type(COAP_PACKET, sizeof(coap_packet_t));

  /* this is fatal because due to the short life of the packet, never should there be more than one coap_packet_t required */
  LWIP_ASSERT("Insufficient coap_packet_t resources.", packet != NULL);
  packet->pbuf = p;
  packet->src.port = port;
  packet->src.addr = *addr;
  packet->dst.port = upcb->local_port;
  packet->dst.addr = *ip_current_dest_addr();
  packet->ifindex = netif_get_index(ip_current_netif());

  pdu = coap_pdu_from_pbuf(p);
  if (!pdu)
    goto error;

  if (!coap_pdu_parse(ep->proto, p->payload, p->len, pdu)) {
    goto error;
  }

  coap_ticks(&now);
  session = coap_endpoint_get_session(ep, packet, now);
  if (!session)
    goto error;
  LWIP_ASSERT("Proto not supported for LWIP", COAP_PROTO_NOT_RELIABLE(session->proto));
  coap_dispatch(ep->context, session, pdu);

  coap_delete_pdu(pdu);
  packet->pbuf = NULL;
  coap_free_packet(packet);
  return;

error:
  /* FIXME: send back RST? */
  if (pdu) coap_delete_pdu(pdu);
  if (packet) {
    packet->pbuf = NULL;
    coap_free_packet(packet);
  }
  return;
}

coap_endpoint_t *
coap_new_endpoint(coap_context_t *context, const coap_address_t *addr, coap_proto_t proto) {
        coap_endpoint_t *result;
        err_t err;

        LWIP_ASSERT("Proto not supported for LWIP endpoints", proto == COAP_PROTO_UDP);

        result = coap_malloc_type(COAP_ENDPOINT, sizeof(coap_endpoint_t));
        if (!result) return NULL;

        result->sock.pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
        if (result->sock.pcb == NULL) goto error;

        udp_recv(result->sock.pcb, coap_recv, (void*)result);
        err = udp_bind(result->sock.pcb, &addr->addr, addr->port);
        if (err) {
                udp_remove(result->sock.pcb);
                goto error;
        }

        result->default_mtu = COAP_DEFAULT_MTU;
        result->context = context;
        result->proto = proto;

        return result;

error:
        coap_free_type(COAP_ENDPOINT, result);
        return NULL;
}

void coap_free_endpoint(coap_endpoint_t *ep)
{
        udp_remove(ep->sock.pcb);
        coap_free_type(COAP_ENDPOINT, ep);
}

ssize_t
coap_socket_send_pdu(coap_socket_t *sock, coap_session_t *session,
  coap_pdu_t *pdu) {
  /* FIXME: we can't check this here with the existing infrastructure, but we
  * should actually check that the pdu is not held by anyone but us. the
  * respective pbuf is already exclusively owned by the pdu. */

  pbuf_realloc(pdu->pbuf, pdu->used_size + coap_pdu_parse_header_size(session->proto, pdu->pbuf->payload));
  udp_sendto(sock->pcb, pdu->pbuf, &session->remote_addr.addr,
    session->remote_addr.port);
  return pdu->used_size;
}

ssize_t
coap_socket_send(coap_socket_t *sock, coap_session_t *session,
  const uint8_t *data, size_t data_len ) {
  /* Not implemented, use coap_socket_send_pdu instead */
  return -1;
}

int
coap_socket_bind_udp(coap_socket_t *sock,
  const coap_address_t *listen_addr,
  coap_address_t *bound_addr) {
  return 0;
}

int
coap_socket_connect_udp(coap_socket_t *sock,
  const coap_address_t *local_if,
  const coap_address_t *server,
  int default_port,
  coap_address_t *local_addr,
  coap_address_t *remote_addr) {
  return 0;
}

int
coap_socket_connect_tcp1(coap_socket_t *sock,
                         const coap_address_t *local_if,
                         const coap_address_t *server,
                         int default_port,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr) {
  return 0;
}

int
coap_socket_connect_tcp2(coap_socket_t *sock,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr) {
  return 0;
}

int
coap_socket_bind_tcp(coap_socket_t *sock,
                     const coap_address_t *listen_addr,
                     coap_address_t *bound_addr) {
  return 0;
}

int
coap_socket_accept_tcp(coap_socket_t *server,
                        coap_socket_t *new_client,
                        coap_address_t *local_addr,
                        coap_address_t *remote_addr) {
  return 0;
}

ssize_t
coap_socket_write(coap_socket_t *sock, const uint8_t *data, size_t data_len) {
  return -1;
}

ssize_t
coap_socket_read(coap_socket_t *sock, uint8_t *data, size_t data_len) {
  return -1;
}

void coap_socket_close(coap_socket_t *sock) {
  return;
}

/*
* coap_notls.c -- Stub Datagram Transport Layer Support for libcoap
*
* Copyright (C) 2016 Olaf Bergmann <bergmann@tzi.org>
*
* This file is part of the CoAP library libcoap. Please see README for terms
* of use.
*/

#include "coap_config.h"

#if !defined(HAVE_LIBTINYDTLS) && !defined(HAVE_OPENSSL) && !defined(HAVE_LIBGNUTLS)

#include "net.h"

#ifdef __GNUC__
#define UNUSED __attribute__((unused))
#else /* __GNUC__ */
#define UNUSED
#endif /* __GNUC__ */

int
coap_dtls_is_supported(void) {
  return 0;
}

int
coap_tls_is_supported(void) {
  return 0;
}

coap_tls_version_t *
coap_get_tls_library_version(void) {
  static coap_tls_version_t version;
  version.version = 0;
  version.type = COAP_TLS_LIBRARY_NOTLS;
  return &version;
}

int
coap_dtls_context_set_pki(coap_context_t *ctx UNUSED,
                          coap_dtls_pki_t* setup_data UNUSED,
                          coap_dtls_role_t role UNUSED
) {
  return 0;
}

int
coap_dtls_context_set_pki_root_cas(struct coap_context_t *ctx UNUSED,
                                   const char *ca_file UNUSED,
                                   const char *ca_path UNUSED
) {
  return 0;
}

int
coap_dtls_context_set_psk(coap_context_t *ctx UNUSED,
                          const char *hint UNUSED,
                          coap_dtls_role_t role UNUSED
) {
  return 0;
}

int
coap_dtls_context_check_keys_enabled(coap_context_t *ctx UNUSED)
{
  return 0;
}

static int dtls_log_level = 0;

void coap_dtls_startup(void) {
}

void
coap_dtls_set_log_level(int level) {
  dtls_log_level = level;
}

int
coap_dtls_get_log_level(void) {
  return dtls_log_level;
}

void *
coap_dtls_new_context(struct coap_context_t *coap_context UNUSED) {
  return NULL;
}

void
coap_dtls_free_context(void *handle UNUSED) {
}

void *coap_dtls_new_server_session(coap_session_t *session UNUSED) {
  return NULL;
}

void *coap_dtls_new_client_session(coap_session_t *session UNUSED) {
  return NULL;
}

void coap_dtls_free_session(coap_session_t *coap_session UNUSED) {
}

void coap_dtls_session_update_mtu(coap_session_t *session UNUSED) {
}

int
coap_dtls_send(coap_session_t *session UNUSED,
  const uint8_t *data UNUSED,
  size_t data_len UNUSED
) {
  return -1;
}

int coap_dtls_is_context_timeout(void) {
  return 1;
}

coap_tick_t coap_dtls_get_context_timeout(void *dtls_context UNUSED) {
  return 0;
}

coap_tick_t coap_dtls_get_timeout(coap_session_t *session UNUSED) {
  return 0;
}

void coap_dtls_handle_timeout(coap_session_t *session UNUSED) {
}

int
coap_dtls_receive(coap_session_t *session UNUSED,
  const uint8_t *data UNUSED,
  size_t data_len UNUSED
) {
  return -1;
}

int
coap_dtls_hello(coap_session_t *session UNUSED,
  const uint8_t *data UNUSED,
  size_t data_len UNUSED
) {
  return 0;
}

unsigned int coap_dtls_get_overhead(coap_session_t *session UNUSED) {
  return 0;
}

void *coap_tls_new_client_session(coap_session_t *session UNUSED, int *connected UNUSED) {
  return NULL;
}

void *coap_tls_new_server_session(coap_session_t *session UNUSED, int *connected UNUSED) {
  return NULL;
}

void coap_tls_free_session(coap_session_t *coap_session UNUSED) {
}

ssize_t coap_tls_write(coap_session_t *session UNUSED,
                       const uint8_t *data UNUSED,
                       size_t data_len UNUSED
) {
  return -1;
}

ssize_t coap_tls_read(coap_session_t *session UNUSED,
                      uint8_t *data UNUSED,
                      size_t data_len UNUSED
) {
  return -1;
}

#undef UNUSED

#else /* !HAVE_LIBTINYDTLS && !HAVE_OPENSSL && !HAVE_LIBGNUTLS */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void dummy(void) {
}

#endif /* !HAVE_LIBTINYDTLS && !HAVE_OPENSSL && !HAVE_LIBGNUTLS */
/*
* coap_openssl.c -- Datagram Transport Layer Support for libcoap with openssl
*
* Copyright (C) 2017 Jean-Claude Michelou <jcm@spinetix.com>
* Copyright (C) 2018 Jon Shallow <supjps-libcoap@jpshallow.com>
*
* This file is part of the CoAP library libcoap. Please see README for terms
* of use.
*/

#include "coap_config.h"

#ifdef HAVE_OPENSSL

/*
 * OpenSSL 1.1.0 has support for making decisions during receipt of
 * the Client Hello - the call back function is set up using
 * SSL_CTX_set_tlsext_servername_callback() which is called later in the
 * Client Hello processing - but called every Client Hello.
 * Certificates and Preshared Keys have to be set up in the SSL CTX before
 * SSL_Accept() is called, making the code messy to decide whether this is a
 * PKI or PSK incoming request to handle things accordingly if both are
 * defined.  SNI has to create a new SSL CTX to handle different server names
 * with different crtificates.
 *
 * OpenSSL 1.1.1 introduces a new function SSL_CTX_set_client_hello_cb().
 * The call back is invoked early on in the Client Hello processing giving
 * the ability to easily use different Preshared Keys, Certificates etc.
 * Certificates do not have to be set up in the SSL CTX before SSL_Accept is
 * called.
 * Later in the Client Hello code, the callback for
 * SSL_CTX_set_tlsext_servername_callback() is still called, but only if SNI
 * is being used by the client, so cannot be used for doing things the
 * OpenSSL 1.1.0 way.
 *
 * OpenSSL 1.1.1 supports TLS1.3.
 *
 * Consequently, this code has to have compile time options to include /
 * exclude code based on whether compiled against 1.1.0 or 1.1.1, as well as
 * have additional run time checks.
 *
 */
#include "net.h"
#include "mem.h"
#include "coap_debug.h"
#include "prng.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/x509v3.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#error Must be compiled against OpenSSL 1.1.0 or later
#endif

#ifdef __GNUC__
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif /* __GNUC__ */

/* RFC6091/RFC7250 */
#ifndef TLSEXT_TYPE_client_certificate_type
#define TLSEXT_TYPE_client_certificate_type 19
#endif
#ifndef TLSEXT_TYPE_server_certificate_type
#define TLSEXT_TYPE_server_certificate_type 20
#endif

/* This structure encapsulates the OpenSSL context object. */
typedef struct coap_dtls_context_t {
  SSL_CTX *ctx;
  SSL *ssl;        /* OpenSSL object for listening to connection requests */
  HMAC_CTX *cookie_hmac;
  BIO_METHOD *meth;
  BIO_ADDR *bio_addr;
} coap_dtls_context_t;

typedef struct coap_tls_context_t {
  SSL_CTX *ctx;
  BIO_METHOD *meth;
} coap_tls_context_t;

#define IS_PSK 0x1
#define IS_PKI 0x2

typedef struct sni_entry {
  char *sni;
#if OPENSSL_VERSION_NUMBER < 0x10101000L
  SSL_CTX *ctx;
#else /* OPENSSL_VERSION_NUMBER >= 0x10101000L */
  coap_dtls_key_t pki_key;
#endif /* OPENSSL_VERSION_NUMBER >= 0x10101000L */
} sni_entry;

typedef struct coap_openssl_context_t {
  coap_dtls_context_t dtls;
  coap_tls_context_t tls;
  coap_dtls_pki_t setup_data;
  int psk_pki_enabled;
  size_t sni_count;
  sni_entry *sni_entry_list;
} coap_openssl_context_t;

int coap_dtls_is_supported(void) {
  if (SSLeay() < 0x10100000L) {
    coap_log(LOG_WARNING, "OpenSSL version 1.1.0 or later is required\n");
    return 0;
  }
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
  /*
   * For 1.1.1, we need to use SSL_CTX_set_client_hello_cb()
   * which is not in 1.1.0 instead of SSL_CTX_set_tlsext_servername_callback()
   *
   * However, there could be a runtime undefined external reference error
   * as SSL_CTX_set_client_hello_cb() is not there in 1.1.0.
   */
  if (SSLeay() < 0x10101000L) {
    coap_log(LOG_WARNING, "OpenSSL version 1.1.1 or later is required\n");
    return 0;
  }
#endif /* OPENSSL_VERSION_NUMBER >= 0x10101000L */
  return 1;
}

int coap_tls_is_supported(void) {
  if (SSLeay() < 0x10100000L) {
    coap_log(LOG_WARNING, "OpenSSL version 1.1.0 or later is required\n");
    return 0;
  }
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
  if (SSLeay() < 0x10101000L) {
    coap_log(LOG_WARNING, "OpenSSL version 1.1.1 or later is required\n");
    return 0;
  }
#endif /* OPENSSL_VERSION_NUMBER >= 0x10101000L */
  return 1;
}

coap_tls_version_t *
coap_get_tls_library_version(void) {
  static coap_tls_version_t version;
  version.version = SSLeay();
  version.built_version = OPENSSL_VERSION_NUMBER;
  version.type = COAP_TLS_LIBRARY_OPENSSL;
  return &version;
}

void coap_dtls_startup(void) {
  SSL_load_error_strings();
  SSL_library_init();
}

static int dtls_log_level = 0;

void coap_dtls_set_log_level(int level) {
  dtls_log_level = level;
}

int coap_dtls_get_log_level(void) {
  return dtls_log_level;
}

typedef struct coap_ssl_st {
  coap_session_t *session;
  const void *pdu;
  unsigned pdu_len;
  unsigned peekmode;
  coap_tick_t timeout;
} coap_ssl_data;

static int coap_dgram_create(BIO *a) {
  coap_ssl_data *data = NULL;
  data = malloc(sizeof(coap_ssl_data));
  if (data == NULL)
    return 0;
  BIO_set_init(a, 1);
  BIO_set_data(a, data);
  memset(data, 0x00, sizeof(coap_ssl_data));
  return 1;
}

static int coap_dgram_destroy(BIO *a) {
  coap_ssl_data *data;
  if (a == NULL)
    return 0;
  data = (coap_ssl_data *)BIO_get_data(a);
  if (data != NULL)
    free(data);
  return 1;
}

static int coap_dgram_read(BIO *a, char *out, int outl) {
  int ret = 0;
  coap_ssl_data *data = (coap_ssl_data *)BIO_get_data(a);

  if (out != NULL) {
    if (data != NULL && data->pdu_len > 0) {
      if (outl < (int)data->pdu_len) {
        memcpy(out, data->pdu, outl);
        ret = outl;
      } else {
        memcpy(out, data->pdu, data->pdu_len);
        ret = (int)data->pdu_len;
      }
      if (!data->peekmode) {
        data->pdu_len = 0;
        data->pdu = NULL;
      }
    } else {
      ret = -1;
    }
    BIO_clear_retry_flags(a);
    if (ret < 0)
      BIO_set_retry_read(a);
  }
  return ret;
}

static int coap_dgram_write(BIO *a, const char *in, int inl) {
  int ret = 0;
  coap_ssl_data *data = (coap_ssl_data *)BIO_get_data(a);

  if (data->session) {
    if (data->session->sock.flags == COAP_SOCKET_EMPTY && data->session->endpoint == NULL) {
      /* socket was closed on client due to error */
      BIO_clear_retry_flags(a);
      return -1;
    }
    ret = (int)coap_session_send(data->session, (const uint8_t *)in, (size_t)inl);
    BIO_clear_retry_flags(a);
    if (ret <= 0)
      BIO_set_retry_write(a);
  } else {
    BIO_clear_retry_flags(a);
    ret = -1;
  }
  return ret;
}

static int coap_dgram_puts(BIO *a, const char *pstr) {
  return coap_dgram_write(a, pstr, (int)strlen(pstr));
}

static long coap_dgram_ctrl(BIO *a, int cmd, long num, void *ptr) {
  long ret = 1;
  coap_ssl_data *data = BIO_get_data(a);

  (void)ptr;

  switch (cmd) {
  case BIO_CTRL_GET_CLOSE:
    ret = BIO_get_shutdown(a);
    break;
  case BIO_CTRL_SET_CLOSE:
    BIO_set_shutdown(a, (int)num);
    ret = 1;
    break;
  case BIO_CTRL_DGRAM_SET_PEEK_MODE:
    data->peekmode = (unsigned)num;
    break;
  case BIO_CTRL_DGRAM_CONNECT:
  case BIO_C_SET_FD:
  case BIO_C_GET_FD:
  case BIO_CTRL_DGRAM_SET_DONT_FRAG:
  case BIO_CTRL_DGRAM_GET_MTU:
  case BIO_CTRL_DGRAM_SET_MTU:
  case BIO_CTRL_DGRAM_QUERY_MTU:
  case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
    ret = -1;
    break;
  case BIO_CTRL_DUP:
  case BIO_CTRL_FLUSH:
  case BIO_CTRL_DGRAM_MTU_DISCOVER:
  case BIO_CTRL_DGRAM_SET_CONNECTED:
    ret = 1;
    break;
  case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
    data->timeout = coap_ticks_from_rt_us((uint64_t)((struct timeval*)ptr)->tv_sec * 1000000 + ((struct timeval*)ptr)->tv_usec);
    ret = 1;
    break;
  case BIO_CTRL_RESET:
  case BIO_C_FILE_SEEK:
  case BIO_C_FILE_TELL:
  case BIO_CTRL_INFO:
  case BIO_CTRL_PENDING:
  case BIO_CTRL_WPENDING:
  case BIO_CTRL_DGRAM_GET_PEER:
  case BIO_CTRL_DGRAM_SET_PEER:
  case BIO_CTRL_DGRAM_SET_RECV_TIMEOUT:
  case BIO_CTRL_DGRAM_GET_RECV_TIMEOUT:
  case BIO_CTRL_DGRAM_SET_SEND_TIMEOUT:
  case BIO_CTRL_DGRAM_GET_SEND_TIMEOUT:
  case BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP:
  case BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP:
  case BIO_CTRL_DGRAM_MTU_EXCEEDED:
  case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
  default:
    ret = 0;
    break;
  }
  return ret;
}

static int coap_dtls_generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
  coap_dtls_context_t *dtls = (coap_dtls_context_t *)SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl));
  coap_ssl_data *data = (coap_ssl_data*)BIO_get_data(SSL_get_rbio(ssl));
  int r = HMAC_Init_ex(dtls->cookie_hmac, NULL, 0, NULL, NULL);
  r &= HMAC_Update(dtls->cookie_hmac, (const uint8_t*)&data->session->local_addr.addr, (size_t)data->session->local_addr.size);
  r &= HMAC_Update(dtls->cookie_hmac, (const uint8_t*)&data->session->remote_addr.addr, (size_t)data->session->remote_addr.size);
  r &= HMAC_Final(dtls->cookie_hmac, cookie, cookie_len);
  return r;
}

static int coap_dtls_verify_cookie(SSL *ssl, const uint8_t *cookie, unsigned int cookie_len) {
  uint8_t hmac[32];
  unsigned len = 32;
  if (coap_dtls_generate_cookie(ssl, hmac, &len) && cookie_len == len && memcmp(cookie, hmac, len) == 0)
    return 1;
  else
    return 0;
}

static unsigned coap_dtls_psk_client_callback(SSL *ssl, const char *hint, char *identity, unsigned int max_identity_len, unsigned char *buf, unsigned max_len) {
  size_t hint_len = 0, identity_len = 0, psk_len;
  coap_session_t *session = (coap_session_t*)SSL_get_app_data(ssl);

  if (hint)
    hint_len = strlen(hint);
  else
    hint = "";

  coap_log(LOG_DEBUG, "got psk_identity_hint: '%.*s'\n", (int)hint_len, hint);

  if (session == NULL || session->context == NULL || session->context->get_client_psk == NULL)
    return 0;

  psk_len = session->context->get_client_psk(session, (const uint8_t*)hint, hint_len, (uint8_t*)identity, &identity_len, max_identity_len - 1, (uint8_t*)buf, max_len);
  if (identity_len < max_identity_len)
    identity[identity_len] = 0;
  return (unsigned)psk_len;
}

static unsigned coap_dtls_psk_server_callback(SSL *ssl, const char *identity, unsigned char *buf, unsigned max_len) {
  size_t identity_len = 0;
  coap_session_t *session = (coap_session_t*)SSL_get_app_data(ssl);

  if (identity)
    identity_len = strlen(identity);
  else
    identity = "";

  coap_log(LOG_DEBUG, "got psk_identity: '%.*s'\n",
           (int)identity_len, identity);

  if (session == NULL || session->context == NULL || session->context->get_server_psk == NULL)
    return 0;

  return (unsigned)session->context->get_server_psk(session, (const uint8_t*)identity, identity_len, (uint8_t*)buf, max_len);
}

static void coap_dtls_info_callback(const SSL *ssl, int where, int ret) {
  coap_session_t *session = (coap_session_t*)SSL_get_app_data(ssl);
  const char *pstr;
  int w = where &~SSL_ST_MASK;

  if (w & SSL_ST_CONNECT)
    pstr = "SSL_connect";
  else if (w & SSL_ST_ACCEPT)
    pstr = "SSL_accept";
  else
    pstr = "undefined";

  if (where & SSL_CB_LOOP) {
    if (dtls_log_level >= LOG_DEBUG)
      coap_log(LOG_DEBUG, "*  %s: %s:%s\n",
               coap_session_str(session), pstr, SSL_state_string_long(ssl));
  } else if (where & SSL_CB_ALERT) {
    pstr = (where & SSL_CB_READ) ? "read" : "write";
    if (dtls_log_level >= LOG_INFO)
      coap_log(LOG_INFO, "*  %s: SSL3 alert %s:%s:%s\n",
               coap_session_str(session),
               pstr,
               SSL_alert_type_string_long(ret),
               SSL_alert_desc_string_long(ret));
    if ((where & (SSL_CB_WRITE|SSL_CB_READ)) && (ret >> 8) == SSL3_AL_FATAL)
      session->dtls_event = COAP_EVENT_DTLS_ERROR;
  } else if (where & SSL_CB_EXIT) {
    if (ret == 0) {
      if (dtls_log_level >= LOG_WARNING) {
        unsigned long e;
        coap_log(LOG_WARNING, "*  %s: %s:failed in %s\n",
                 coap_session_str(session), pstr, SSL_state_string_long(ssl));
        while ((e = ERR_get_error()))
          coap_log(LOG_WARNING, "*  %s:   %s at %s:%s\n",
                   coap_session_str(session), ERR_reason_error_string(e),
                   ERR_lib_error_string(e), ERR_func_error_string(e));
      }
    } else if (ret < 0) {
      if (dtls_log_level >= LOG_WARNING) {
        int err = SSL_get_error(ssl, ret);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_WANT_CONNECT && err != SSL_ERROR_WANT_ACCEPT && err != SSL_ERROR_WANT_X509_LOOKUP) {
          long e;
          coap_log(LOG_WARNING, "*  %s: %s:error in %s\n",
                   coap_session_str(session), pstr, SSL_state_string_long(ssl));
          while ((e = ERR_get_error()))
            coap_log(LOG_WARNING, "*  %s: %s at %s:%s\n",
                     coap_session_str(session), ERR_reason_error_string(e),
                     ERR_lib_error_string(e), ERR_func_error_string(e));
        }
      }
    }
  }

  if (where == SSL_CB_HANDSHAKE_START && SSL_get_state(ssl) == TLS_ST_OK)
    session->dtls_event = COAP_EVENT_DTLS_RENEGOTIATE;
}

static int coap_sock_create(BIO *a) {
  BIO_set_init(a, 1);
  return 1;
}

static int coap_sock_destroy(BIO *a) {
  (void)a;
  return 1;
}

static int coap_sock_read(BIO *a, char *out, int outl) {
  int ret = 0;
  coap_session_t *session = (coap_session_t *)BIO_get_data(a);

  if (out != NULL) {
    ret = (int)coap_socket_read(&session->sock, (uint8_t*)out, (size_t)outl);
    if (ret == 0) {
      BIO_set_retry_read(a);
      ret = -1;
    } else {
      BIO_clear_retry_flags(a);
    }
  }
  return ret;
}

static int coap_sock_write(BIO *a, const char *in, int inl) {
  int ret = 0;
  coap_session_t *session = (coap_session_t *)BIO_get_data(a);

  ret = (int)coap_socket_write(&session->sock, (const uint8_t*)in, (size_t)inl);
  BIO_clear_retry_flags(a);
  if (ret == 0) {
    BIO_set_retry_read(a);
    ret = -1;
  } else {
    BIO_clear_retry_flags(a);
  }
  return ret;
}

static int coap_sock_puts(BIO *a, const char *pstr) {
  return coap_sock_write(a, pstr, (int)strlen(pstr));
}

static long coap_sock_ctrl(BIO *a, int cmd, long num, void *ptr) {
  int r = 1;
  (void)a;
  (void)ptr;
  (void)num;

  switch (cmd) {
  case BIO_C_SET_FD:
  case BIO_C_GET_FD:
    r = -1;
    break;
  case BIO_CTRL_SET_CLOSE:
  case BIO_CTRL_DUP:
  case BIO_CTRL_FLUSH:
    r = 1;
    break;
  default:
  case BIO_CTRL_GET_CLOSE:
    r = 0;
    break;
  }
  return r;
}

void *coap_dtls_new_context(struct coap_context_t *coap_context) {
  coap_openssl_context_t *context;
  (void)coap_context;

  context = (coap_openssl_context_t *)coap_malloc(sizeof(coap_openssl_context_t));
  if (context) {
    uint8_t cookie_secret[32];

    memset(context, 0, sizeof(coap_openssl_context_t));

    /* Set up DTLS context */
    context->dtls.ctx = SSL_CTX_new(DTLS_method());
    if (!context->dtls.ctx)
      goto error;
    SSL_CTX_set_min_proto_version(context->dtls.ctx, DTLS1_2_VERSION);
    SSL_CTX_set_app_data(context->dtls.ctx, &context->dtls);
    SSL_CTX_set_read_ahead(context->dtls.ctx, 1);
    SSL_CTX_set_cipher_list(context->dtls.ctx, "TLSv1.2:TLSv1.0");
    if (!RAND_bytes(cookie_secret, (int)sizeof(cookie_secret))) {
      if (dtls_log_level >= LOG_WARNING)
        coap_log(LOG_WARNING,
                 "Insufficient entropy for random cookie generation");
      prng(cookie_secret, sizeof(cookie_secret));
    }
    context->dtls.cookie_hmac = HMAC_CTX_new();
    if (!HMAC_Init_ex(context->dtls.cookie_hmac, cookie_secret, (int)sizeof(cookie_secret), EVP_sha256(), NULL))
      goto error;
    SSL_CTX_set_cookie_generate_cb(context->dtls.ctx, coap_dtls_generate_cookie);
    SSL_CTX_set_cookie_verify_cb(context->dtls.ctx, coap_dtls_verify_cookie);
    SSL_CTX_set_info_callback(context->dtls.ctx, coap_dtls_info_callback);
    SSL_CTX_set_options(context->dtls.ctx, SSL_OP_NO_QUERY_MTU);
    context->dtls.meth = BIO_meth_new(BIO_TYPE_DGRAM, "coapdgram");
    if (!context->dtls.meth)
      goto error;
    context->dtls.bio_addr = BIO_ADDR_new();
    if (!context->dtls.bio_addr)
      goto error;
    BIO_meth_set_write(context->dtls.meth, coap_dgram_write);
    BIO_meth_set_read(context->dtls.meth, coap_dgram_read);
    BIO_meth_set_puts(context->dtls.meth, coap_dgram_puts);
    BIO_meth_set_ctrl(context->dtls.meth, coap_dgram_ctrl);
    BIO_meth_set_create(context->dtls.meth, coap_dgram_create);
    BIO_meth_set_destroy(context->dtls.meth, coap_dgram_destroy);

    /* Set up TLS context */
    context->tls.ctx = SSL_CTX_new(TLS_method());
    if (!context->tls.ctx)
      goto error;
    SSL_CTX_set_app_data(context->tls.ctx, &context->tls);
    SSL_CTX_set_min_proto_version(context->tls.ctx, TLS1_VERSION);
    SSL_CTX_set_cipher_list(context->tls.ctx, "TLSv1.2:TLSv1.0");
    SSL_CTX_set_info_callback(context->tls.ctx, coap_dtls_info_callback);
    context->tls.meth = BIO_meth_new(BIO_TYPE_SOCKET, "coapsock");
    if (!context->tls.meth)
      goto error;
    BIO_meth_set_write(context->tls.meth, coap_sock_write);
    BIO_meth_set_read(context->tls.meth, coap_sock_read);
    BIO_meth_set_puts(context->tls.meth, coap_sock_puts);
    BIO_meth_set_ctrl(context->tls.meth, coap_sock_ctrl);
    BIO_meth_set_create(context->tls.meth, coap_sock_create);
    BIO_meth_set_destroy(context->tls.meth, coap_sock_destroy);
  }

  return context;

error:
  coap_dtls_free_context(context);
  return NULL;
}

int
coap_dtls_context_set_psk(coap_context_t *ctx,
                          const char *identity_hint,
                          coap_dtls_role_t role
) {
  coap_openssl_context_t *context = ((coap_openssl_context_t *)ctx->dtls_context);
  BIO *bio;

  if (role == COAP_DTLS_ROLE_SERVER) {
    SSL_CTX_set_psk_server_callback(context->dtls.ctx, coap_dtls_psk_server_callback);
    SSL_CTX_set_psk_server_callback(context->tls.ctx, coap_dtls_psk_server_callback);
    SSL_CTX_use_psk_identity_hint(context->dtls.ctx, identity_hint ? identity_hint : "");
    SSL_CTX_use_psk_identity_hint(context->tls.ctx, identity_hint ? identity_hint : "");
  }
  if (!context->dtls.ssl) {
    /* This is set up to handle new incoming sessions to a server */
    context->dtls.ssl = SSL_new(context->dtls.ctx);
    if (!context->dtls.ssl)
      return 0;
    bio = BIO_new(context->dtls.meth);
    if (!bio) {
      SSL_free (context->dtls.ssl);
      context->dtls.ssl = NULL;
      return 0;
    }
    SSL_set_bio(context->dtls.ssl, bio, bio);
    SSL_set_app_data(context->dtls.ssl, NULL);
    SSL_set_options(context->dtls.ssl, SSL_OP_COOKIE_EXCHANGE);
    SSL_set_mtu(context->dtls.ssl, COAP_DEFAULT_MTU);
  }
  context->psk_pki_enabled |= IS_PSK;
  return 1;
}

static int
map_key_type(int asn1_private_key_type
) {
  switch (asn1_private_key_type) {
  case COAP_ASN1_PKEY_NONE: return EVP_PKEY_NONE;
  case COAP_ASN1_PKEY_RSA: return EVP_PKEY_RSA;
  case COAP_ASN1_PKEY_RSA2: return EVP_PKEY_RSA2;
  case COAP_ASN1_PKEY_DSA: return EVP_PKEY_DSA;
  case COAP_ASN1_PKEY_DSA1: return EVP_PKEY_DSA1;
  case COAP_ASN1_PKEY_DSA2: return EVP_PKEY_DSA2;
  case COAP_ASN1_PKEY_DSA3: return EVP_PKEY_DSA3;
  case COAP_ASN1_PKEY_DSA4: return EVP_PKEY_DSA4;
  case COAP_ASN1_PKEY_DH: return EVP_PKEY_DH;
  case COAP_ASN1_PKEY_DHX: return EVP_PKEY_DHX;
  case COAP_ASN1_PKEY_EC: return EVP_PKEY_EC;
  case COAP_ASN1_PKEY_HMAC: return EVP_PKEY_HMAC;
  case COAP_ASN1_PKEY_CMAC: return EVP_PKEY_CMAC;
  case COAP_ASN1_PKEY_TLS1_PRF: return EVP_PKEY_TLS1_PRF;
  case COAP_ASN1_PKEY_HKDF: return EVP_PKEY_HKDF;
  default:
    coap_log(LOG_WARNING,
             "*** setup_pki: DTLS: Unknown Private Key type %d for ASN1\n",
             asn1_private_key_type);
    break;
  }
  return 0;
}
static uint8_t coap_alpn[] = { 4, 'c', 'o', 'a', 'p' };

static int
server_alpn_callback (SSL *ssl UNUSED,
                      const unsigned char **out,
                      unsigned char *outlen,
                      const unsigned char *in,
                      unsigned int inlen,
                      void *arg UNUSED
) {
  unsigned char *tout = NULL;
  int ret;
  if (inlen == 0)
    return SSL_TLSEXT_ERR_NOACK;
  ret = SSL_select_next_proto(&tout,
                              outlen,
                              coap_alpn,
                              sizeof(coap_alpn),
                              in,
                              inlen);
  *out = tout;
  return (ret != OPENSSL_NPN_NEGOTIATED) ? SSL_TLSEXT_ERR_NOACK : SSL_TLSEXT_ERR_OK;
}

static void
add_ca_to_cert_store(X509_STORE *st, X509 *x509)
{
  long e;

  /* Flush out existing errors */
  while ((e = ERR_get_error()) != 0) {
  }

  if (!X509_STORE_add_cert(st, x509)) {
    while ((e = ERR_get_error()) != 0) {
      int r = ERR_GET_REASON(e);
      if (r != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
        /* Not already added */
        coap_log(LOG_WARNING, "***setup_pki: (D)TLS: %s at %s:%s\n",
                 ERR_reason_error_string(e),
                 ERR_lib_error_string(e),
                 ERR_func_error_string(e));
      }
    }
  }
}

#if OPENSSL_VERSION_NUMBER < 0x10101000L
static int
setup_pki_server(SSL_CTX *ctx,
                 coap_dtls_pki_t* setup_data
) {
  switch (setup_data->pki_key.key_type) {
  case COAP_PKI_KEY_PEM:
    if (setup_data->pki_key.key.pem.public_cert &&
        setup_data->pki_key.key.pem.public_cert[0]) {
      if (!(SSL_CTX_use_certificate_file(ctx,
                                        setup_data->pki_key.key.pem.public_cert,
                                        SSL_FILETYPE_PEM))) {
        coap_log(LOG_WARNING,
                 "*** setup_pki: (D)TLS: %s: Unable to configure "
                 "Server Certificate\n",
                 setup_data->pki_key.key.pem.public_cert);
        return 0;
      }
    }
    else {
      coap_log(LOG_ERR,
             "*** setup_pki: (D)TLS: No Server Certificate defined\n");
      return 0;
    }

    if (setup_data->pki_key.key.pem.private_key &&
        setup_data->pki_key.key.pem.private_key[0]) {
      if (!(SSL_CTX_use_PrivateKey_file(ctx,
                                        setup_data->pki_key.key.pem.private_key,
                                        SSL_FILETYPE_PEM))) {
        coap_log(LOG_WARNING,
                 "*** setup_pki: (D)TLS: %s: Unable to configure "
                 "Server Private Key\n",
                  setup_data->pki_key.key.pem.private_key);
        return 0;
      }
    }
    else {
      coap_log(LOG_ERR,
           "*** setup_pki: (D)TLS: No Server Private Key defined\n");
      return 0;
    }

    if (setup_data->pki_key.key.pem.ca_file &&
        setup_data->pki_key.key.pem.ca_file[0]) {
      STACK_OF(X509_NAME) *cert_names;
      X509_STORE *st;
      BIO *in;
      X509 *x = NULL;
      char *rw_var = NULL;
      cert_names = SSL_load_client_CA_file(setup_data->pki_key.key.pem.ca_file);
      if (cert_names != NULL)
        SSL_CTX_set_client_CA_list(ctx, cert_names);
      else {
        coap_log(LOG_WARNING,
                 "*** setup_pki: (D)TLS: %s: Unable to configure "
                 "client CA File\n",
                  setup_data->pki_key.key.pem.ca_file);
        return 0;
      }
      st = SSL_CTX_get_cert_store(ctx);
      in = BIO_new(BIO_s_file());
      /* Need to do this to not get a compiler warning about const parameters */
      memcpy(&rw_var, &setup_data->pki_key.key.pem.ca_file, sizeof (rw_var));
      if (!BIO_read_filename(in, rw_var)) {
        BIO_free(in);
        X509_free(x);
        break;
      }

      for (;;) {
        if (PEM_read_bio_X509(in, &x, NULL, NULL) == NULL)
            break;
        add_ca_to_cert_store(st, x);
      }
      BIO_free(in);
      X509_free(x);
    }
    break;

  case COAP_PKI_KEY_ASN1:
    if (setup_data->pki_key.key.asn1.public_cert &&
        setup_data->pki_key.key.asn1.public_cert_len > 0) {
      if (!(SSL_CTX_use_certificate_ASN1(ctx,
                                 setup_data->pki_key.key.asn1.public_cert_len,
                                 setup_data->pki_key.key.asn1.public_cert))) {
        coap_log(LOG_WARNING,
                 "*** setup_pki: (D)TLS: %s: Unable to configure "
                 "Server Certificate\n",
                 "ASN1");
        return 0;
      }
    }
    else {
      coap_log(LOG_ERR,
             "*** setup_pki: (D)TLS: No Server Certificate defined\n");
      return 0;
    }

    if (setup_data->pki_key.key.asn1.private_key &&
             setup_data->pki_key.key.asn1.private_key_len > 0) {
      int pkey_type = map_key_type(setup_data->pki_key.key.asn1.private_key_type);
      if (!(SSL_CTX_use_PrivateKey_ASN1(pkey_type, ctx,
                             setup_data->pki_key.key.asn1.private_key,
                             setup_data->pki_key.key.asn1.private_key_len))) {
        coap_log(LOG_WARNING,
                 "*** setup_pki: (D)TLS: %s: Unable to configure "
                 "Server Private Key\n",
                 "ASN1");
        return 0;
      }
    }
    else {
      coap_log(LOG_ERR,
             "*** setup_pki: (D)TLS: No Server Private Key defined\n");
      return 0;
    }

    if (setup_data->pki_key.key.asn1.ca_cert &&
        setup_data->pki_key.key.asn1.ca_cert_len > 0) {
      /* Need to use a temp variable as it gets incremented*/
      const uint8_t *p = setup_data->pki_key.key.asn1.ca_cert;
      X509* x509 = d2i_X509(NULL, &p, setup_data->pki_key.key.asn1.ca_cert_len);
      X509_STORE *st;
      if (!x509 || !SSL_CTX_add_client_CA(ctx, x509)) {
        coap_log(LOG_WARNING,
                 "*** setup_pki: (D)TLS: %s: Unable to configure "
                 "client CA File\n",
                  "ASN1");
        X509_free(x509);
        return 0;
      }
      st = SSL_CTX_get_cert_store(ctx);
      add_ca_to_cert_store(st, x509);
      X509_free(x509);
    }
    break;
  default:
    coap_log(LOG_ERR,
             "*** setup_pki: (D)TLS: Unknown key type %d\n",
             setup_data->pki_key.key_type);
    return 0;
  }

  return 1;
}
#endif /* OPENSSL_VERSION_NUMBER < 0x10101000L */

static int
setup_pki_ssl(SSL *ssl,
                 coap_dtls_pki_t* setup_data, coap_dtls_role_t role
) {
  switch (setup_data->pki_key.key_type) {
  case COAP_PKI_KEY_PEM:
    if (setup_data->pki_key.key.pem.public_cert &&
        setup_data->pki_key.key.pem.public_cert[0]) {
      if (!(SSL_use_certificate_file(ssl,
                                   setup_data->pki_key.key.pem.public_cert,
                                   SSL_FILETYPE_PEM))) {
        coap_log(LOG_WARNING,
                 "*** setup_pki: (D)TLS: %s: Unable to configure "
                 "%s Certificate\n",
                 setup_data->pki_key.key.pem.public_cert,
                 role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
        return 0;
      }
    }
    else if (role == COAP_DTLS_ROLE_SERVER ||
             (setup_data->pki_key.key.pem.private_key &&
              setup_data->pki_key.key.pem.private_key[0])) {
      coap_log(LOG_ERR,
             "*** setup_pki: (D)TLS: No %s Certificate defined\n",
             role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      return 0;
    }
    if (setup_data->pki_key.key.pem.private_key &&
        setup_data->pki_key.key.pem.private_key[0]) {
      if (!(SSL_use_PrivateKey_file(ssl,
                                  setup_data->pki_key.key.pem.private_key,
                                  SSL_FILETYPE_PEM))) {
        coap_log(LOG_WARNING,
                 "*** setup_pki: (D)TLS: %s: Unable to configure "
                 "Client Private Key\n",
                  setup_data->pki_key.key.pem.private_key);
        return 0;
      }
    }
    else if (role == COAP_DTLS_ROLE_SERVER ||
             (setup_data->pki_key.key.pem.public_cert &&
              setup_data->pki_key.key.pem.public_cert[0])) {
      coap_log(LOG_ERR,
             "*** setup_pki: (D)TLS: No %s Private Key defined\n",
             role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      return 0;
    }
    if (setup_data->pki_key.key.pem.ca_file &&
        setup_data->pki_key.key.pem.ca_file[0]) {
      X509_STORE *st;
      BIO *in;
      X509 *x = NULL;
      char *rw_var = NULL;
      SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);

      if (role == COAP_DTLS_ROLE_SERVER) {
        STACK_OF(X509_NAME) *cert_names = SSL_load_client_CA_file(setup_data->pki_key.key.pem.ca_file);

        if (cert_names != NULL)
          SSL_set_client_CA_list(ssl, cert_names);
        else {
          coap_log(LOG_WARNING,
                   "*** setup_pki: (D)TLS: %s: Unable to configure "
                   "%s CA File\n",
                    setup_data->pki_key.key.pem.ca_file,
                    role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
          return 0;
        }
      }

      /* Add CA to the trusted root CA store */
      in = BIO_new(BIO_s_file());
      /* Need to do this to not get a compiler warning about const parameters */
      memcpy(&rw_var, &setup_data->pki_key.key.pem.ca_file, sizeof (rw_var));
      if (!BIO_read_filename(in, rw_var)) {
        BIO_free(in);
        X509_free(x);
        break;
      }
      st = SSL_CTX_get_cert_store(ctx);
      for (;;) {
        if (PEM_read_bio_X509(in, &x, NULL, NULL) == NULL)
            break;
        add_ca_to_cert_store(st, x);
      }
      BIO_free(in);
      X509_free(x);
    }
    break;

  case COAP_PKI_KEY_ASN1:
    if (setup_data->pki_key.key.asn1.public_cert &&
        setup_data->pki_key.key.asn1.public_cert_len > 0) {
      if (!(SSL_use_certificate_ASN1(ssl,
                           setup_data->pki_key.key.asn1.public_cert,
                           setup_data->pki_key.key.asn1.public_cert_len))) {
        coap_log(LOG_WARNING,
                 "*** setup_pki: (D)TLS: %s: Unable to configure "
                 "%s Certificate\n",
                 role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client",
                 "ASN1");
        return 0;
      }
    }
    else if (role == COAP_DTLS_ROLE_SERVER ||
             (setup_data->pki_key.key.asn1.private_key &&
              setup_data->pki_key.key.asn1.private_key[0])) {
      coap_log(LOG_ERR,
             "*** setup_pki: (D)TLS: No %s Certificate defined\n",
             role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      return 0;
    }
    if (setup_data->pki_key.key.asn1.private_key &&
             setup_data->pki_key.key.asn1.private_key_len > 0) {
      int pkey_type = map_key_type(setup_data->pki_key.key.asn1.private_key_type);
      if (!(SSL_use_PrivateKey_ASN1(pkey_type, ssl,
                        setup_data->pki_key.key.asn1.private_key,
                        setup_data->pki_key.key.asn1.private_key_len))) {
        coap_log(LOG_WARNING,
                 "*** setup_pki: (D)TLS: %s: Unable to configure "
                 "%s Private Key\n",
                 role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client",
                 "ASN1");
        return 0;
      }
    }
    else if (role == COAP_DTLS_ROLE_SERVER ||
             (setup_data->pki_key.key.asn1.public_cert &&
              setup_data->pki_key.key.asn1.public_cert_len > 0)) {
      coap_log(LOG_ERR,
             "*** setup_pki: (D)TLS: No %s Private Key defined",
             role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      return 0;
    }
    if (setup_data->pki_key.key.asn1.ca_cert &&
        setup_data->pki_key.key.asn1.ca_cert_len > 0) {
      /* Need to use a temp variable as it gets incremented*/
      const uint8_t *p = setup_data->pki_key.key.asn1.ca_cert;
      X509* x509 = d2i_X509(NULL, &p, setup_data->pki_key.key.asn1.ca_cert_len);
      X509_STORE *st;
      SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);

      if (role == COAP_DTLS_ROLE_SERVER) {
        if (!x509 || !SSL_add_client_CA(ssl, x509)) {
          coap_log(LOG_WARNING,
                   "*** setup_pki: (D)TLS: %s: Unable to configure "
                   "client CA File\n",
                    "ASN1");
          X509_free(x509);
          return 0;
        }
      }

      /* Add CA to the trusted root CA store */
      st = SSL_CTX_get_cert_store(ctx);
      add_ca_to_cert_store(st, x509);
      X509_free(x509);
    }
    break;
  default:
    coap_log(LOG_ERR,
             "*** setup_pki: (D)TLS: Unknown key type %d\n",
             setup_data->pki_key.key_type);
    return 0;
  }
  return 1;
}

static char*
get_common_name_from_cert(X509* x509) {
  if (x509) {
    char *cn;
    int n;
    STACK_OF(GENERAL_NAME) *san_list;
    char buffer[256];

    san_list = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
    if (san_list) {
      int san_count = sk_GENERAL_NAME_num(san_list);

      for (n = 0; n < san_count; n++) {
        const GENERAL_NAME * name = sk_GENERAL_NAME_value (san_list, n);

        if (name->type == GEN_DNS) {
          const char *dns_name = (const char *)ASN1_STRING_get0_data(name->d.dNSName);

          /* Make sure that there is not an embedded NUL in the dns_name */
          if (ASN1_STRING_length(name->d.dNSName) != (int)strlen (dns_name))
            continue;
          cn = OPENSSL_strdup(dns_name);
          sk_GENERAL_NAME_pop_free(san_list, GENERAL_NAME_free);
          return cn;
        }
      }
      sk_GENERAL_NAME_pop_free(san_list, GENERAL_NAME_free);
    }
    /* Otherwise look for the CN= field */
    X509_NAME_oneline(X509_get_subject_name(x509), buffer, sizeof(buffer));

    /* Need to emulate strcasestr() here.  Looking for CN= */
    n = strlen(buffer) - 3;
    cn = buffer;
    while (n > 0) {
      if (((cn[0] == 'C') || (cn[0] == 'c')) &&
          ((cn[1] == 'N') || (cn[1] == 'n')) &&
          (cn[2] == '=')) {
        cn += 3;
        break;
      }
      cn++;
      n--;
    }
    if (n > 0) {
      char * ecn = strchr(cn, '/');
      if (ecn) {
        return OPENSSL_strndup(cn, ecn-cn);
      }
      else {
        return OPENSSL_strdup(cn);
      }
    }
  }
  return NULL;
}

static int
tls_verify_call_back(int preverify_ok, X509_STORE_CTX *ctx) {
  SSL *ssl = X509_STORE_CTX_get_ex_data(ctx,
                              SSL_get_ex_data_X509_STORE_CTX_idx());
  coap_session_t *session = SSL_get_app_data(ssl);
  coap_openssl_context_t *context =
           ((coap_openssl_context_t *)session->context->dtls_context);
  coap_dtls_pki_t *setup_data = &context->setup_data;
  int depth = X509_STORE_CTX_get_error_depth(ctx);
  int err = X509_STORE_CTX_get_error(ctx);
  X509 *x509 = X509_STORE_CTX_get_current_cert(ctx);
  char *cn = get_common_name_from_cert(x509);
  int keep_preverify_ok = preverify_ok;

  if (!preverify_ok) {
    switch (err) {
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_CERT_HAS_EXPIRED:
      if (setup_data->allow_expired_certs)
        preverify_ok = 1;
      break;
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
      if (setup_data->allow_self_signed)
        preverify_ok = 1;
      break;
    case X509_V_ERR_UNABLE_TO_GET_CRL:
      if (setup_data->allow_no_crl)
        preverify_ok = 1;
      break;
    case X509_V_ERR_CRL_NOT_YET_VALID:
    case X509_V_ERR_CRL_HAS_EXPIRED:
      if (setup_data->allow_expired_crl)
        preverify_ok = 1;
      break;
    default:
      break;
    }
    if (!preverify_ok) {
        coap_log(LOG_WARNING,
               "    %s: %s: '%s' depth=%d\n",
               coap_session_str(session),
               X509_verify_cert_error_string(err), cn ? cn : "?", depth);
        /* Invoke the CN callback function for this failure */
        keep_preverify_ok = 1;
    }
    else {
        coap_log(LOG_WARNING,
               "    %s: %s: overridden: '%s' depth=%d\n",
               coap_session_str(session),
               X509_verify_cert_error_string(err), cn ? cn : "?", depth);
    }
  }
  /* Certificate - depth == 0 is the Client Cert */
  if (setup_data->validate_cn_call_back && keep_preverify_ok) {
    int length = i2d_X509(x509, NULL);
    uint8_t *base_buf;
    uint8_t *base_buf2 = base_buf = OPENSSL_malloc(length);

    /* base_buf2 gets moved to the end */
    i2d_X509(x509, &base_buf2);
    if (!setup_data->validate_cn_call_back(cn, base_buf, length, session,
                                           depth, preverify_ok,
                                           setup_data->cn_call_back_arg)) {
      if (depth == 0) {
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REJECTED);
      }
      else {
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_INVALID_CA);
      }
      preverify_ok = 0;
    }
    OPENSSL_free(base_buf);
  }
  OPENSSL_free(cn);
  return preverify_ok;
}

#if OPENSSL_VERSION_NUMBER < 0x10101000L
/*
 * During the SSL/TLS initial negotiations, tls_secret_call_back() is called so
 * it is possible to determine whether this is a PKI or PSK incoming
 * request and adjust the Ciphers if necessary
 *
 * Set up by SSL_set_session_secret_cb() in tls_server_name_call_back()
 */
static int
tls_secret_call_back(SSL *ssl,
  void *secret UNUSED,
  int *secretlen UNUSED,
  STACK_OF(SSL_CIPHER) *peer_ciphers,
  const SSL_CIPHER **cipher UNUSED,
  void *arg
) {
  int     ii;
  int     psk_requested = 0;
  coap_session_t *session = SSL_get_app_data(ssl);
  coap_dtls_pki_t *setup_data = (coap_dtls_pki_t*)arg;

  if (session && session->context->psk_key && session->context->psk_key_len) {
    /* Is PSK being requested - if so, we need to change algorithms */
    for (ii = 0; ii < sk_SSL_CIPHER_num (peer_ciphers); ii++) {
      const SSL_CIPHER *peer_cipher = sk_SSL_CIPHER_value(peer_ciphers, ii);

      if (strstr (SSL_CIPHER_get_name (peer_cipher), "PSK")) {
        psk_requested = 1;
        break;
      }
    }
  }
  if (!psk_requested) {
    if (session) {
      coap_log(LOG_DEBUG, "   %s: Using PKI ciphers\n",
                coap_session_str(session));
    }
    else {
      coap_log(LOG_DEBUG, "Using PKI ciphers\n");
    }
    if (setup_data->verify_peer_cert) {
      if (setup_data->require_peer_cert) {
        SSL_set_verify(ssl,
                       SSL_VERIFY_PEER |
                       SSL_VERIFY_CLIENT_ONCE |
                       SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       tls_verify_call_back);
      }
      else {
        SSL_set_verify(ssl,
                       SSL_VERIFY_PEER |
                       SSL_VERIFY_CLIENT_ONCE,
                       tls_verify_call_back);
      }
    }
    else {
      SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
    }

    /* Check CA Chain */
    if (setup_data->cert_chain_validation)
      SSL_set_verify_depth(ssl, setup_data->cert_chain_verify_depth);

    /* Certificate Revocation */
    if (setup_data->check_cert_revocation) {
       X509_VERIFY_PARAM *param;

       param = X509_VERIFY_PARAM_new();
       X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK);
       SSL_set1_param(ssl, param);
       X509_VERIFY_PARAM_free(param);
    }
  }
  else {
    if (session) {
      if (session->context->psk_key && session->context->psk_key_len) {
        memcpy(secret, session->context->psk_key, session->context->psk_key_len);
        *secretlen = session->context->psk_key_len;
      }
      coap_log(LOG_DEBUG, "   %s: Setting PSK ciphers\n",
               coap_session_str(session));
    }
    else {
      coap_log(LOG_DEBUG, "Setting PSK ciphers\n");
    }
    /*
     * Force a PSK algorithm to be used, so we do PSK
     */
    SSL_set_cipher_list (ssl, "PSK:!NULL");
    SSL_set_psk_server_callback(ssl, coap_dtls_psk_server_callback);
  }
  if (setup_data->additional_tls_setup_call_back) {
    /* Additional application setup wanted */
    if (!setup_data->additional_tls_setup_call_back(ssl, setup_data))
     return 0;
  }
  return 0;
}

/*
 * During the SSL/TLS initial negotiations, tls_server_name_call_back() is called
 * so it is possible to set up an extra callback to determine whether this is
 * a PKI or PSK incoming request and adjust the Ciphers if necessary
 *
 * Set up by SSL_CTX_set_tlsext_servername_callback() in coap_dtls_context_set_pki()
 */
static int
tls_server_name_call_back(SSL *ssl,
                          int *sd UNUSED,
                          void *arg
) {
  coap_dtls_pki_t *setup_data = (coap_dtls_pki_t*)arg;

  if (!ssl) {
    return SSL_TLSEXT_ERR_NOACK;
  }

  if (setup_data->validate_sni_call_back) {
    /* SNI checking requested */
    coap_session_t *session = (coap_session_t*)SSL_get_app_data(ssl);
    coap_openssl_context_t *context =
                  ((coap_openssl_context_t *)session->context->dtls_context);
    const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    size_t i;

    if (!sni || !sni[0]) {
      sni = "";
    }
    for (i = 0; i < context->sni_count; i++) {
      if (!strcmp(sni, context->sni_entry_list[i].sni)) {
        break;
      }
    }
    if (i == context->sni_count) {
      SSL_CTX *ctx;
      coap_dtls_pki_t sni_setup_data;
      coap_dtls_key_t *new_entry = setup_data->validate_sni_call_back(sni,
                                               setup_data->sni_call_back_arg);
      if (!new_entry) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
      }
      /* Need to set up a new SSL_CTX to switch to */
      if (session->proto == COAP_PROTO_DTLS) {
        /* Set up DTLS context */
        ctx = SSL_CTX_new(DTLS_method());
        if (!ctx)
          goto error;
        SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
        SSL_CTX_set_app_data(ctx, &context->dtls);
        SSL_CTX_set_read_ahead(ctx, 1);
        SSL_CTX_set_cipher_list(ctx, "TLSv1.2:TLSv1.0");
        SSL_CTX_set_cookie_generate_cb(ctx, coap_dtls_generate_cookie);
        SSL_CTX_set_cookie_verify_cb(ctx, coap_dtls_verify_cookie);
        SSL_CTX_set_info_callback(ctx, coap_dtls_info_callback);
        SSL_CTX_set_options(ctx, SSL_OP_NO_QUERY_MTU);
      }
      else {
        /* Set up TLS context */
        ctx = SSL_CTX_new(TLS_method());
        if (!ctx)
          goto error;
        SSL_CTX_set_app_data(ctx, &context->tls);
        SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
        SSL_CTX_set_cipher_list(ctx, "TLSv1.2:TLSv1.0");
        SSL_CTX_set_info_callback(ctx, coap_dtls_info_callback);
        SSL_CTX_set_alpn_select_cb(ctx, server_alpn_callback, NULL);
      }
      memset(&sni_setup_data, 0, sizeof(sni_setup_data));
      sni_setup_data.pki_key.key_type = new_entry->key_type;
      sni_setup_data.pki_key.key.pem = new_entry->key.pem;
      sni_setup_data.pki_key.key.asn1 = new_entry->key.asn1;
      setup_pki_server(ctx, &sni_setup_data);

      context->sni_entry_list = OPENSSL_realloc(context->sni_entry_list,
                                     (context->sni_count+1)*sizeof(sni_entry));
      context->sni_entry_list[context->sni_count].sni = OPENSSL_strdup(sni);
      context->sni_entry_list[context->sni_count].ctx = ctx;
      context->sni_count++;
    }
    SSL_set_SSL_CTX (ssl, context->sni_entry_list[i].ctx);
    SSL_clear_options (ssl, 0xFFFFFFFFL);
    SSL_set_options (ssl, SSL_CTX_get_options (context->sni_entry_list[i].ctx));
  }

  /*
   * Have to do extra call back next to get client algorithms
   * SSL_get_client_ciphers() does not work this early on
   */
  SSL_set_session_secret_cb(ssl, tls_secret_call_back, arg);
  return SSL_TLSEXT_ERR_OK;

error:
  return SSL_TLSEXT_ERR_ALERT_WARNING;
}
#else /* OPENSSL_VERSION_NUMBER >= 0x10101000L */
/*
 * During the SSL/TLS initial negotiations, tls_client_hello_call_back() is
 * called early in the Client Hello processing so it is possible to determine
 * whether this is a PKI or PSK incoming request and adjust the Ciphers if
 * necessary.
 *
 * Set up by SSL_CTX_set_client_hello_cb().
 */
static int
tls_client_hello_call_back(SSL *ssl,
                          int *al,
                          void *arg UNUSED
) {
  coap_session_t *session;
  coap_openssl_context_t *dtls_context;
  coap_dtls_pki_t *setup_data;
  int psk_requested = 0;
  const unsigned char *out;
  size_t outlen;

  if (!ssl) {
    *al = SSL_AD_INTERNAL_ERROR;
    return SSL_CLIENT_HELLO_ERROR;
  }
  session = (coap_session_t *)SSL_get_app_data(ssl);
  assert(session != NULL);
  assert(session->context != NULL);
  assert(session->context->dtls_context != NULL);
  dtls_context = (coap_openssl_context_t *)session->context->dtls_context;
  setup_data = &dtls_context->setup_data;

  /*
   * See if PSK being requested
   */
  if (session->context->psk_key && session->context->psk_key_len) {
    int len = SSL_client_hello_get0_ciphers(ssl, &out);
    STACK_OF(SSL_CIPHER) *peer_ciphers = NULL;
    STACK_OF(SSL_CIPHER) *scsvc = NULL;

    if (len && SSL_bytes_to_cipher_list(ssl, out, len,
                                        SSL_client_hello_isv2(ssl),
                                        &peer_ciphers, &scsvc)) {
      int ii;
      for (ii = 0; ii < sk_SSL_CIPHER_num (peer_ciphers); ii++) {
        const SSL_CIPHER *peer_cipher = sk_SSL_CIPHER_value(peer_ciphers, ii);

        if (strstr (SSL_CIPHER_get_name (peer_cipher), "PSK")) {
          psk_requested = 1;
          break;
        }
      }
    }
    sk_SSL_CIPHER_free(peer_ciphers);
    sk_SSL_CIPHER_free(scsvc);
  }

  if (psk_requested) {
    /*
     * Client has requested PSK and it is supported
     */
    if (session) {
      coap_log(LOG_DEBUG, "   %s: PSK request\n",
               coap_session_str(session));
    }
    else {
      coap_log(LOG_DEBUG, "PSK request\n");
    }
    SSL_set_psk_server_callback(ssl, coap_dtls_psk_server_callback);
    if (setup_data->additional_tls_setup_call_back) {
      /* Additional application setup wanted */
      if (!setup_data->additional_tls_setup_call_back(ssl, setup_data))
       return 0;
    }
    return SSL_CLIENT_HELLO_SUCCESS;
  }

  /*
   * Handle Certificate requests
   */

  /*
   * Determine what type of certificate is being requested
   */
  if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_client_certificate_type,
                                &out, &outlen)) {
    size_t ii;
    for (ii = 0; ii < outlen; ii++) {
      switch (out[ii]) {
      case 0:
        /* RFC6091 X.509 */
        if (outlen >= 2) {
          /* X.509 cannot be the singular entry. RFC6091 3.1. Client Hello */
          goto is_x509;
        }
        break;
      case 2:
        /* RFC7250 RPK - not yet supported */
        break;
      default:
        break;
      }
    }
    *al = SSL_AD_UNSUPPORTED_EXTENSION;
    return SSL_CLIENT_HELLO_ERROR;
  }

is_x509:
  if (setup_data->validate_sni_call_back) {
    /*
     * SNI checking requested
     */
    coap_dtls_pki_t sni_setup_data;
    coap_openssl_context_t *context =
                  ((coap_openssl_context_t *)session->context->dtls_context);
    const char *sni = "";
    char *sni_tmp = NULL;
    size_t i;

    if (SSL_client_hello_get0_ext (ssl, TLSEXT_TYPE_server_name, &out, &outlen) &&
        outlen > 5 &&
        (((out[0]<<8) + out[1] +2) == (int)outlen) &&
        out[2] == TLSEXT_NAMETYPE_host_name &&
        (((out[3]<<8) + out[4] +2 +3) == (int)outlen)) {
      /* Skip over length, type and length */
      out += 5;
      outlen -= 5;
      sni_tmp = OPENSSL_malloc(outlen+1);
      sni_tmp[outlen] = '\000';
      memcpy(sni_tmp, out, outlen);
      sni = sni_tmp;
    }
    /* Is this a cached entry? */
    for (i = 0; i < context->sni_count; i++) {
      if (!strcmp(sni, context->sni_entry_list[i].sni)) {
        break;
      }
    }
    if (i == context->sni_count) {
      /*
       * New SNI request
       */
      coap_dtls_key_t *new_entry = setup_data->validate_sni_call_back(sni,
                                               setup_data->sni_call_back_arg);
      if (!new_entry) {
        *al = SSL_AD_UNRECOGNIZED_NAME;
        return SSL_CLIENT_HELLO_ERROR;
      }


      context->sni_entry_list = OPENSSL_realloc(context->sni_entry_list,
                                     (context->sni_count+1)*sizeof(sni_entry));
      context->sni_entry_list[context->sni_count].sni = OPENSSL_strdup(sni);
      context->sni_entry_list[context->sni_count].pki_key = *new_entry;
      context->sni_count++;
    }
    if (sni_tmp) {
      OPENSSL_free(sni_tmp);
    }
    memset(&sni_setup_data, 0, sizeof(sni_setup_data));
    sni_setup_data.pki_key = context->sni_entry_list[i].pki_key;
    setup_pki_ssl(ssl, &sni_setup_data, 1);
  }
  else {
    setup_pki_ssl(ssl, setup_data, 1);
  }

  if (session) {
    coap_log(LOG_DEBUG, "   %s: Using PKI ciphers\n",
              coap_session_str(session));
  }
  else {
    coap_log(LOG_DEBUG, "Using PKI ciphers\n");
  }
  if (setup_data->verify_peer_cert) {
    if (setup_data->require_peer_cert) {
      SSL_set_verify(ssl,
                     SSL_VERIFY_PEER |
                     SSL_VERIFY_CLIENT_ONCE |
                     SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     tls_verify_call_back);
    }
    else {
      SSL_set_verify(ssl,
                     SSL_VERIFY_PEER |
                     SSL_VERIFY_CLIENT_ONCE,
                     tls_verify_call_back);
    }
  }
  else {
    SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
  }

  /* Check CA Chain */
  if (setup_data->cert_chain_validation)
    SSL_set_verify_depth(ssl, setup_data->cert_chain_verify_depth);

  /* Certificate Revocation */
  if (setup_data->check_cert_revocation) {
     X509_VERIFY_PARAM *param;

     param = X509_VERIFY_PARAM_new();
     X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK);
     SSL_set1_param(ssl, param);
     X509_VERIFY_PARAM_free(param);
  }
  if (setup_data->additional_tls_setup_call_back) {
    /* Additional application setup wanted */
    if (!setup_data->additional_tls_setup_call_back(ssl, setup_data))
     return 0;
  }
  return SSL_CLIENT_HELLO_SUCCESS;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x10101000L */

int
coap_dtls_context_set_pki(coap_context_t *ctx,
                          coap_dtls_pki_t *setup_data,
                          coap_dtls_role_t role
) {
  coap_openssl_context_t *context =
                                ((coap_openssl_context_t *)ctx->dtls_context);
  BIO *bio;
  if (!setup_data)
    return 0;
  context->setup_data = *setup_data;
  if (role == COAP_DTLS_ROLE_SERVER) {
    if (context->dtls.ctx) {
      /* SERVER DTLS */
#if OPENSSL_VERSION_NUMBER < 0x10101000L
      if (!setup_pki_server(context->dtls.ctx, setup_data))
        return 0;
#endif /* OPENSSL_VERSION_NUMBER < 0x10101000L */
      /* libcoap is managing TLS connection based on setup_data options */
      /* Need to set up logic to differentiate between a PSK or PKI session */
      /*
       * For OpenSSL 1.1.1, we need to use SSL_CTX_set_client_hello_cb()
       * which is not in 1.1.0
       */
#if OPENSSL_VERSION_NUMBER < 0x10101000L
      if (SSLeay() >= 0x10101000L) {
        coap_log(LOG_WARNING,
                 "OpenSSL compiled with %lux, linked with %lux, so "
                 "no certificate checking\n",
                 OPENSSL_VERSION_NUMBER, SSLeay());
      }
      SSL_CTX_set_tlsext_servername_arg(context->dtls.ctx, &context->setup_data);
      SSL_CTX_set_tlsext_servername_callback(context->dtls.ctx,
                                             tls_server_name_call_back);
#else /* OPENSSL_VERSION_NUMBER >= 0x10101000L */
      SSL_CTX_set_client_hello_cb(context->dtls.ctx,
                                    tls_client_hello_call_back,
                                    NULL);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10101000L */
    }
    if (context->tls.ctx) {
      /* SERVER TLS */
#if OPENSSL_VERSION_NUMBER < 0x10101000L
      if (!setup_pki_server(context->tls.ctx, setup_data))
        return 0;
#endif /* OPENSSL_VERSION_NUMBER < 0x10101000L */
      /* libcoap is managing TLS connection based on setup_data options */
      /* Need to set up logic to differentiate between a PSK or PKI session */
      /*
       * For OpenSSL 1.1.1, we need to use SSL_CTX_set_client_hello_cb()
       * which is not in 1.1.0
       */
#if OPENSSL_VERSION_NUMBER < 0x10101000L
      if (SSLeay() >= 0x10101000L) {
        coap_log(LOG_WARNING,
                 "OpenSSL compiled with %lux, linked with %lux, so "
                 "no certificate checking\n",
                 OPENSSL_VERSION_NUMBER, SSLeay());
      }
      SSL_CTX_set_tlsext_servername_arg(context->tls.ctx, &context->setup_data);
      SSL_CTX_set_tlsext_servername_callback(context->tls.ctx,
                                             tls_server_name_call_back);
#else /* OPENSSL_VERSION_NUMBER >= 0x10101000L */
      SSL_CTX_set_client_hello_cb(context->tls.ctx,
                                    tls_client_hello_call_back,
                                      NULL);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10101000L */
      /* TLS Only */
      SSL_CTX_set_alpn_select_cb(context->tls.ctx, server_alpn_callback, NULL);
    }
  }

  if (!context->dtls.ssl) {
    /* This is set up to handle new incoming sessions to a server */
    context->dtls.ssl = SSL_new(context->dtls.ctx);
    if (!context->dtls.ssl)
      return 0;
    bio = BIO_new(context->dtls.meth);
    if (!bio) {
      SSL_free (context->dtls.ssl);
      context->dtls.ssl = NULL;
      return 0;
    }
    SSL_set_bio(context->dtls.ssl, bio, bio);
    SSL_set_app_data(context->dtls.ssl, NULL);
    SSL_set_options(context->dtls.ssl, SSL_OP_COOKIE_EXCHANGE);
    SSL_set_mtu(context->dtls.ssl, COAP_DEFAULT_MTU);
  }
  context->psk_pki_enabled |= IS_PKI;
  return 1;
}

int
coap_dtls_context_set_pki_root_cas(struct coap_context_t *ctx,
                                   const char *ca_file,
                                   const char *ca_dir
) {
  coap_openssl_context_t *context =
                                ((coap_openssl_context_t *)ctx->dtls_context);
  if (context->dtls.ctx) {
    if (!SSL_CTX_load_verify_locations(context->dtls.ctx, ca_file, ca_dir)) {
      coap_log(LOG_WARNING, "Unable to install root CAs (%s/%s)\n",
               ca_file ? ca_file : "NULL", ca_dir ? ca_dir : "NULL");
      return 0;
    }
  }
  if (context->tls.ctx) {
    if (!SSL_CTX_load_verify_locations(context->tls.ctx, ca_file, ca_dir)) {
      coap_log(LOG_WARNING, "Unable to install root CAs (%s/%s)\n",
               ca_file ? ca_file : "NULL", ca_dir ? ca_dir : "NULL");
      return 0;
    }
  }
  return 1;
}

int
coap_dtls_context_check_keys_enabled(coap_context_t *ctx)
{
  coap_openssl_context_t *context =
                                 ((coap_openssl_context_t *)ctx->dtls_context);
  return context->psk_pki_enabled ? 1 : 0;
}


void coap_dtls_free_context(void *handle) {
  size_t i;
  coap_openssl_context_t *context = (coap_openssl_context_t *)handle;

  if (context->dtls.ssl)
    SSL_free(context->dtls.ssl);
  if (context->dtls.ctx)
    SSL_CTX_free(context->dtls.ctx);
  if (context->dtls.cookie_hmac)
    HMAC_CTX_free(context->dtls.cookie_hmac);
  if (context->dtls.meth)
    BIO_meth_free(context->dtls.meth);
  if (context->dtls.bio_addr)
    BIO_ADDR_free(context->dtls.bio_addr);
  if ( context->tls.ctx )
      SSL_CTX_free( context->tls.ctx );
  if ( context->tls.meth )
      BIO_meth_free( context->tls.meth );
  for (i = 0; i < context->sni_count; i++) {
    OPENSSL_free(context->sni_entry_list[i].sni);
#if OPENSSL_VERSION_NUMBER < 0x10101000L
    SSL_CTX_free(context->sni_entry_list[i].ctx);
#endif /* OPENSSL_VERSION_NUMBER < 0x10101000L */
  }
  if (context->sni_count)
    OPENSSL_free(context->sni_entry_list);
  coap_free(context);
}

void * coap_dtls_new_server_session(coap_session_t *session) {
  BIO *nbio = NULL;
  SSL *nssl = NULL, *ssl = NULL;
  coap_ssl_data *data;
  coap_dtls_context_t *dtls = &((coap_openssl_context_t *)session->context->dtls_context)->dtls;
  int r;

  nssl = SSL_new(dtls->ctx);
  if (!nssl)
    goto error;
  nbio = BIO_new(dtls->meth);
  if (!nbio)
    goto error;
  SSL_set_bio(nssl, nbio, nbio);
  SSL_set_app_data(nssl, NULL);
  SSL_set_options(nssl, SSL_OP_COOKIE_EXCHANGE);
  SSL_set_mtu(nssl, session->mtu);
  ssl = dtls->ssl;
  dtls->ssl = nssl;
  nssl = NULL;
  SSL_set_app_data(ssl, session);

  data = (coap_ssl_data*)BIO_get_data(SSL_get_rbio(ssl));
  data->session = session;

  if (session->context->get_server_hint) {
    char hint[128] = "";
    size_t hint_len = session->context->get_server_hint(session, (uint8_t*)hint, sizeof(hint) - 1);
    if (hint_len > 0 && hint_len < sizeof(hint)) {
      hint[hint_len] = 0;
      SSL_use_psk_identity_hint(ssl, hint);
    }
  }

  r = SSL_accept(ssl);
  if (r == -1) {
    int err = SSL_get_error(ssl, r);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
      r = 0;
  }

  if (r == 0) {
    SSL_free(ssl);
    return NULL;
  }

  return ssl;

error:
  if (nssl)
    SSL_free(nssl);
  return NULL;
}

static int
setup_client_ssl_session(coap_session_t *session, SSL *ssl
) {
  coap_openssl_context_t *context = ((coap_openssl_context_t *)session->context->dtls_context);

  if (context->psk_pki_enabled & IS_PSK) {
    SSL_set_psk_client_callback(ssl, coap_dtls_psk_client_callback);
    SSL_set_psk_server_callback(ssl, coap_dtls_psk_server_callback);
    SSL_set_cipher_list(ssl, "PSK:!NULL");
  }
  if (context->psk_pki_enabled & IS_PKI) {
    coap_dtls_pki_t *setup_data = &context->setup_data;
    if (!setup_pki_ssl(ssl, setup_data, 0))
      return 0;
    /* libcoap is managing (D)TLS connection based on setup_data options */
    if (session->proto == COAP_PROTO_TLS)
      SSL_set_alpn_protos(ssl, coap_alpn, sizeof(coap_alpn));

    /* Issue SNI if requested */
    if (setup_data->client_sni &&
        SSL_set_tlsext_host_name (ssl, setup_data->client_sni) != 1) {
          coap_log(LOG_WARNING, "SSL_set_tlsext_host_name: set '%s' failed",
                   setup_data->client_sni);
    }
    /* Certificate Revocation */
    if (setup_data->check_cert_revocation) {
       X509_VERIFY_PARAM *param;

       param = X509_VERIFY_PARAM_new();
       X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK);
       SSL_set1_param(ssl, param);
       X509_VERIFY_PARAM_free(param);
    }

    /* Verify Peer */
    if (setup_data->verify_peer_cert)
      SSL_set_verify(ssl, SSL_VERIFY_PEER, tls_verify_call_back);
    else
      SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);

    /* Check CA Chain */
    if (setup_data->cert_chain_validation)
      SSL_set_verify_depth(ssl, setup_data->cert_chain_verify_depth);

  }
  return 1;
}

void *coap_dtls_new_client_session(coap_session_t *session) {
  BIO *bio = NULL;
  SSL *ssl = NULL;
  coap_ssl_data *data;
  int r;
  coap_openssl_context_t *context = ((coap_openssl_context_t *)session->context->dtls_context);
  coap_dtls_context_t *dtls = &context->dtls;

  ssl = SSL_new(dtls->ctx);
  if (!ssl)
    goto error;
  bio = BIO_new(dtls->meth);
  if (!bio)
    goto error;
  data = (coap_ssl_data *)BIO_get_data(bio);
  data->session = session;
  SSL_set_bio(ssl, bio, bio);
  SSL_set_app_data(ssl, session);
  SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
  SSL_set_mtu(ssl, session->mtu);

  if (!setup_client_ssl_session(session, ssl))
    goto error;

  session->dtls_timeout_count = 0;

  r = SSL_connect(ssl);
  if (r == -1) {
    int ret = SSL_get_error(ssl, r);
    if (ret != SSL_ERROR_WANT_READ && ret != SSL_ERROR_WANT_WRITE)
      r = 0;
  }

  if (r == 0)
    goto error;

  return ssl;

error:
  if (ssl)
    SSL_free(ssl);
  return NULL;
}

void coap_dtls_session_update_mtu(coap_session_t *session) {
  SSL *ssl = (SSL *)session->tls;
  if (ssl)
    SSL_set_mtu(ssl, session->mtu);
}

void coap_dtls_free_session(coap_session_t *session) {
  SSL *ssl = (SSL *)session->tls;
  if (ssl) {
    if (!SSL_in_init(ssl) && !(SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN)) {
      int r = SSL_shutdown(ssl);
      if (r == 0) r = SSL_shutdown(ssl);
    }
    SSL_free(ssl);
    session->tls = NULL;
  }
}

int coap_dtls_send(coap_session_t *session,
  const uint8_t *data, size_t data_len) {
  int r;
  SSL *ssl = (SSL *)session->tls;

  assert(ssl != NULL);

  session->dtls_event = -1;
  r = SSL_write(ssl, data, (int)data_len);

  if (r <= 0) {
    int err = SSL_get_error(ssl, r);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      r = 0;
    } else {
      coap_log(LOG_WARNING, "coap_dtls_send: cannot send PDU\n");
      if (err == SSL_ERROR_ZERO_RETURN)
        session->dtls_event = COAP_EVENT_DTLS_CLOSED;
      else if (err == SSL_ERROR_SSL)
        session->dtls_event = COAP_EVENT_DTLS_ERROR;
      r = -1;
    }
  }

  if (session->dtls_event >= 0) {
    coap_handle_event(session->context, session->dtls_event, session);
    if (session->dtls_event == COAP_EVENT_DTLS_ERROR ||
        session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected(session, COAP_NACK_TLS_FAILED);
      r = -1;
    }
  }

  return r;
}

int coap_dtls_is_context_timeout(void) {
  return 0;
}

coap_tick_t coap_dtls_get_context_timeout(void *dtls_context) {
  (void)dtls_context;
  return 0;
}

coap_tick_t coap_dtls_get_timeout(coap_session_t *session) {
  SSL *ssl = (SSL *)session->tls;
  coap_ssl_data *ssl_data;

  assert(ssl != NULL);
  ssl_data = (coap_ssl_data*)BIO_get_data(SSL_get_rbio(ssl));
  return ssl_data->timeout;
}

void coap_dtls_handle_timeout(coap_session_t *session) {
  SSL *ssl = (SSL *)session->tls;

  assert(ssl != NULL);
  if (((session->state == COAP_SESSION_STATE_HANDSHAKE) &&
       (++session->dtls_timeout_count > session->max_retransmit)) ||
      (DTLSv1_handle_timeout(ssl) < 0)) {
    /* Too many retries */
    coap_session_disconnected(session, COAP_NACK_TLS_FAILED);
  }
}

int coap_dtls_hello(coap_session_t *session,
  const uint8_t *data, size_t data_len) {
  coap_dtls_context_t *dtls = &((coap_openssl_context_t *)session->context->dtls_context)->dtls;
  coap_ssl_data *ssl_data;
  int r;

  SSL_set_mtu(dtls->ssl, session->mtu);
  ssl_data = (coap_ssl_data*)BIO_get_data(SSL_get_rbio(dtls->ssl));
  ssl_data->session = session;
  ssl_data->pdu = data;
  ssl_data->pdu_len = (unsigned)data_len;
  r = DTLSv1_listen(dtls->ssl, dtls->bio_addr);
  if (r <= 0) {
    int err = SSL_get_error(dtls->ssl, r);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      /* Got a ClientHello, sent-out a VerifyRequest */
      r = 0;
    }
  } else {
    /* Got a valid answer to a VerifyRequest */
    r = 1;
  }

  return r;
}

int coap_dtls_receive(coap_session_t *session,
  const uint8_t *data, size_t data_len) {
  coap_ssl_data *ssl_data;
  SSL *ssl = (SSL *)session->tls;
  int r;

  assert(ssl != NULL);

  int in_init = SSL_in_init(ssl);
  uint8_t pdu[COAP_RXBUFFER_SIZE];
  ssl_data = (coap_ssl_data*)BIO_get_data(SSL_get_rbio(ssl));
  ssl_data->pdu = data;
  ssl_data->pdu_len = (unsigned)data_len;

  session->dtls_event = -1;
  r = SSL_read(ssl, pdu, (int)sizeof(pdu));
  if (r > 0) {
    return coap_handle_dgram(session->context, session, pdu, (size_t)r);
  } else {
    int err = SSL_get_error(ssl, r);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      if (in_init && SSL_is_init_finished(ssl)) {
        coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
        coap_session_connected(session);
      }
      r = 0;
    } else {
      if (err == SSL_ERROR_ZERO_RETURN)        /* Got a close notify alert from the remote side */
        session->dtls_event = COAP_EVENT_DTLS_CLOSED;
      else if (err == SSL_ERROR_SSL)
        session->dtls_event = COAP_EVENT_DTLS_ERROR;
      r = -1;
    }
    if (session->dtls_event >= 0) {
      coap_handle_event(session->context, session->dtls_event, session);
      if (session->dtls_event == COAP_EVENT_DTLS_ERROR ||
          session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
        coap_session_disconnected(session, COAP_NACK_TLS_FAILED);
        r = -1;
      }
    }
  }

  return r;
}

unsigned int coap_dtls_get_overhead(coap_session_t *session) {
  unsigned int overhead = 37;
  const SSL_CIPHER *s_ciph = NULL;
  if (session->tls != NULL)
    s_ciph = SSL_get_current_cipher(session->tls);
  if ( s_ciph ) {
    unsigned int ivlen, maclen, blocksize = 1, pad = 0;

    const EVP_CIPHER *e_ciph;
    const EVP_MD *e_md;
    char cipher[128];

    e_ciph = EVP_get_cipherbynid(SSL_CIPHER_get_cipher_nid(s_ciph));

    switch (EVP_CIPHER_mode(e_ciph)) {
    case EVP_CIPH_GCM_MODE:
      ivlen = EVP_GCM_TLS_EXPLICIT_IV_LEN;
      maclen = EVP_GCM_TLS_TAG_LEN;
      break;

    case EVP_CIPH_CCM_MODE:
      ivlen = EVP_CCM_TLS_EXPLICIT_IV_LEN;
      SSL_CIPHER_description(s_ciph, cipher, sizeof(cipher));
      if (strstr(cipher, "CCM8"))
        maclen = 8;
      else
        maclen = 16;
      break;

    case EVP_CIPH_CBC_MODE:
      e_md = EVP_get_digestbynid(SSL_CIPHER_get_digest_nid(s_ciph));
      blocksize = EVP_CIPHER_block_size(e_ciph);
      ivlen = EVP_CIPHER_iv_length(e_ciph);
      pad = 1;
      maclen = EVP_MD_size(e_md);
      break;

    case EVP_CIPH_STREAM_CIPHER:
      /* Seen with PSK-CHACHA20-POLY1305 */
      ivlen = 8;
      maclen = 8;
      break;

    default:
      SSL_CIPHER_description(s_ciph, cipher, sizeof(cipher));
      coap_log(LOG_WARNING, "Unknown overhead for DTLS with cipher %s\n",
               cipher);
      ivlen = 8;
      maclen = 16;
      break;
    }
    overhead = DTLS1_RT_HEADER_LENGTH + ivlen + maclen + blocksize - 1 + pad;
  }
  return overhead;
}

void *coap_tls_new_client_session(coap_session_t *session, int *connected) {
  BIO *bio = NULL;
  SSL *ssl = NULL;
  int r;
  coap_openssl_context_t *context = ((coap_openssl_context_t *)session->context->dtls_context);
  coap_tls_context_t *tls = &context->tls;

  *connected = 0;
  ssl = SSL_new(tls->ctx);
  if (!ssl)
    goto error;
  bio = BIO_new(tls->meth);
  if (!bio)
    goto error;
  BIO_set_data(bio, session);
  SSL_set_bio(ssl, bio, bio);
  SSL_set_app_data(ssl, session);

  if (!setup_client_ssl_session(session, ssl))
    return 0;

  r = SSL_connect(ssl);
  if (r == -1) {
    int ret = SSL_get_error(ssl, r);
    if (ret != SSL_ERROR_WANT_READ && ret != SSL_ERROR_WANT_WRITE)
      r = 0;
    if (ret == SSL_ERROR_WANT_READ)
      session->sock.flags |= COAP_SOCKET_WANT_READ;
    if (ret == SSL_ERROR_WANT_WRITE)
      session->sock.flags |= COAP_SOCKET_WANT_WRITE;
  }

  if (r == 0)
    goto error;

  *connected = SSL_is_init_finished(ssl);

  return ssl;

error:
  if (ssl)
    SSL_free(ssl);
  return NULL;
}

void *coap_tls_new_server_session(coap_session_t *session, int *connected) {
  BIO *bio = NULL;
  SSL *ssl = NULL;
  coap_tls_context_t *tls = &((coap_openssl_context_t *)session->context->dtls_context)->tls;
  int r;

  *connected = 0;
  ssl = SSL_new(tls->ctx);
  if (!ssl)
    goto error;
  bio = BIO_new(tls->meth);
  if (!bio)
    goto error;
  BIO_set_data(bio, session);
  SSL_set_bio(ssl, bio, bio);
  SSL_set_app_data(ssl, session);

  if (session->context->get_server_hint) {
    char hint[128] = "";
    size_t hint_len = session->context->get_server_hint(session, (uint8_t*)hint, sizeof(hint) - 1);
    if (hint_len > 0 && hint_len < sizeof(hint)) {
      hint[hint_len] = 0;
      SSL_use_psk_identity_hint(ssl, hint);
    }
  }

  r = SSL_accept(ssl);
  if (r == -1) {
    int err = SSL_get_error(ssl, r);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
      r = 0;
    if (err == SSL_ERROR_WANT_READ)
      session->sock.flags |= COAP_SOCKET_WANT_READ;
    if (err == SSL_ERROR_WANT_WRITE)
      session->sock.flags |= COAP_SOCKET_WANT_WRITE;
  }

  if (r == 0)
    goto error;

  *connected = SSL_is_init_finished(ssl);

  return ssl;

error:
  if (ssl)
    SSL_free(ssl);
  return NULL;
}

void coap_tls_free_session(coap_session_t *session) {
  SSL *ssl = (SSL *)session->tls;
  if (ssl) {
    if (!SSL_in_init(ssl) && !(SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN)) {
      int r = SSL_shutdown(ssl);
      if (r == 0) r = SSL_shutdown(ssl);
    }
    SSL_free(ssl);
    session->tls = NULL;
  }
}

ssize_t coap_tls_write(coap_session_t *session,
                       const uint8_t *data,
                       size_t data_len
) {
  SSL *ssl = (SSL *)session->tls;
  int r, in_init;

  if (ssl == NULL)
    return -1;

  in_init = !SSL_is_init_finished(ssl);
  session->dtls_event = -1;
  r = SSL_write(ssl, data, (int)data_len);

  if (r <= 0) {
    int err = SSL_get_error(ssl, r);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      if (in_init && SSL_is_init_finished(ssl)) {
        coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
        coap_session_send_csm(session);
      }
      if (err == SSL_ERROR_WANT_READ)
        session->sock.flags |= COAP_SOCKET_WANT_READ;
      if (err == SSL_ERROR_WANT_WRITE)
        session->sock.flags |= COAP_SOCKET_WANT_WRITE;
      r = 0;
    } else {
      coap_log(LOG_WARNING, "***%s: coap_tls_write: cannot send PDU\n",
               coap_session_str(session));
      if (err == SSL_ERROR_ZERO_RETURN)
        session->dtls_event = COAP_EVENT_DTLS_CLOSED;
      else if (err == SSL_ERROR_SSL)
        session->dtls_event = COAP_EVENT_DTLS_ERROR;
      r = -1;
    }
  } else if (in_init && SSL_is_init_finished(ssl)) {
    coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
    coap_session_send_csm(session);
  }

  if (session->dtls_event >= 0) {
    coap_handle_event(session->context, session->dtls_event, session);
    if (session->dtls_event == COAP_EVENT_DTLS_ERROR ||
        session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected(session, COAP_NACK_TLS_FAILED);
      r = -1;
    }
  }

  return r;
}

ssize_t coap_tls_read(coap_session_t *session,
                      uint8_t *data,
                      size_t data_len
) {
  SSL *ssl = (SSL *)session->tls;
  int r, in_init;

  if (ssl == NULL)
    return -1;

  in_init = !SSL_is_init_finished(ssl);
  session->dtls_event = -1;
  r = SSL_read(ssl, data, (int)data_len);
  if (r <= 0) {
    int err = SSL_get_error(ssl, r);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      if (in_init && SSL_is_init_finished(ssl)) {
        coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
        coap_session_send_csm(session);
      }
      if (err == SSL_ERROR_WANT_READ)
        session->sock.flags |= COAP_SOCKET_WANT_READ;
      if (err == SSL_ERROR_WANT_WRITE)
        session->sock.flags |= COAP_SOCKET_WANT_WRITE;
      r = 0;
    } else {
      if (err == SSL_ERROR_ZERO_RETURN)        /* Got a close notify alert from the remote side */
        session->dtls_event = COAP_EVENT_DTLS_CLOSED;
      else if (err == SSL_ERROR_SSL)
        session->dtls_event = COAP_EVENT_DTLS_ERROR;
      r = -1;
    }
  } else if (in_init && SSL_is_init_finished(ssl)) {
    coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
    coap_session_send_csm(session);
  }

  if (session->dtls_event >= 0) {
    coap_handle_event(session->context, session->dtls_event, session);
    if (session->dtls_event == COAP_EVENT_DTLS_ERROR ||
        session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected(session, COAP_NACK_TLS_FAILED);
      r = -1;
    }
  }

  return r;
}

#else /* !HAVE_OPENSSL */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void dummy(void) {
}

#endif /* HAVE_OPENSSL */
/* session.c -- Session management for libcoap
*
* Copyright (C) 2017 Jean-Claue Michelou <jcm@spinetix.com>
*
* This file is part of the CoAP library libcoap. Please see
* README for terms of use.
*/

#ifndef COAP_SESSION_C_
#define COAP_SESSION_C_


#include "coap_config.h"
#include "coap_io.h"
#include "coap_session.h"
#include "net.h"
#include "coap_debug.h"
#include "mem.h"
#include "resource.h"
#include "utlist.h"
#include "encode.h"
#include <stdio.h>


void
coap_session_set_max_retransmit (coap_session_t *session, unsigned int value) {
  if (value > 0)
    session->max_retransmit = value;
  coap_log(LOG_DEBUG, "***%s: session max_retransmit set to %d\n",
           coap_session_str(session), session->max_retransmit);
  return;
}

void
coap_session_set_ack_timeout (coap_session_t *session, coap_fixed_point_t value) {
  if (value.integer_part > 0 && value.fractional_part < 1000)
    session->ack_timeout = value;
  coap_log(LOG_DEBUG, "***%s: session ack_timeout set to %d.%03d\n",
           coap_session_str(session), session->ack_timeout.integer_part,
           session->ack_timeout.fractional_part);
  return;
}

void
coap_session_set_ack_random_factor (coap_session_t *session,
                                    coap_fixed_point_t value) {
  if (value.integer_part > 0 && value.fractional_part < 1000)
    session->ack_random_factor = value;
  coap_log(LOG_DEBUG, "***%s: session ack_random_factor set to %d.%03d\n",
           coap_session_str(session), session->ack_random_factor.integer_part,
           session->ack_random_factor.fractional_part);
  return;
}

unsigned int
coap_session_get_max_transmit (coap_session_t *session) {
  return session->max_retransmit;
}

coap_fixed_point_t
coap_session_get_ack_timeout (coap_session_t *session) {
  return session->ack_timeout;
}

coap_fixed_point_t
coap_session_get_ack_random_factor (coap_session_t *session) {
  return session->ack_random_factor;
}

coap_session_t *
coap_session_reference(coap_session_t *session) {
  ++session->ref;
  return session;
}

void
coap_session_release(coap_session_t *session) {
  if (session) {
    assert(session->ref > 0);
    if (session->ref > 0)
      --session->ref;
    if (session->ref == 0 && session->type == COAP_SESSION_TYPE_CLIENT)
      coap_session_free(session);
  }
}

void
coap_session_set_app_data(coap_session_t *session, void *app_data) {
  assert(session);
  session->app = app_data;
}

void *
coap_session_get_app_data(const coap_session_t *session) {
  assert(session);
  return session->app;
}

static coap_session_t *
coap_make_session(coap_proto_t proto, coap_session_type_t type,
  const coap_address_t *local_if, const coap_address_t *local_addr,
  const coap_address_t *remote_addr, int ifindex, coap_context_t *context,
  coap_endpoint_t *endpoint) {
  coap_session_t *session = (coap_session_t*)coap_malloc_type(COAP_SESSION, sizeof(coap_session_t));
  if (!session)
    return NULL;
  memset(session, 0, sizeof(*session));
  session->proto = proto;
  session->type = type;
  if (local_if)
    coap_address_copy(&session->local_if, local_if);
  else
    coap_address_init(&session->local_if);
  if (local_addr)
    coap_address_copy(&session->local_addr, local_addr);
  else
    coap_address_init(&session->local_addr);
  if (remote_addr)
    coap_address_copy(&session->remote_addr, remote_addr);
  else
    coap_address_init(&session->remote_addr);
  session->ifindex = ifindex;
  session->context = context;
  session->endpoint = endpoint;
  if (endpoint)
    session->mtu = endpoint->default_mtu;
  else
    session->mtu = COAP_DEFAULT_MTU;
  if (proto == COAP_PROTO_DTLS) {
    session->tls_overhead = 29;
    if (session->tls_overhead >= session->mtu) {
      session->tls_overhead = session->mtu;
      coap_log(LOG_ERR, "DTLS overhead exceeds MTU\n");
    }
  }
  session->max_retransmit = COAP_DEFAULT_MAX_RETRANSMIT;
  session->ack_timeout = COAP_DEFAULT_ACK_TIMEOUT;
  session->ack_random_factor = COAP_DEFAULT_ACK_RANDOM_FACTOR;
  session->dtls_event = -1;

  /* initialize message id */
  prng((unsigned char *)&session->tx_mid, sizeof(session->tx_mid));

  return session;
}

void coap_session_mfree(coap_session_t *session) {
  coap_queue_t *q, *tmp;

  if (session->partial_pdu)
    coap_delete_pdu(session->partial_pdu);
  if (session->proto == COAP_PROTO_DTLS)
    coap_dtls_free_session(session);
  else if (session->proto == COAP_PROTO_TLS)
    coap_tls_free_session(session);
  if (session->sock.flags != COAP_SOCKET_EMPTY)
    coap_socket_close(&session->sock);
  if (session->psk_identity)
    coap_free(session->psk_identity);
  if (session->psk_key)
    coap_free(session->psk_key);

  LL_FOREACH_SAFE(session->delayqueue, q, tmp) {
    if (q->pdu->type==COAP_MESSAGE_CON && session->context && session->context->nack_handler)
      session->context->nack_handler(session->context, session, q->pdu, session->proto == COAP_PROTO_DTLS ? COAP_NACK_TLS_FAILED : COAP_NACK_NOT_DELIVERABLE, q->id);
    coap_delete_node(q);
  }
}

void coap_session_free(coap_session_t *session) {
  if (!session)
    return;
  assert(session->ref == 0);
  if (session->ref)
    return;
  coap_session_mfree(session);
  if (session->endpoint) {
    if (session->endpoint->sessions)
      LL_DELETE(session->endpoint->sessions, session);
  } else if (session->context) {
    if (session->context->sessions)
      LL_DELETE(session->context->sessions, session);
  }
  coap_log(LOG_DEBUG, "***%s: session closed\n", coap_session_str(session));

  coap_free_type(COAP_SESSION, session);
}

size_t coap_session_max_pdu_size(const coap_session_t *session) {
  size_t max_with_header = (size_t)(session->mtu - session->tls_overhead);
  if (COAP_PROTO_NOT_RELIABLE(session->proto))
    return max_with_header > 4 ? max_with_header - 4 : 0;
  /* we must assume there is no token to be on the safe side */
  if (max_with_header <= 2)
    return 0;
  else if (max_with_header <= COAP_MAX_MESSAGE_SIZE_TCP0 + 2)
    return max_with_header - 2;
  else if (max_with_header <= COAP_MAX_MESSAGE_SIZE_TCP8 + 3)
    return max_with_header - 3;
  else if (max_with_header <= COAP_MAX_MESSAGE_SIZE_TCP16 + 4)
    return max_with_header - 4;
  else
    return max_with_header - 6;
}

void coap_session_set_mtu(coap_session_t *session, unsigned mtu) {
#if defined(WITH_CONTIKI) || defined(WITH_LWIP)
  if (mtu > COAP_MAX_MESSAGE_SIZE_TCP16 + 4)
    mtu = COAP_MAX_MESSAGE_SIZE_TCP16 + 4;
#endif
  session->mtu = mtu;
  if (session->tls_overhead >= session->mtu) {
    session->tls_overhead = session->mtu;
    coap_log(LOG_ERR, "DTLS overhead exceeds MTU\n");
  }
}

ssize_t coap_session_send(coap_session_t *session, const uint8_t *data, size_t datalen) {
  ssize_t bytes_written;

  coap_socket_t *sock = &session->sock;
  if (sock->flags == COAP_SOCKET_EMPTY) {
    assert(session->endpoint != NULL);
    sock = &session->endpoint->sock;
  }

  bytes_written = coap_socket_send(sock, session, data, datalen);
  if (bytes_written == (ssize_t)datalen) {
    coap_ticks(&session->last_rx_tx);
    coap_log(LOG_DEBUG, "*  %s: sent %zd bytes\n",
             coap_session_str(session), datalen);
  } else {
    coap_log(LOG_DEBUG, "*  %s: failed to send %zd bytes\n",
             coap_session_str(session), datalen);
  }
  return bytes_written;
}

ssize_t coap_session_write(coap_session_t *session, const uint8_t *data, size_t datalen) {
  ssize_t bytes_written = coap_socket_write(&session->sock, data, datalen);
  if (bytes_written > 0) {
    coap_ticks(&session->last_rx_tx);
    coap_log(LOG_DEBUG, "*  %s: sent %zd bytes\n",
             coap_session_str(session), datalen);
  } else if (bytes_written < 0) {
    coap_log(LOG_DEBUG,  "*   %s: failed to send %zd bytes\n",
             coap_session_str(session), datalen );
  }
  return bytes_written;
}

ssize_t
coap_session_delay_pdu(coap_session_t *session, coap_pdu_t *pdu,
                       coap_queue_t *node)
{
  if ( node ) {
    coap_queue_t *removed = NULL;
    coap_remove_from_queue(&session->context->sendqueue, session, node->id, &removed);
    assert(removed == node);
    coap_session_release(node->session);
    node->session = NULL;
    node->t = 0;
  } else {
    coap_queue_t *q = NULL;
    /* Check that the same tid is not getting re-used in violation of RFC7252 */
    LL_FOREACH(session->delayqueue, q) {
      if (q->id == pdu->tid) {
        coap_log(LOG_ERR, "**  %s: tid=%d: already in-use - dropped\n", coap_session_str(session), pdu->tid);
        return COAP_INVALID_TID;
      }
    }
    node = coap_new_node();
    if (node == NULL)
      return COAP_INVALID_TID;
    node->id = pdu->tid;
    node->pdu = pdu;
    if (pdu->type == COAP_MESSAGE_CON && COAP_PROTO_NOT_RELIABLE(session->proto)) {
      uint8_t r;
      prng(&r, sizeof(r));
      /* add timeout in range [ACK_TIMEOUT...ACK_TIMEOUT * ACK_RANDOM_FACTOR] */
      node->timeout = coap_calc_timeout(session, r);
    }
  }
  LL_APPEND(session->delayqueue, node);
  coap_log(LOG_DEBUG, "** %s: tid=%d: delayed\n",
           coap_session_str(session), node->id);
  return COAP_PDU_DELAYED;
}

void coap_session_send_csm(coap_session_t *session) {
  coap_pdu_t *pdu;
  uint8_t buf[4];
  assert(COAP_PROTO_RELIABLE(session->proto));
  coap_log(LOG_DEBUG, "***%s: sending CSM\n", coap_session_str(session));
  session->state = COAP_SESSION_STATE_CSM;
  session->partial_write = 0;
  if (session->mtu == 0)
    session->mtu = COAP_DEFAULT_MTU;  /* base value */
  pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_SIGNALING_CSM, 0, 16);
  if ( pdu == NULL
    || coap_add_option(pdu, COAP_SIGNALING_OPTION_MAX_MESSAGE_SIZE,
         coap_encode_var_safe(buf, sizeof(buf),
                                COAP_DEFAULT_MAX_PDU_RX_SIZE), buf) == 0
    || coap_pdu_encode_header(pdu, session->proto) == 0
  ) {
    coap_session_disconnected(session, COAP_NACK_NOT_DELIVERABLE);
  } else {
    ssize_t bytes_written = coap_session_send_pdu(session, pdu);
    if (bytes_written != (ssize_t)pdu->used_size + pdu->hdr_size)
      coap_session_disconnected(session, COAP_NACK_NOT_DELIVERABLE);
  }
  if (pdu)
    coap_delete_pdu(pdu);
}

coap_tid_t coap_session_send_ping(coap_session_t *session) {
  coap_pdu_t *ping;
  if (session->state != COAP_SESSION_STATE_ESTABLISHED)
    return 0;
  ping = coap_pdu_init(COAP_MESSAGE_CON, COAP_SIGNALING_PING, 0, 1);
  if (!ping)
    return COAP_INVALID_TID;
  return coap_send(session, ping);
}

void coap_session_connected(coap_session_t *session) {
  if (session->state != COAP_SESSION_STATE_ESTABLISHED) {
    coap_log(LOG_DEBUG, "***%s: session connected\n",
             coap_session_str(session));
    if (session->state == COAP_SESSION_STATE_CSM)
      coap_handle_event(session->context, COAP_EVENT_SESSION_CONNECTED, session);
  }

  session->state = COAP_SESSION_STATE_ESTABLISHED;
  session->partial_write = 0;

  if ( session->proto==COAP_PROTO_DTLS) {
    session->tls_overhead = coap_dtls_get_overhead(session);
    if (session->tls_overhead >= session->mtu) {
      session->tls_overhead = session->mtu;
      coap_log(LOG_ERR, "DTLS overhead exceeds MTU\n");
    }
  }

  while (session->delayqueue && session->state == COAP_SESSION_STATE_ESTABLISHED) {
    ssize_t bytes_written;
    coap_queue_t *q = session->delayqueue;
    if (q->pdu->type == COAP_MESSAGE_CON && COAP_PROTO_NOT_RELIABLE(session->proto)) {
      if (session->con_active >= COAP_DEFAULT_NSTART)
        break;
      session->con_active++;
    }
    /* Take entry off the queue */
    session->delayqueue = q->next;
    q->next = NULL;

    coap_log(LOG_DEBUG, "** %s: tid=%d: transmitted after delay\n",
             coap_session_str(session), (int)q->pdu->tid);
    bytes_written = coap_session_send_pdu(session, q->pdu);
    if (q->pdu->type == COAP_MESSAGE_CON && COAP_PROTO_NOT_RELIABLE(session->proto)) {
      if (coap_wait_ack(session->context, session, q) >= 0)
        q = NULL;
    }
    if (COAP_PROTO_NOT_RELIABLE(session->proto)) {
      if (q)
        coap_delete_node(q);
      if (bytes_written < 0)
        break;
    } else {
      if (bytes_written <= 0 || (size_t)bytes_written < q->pdu->used_size + q->pdu->hdr_size) {
        q->next = session->delayqueue;
        session->delayqueue = q;
        if (bytes_written > 0)
          session->partial_write = (size_t)bytes_written;
        break;
      } else {
        coap_delete_node(q);
      }
    }
  }
}

void coap_session_disconnected(coap_session_t *session, coap_nack_reason_t reason) {
  (void)reason;
  coap_session_state_t state = session->state;

  coap_log(LOG_DEBUG, "***%s: session disconnected (reason %d)\n",
           coap_session_str(session), reason);
#ifndef WITHOUT_OBSERVE
  coap_delete_observers( session->context, session );
#endif

  if ( session->tls) {
    if (session->proto == COAP_PROTO_DTLS)
      coap_dtls_free_session(session);
    else if (session->proto == COAP_PROTO_TLS)
      coap_tls_free_session(session);
    session->tls = NULL;
  }

  session->state = COAP_SESSION_STATE_NONE;

  if (session->partial_pdu) {
    coap_delete_pdu(session->partial_pdu);
    session->partial_pdu = NULL;
  }
  session->partial_read = 0;

  while (session->delayqueue) {
    coap_queue_t *q = session->delayqueue;
    session->delayqueue = q->next;
    q->next = NULL;
    coap_log(LOG_DEBUG, "** %s: tid=%d: not transmitted after delay\n",
             coap_session_str(session), q->id);
    if (q->pdu->type==COAP_MESSAGE_CON
      && COAP_PROTO_NOT_RELIABLE(session->proto)
      && reason != COAP_NACK_RST)
    {
      if (coap_wait_ack(session->context, session, q) >= 0)
        q = NULL;
    }
    if (q && q->pdu->type == COAP_MESSAGE_CON
      && session->context->nack_handler)
    {
      session->context->nack_handler(session->context, session, q->pdu,
                                     reason, q->id);
    }
    if (q)
      coap_delete_node(q);
  }
  if ( COAP_PROTO_RELIABLE(session->proto) ) {
    if (session->sock.flags != COAP_SOCKET_EMPTY) {
      coap_socket_close(&session->sock);
      coap_handle_event(session->context,
        state == COAP_SESSION_STATE_CONNECTING ?
        COAP_EVENT_TCP_FAILED : COAP_EVENT_TCP_CLOSED, session);
    }
    if (state != COAP_SESSION_STATE_NONE) {
      coap_handle_event(session->context,
        state == COAP_SESSION_STATE_ESTABLISHED ?
        COAP_EVENT_SESSION_CLOSED : COAP_EVENT_SESSION_FAILED, session);
    }
  }
}

coap_session_t *
coap_endpoint_get_session(coap_endpoint_t *endpoint,
  const coap_packet_t *packet, coap_tick_t now) {
  coap_session_t *session = NULL;
  unsigned int num_idle = 0;
  unsigned int num_hs = 0;
  coap_session_t *oldest = NULL;
  coap_session_t *oldest_hs = NULL;

  LL_FOREACH(endpoint->sessions, session) {
    if (session->ifindex == packet->ifindex &&
      coap_address_equals(&session->local_addr, &packet->dst) &&
      coap_address_equals(&session->remote_addr, &packet->src))
    {
      session->last_rx_tx = now;
      return session;
    }
    if (session->ref == 0 && session->delayqueue == NULL) {
      if (session->type == COAP_SESSION_TYPE_SERVER) {
        ++num_idle;
        if (oldest==NULL || session->last_rx_tx < oldest->last_rx_tx)
          oldest = session;

        if (session->state == COAP_SESSION_STATE_HANDSHAKE) {
          ++num_hs;
          /* See if this is a partial (D)TLS session set up
             which needs to be cleared down to prevent DOS */
          if ((session->last_rx_tx + COAP_PARTIAL_SESSION_TIMEOUT_TICKS) < now) {
            if (oldest_hs == NULL ||
                session->last_rx_tx < oldest_hs->last_rx_tx)
              oldest_hs = session;
          }
        }
      }
      else if (session->type == COAP_SESSION_TYPE_HELLO) {
        ++num_hs;
        /* See if this is a partial (D)TLS session set up for Client Hello
           which needs to be cleared down to prevent DOS */
        if ((session->last_rx_tx + COAP_PARTIAL_SESSION_TIMEOUT_TICKS) < now) {
          if (oldest_hs == NULL ||
              session->last_rx_tx < oldest_hs->last_rx_tx)
            oldest_hs = session;
        }
      }
    }
  }

  if (endpoint->context->max_idle_sessions > 0 &&
      num_idle >= endpoint->context->max_idle_sessions) {
    coap_session_free(oldest);
  }
  else if (oldest_hs) {
    coap_log(LOG_WARNING, "***%s: Incomplete session timed out\n",
             coap_session_str(oldest_hs));
    coap_session_free(oldest_hs);
  }

  if (num_hs > (endpoint->context->max_handshake_sessions ?
              endpoint->context->max_handshake_sessions :
              COAP_DEFAULT_MAX_HANDSHAKE_SESSIONS)) {
    /* Maxed out on number of sessions in (D)TLS negotiation state */
    coap_log(LOG_DEBUG,
             "Oustanding sessions in COAP_SESSION_STATE_HANDSHAKE too "
             "large.  New request ignored\n");
    return NULL;
  }

  if (endpoint->proto == COAP_PROTO_DTLS) {
    /*
     * Need to check that this actually is a Client Hello before wasting
     * time allocating and then freeing off session.
     */

    /*
     * Generic header structure of the DTLS record layer.
     * typedef struct __attribute__((__packed__)) {
     *   uint8_t content_type;           content type of the included message
     *   uint16_t version;               Protocol version
     *   uint16_t epoch;                 counter for cipher state changes
     *   uint8_t sequence_number[6];     sequence number
     *   uint16_t length;                length of the following fragment
     *   uint8_t handshake;              If content_type == DTLS_CT_HANDSHAKE
     * } dtls_record_handshake_t;
     */
#define OFF_CONTENT_TYPE      0  /* offset of content_type in dtls_record_handshake_t */
#define OFF_HANDSHAKE_TYPE   13  /* offset of handshake in dtls_record_handshake_t */
#define DTLS_CT_HANDSHAKE    22  /* Content Type value */
#define DTLS_HT_CLIENT_HELLO  1  /* Client Hello handshake type */

#ifdef WITH_LWIP
    const uint8_t *payload = (const uint8_t*)packet->pbuf->payload;
    size_t length = packet->pbuf->len;
#else /* ! WITH_LWIP */
    const uint8_t *payload = (const uint8_t*)packet->payload;
    size_t length = packet->length;
#endif /* ! WITH_LWIP */
    if (length < (OFF_HANDSHAKE_TYPE + 1)) {
      coap_log(LOG_DEBUG,
         "coap_dtls_hello: ContentType %d Short Packet (%ld < %d) dropped\n",
         payload[OFF_CONTENT_TYPE], length,
         OFF_HANDSHAKE_TYPE + 1);
      return NULL;
    }
    if (payload[OFF_CONTENT_TYPE] != DTLS_CT_HANDSHAKE ||
        payload[OFF_HANDSHAKE_TYPE] != DTLS_HT_CLIENT_HELLO) {
      coap_log(LOG_DEBUG,
         "coap_dtls_hello: ContentType %d Handshake %d dropped\n",
         payload[OFF_CONTENT_TYPE], payload[OFF_HANDSHAKE_TYPE]);
      return NULL;
    }
  }
  session = coap_make_session(endpoint->proto, COAP_SESSION_TYPE_SERVER,
    NULL, &packet->dst, &packet->src, packet->ifindex, endpoint->context,
    endpoint);
  if (session) {
    session->last_rx_tx = now;
    if (endpoint->proto == COAP_PROTO_UDP)
      session->state = COAP_SESSION_STATE_ESTABLISHED;
    else if (endpoint->proto == COAP_PROTO_DTLS) {
      session->type = COAP_SESSION_TYPE_HELLO;
    }
    LL_PREPEND(endpoint->sessions, session);
    coap_log(LOG_DEBUG, "***%s: new incoming session\n",
             coap_session_str(session));
  }
  return session;
}

coap_session_t *
coap_session_new_dtls_session(coap_session_t *session,
  coap_tick_t now) {
  if (session) {
    session->last_rx_tx = now;
    session->type = COAP_SESSION_TYPE_SERVER;
    session->tls = coap_dtls_new_server_session(session);
    if (session->tls) {
      session->state = COAP_SESSION_STATE_HANDSHAKE;
    } else {
      coap_session_free(session);
      session = NULL;
    }
  }
  return session;
}

static coap_session_t *
coap_session_create_client(
  coap_context_t *ctx,
  const coap_address_t *local_if,
  const coap_address_t *server,
  coap_proto_t proto
) {
  coap_session_t *session = NULL;

  assert(server);
  assert(proto != COAP_PROTO_NONE);

  session = coap_make_session(proto, COAP_SESSION_TYPE_CLIENT, local_if,
    local_if, server, 0, ctx, NULL);
  if (!session)
    goto error;

  coap_session_reference(session);

  if (proto == COAP_PROTO_UDP || proto == COAP_PROTO_DTLS) {
    if (!coap_socket_connect_udp(&session->sock, &session->local_if, server,
      proto == COAP_PROTO_DTLS ? COAPS_DEFAULT_PORT : COAP_DEFAULT_PORT,
      &session->local_addr, &session->remote_addr)) {
      goto error;
    }
  } else if (proto == COAP_PROTO_TCP || proto == COAP_PROTO_TLS) {
    if (!coap_socket_connect_tcp1(&session->sock, &session->local_if, server,
      proto == COAP_PROTO_TLS ? COAPS_DEFAULT_PORT : COAP_DEFAULT_PORT,
      &session->local_addr, &session->remote_addr)) {
      goto error;
    }
  }

  session->sock.flags |= COAP_SOCKET_NOT_EMPTY | COAP_SOCKET_WANT_READ;
  if (local_if)
    session->sock.flags |= COAP_SOCKET_BOUND;
  LL_PREPEND(ctx->sessions, session);
  return session;

error:
  coap_session_release(session);
  return NULL;
}

static coap_session_t *
coap_session_connect(coap_session_t *session) {
  if (session->proto == COAP_PROTO_UDP) {
    session->state = COAP_SESSION_STATE_ESTABLISHED;
  } else if (session->proto == COAP_PROTO_DTLS) {
    session->tls = coap_dtls_new_client_session(session);
    if (session->tls) {
      session->state = COAP_SESSION_STATE_HANDSHAKE;
    } else {
      /* Need to free session object. As a new session may not yet
       * have been referenced, we call coap_session_reference() first
       * before trying to release the object.
       */
      coap_session_reference(session);
      coap_session_release(session);
      return NULL;
    }
  } else if (session->proto == COAP_PROTO_TCP || session->proto == COAP_PROTO_TLS) {
    if (session->sock.flags & COAP_SOCKET_WANT_CONNECT) {
      session->state = COAP_SESSION_STATE_CONNECTING;
    } else if (session->proto == COAP_PROTO_TLS) {
      int connected = 0;
      session->tls = coap_tls_new_client_session(session, &connected);
      if (session->tls) {
        session->state = COAP_SESSION_STATE_HANDSHAKE;
        if (connected)
          coap_session_send_csm(session);
      } else {
        /* Need to free session object. As a new session may not yet
         * have been referenced, we call coap_session_reference()
         * first before trying to release the object.
         */
        coap_session_reference(session);
        coap_session_release(session);
        return NULL;
      }
    } else {
      coap_session_send_csm(session);
    }
  }
  coap_ticks(&session->last_rx_tx);
  return session;
}

static coap_session_t *
coap_session_accept(coap_session_t *session) {
  if (session->proto == COAP_PROTO_TCP || session->proto == COAP_PROTO_TLS)
    coap_handle_event(session->context, COAP_EVENT_TCP_CONNECTED, session);
  if (session->proto == COAP_PROTO_TCP) {
    coap_session_send_csm(session);
  } else if (session->proto == COAP_PROTO_TLS) {
    int connected = 0;
    session->tls = coap_tls_new_server_session(session, &connected);
    if (session->tls) {
      session->state = COAP_SESSION_STATE_HANDSHAKE;
      if (connected) {
        coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
        coap_session_send_csm(session);
      }
    } else {
      /* Need to free session object. As a new session may not yet
       * have been referenced, we call coap_session_reference() first
       * before trying to release the object.
       */
      coap_session_reference(session);
      coap_session_release(session);
      session = NULL;
    }
  }
  return session;
}

coap_session_t *coap_new_client_session(
  struct coap_context_t *ctx,
  const coap_address_t *local_if,
  const coap_address_t *server,
  coap_proto_t proto
) {
  coap_session_t *session = coap_session_create_client(ctx, local_if, server, proto);
  if (session) {
    coap_log(LOG_DEBUG, "***%s: new outgoing session\n",
             coap_session_str(session));
    session = coap_session_connect(session);
  }
  return session;
}

coap_session_t *coap_new_client_session_psk(
  struct coap_context_t *ctx,
  const coap_address_t *local_if,
  const coap_address_t *server,
  coap_proto_t proto,
  const char *identity,
  const uint8_t *key,
  unsigned key_len
) {
  coap_session_t *session = coap_session_create_client(ctx, local_if, server, proto);

  if (!session)
    return NULL;

  if (identity && (strlen(identity) > 0)) {
    size_t identity_len = strlen(identity);
    session->psk_identity = (uint8_t*)coap_malloc(identity_len);
    if (session->psk_identity) {
      memcpy(session->psk_identity, identity, identity_len);
      session->psk_identity_len = identity_len;
    } else {
      coap_log(LOG_WARNING, "Cannot store session PSK identity\n");
      coap_session_release(session);
      return NULL;
    }
  }
  else if (coap_dtls_is_supported()) {
    coap_log(LOG_WARNING, "PSK identity not defined\n");
    coap_session_release(session);
    return NULL;
  }

  if (key && key_len > 0) {
    session->psk_key = (uint8_t*)coap_malloc(key_len);
    if (session->psk_key) {
      memcpy(session->psk_key, key, key_len);
      session->psk_key_len = key_len;
    } else {
      coap_log(LOG_WARNING, "Cannot store session PSK key\n");
      coap_session_release(session);
      return NULL;
    }
  }
  else if (coap_dtls_is_supported()) {
    coap_log(LOG_WARNING, "PSK key not defined\n");
    coap_session_release(session);
    return NULL;
  }

  if (coap_dtls_is_supported()) {
    if (!coap_dtls_context_set_psk(ctx, NULL, COAP_DTLS_ROLE_CLIENT)) {
      coap_session_release(session);
      return NULL;
    }
  }
  coap_log(LOG_DEBUG, "***%s: new outgoing session\n",
           coap_session_str(session));
  return coap_session_connect(session);
}

coap_session_t *coap_new_client_session_pki(
  struct coap_context_t *ctx,
  const coap_address_t *local_if,
  const coap_address_t *server,
  coap_proto_t proto,
  coap_dtls_pki_t* setup_data
) {
  coap_session_t *session;

  if (coap_dtls_is_supported()) {
    if (!setup_data) {
      return NULL;
    } else {
      if (setup_data->version != COAP_DTLS_PKI_SETUP_VERSION) {
        coap_log(LOG_ERR,
                 "coap_new_client_session_pki: Wrong version of setup_data\n");
        return NULL;
      }
    }

  }
  session = coap_session_create_client(ctx, local_if, server, proto);

  if (!session) {
    return NULL;
  }

  if (coap_dtls_is_supported()) {
    /* we know that setup_data is not NULL */
    if (!coap_dtls_context_set_pki(ctx, setup_data, COAP_DTLS_ROLE_CLIENT)) {
      coap_session_release(session);
      return NULL;
    }
  }
  coap_log(LOG_DEBUG, "***%s: new outgoing session\n",
           coap_session_str(session));
  return coap_session_connect(session);
}


coap_session_t *coap_new_server_session(
  struct coap_context_t *ctx,
  coap_endpoint_t *ep
) {
  coap_session_t *session;
  session = coap_make_session( ep->proto, COAP_SESSION_TYPE_SERVER,
                               &ep->bind_addr, NULL, NULL, 0, ctx, ep );
  if (!session)
    goto error;

  if (!coap_socket_accept_tcp(&ep->sock, &session->sock,
                              &session->local_addr, &session->remote_addr))
    goto error;
  session->sock.flags |= COAP_SOCKET_NOT_EMPTY | COAP_SOCKET_CONNECTED
                       | COAP_SOCKET_WANT_READ;
  LL_PREPEND(ep->sessions, session);
  if (session) {
    coap_log(LOG_DEBUG, "***%s: new incoming session\n",
             coap_session_str(session));
    session = coap_session_accept(session);
  }
  return session;

error:
  coap_session_free(session);
  return NULL;
}

#ifndef WITH_LWIP
coap_endpoint_t *
coap_new_endpoint(coap_context_t *context, const coap_address_t *listen_addr, coap_proto_t proto) {
  struct coap_endpoint_t *ep = NULL;

  assert(context);
  assert(listen_addr);
  assert(proto != COAP_PROTO_NONE);

  if (proto == COAP_PROTO_DTLS && !coap_dtls_is_supported()) {
    coap_log(LOG_CRIT, "coap_new_endpoint: DTLS not supported\n");
    goto error;
  }

  if (proto == COAP_PROTO_TLS && !coap_tls_is_supported()) {
    coap_log(LOG_CRIT, "coap_new_endpoint: TLS not supported\n");
    goto error;
  }

  if (proto == COAP_PROTO_DTLS || proto == COAP_PROTO_TLS) {
    if (!coap_dtls_context_check_keys_enabled(context)) {
      coap_log(LOG_INFO,
               "coap_new_endpoint: one of coap_context_set_psk() or "
               "coap_context_set_pki() not called\n");
      goto error;
    }
  }

  ep = coap_malloc_endpoint();
  if (!ep) {
    coap_log(LOG_WARNING, "coap_new_endpoint: malloc");
    goto error;
  }

  memset(ep, 0, sizeof(struct coap_endpoint_t));
  ep->context = context;
  ep->proto = proto;

  if (proto==COAP_PROTO_TCP || proto==COAP_PROTO_TLS) {
    if (!coap_socket_bind_tcp(&ep->sock, listen_addr, &ep->bind_addr))
      goto error;
    ep->sock.flags |= COAP_SOCKET_WANT_ACCEPT;
  } else if (proto==COAP_PROTO_UDP || proto==COAP_PROTO_DTLS) {
    if (!coap_socket_bind_udp(&ep->sock, listen_addr, &ep->bind_addr))
      goto error;
    ep->sock.flags |= COAP_SOCKET_WANT_READ;
  } else {
    coap_log(LOG_CRIT, "coap_new_endpoint: protocol not supported\n");
    goto error;
  }

#ifndef NDEBUG
  if (LOG_DEBUG <= coap_get_log_level()) {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif
    unsigned char addr_str[INET6_ADDRSTRLEN + 8];

    if (coap_print_addr(&ep->bind_addr, addr_str, INET6_ADDRSTRLEN + 8)) {
      coap_log(LOG_DEBUG, "created %s endpoint %s\n",
          ep->proto == COAP_PROTO_TLS ? "TLS "
        : ep->proto == COAP_PROTO_TCP ? "TCP "
        : ep->proto == COAP_PROTO_DTLS ? "DTLS" : "UDP ",
        addr_str);
    }
  }
#endif /* NDEBUG */

  ep->sock.flags |= COAP_SOCKET_NOT_EMPTY | COAP_SOCKET_BOUND;

  ep->default_mtu = COAP_DEFAULT_MTU;

  LL_PREPEND(context->endpoint, ep);
  return ep;

error:
  coap_free_endpoint(ep);
  return NULL;
}

void coap_endpoint_set_default_mtu(coap_endpoint_t *ep, unsigned mtu) {
  ep->default_mtu = (uint16_t)mtu;
}

void
coap_free_endpoint(coap_endpoint_t *ep) {
  if (ep) {
    coap_session_t *session, *tmp;

    if (ep->sock.flags != COAP_SOCKET_EMPTY)
      coap_socket_close(&ep->sock);

    LL_FOREACH_SAFE(ep->sessions, session, tmp) {
      assert(session->ref == 0);
      if (session->ref == 0) {
        coap_session_free(session);
      }
    }

    coap_mfree_endpoint(ep);
  }
}
#endif /* WITH_LWIP */

coap_session_t *
coap_session_get_by_peer(coap_context_t *ctx,
  const coap_address_t *remote_addr,
  int ifindex) {
  coap_session_t *s;
  coap_endpoint_t *ep;
  LL_FOREACH(ctx->sessions, s) {
    if (s->ifindex == ifindex && coap_address_equals(&s->remote_addr, remote_addr))
      return s;
  }
  LL_FOREACH(ctx->endpoint, ep) {
    LL_FOREACH(ep->sessions, s) {
      if (s->ifindex == ifindex && coap_address_equals(&s->remote_addr, remote_addr))
        return s;
    }
  }
  return NULL;
}

const char *coap_session_str(const coap_session_t *session) {
  static char szSession[256];
  char *p = szSession, *end = szSession + sizeof(szSession);
  if (coap_print_addr(&session->local_addr, (unsigned char*)p, end - p) > 0)
    p += strlen(p);
  if (p + 6 < end) {
    strcpy(p, " <-> ");
    p += 5;
  }
  if (p + 1 < end) {
    if (coap_print_addr(&session->remote_addr, (unsigned char*)p, end - p) > 0)
      p += strlen(p);
  }
  if (session->ifindex > 0 && p + 1 < end)
    p += snprintf(p, end - p, " (if%d)", session->ifindex);
  if (p + 6 < end) {
    if (session->proto == COAP_PROTO_UDP) {
      strcpy(p, " UDP ");
      p += 4;
    } else if (session->proto == COAP_PROTO_DTLS) {
      strcpy(p, " DTLS");
      p += 5;
    } else if (session->proto == COAP_PROTO_TCP) {
      strcpy(p, " TCP ");
      p += 4;
    } else if (session->proto == COAP_PROTO_TLS) {
      strcpy(p, " TLS ");
      p += 4;
    } else {
      strcpy(p, " NONE");
      p += 5;
    }
  }

  return szSession;
}

const char *coap_endpoint_str(const coap_endpoint_t *endpoint) {
  static char szEndpoint[128];
  char *p = szEndpoint, *end = szEndpoint + sizeof(szEndpoint);
  if (coap_print_addr(&endpoint->bind_addr, (unsigned char*)p, end - p) > 0)
    p += strlen(p);
  if (p + 6 < end) {
    if (endpoint->proto == COAP_PROTO_UDP) {
      strcpy(p, " UDP");
      p += 4;
    } else if (endpoint->proto == COAP_PROTO_DTLS) {
      strcpy(p, " DTLS");
      p += 5;
    } else {
      strcpy(p, " NONE");
      p += 5;
    }
  }

  return szEndpoint;
}

#endif  /* COAP_SESSION_C_ */
/* coap_time.c -- Clock Handling
 *
 * Copyright (C) 2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_config.h"

#ifdef HAVE_TIME_H
#include <time.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>  /* _POSIX_TIMERS */
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#include <stdint.h>
#endif

#include "libcoap.h"
#include "coap_time.h"

static coap_tick_t coap_clock_offset = 0;

#if _POSIX_TIMERS && !defined(__APPLE__)
  /* _POSIX_TIMERS is > 0 when clock_gettime() is available */

  /* Use real-time clock for correct timestamps in coap_log(). */
#define COAP_CLOCK CLOCK_REALTIME
#endif

#ifdef HAVE_WINSOCK2_H
static int
gettimeofday(struct timeval *tp, TIME_ZONE_INFORMATION *tzp) {
  (void)tzp;
  static const uint64_t s_tUnixEpoch = 116444736000000000Ui64;

  FILETIME file_time;
  ULARGE_INTEGER time;
  uint64_t tUsSinceUnicEpoch;

  GetSystemTimeAsFileTime( &file_time );
  time.LowPart = file_time.dwLowDateTime;
  time.HighPart = file_time.dwHighDateTime;
  tUsSinceUnicEpoch = ( time.QuadPart - s_tUnixEpoch ) / 10;

  tp->tv_sec = (long)(tUsSinceUnicEpoch / 1000000);
  tp->tv_usec = (long)(tUsSinceUnicEpoch % 1000000);
  return 0;
}
#endif

void
coap_clock_init(void) {
#ifdef COAP_CLOCK
  struct timespec tv;
  clock_gettime(COAP_CLOCK, &tv);
#else /* _POSIX_TIMERS */
  struct timeval tv;
  gettimeofday(&tv, NULL);
#endif /* not _POSIX_TIMERS */

  coap_clock_offset = tv.tv_sec;
}

/* creates a Qx.frac from fval */
#define Q(frac,fval) ((coap_tick_t)(((1 << (frac)) * (fval))))

/* number of frac bits for sub-seconds */
#define FRAC 10

/* rounds val up and right shifts by frac positions */
#define SHR_FP(val,frac) (((val) + (1 << ((frac) - 1))) >> (frac))

void
coap_ticks(coap_tick_t *t) {
  coap_tick_t tmp;

#ifdef COAP_CLOCK
  struct timespec tv;
  clock_gettime(COAP_CLOCK, &tv);
  /* Possible errors are (see clock_gettime(2)):
   *  EFAULT tp points outside the accessible address space.
   *  EINVAL The clk_id specified is not supported on this system.
   * Both cases should not be possible here.
   */

  tmp = SHR_FP(tv.tv_nsec * Q(FRAC, (COAP_TICKS_PER_SECOND/1000000000.0)), FRAC);
#else /* _POSIX_TIMERS */
  /* Fall back to gettimeofday() */

  struct timeval tv;
  gettimeofday(&tv, NULL);
  /* Possible errors are (see gettimeofday(2)):
   *  EFAULT One of tv or tz pointed outside the accessible address space.
   *  EINVAL Timezone (or something else) is invalid.
   * Both cases should not be possible here.
   */

  tmp = SHR_FP(tv.tv_usec * Q(FRAC, (COAP_TICKS_PER_SECOND/1000000.0)), FRAC);
#endif /* not _POSIX_TIMERS */

  /* Finally, convert temporary FP representation to multiple of
   * COAP_TICKS_PER_SECOND */
  *t = tmp + (tv.tv_sec - coap_clock_offset) * COAP_TICKS_PER_SECOND;
}

coap_time_t
coap_ticks_to_rt(coap_tick_t t) {
  return coap_clock_offset + (t / COAP_TICKS_PER_SECOND);
}

uint64_t coap_ticks_to_rt_us(coap_tick_t t) {
  return (uint64_t)coap_clock_offset * 1000000 + (uint64_t)t * 1000000 / COAP_TICKS_PER_SECOND;
}

coap_tick_t coap_ticks_from_rt_us(uint64_t t) {
  return (coap_tick_t)((t - (uint64_t)coap_clock_offset * 1000000) * COAP_TICKS_PER_SECOND / 1000000);
}

#undef Q
#undef FRAC
#undef SHR_FP

#else /* HAVE_TIME_H */

/* make compilers happy that do not like empty modules */
COAP_STATIC_INLINE void dummy(void)
{
}

#endif /* not HAVE_TIME_H */

/*
 * coap_tinydtls.c -- Datagram Transport Layer Support for libcoap with tinydtls
 *
 * Copyright (C) 2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#include "coap_config.h"

#ifdef HAVE_LIBTINYDTLS

#include "net.h"
#include "address.h"
#include "coap_debug.h"
#include "mem.h"

/* We want TinyDTLS versions of these, not libcoap versions */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_URL
#undef PACKAGE_VERSION

#include <tinydtls.h>
#include <dtls.h>
#include <dtls_debug.h>

static dtls_tick_t dtls_tick_0 = 0;
static coap_tick_t coap_tick_0 = 0;

int
coap_dtls_is_supported(void) {
  return 1;
}

void coap_dtls_startup(void) {
  dtls_init();
  dtls_ticks(&dtls_tick_0);
  coap_ticks(&coap_tick_0);
}

void
coap_dtls_set_log_level(int level) {
  dtls_set_log_level(level);
}

int
coap_dtls_get_log_level(void) {
  return dtls_get_log_level();
}

static void get_session_addr(const session_t *s, coap_address_t *a) {
#ifdef WITH_CONTIKI
  a->addr = s->addr;
  a->port = s->port;
#else
  if (s->addr.sa.sa_family == AF_INET6) {
    a->size = (socklen_t)sizeof(a->addr.sin6);
    a->addr.sin6 = s->addr.sin6;
  } else if (s->addr.sa.sa_family == AF_INET) {
    a->size = (socklen_t)sizeof(a->addr.sin);
    a->addr.sin = s->addr.sin;
  } else {
    a->size = (socklen_t)s->size;
    a->addr.sa = s->addr.sa;
  }
#endif
}

static void put_session_addr(const coap_address_t *a, session_t *s) {
#ifdef WITH_CONTIKI
  s->size = (unsigned char)sizeof(s->addr);
  s->addr = a->addr;
  s->port = a->port;
#else
  if (a->addr.sa.sa_family == AF_INET6) {
    s->size = (socklen_t)sizeof(s->addr.sin6);
    s->addr.sin6 = a->addr.sin6;
  } else if (a->addr.sa.sa_family == AF_INET) {
    s->size = (socklen_t)sizeof(s->addr.sin);
    s->addr.sin = a->addr.sin;
  } else {
    s->size = (socklen_t)a->size;
    s->addr.sa = a->addr.sa;
  }
#endif
}

static int
dtls_send_to_peer(struct dtls_context_t *dtls_context,
  session_t *dtls_session, uint8 *data, size_t len) {
  coap_context_t *coap_context = (coap_context_t *)dtls_get_app_data(dtls_context);
  coap_session_t *coap_session;
  coap_address_t remote_addr;

  get_session_addr(dtls_session, &remote_addr);
  coap_session = coap_session_get_by_peer(coap_context, &remote_addr, dtls_session->ifindex);
  if (!coap_session) {
    coap_log(LOG_WARNING, "dtls_send_to_peer: cannot find local interface\n");
    return -3;
  }
  return (int)coap_session_send(coap_session, data, len);
}

static int
dtls_application_data(struct dtls_context_t *dtls_context,
  session_t *dtls_session, uint8 *data, size_t len) {
  coap_context_t *coap_context = (coap_context_t *)dtls_get_app_data(dtls_context);
  coap_session_t *coap_session;
  coap_address_t remote_addr;

  get_session_addr(dtls_session, &remote_addr);
  coap_session = coap_session_get_by_peer(coap_context, &remote_addr, dtls_session->ifindex);
  if (!coap_session) {
    coap_log(LOG_DEBUG,
             "dropped message that was received on invalid interface\n");
    return -1;
  }

  return coap_handle_dgram(coap_context, coap_session, data, len);
}

static int coap_event_dtls = 0;

static int
dtls_event(struct dtls_context_t *dtls_context,
  session_t *dtls_session,
  dtls_alert_level_t level,
  uint16_t code) {
  (void)dtls_context;
  (void)dtls_session;

  if (level == DTLS_ALERT_LEVEL_FATAL)
    coap_event_dtls = COAP_EVENT_DTLS_ERROR;

  /* handle DTLS events */
  switch (code) {
  case DTLS_ALERT_CLOSE_NOTIFY:
  {
    coap_event_dtls = COAP_EVENT_DTLS_CLOSED;
    break;
  }
  case DTLS_EVENT_CONNECTED:
  {
    coap_event_dtls = COAP_EVENT_DTLS_CONNECTED;
    break;
  }
  case DTLS_EVENT_RENEGOTIATE:
  {
    coap_event_dtls = COAP_EVENT_DTLS_RENEGOTIATE;
    break;
  }
  default:
    ;
  }

  return 0;
}

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *dtls_context,
  const session_t *dtls_session,
  dtls_credentials_type_t type,
  const uint8_t *id, size_t id_len,
  unsigned char *result, size_t result_length) {
  coap_context_t *coap_context;
  coap_session_t *coap_session;
  int fatal_error = DTLS_ALERT_INTERNAL_ERROR;
  size_t identity_length;
  static int client = 0;
  static uint8_t psk[128];
  static size_t psk_len = 0;
  coap_address_t remote_addr;


  if (type == DTLS_PSK_KEY && client) {
    if (psk_len > result_length) {
      coap_log(LOG_WARNING, "cannot set psk -- buffer too small\n");
      goto error;
    }
    memcpy(result, psk, psk_len);
    client = 0;
    return (int)psk_len;
  }

  client = 0;
  coap_context = (coap_context_t *)dtls_get_app_data(dtls_context);
  get_session_addr(dtls_session, &remote_addr);
  coap_session = coap_session_get_by_peer(coap_context, &remote_addr, dtls_session->ifindex);
  if (!coap_session) {
    coap_log(LOG_DEBUG, "cannot get PSK, session not found\n");
    goto error;
  }

  switch (type) {
  case DTLS_PSK_IDENTITY:

    if (id_len)
      coap_log(LOG_DEBUG, "got psk_identity_hint: '%.*s'\n", (int)id_len, id);

    if (!coap_context || !coap_context->get_client_psk)
      goto error;

    identity_length = 0;
    psk_len = coap_context->get_client_psk(coap_session, (const uint8_t*)id, id_len, (uint8_t*)result, &identity_length, result_length, psk, sizeof(psk));
    if (!psk_len) {
      coap_log(LOG_WARNING, "no PSK identity for given realm\n");
      fatal_error = DTLS_ALERT_CLOSE_NOTIFY;
      goto error;
    }
    client = 1;
    return (int)identity_length;

  case DTLS_PSK_KEY:
    if (coap_context->get_server_psk)
      return (int)coap_context->get_server_psk(coap_session, (const uint8_t*)id, id_len, (uint8_t*)result, result_length);
    return 0;
    break;

  case DTLS_PSK_HINT:
    client = 0;
    if (coap_context->get_server_hint)
      return (int)coap_context->get_server_hint(coap_session, (uint8_t *)result, result_length);
    return 0;

  default:
    coap_log(LOG_WARNING, "unsupported request type: %d\n", type);
  }

error:
  client = 0;
  return dtls_alert_fatal_create(fatal_error);
}

static dtls_handler_t cb = {
  .write = dtls_send_to_peer,
  .read = dtls_application_data,
  .event = dtls_event,
  .get_psk_info = get_psk_info,
#ifdef WITH_ECC
  .get_ecdsa_key = NULL,
  .verify_ecdsa_key = NULL
#endif
};

void *
coap_dtls_new_context(struct coap_context_t *coap_context) {
  struct dtls_context_t *dtls_context = dtls_new_context(coap_context);
  if (!dtls_context)
    goto error;
  dtls_set_handler(dtls_context, &cb);
  return dtls_context;
error:
  coap_dtls_free_context(dtls_context);
  return NULL;
}

void
coap_dtls_free_context(void *handle) {
  if (handle) {
    struct dtls_context_t *dtls_context = (struct dtls_context_t *)handle;
    dtls_free_context(dtls_context);
  }
}

static session_t *
coap_dtls_new_session(coap_session_t *session) {
  session_t *dtls_session = coap_malloc_type(COAP_DTLS_SESSION, sizeof(session_t));

  if (dtls_session) {
    /* create tinydtls session object from remote address and local
    * endpoint handle */
    dtls_session_init(dtls_session);
    put_session_addr(&session->remote_addr, dtls_session);
    dtls_session->ifindex = session->ifindex;
    coap_log(LOG_DEBUG, "***new session %p\n", (void *)dtls_session);
  }

  return dtls_session;
}

void *coap_dtls_new_server_session(coap_session_t *session) {
  return coap_dtls_new_session(session);
}

void *coap_dtls_new_client_session(coap_session_t *session) {
  dtls_peer_t *peer;
  session_t *dtls_session = coap_dtls_new_session(session);
  if (!dtls_session)
    return NULL;
  peer =
    dtls_get_peer((struct dtls_context_t *)session->context->dtls_context,
      dtls_session);

  if (!peer) {
    /* The peer connection does not yet exist. */
    /* dtls_connect() returns a value greater than zero if a new
    * connection attempt is made, 0 for session reuse. */
    if (dtls_connect((struct dtls_context_t *)session->context->dtls_context,
      dtls_session) >= 0) {
      peer =
        dtls_get_peer((struct dtls_context_t *)session->context->dtls_context,
          dtls_session);
    }
  }

  if (!peer) {
    /* delete existing session because the peer object has been invalidated */
    coap_free_type(COAP_DTLS_SESSION, dtls_session);
    dtls_session = NULL;
  }

  return dtls_session;
}

void
coap_dtls_session_update_mtu(coap_session_t *session) {
  (void)session;
}

void
coap_dtls_free_session(coap_session_t *coap_session) {
  struct dtls_context_t *ctx = (struct dtls_context_t *)coap_session->context->dtls_context;
  if (coap_session->tls) {
    dtls_peer_t *peer = dtls_get_peer(ctx, (session_t *)coap_session->tls);
    if ( peer )
      dtls_reset_peer(ctx, peer);
    else
      dtls_close(ctx, (session_t *)coap_session->tls);
    coap_log(LOG_DEBUG, "***removed session %p\n", coap_session->tls);
    coap_free_type(COAP_DTLS_SESSION, coap_session->tls);
    coap_session->tls = NULL;
  }
}

int
coap_dtls_send(coap_session_t *session,
  const uint8_t *data,
  size_t data_len
) {
  int res;
  uint8_t *data_rw;

  coap_log(LOG_DEBUG, "call dtls_write\n");

  coap_event_dtls = -1;
  /* Need to do this to not get a compiler warning about const parameters */
  memcpy (&data_rw, &data, sizeof(data_rw));
  res = dtls_write((struct dtls_context_t *)session->context->dtls_context,
    (session_t *)session->tls, data_rw, data_len);

  if (res < 0)
    coap_log(LOG_WARNING, "coap_dtls_send: cannot send PDU\n");

  if (coap_event_dtls >= 0) {
    coap_handle_event(session->context, coap_event_dtls, session);
    if (coap_event_dtls == COAP_EVENT_DTLS_CONNECTED)
      coap_session_connected(session);
    else if (coap_event_dtls == DTLS_ALERT_CLOSE_NOTIFY || coap_event_dtls == COAP_EVENT_DTLS_ERROR)
      coap_session_disconnected(session, COAP_NACK_TLS_FAILED);
  }

  return res;
}

int coap_dtls_is_context_timeout(void) {
  return 1;
}

coap_tick_t coap_dtls_get_context_timeout(void *dtls_context) {
  clock_time_t next = 0;
  dtls_check_retransmit((struct dtls_context_t *)dtls_context, &next);
  if (next > 0)
    return ((coap_tick_t)(next - dtls_tick_0)) * COAP_TICKS_PER_SECOND / DTLS_TICKS_PER_SECOND + coap_tick_0;
  return 0;
}

coap_tick_t coap_dtls_get_timeout(coap_session_t *session) {
  (void)session;
  return 0;
}

void coap_dtls_handle_timeout(coap_session_t *session) {
  (void)session;
  return;
}

int
coap_dtls_receive(coap_session_t *session,
  const uint8_t *data,
  size_t data_len
) {
  session_t *dtls_session = (session_t *)session->tls;
  int err;
  uint8_t *data_rw;

  coap_event_dtls = -1;
  /* Need to do this to not get a compiler warning about const parameters */
  memcpy (&data_rw, &data, sizeof(data_rw));
  err = dtls_handle_message(
    (struct dtls_context_t *)session->context->dtls_context,
    dtls_session, data_rw, (int)data_len);

  if (err){
    coap_event_dtls = COAP_EVENT_DTLS_ERROR;
  }

  if (coap_event_dtls >= 0) {
    coap_handle_event(session->context, coap_event_dtls, session);
    if (coap_event_dtls == COAP_EVENT_DTLS_CONNECTED)
      coap_session_connected(session);
    else if (coap_event_dtls == DTLS_ALERT_CLOSE_NOTIFY || coap_event_dtls == COAP_EVENT_DTLS_ERROR)
      coap_session_disconnected(session, COAP_NACK_TLS_FAILED);
  }

  return err;
}

int
coap_dtls_hello(coap_session_t *session,
  const uint8_t *data,
  size_t data_len
) {
  session_t dtls_session;
  struct dtls_context_t *dtls_context =
    (struct dtls_context_t *)session->context->dtls_context;
  uint8_t *data_rw;

  dtls_session_init(&dtls_session);
  put_session_addr(&session->remote_addr, &dtls_session);
  dtls_session.ifindex = session->ifindex;
  /* Need to do this to not get a compiler warning about const parameters */
  memcpy (&data_rw, &data, sizeof(data_rw));
  int res = dtls_handle_message(dtls_context, &dtls_session,
    data_rw, (int)data_len);
  if (res >= 0) {
    if (dtls_get_peer(dtls_context, &dtls_session))
      res = 1;
    else
      res = 0;
  }
  return res;
}

unsigned int coap_dtls_get_overhead(coap_session_t *session) {
  (void)session;
  return 13 + 8 + 8;
}

#ifdef __GNUC__
#define UNUSED __attribute__((unused))
#else /* __GNUC__ */
#define UNUSED
#endif /* __GNUC__ */

int coap_tls_is_supported(void) {
  return 0;
}

coap_tls_version_t *
coap_get_tls_library_version(void) {
  static coap_tls_version_t version;
  const char *vers = dtls_package_version();

  version.version = 0;
  if (vers) {
    long int p1, p2 = 0, p3 = 0;
    char* endptr;

    p1 = strtol(vers, &endptr, 10);
    if (*endptr == '.') {
      p2 = strtol(endptr+1, &endptr, 10);
      if (*endptr == '.') {
        p3 = strtol(endptr+1, &endptr, 10);
      }
    }
    version.version = (p1 << 16) | (p2 << 8) | p3;
  }
  version.built_version = version.version;
  version.type = COAP_TLS_LIBRARY_TINYDTLS;
  return &version;
}

int
coap_dtls_context_set_pki(coap_context_t *ctx UNUSED,
  coap_dtls_pki_t* setup_data UNUSED,
  coap_dtls_role_t role UNUSED
) {
  return 0;
}

int
coap_dtls_context_set_pki_root_cas(struct coap_context_t *ctx UNUSED,
  const char *ca_file UNUSED,
  const char *ca_path UNUSED
) {
  return 0;
}

int
coap_dtls_context_set_psk(coap_context_t *ctx UNUSED,
  const char *hint UNUSED,
  coap_dtls_role_t role UNUSED
) {
  return 1;
}

int
coap_dtls_context_check_keys_enabled(coap_context_t *ctx UNUSED)
{
  return 1;
}

void *coap_tls_new_client_session(coap_session_t *session UNUSED, int *connected UNUSED) {
  return NULL;
}

void *coap_tls_new_server_session(coap_session_t *session UNUSED, int *connected UNUSED) {
  return NULL;
}

void coap_tls_free_session(coap_session_t *coap_session UNUSED) {
}

ssize_t coap_tls_write(coap_session_t *session UNUSED,
                       const uint8_t *data UNUSED,
                       size_t data_len UNUSED
) {
  return -1;
}

ssize_t coap_tls_read(coap_session_t *session UNUSED,
                      uint8_t *data UNUSED,
                      size_t data_len UNUSED
) {
  return -1;
}

#undef UNUSED

#else /* !HAVE_LIBTINYDTLS */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void dummy(void) {
}

#endif /* HAVE_LIBTINYDTLS */
/* encode.c -- encoding and decoding of CoAP data types
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#ifndef NDEBUG
#  include <stdio.h>
#endif

#include "coap_config.h"
#include "coap.h"
#include "mem.h"
#include "encode.h"

/* Carsten suggested this when fls() is not available: */
#ifndef HAVE_FLS
int coap_fls(unsigned int i) {
  return coap_flsll(i);
}
#endif

#ifndef HAVE_FLSLL
int coap_flsll(long long i)
{
  int n;
  for (n = 0; i; n++)
    i >>= 1;
  return n;
}
#endif

unsigned int
coap_decode_var_bytes(const uint8_t *buf,unsigned int len) {
  unsigned int i, n = 0;
  for (i = 0; i < len; ++i)
    n = (n << 8) + buf[i];

  return n;
}

unsigned int
coap_encode_var_safe(uint8_t *buf, size_t length, unsigned int val) {
  unsigned int n, i;

  for (n = 0, i = val; i && n < sizeof(val); ++n)
    i >>= 8;

  if (n > length) {
    assert (n <= length);
    return 0;
  }
  i = n;
  while (i--) {
    buf[i] = val & 0xff;
    val >>= 8;
  }

  return n;
}

/* mem.c -- CoAP memory handling
 *
 * Copyright (C) 2014--2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */


#include "coap_config.h"
#include "libcoap.h"
#include "mem.h"
#include "coap_debug.h"

#ifdef HAVE_ASSERT_H
#include <assert.h>
#else /* HAVE_ASSERT_H */
#define assert(...)
#endif /* HAVE_ASSERT_H */

#ifdef HAVE_MALLOC
#include <stdlib.h>

void
coap_memory_init(void) {
}

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__((unused))
#else
#define UNUSED_PARAM
#endif /* __GNUC__ */

void *
coap_malloc_type(coap_memory_tag_t type, size_t size) {
  (void)type;
  return malloc(size);
}

void
coap_free_type(coap_memory_tag_t type, void *p) {
  (void)type;
  free(p);
}

#else /* HAVE_MALLOC */

#ifdef WITH_CONTIKI

/**
 * The maximum size of a string on platforms that allocate fixed-size
 * memory blocks.
 */
#ifndef COAP_MAX_STRING_SIZE
#define COAP_MAX_STRING_SIZE 64
#endif /* COAP_MAX_STRING_SIZE */

/**
 * The maximum number of a strings on platforms that allocate
 * fixed-size memory blocks.
 */
#ifndef COAP_MAX_STRINGS
#define COAP_MAX_STRINGS      10
#endif /* COAP_MAX_STRINGS */

struct coap_stringbuf_t {
  char data[COAP_MAX_STRING_SIZE];
};

#include "coap_config.h"
#include "net.h"
#include "pdu.h"
#include "coap_io.h"
#include "resource.h"
#include "coap_session.h"

#define COAP_MAX_PACKET_SIZE (sizeof(coap_packet_t) + COAP_RXBUFFER_SIZE)
#ifndef COAP_MAX_PACKETS
#define COAP_MAX_PACKETS     2
#endif /* COAP_MAX_PACKETS */

typedef union {
  coap_pdu_t packet; /* try to convince the compiler to word-align this structure  */
  char buf[COAP_MAX_PACKET_SIZE];
} coap_packetbuf_t;

MEMB(string_storage, struct coap_stringbuf_t, COAP_MAX_STRINGS);
MEMB(packet_storage, coap_packetbuf_t, COAP_MAX_PACKETS);
MEMB(session_storage, coap_session_t, COAP_MAX_SESSIONS);
MEMB(node_storage, coap_queue_t, COAP_PDU_MAXCNT);
MEMB(pdu_storage, coap_pdu_t, COAP_PDU_MAXCNT);
MEMB(pdu_buf_storage, coap_packetbuf_t, COAP_PDU_MAXCNT);
MEMB(resource_storage, coap_resource_t, COAP_MAX_RESOURCES);
MEMB(attribute_storage, coap_attr_t, COAP_MAX_ATTRIBUTES);

static struct memb *
get_container(coap_memory_tag_t type) {
  switch(type) {
  case COAP_PACKET: return &packet_storage;
  case COAP_NODE:   return &node_storage;
  case COAP_SESSION: return &session_storage;
  case COAP_PDU:     return &pdu_storage;
  case COAP_PDU_BUF: return &pdu_buf_storage;
  case COAP_RESOURCE: return &resource_storage;
  case COAP_RESOURCEATTR: return &attribute_storage;
  default:
    return &string_storage;
  }
}

void
coap_memory_init(void) {
  memb_init(&string_storage);
  memb_init(&packet_storage);
  memb_init(&node_storage);
  memb_init(&session_storage);
  memb_init(&pdu_storage);
  memb_init(&pdu_buf_storage);
  memb_init(&resource_storage);
  memb_init(&attribute_storage);
}

void *
coap_malloc_type(coap_memory_tag_t type, size_t size) {
  struct memb *container =  get_container(type);
  void *ptr;

  assert(container);

  if (size > container->size) {
    coap_log(LOG_WARNING,
             "coap_malloc_type: Requested memory exceeds maximum object "
             "size (type %d, size %d, max %d)\n",
             type, (int)size, container->size);
    return NULL;
  }

  ptr = memb_alloc(container);
  if (!ptr)
    coap_log(LOG_WARNING,
             "coap_malloc_type: Failure (no free blocks) for type %d\n",
             type);
  return ptr;
}

void
coap_free_type(coap_memory_tag_t type, void *object) {
  memb_free(get_container(type), object);
}
#endif /* WITH_CONTIKI */

#endif /* HAVE_MALLOC */
/* net.c -- CoAP network interface
 *
 * Copyright (C) 2010--2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_config.h"

#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#elif HAVE_SYS_UNISTD_H
#include <sys/unistd.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef WITH_LWIP
#include <lwip/pbuf.h>
#include <lwip/udp.h>
#include <lwip/timeouts.h>
#endif

#include "libcoap.h"
#include "utlist.h"
#include "coap_debug.h"
#include "mem.h"
#include "str.h"
#include "async.h"
#include "resource.h"
#include "option.h"
#include "encode.h"
#include "block.h"
#include "net.h"
#include "utlist.h"
#include "coap_mutex.h"

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

      /**
       * The number of bits for the fractional part of ACK_TIMEOUT and
       * ACK_RANDOM_FACTOR. Must be less or equal 8.
       */
#define FRAC_BITS 6

       /**
        * The maximum number of bits for fixed point integers that are used
        * for retransmission time calculation. Currently this must be @c 8.
        */
#define MAX_BITS 8

#if FRAC_BITS > 8
#error FRAC_BITS must be less or equal 8
#endif

        /** creates a Qx.frac from fval in coap_fixed_point_t */
#define Q(frac,fval) ((uint16_t)(((1 << (frac)) * fval.integer_part) + \
                      ((1 << (frac)) * fval.fractional_part + 500)/1000))

/** creates a Qx.FRAC_BITS from session's 'ack_random_factor' */
#define ACK_RANDOM_FACTOR                                        \
  Q(FRAC_BITS, session->ack_random_factor)

/** creates a Qx.FRAC_BITS from session's 'ack_timeout' */
#define ACK_TIMEOUT Q(FRAC_BITS, session->ack_timeout)

#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI)

COAP_STATIC_INLINE coap_queue_t *
coap_malloc_node(void) {
  return (coap_queue_t *)coap_malloc_type(COAP_NODE, sizeof(coap_queue_t));
}

COAP_STATIC_INLINE void
coap_free_node(coap_queue_t *node) {
  coap_free_type(COAP_NODE, node);
}
#endif /* !defined(WITH_LWIP) && !defined(WITH_CONTIKI) */

void coap_free_endpoint(coap_endpoint_t *ep);

#ifdef WITH_LWIP

#include <lwip/memp.h>

static void coap_retransmittimer_execute(void *arg);
static void coap_retransmittimer_restart(coap_context_t *ctx);

COAP_STATIC_INLINE coap_queue_t *
coap_malloc_node() {
  return (coap_queue_t *)memp_malloc(MEMP_COAP_NODE);
}

COAP_STATIC_INLINE void
coap_free_node(coap_queue_t *node) {
  memp_free(MEMP_COAP_NODE, node);
}

#endif /* WITH_LWIP */
#ifdef WITH_CONTIKI
# ifndef DEBUG
#  define DEBUG DEBUG_PRINT
# endif /* DEBUG */

#include "mem.h"
#include "net/ip/uip-debug.h"

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])

void coap_resources_init();

unsigned char initialized = 0;
coap_context_t the_coap_context;

PROCESS(coap_retransmit_process, "message retransmit process");

COAP_STATIC_INLINE coap_queue_t *
coap_malloc_node() {
  return (coap_queue_t *)coap_malloc_type(COAP_NODE, 0);
}

COAP_STATIC_INLINE void
coap_free_node(coap_queue_t *node) {
  coap_free_type(COAP_NODE, node);
}
#endif /* WITH_CONTIKI */

unsigned int
coap_adjust_basetime(coap_context_t *ctx, coap_tick_t now) {
  unsigned int result = 0;
  coap_tick_diff_t delta = now - ctx->sendqueue_basetime;

  if (ctx->sendqueue) {
    /* delta < 0 means that the new time stamp is before the old. */
    if (delta <= 0) {
      ctx->sendqueue->t -= delta;
    } else {
      /* This case is more complex: The time must be advanced forward,
       * thus possibly leading to timed out elements at the queue's
       * start. For every element that has timed out, its relative
       * time is set to zero and the result counter is increased. */

      coap_queue_t *q = ctx->sendqueue;
      coap_tick_t t = 0;
      while (q && (t + q->t < (coap_tick_t)delta)) {
        t += q->t;
        q->t = 0;
        result++;
        q = q->next;
      }

      /* finally adjust the first element that has not expired */
      if (q) {
        q->t = (coap_tick_t)delta - t;
      }
    }
  }

  /* adjust basetime */
  ctx->sendqueue_basetime += delta;

  return result;
}

int
coap_insert_node(coap_queue_t **queue, coap_queue_t *node) {
  coap_queue_t *p, *q;
  if (!queue || !node)
    return 0;

  /* set queue head if empty */
  if (!*queue) {
    *queue = node;
    return 1;
  }

  /* replace queue head if PDU's time is less than head's time */
  q = *queue;
  if (node->t < q->t) {
    node->next = q;
    *queue = node;
    q->t -= node->t;                /* make q->t relative to node->t */
    return 1;
  }

  /* search for right place to insert */
  do {
    node->t -= q->t;                /* make node-> relative to q->t */
    p = q;
    q = q->next;
  } while (q && q->t <= node->t);

  /* insert new item */
  if (q) {
    q->t -= node->t;                /* make q->t relative to node->t */
  }
  node->next = q;
  p->next = node;
  return 1;
}

int
coap_delete_node(coap_queue_t *node) {
  if (!node)
    return 0;

  coap_delete_pdu(node->pdu);
  if ( node->session ) {
    /*
     * Need to remove out of context->sendqueue as added in by coap_wait_ack()
     */
    if (node->session->context->sendqueue) {
      LL_DELETE(node->session->context->sendqueue, node);
    }
    coap_session_release(node->session);
  }
  coap_free_node(node);

  return 1;
}

void
coap_delete_all(coap_queue_t *queue) {
  if (!queue)
    return;

  coap_delete_all(queue->next);
  coap_delete_node(queue);
}

coap_queue_t *
coap_new_node(void) {
  coap_queue_t *node;
  node = coap_malloc_node();

  if (!node) {
#ifndef NDEBUG
    coap_log(LOG_WARNING, "coap_new_node: malloc\n");
#endif
    return NULL;
  }

  memset(node, 0, sizeof(*node));
  return node;
}

coap_queue_t *
coap_peek_next(coap_context_t *context) {
  if (!context || !context->sendqueue)
    return NULL;

  return context->sendqueue;
}

coap_queue_t *
coap_pop_next(coap_context_t *context) {
  coap_queue_t *next;

  if (!context || !context->sendqueue)
    return NULL;

  next = context->sendqueue;
  context->sendqueue = context->sendqueue->next;
  if (context->sendqueue) {
    context->sendqueue->t += next->t;
  }
  next->next = NULL;
  return next;
}

static size_t
coap_get_session_client_psk(
  const coap_session_t *session,
  const uint8_t *hint, size_t hint_len,
  uint8_t *identity, size_t *identity_len, size_t max_identity_len,
  uint8_t *psk, size_t max_psk_len
) {
  (void)hint;
  (void)hint_len;
  if (session->psk_identity && session->psk_identity_len > 0 && session->psk_key && session->psk_key_len > 0) {
    if (session->psk_identity_len <= max_identity_len && session->psk_key_len <= max_psk_len) {
      memcpy(identity, session->psk_identity, session->psk_identity_len);
      memcpy(psk, session->psk_key, session->psk_key_len);
      *identity_len = session->psk_identity_len;
      return session->psk_key_len;
    }
  } else if (session->context && session->context->psk_key && session->context->psk_key_len > 0) {
    if (session->context->psk_key_len <= max_psk_len) {
      *identity_len = 0;
      memcpy(psk, session->context->psk_key, session->context->psk_key_len);
      return session->context->psk_key_len;
    }
  }
  *identity_len = 0;
  return 0;
}

static size_t
coap_get_context_server_psk(
  const coap_session_t *session,
  const uint8_t *identity, size_t identity_len,
  uint8_t *psk, size_t max_psk_len
) {
  (void)identity;
  (void)identity_len;
  const coap_context_t *ctx = session->context;
  if (ctx && ctx->psk_key && ctx->psk_key_len > 0 && ctx->psk_key_len <= max_psk_len) {
    memcpy(psk, ctx->psk_key, ctx->psk_key_len);
    return ctx->psk_key_len;
  }
  return 0;
}

static size_t
coap_get_context_server_hint(
  const coap_session_t *session,
  uint8_t *hint, size_t max_hint_len
) {
  const coap_context_t *ctx = session->context;
  if (ctx && ctx->psk_hint && ctx->psk_hint_len > 0 && ctx->psk_hint_len <= max_hint_len) {
    memcpy(hint, ctx->psk_hint, ctx->psk_hint_len);
    return ctx->psk_hint_len;
  }
  return 0;
}

int coap_context_set_psk(coap_context_t *ctx,
  const char *hint,
  const uint8_t *key, size_t key_len
) {

  if (ctx->psk_hint)
    coap_free(ctx->psk_hint);
  ctx->psk_hint = NULL;
  ctx->psk_hint_len = 0;

  if (hint) {
    size_t hint_len = strlen(hint);
    ctx->psk_hint = (uint8_t*)coap_malloc(hint_len);
    if (ctx->psk_hint) {
      memcpy(ctx->psk_hint, hint, hint_len);
      ctx->psk_hint_len = hint_len;
    } else {
      coap_log(LOG_ERR, "No memory to store PSK hint\n");
      return 0;
    }
  }

  if (ctx->psk_key)
    coap_free(ctx->psk_key);
  ctx->psk_key = NULL;
  ctx->psk_key_len = 0;

  if (key && key_len > 0) {
    ctx->psk_key = (uint8_t *)coap_malloc(key_len);
    if (ctx->psk_key) {
      memcpy(ctx->psk_key, key, key_len);
      ctx->psk_key_len = key_len;
    } else {
      coap_log(LOG_ERR, "No memory to store PSK key\n");
      return 0;
    }
  }
  if (coap_dtls_is_supported()) {
    return coap_dtls_context_set_psk(ctx, hint, COAP_DTLS_ROLE_SERVER);
  }
  return 0;
}

int coap_context_set_pki(coap_context_t *ctx,
  coap_dtls_pki_t* setup_data
) {
  if (!setup_data)
    return 0;
  if (setup_data->version != COAP_DTLS_PKI_SETUP_VERSION) {
    coap_log(LOG_ERR, "coap_context_set_pki: Wrong version of setup_data\n");
    return 0;
  }
  if (coap_dtls_is_supported()) {
    return coap_dtls_context_set_pki(ctx, setup_data, COAP_DTLS_ROLE_SERVER);
  }
  return 0;
}

int coap_context_set_pki_root_cas(coap_context_t *ctx,
  const char *ca_file,
  const char *ca_dir
) {
  if (coap_dtls_is_supported()) {
    return coap_dtls_context_set_pki_root_cas(ctx, ca_file, ca_dir);
  }
  return 0;
}

void coap_context_set_keepalive(coap_context_t *context, unsigned int seconds) {
  context->ping_timeout = seconds;
}

coap_context_t *
coap_new_context(
  const coap_address_t *listen_addr) {
  coap_context_t *c;

#ifdef WITH_CONTIKI
  if (initialized)
    return NULL;
#endif /* WITH_CONTIKI */

  coap_startup();

#ifndef WITH_CONTIKI
  c = coap_malloc_type(COAP_CONTEXT, sizeof(coap_context_t));
#endif /* not WITH_CONTIKI */

#ifndef WITH_CONTIKI
  if (!c) {
#ifndef NDEBUG
    coap_log(LOG_EMERG, "coap_init: malloc:\n");
#endif
    return NULL;
  }
#endif /* not WITH_CONTIKI */
#ifdef WITH_CONTIKI
  coap_resources_init();
  coap_memory_init();

  c = &the_coap_context;
  initialized = 1;
#endif /* WITH_CONTIKI */

  memset(c, 0, sizeof(coap_context_t));

  if (coap_dtls_is_supported()) {
    c->dtls_context = coap_dtls_new_context(c);
    if (!c->dtls_context) {
      coap_log(LOG_EMERG, "coap_init: no DTLS context available\n");
      coap_free_context(c);
      return NULL;
    }
  }

  /* set default CSM timeout */
  c->csm_timeout = 30;

  /* initialize message id */
  prng((unsigned char *)&c->message_id, sizeof(uint16_t));

  if (listen_addr) {
    coap_endpoint_t *endpoint = coap_new_endpoint(c, listen_addr, COAP_PROTO_UDP);
    if (endpoint == NULL) {
      goto onerror;
    }
  }

#if !defined(WITH_LWIP)
  c->network_send = coap_network_send;
  c->network_read = coap_network_read;
#endif

  c->get_client_psk = coap_get_session_client_psk;
  c->get_server_psk = coap_get_context_server_psk;
  c->get_server_hint = coap_get_context_server_hint;

#ifdef WITH_CONTIKI
  process_start(&coap_retransmit_process, (char *)c);

  PROCESS_CONTEXT_BEGIN(&coap_retransmit_process);
#ifndef WITHOUT_OBSERVE
  etimer_set(&c->notify_timer, COAP_RESOURCE_CHECK_TIME * COAP_TICKS_PER_SECOND);
#endif /* WITHOUT_OBSERVE */
  /* the retransmit timer must be initialized to some large value */
  etimer_set(&the_coap_context.retransmit_timer, 0xFFFF);
  PROCESS_CONTEXT_END(&coap_retransmit_process);
#endif /* WITH_CONTIKI */

  return c;

onerror:
  coap_free_type(COAP_CONTEXT, c);
  return NULL;
}

void
coap_set_app_data(coap_context_t *ctx, void *app_data) {
  assert(ctx);
  ctx->app = app_data;
}

void *
coap_get_app_data(const coap_context_t *ctx) {
  assert(ctx);
  return ctx->app;
}

void
coap_free_context(coap_context_t *context) {
  coap_endpoint_t *ep, *tmp;
  coap_session_t *sp, *stmp;

  if (!context)
    return;

  coap_delete_all(context->sendqueue);

#ifdef WITH_LWIP
  context->sendqueue = NULL;
  coap_retransmittimer_restart(context);
#endif

  coap_delete_all_resources(context);

  LL_FOREACH_SAFE(context->endpoint, ep, tmp) {
    coap_free_endpoint(ep);
  }

  LL_FOREACH_SAFE(context->sessions, sp, stmp) {
    coap_session_release(sp);
  }

  if (context->dtls_context)
    coap_dtls_free_context(context->dtls_context);

  if (context->psk_hint)
    coap_free(context->psk_hint);

  if (context->psk_key)
    coap_free(context->psk_key);

#ifndef WITH_CONTIKI
  coap_free_type(COAP_CONTEXT, context);
#endif/* not WITH_CONTIKI */
#ifdef WITH_CONTIKI
  memset(&the_coap_context, 0, sizeof(coap_context_t));
  initialized = 0;
#endif /* WITH_CONTIKI */
}

int
coap_option_check_critical(coap_context_t *ctx,
  coap_pdu_t *pdu,
  coap_opt_filter_t unknown) {

  coap_opt_iterator_t opt_iter;
  int ok = 1;

  coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);

  while (coap_option_next(&opt_iter)) {

    /* The following condition makes use of the fact that
     * coap_option_getb() returns -1 if type exceeds the bit-vector
     * filter. As the vector is supposed to be large enough to hold
     * the largest known option, we know that everything beyond is
     * bad.
     */
    if (opt_iter.type & 0x01) {
      /* first check the built-in critical options */
      switch (opt_iter.type) {
      case COAP_OPTION_IF_MATCH:
      case COAP_OPTION_URI_HOST:
      case COAP_OPTION_IF_NONE_MATCH:
      case COAP_OPTION_URI_PORT:
      case COAP_OPTION_URI_PATH:
      case COAP_OPTION_URI_QUERY:
      case COAP_OPTION_ACCEPT:
      case COAP_OPTION_PROXY_URI:
      case COAP_OPTION_PROXY_SCHEME:
      case COAP_OPTION_BLOCK2:
      case COAP_OPTION_BLOCK1:
        break;
      default:
        if (coap_option_filter_get(ctx->known_options, opt_iter.type) <= 0) {
          coap_log(LOG_DEBUG, "unknown critical option %d\n", opt_iter.type);
          ok = 0;

          /* When opt_iter.type is beyond our known option range,
           * coap_option_filter_set() will return -1 and we are safe to leave
           * this loop. */
          if (coap_option_filter_set(unknown, opt_iter.type) == -1) {
            break;
          }
        }
      }
    }
  }

  return ok;
}

coap_tid_t
coap_send_ack(coap_session_t *session, coap_pdu_t *request) {
  coap_pdu_t *response;
  coap_tid_t result = COAP_INVALID_TID;

  if (request && request->type == COAP_MESSAGE_CON &&
    COAP_PROTO_NOT_RELIABLE(session->proto)) {
    response = coap_pdu_init(COAP_MESSAGE_ACK, 0, request->tid, 0);
    if (response)
      result = coap_send(session, response);
  }
  return result;
}

ssize_t
coap_session_send_pdu(coap_session_t *session, coap_pdu_t *pdu) {
  ssize_t bytes_written = -1;
  assert(pdu->hdr_size > 0);
  switch(session->proto) {
    case COAP_PROTO_UDP:
      bytes_written = coap_session_send(session, pdu->token - pdu->hdr_size,
                                        pdu->used_size + pdu->hdr_size);
      break;
    case COAP_PROTO_DTLS:
      bytes_written = coap_dtls_send(session, pdu->token - pdu->hdr_size,
                                     pdu->used_size + pdu->hdr_size);
      break;
    case COAP_PROTO_TCP:
      bytes_written = coap_session_write(session, pdu->token - pdu->hdr_size,
                                         pdu->used_size + pdu->hdr_size);
      break;
    case COAP_PROTO_TLS:
      bytes_written = coap_tls_write(session, pdu->token - pdu->hdr_size,
                                     pdu->used_size + pdu->hdr_size);
      break;
    default:
      break;
  }
  coap_show_pdu(LOG_DEBUG, pdu);
  return bytes_written;
}

static ssize_t
coap_send_pdu(coap_session_t *session, coap_pdu_t *pdu, coap_queue_t *node) {
  ssize_t bytes_written;

#ifdef WITH_LWIP

  coap_socket_t *sock = &session->sock;
  if (sock->flags == COAP_SOCKET_EMPTY) {
    assert(session->endpoint != NULL);
    sock = &session->endpoint->sock;
  }
  if (pdu->type == COAP_MESSAGE_CON && COAP_PROTO_NOT_RELIABLE(session->proto))
    session->con_active++;

  bytes_written = coap_socket_send_pdu(sock, session, pdu);
  if (LOG_DEBUG <= coap_get_log_level()) {
    coap_show_pdu(LOG_DEBUG, pdu);
  }
  coap_ticks(&session->last_rx_tx);

#else

  /* Do not send error responses for requests that were received via
  * IP multicast.
  * FIXME: If No-Response option indicates interest, these responses
  *        must not be dropped. */
  if (coap_is_mcast(&session->local_addr) &&
    COAP_RESPONSE_CLASS(pdu->code) > 2) {
    return COAP_DROPPED_RESPONSE;
  }

  if (session->state == COAP_SESSION_STATE_NONE) {
    if (session->proto == COAP_PROTO_DTLS && !session->tls) {
      session->tls = coap_dtls_new_client_session(session);
      if (session->tls) {
        session->state = COAP_SESSION_STATE_HANDSHAKE;
        return coap_session_delay_pdu(session, pdu, node);
      }
      coap_handle_event(session->context, COAP_EVENT_DTLS_ERROR, session);
      return -1;
    } else if(COAP_PROTO_RELIABLE(session->proto)) {
      if (!coap_socket_connect_tcp1(
        &session->sock, &session->local_if, &session->remote_addr,
        session->proto == COAP_PROTO_TLS ? COAPS_DEFAULT_PORT : COAP_DEFAULT_PORT,
        &session->local_addr, &session->remote_addr
      )) {
        coap_handle_event(session->context, COAP_EVENT_TCP_FAILED, session);
        return -1;
      }
      session->last_ping = 0;
      session->last_pong = 0;
      session->csm_tx = 0;
      coap_ticks( &session->last_rx_tx );
      if ((session->sock.flags & COAP_SOCKET_WANT_CONNECT) != 0) {
        session->state = COAP_SESSION_STATE_CONNECTING;
        return coap_session_delay_pdu(session, pdu, node);
      }
      coap_handle_event(session->context, COAP_EVENT_TCP_CONNECTED, session);
      if (session->proto == COAP_PROTO_TLS) {
        int connected = 0;
        session->state = COAP_SESSION_STATE_HANDSHAKE;
        session->tls = coap_tls_new_client_session(session, &connected);
        if (session->tls) {
          if (connected) {
            coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
            coap_session_send_csm(session);
          }
          return coap_session_delay_pdu(session, pdu, node);
        }
        coap_handle_event(session->context, COAP_EVENT_DTLS_ERROR, session);
        coap_session_disconnected(session, COAP_NACK_TLS_FAILED);
        return -1;
      } else {
        coap_session_send_csm(session);
      }
    } else {
      return -1;
    }
  }

  if (session->state != COAP_SESSION_STATE_ESTABLISHED ||
      (pdu->type == COAP_MESSAGE_CON && session->con_active >= COAP_DEFAULT_NSTART)) {
    return coap_session_delay_pdu(session, pdu, node);
  }

  if ((session->sock.flags & COAP_SOCKET_NOT_EMPTY) &&
    (session->sock.flags & COAP_SOCKET_WANT_WRITE))
    return coap_session_delay_pdu(session, pdu, node);

  if (pdu->type == COAP_MESSAGE_CON && COAP_PROTO_NOT_RELIABLE(session->proto))
    session->con_active++;

  bytes_written = coap_session_send_pdu(session, pdu);

#endif /* WITH_LWIP */

  return bytes_written;
}

coap_tid_t
coap_send_error(coap_session_t *session,
  coap_pdu_t *request,
  unsigned char code,
  coap_opt_filter_t opts) {
  coap_pdu_t *response;
  coap_tid_t result = COAP_INVALID_TID;

  assert(request);
  assert(session);

  response = coap_new_error_response(request, code, opts);
  if (response)
    result = coap_send(session, response);

  return result;
}

coap_tid_t
coap_send_message_type(coap_session_t *session, coap_pdu_t *request, unsigned char type) {
  coap_pdu_t *response;
  coap_tid_t result = COAP_INVALID_TID;

  if (request) {
    response = coap_pdu_init(type, 0, request->tid, 0);
    if (response)
      result = coap_send(session, response);
  }
  return result;
}

/**
 * Calculates the initial timeout based on the session CoAP transmission
 * parameters 'ack_timeout', 'ack_random_factor', and COAP_TICKS_PER_SECOND.
 * The calculation requires 'ack_timeout' and 'ack_random_factor' to be in
 * Qx.FRAC_BITS fixed point notation, whereas the passed parameter @p r
 * is interpreted as the fractional part of a Q0.MAX_BITS random value.
 *
 * @param session session timeout is associated with
 * @param r  random value as fractional part of a Q0.MAX_BITS fixed point
 *           value
 * @return   COAP_TICKS_PER_SECOND * 'ack_timeout' *
 *           (1 + ('ack_random_factor' - 1) * r)
 */
unsigned int
coap_calc_timeout(coap_session_t *session, unsigned char r) {
  unsigned int result;

  /* The integer 1.0 as a Qx.FRAC_BITS */
#define FP1 Q(FRAC_BITS, ((coap_fixed_point_t){1,0}))

  /* rounds val up and right shifts by frac positions */
#define SHR_FP(val,frac) (((val) + (1 << ((frac) - 1))) >> (frac))

  /* Inner term: multiply ACK_RANDOM_FACTOR by Q0.MAX_BITS[r] and
   * make the result a rounded Qx.FRAC_BITS */
  result = SHR_FP((ACK_RANDOM_FACTOR - FP1) * r, MAX_BITS);

  /* Add 1 to the inner term and multiply with ACK_TIMEOUT, then
   * make the result a rounded Qx.FRAC_BITS */
  result = SHR_FP(((result + FP1) * ACK_TIMEOUT), FRAC_BITS);

  /* Multiply with COAP_TICKS_PER_SECOND to yield system ticks
   * (yields a Qx.FRAC_BITS) and shift to get an integer */
  return SHR_FP((COAP_TICKS_PER_SECOND * result), FRAC_BITS);

#undef FP1
#undef SHR_FP
}

coap_tid_t
coap_wait_ack(coap_context_t *context, coap_session_t *session,
              coap_queue_t *node) {
  coap_tick_t now;

  node->session = coap_session_reference(session);

  /* Set timer for pdu retransmission. If this is the first element in
  * the retransmission queue, the base time is set to the current
  * time and the retransmission time is node->timeout. If there is
  * already an entry in the sendqueue, we must check if this node is
  * to be retransmitted earlier. Therefore, node->timeout is first
  * normalized to the base time and then inserted into the queue with
  * an adjusted relative time.
  */
  coap_ticks(&now);
  if (context->sendqueue == NULL) {
    node->t = node->timeout;
    context->sendqueue_basetime = now;
  } else {
    /* make node->t relative to context->sendqueue_basetime */
    node->t = (now - context->sendqueue_basetime) + node->timeout;
  }

  coap_insert_node(&context->sendqueue, node);

#ifdef WITH_LWIP
  if (node == context->sendqueue) /* don't bother with timer stuff if there are earlier retransmits */
    coap_retransmittimer_restart(context);
#endif

#ifdef WITH_CONTIKI
  {                            /* (re-)initialize retransmission timer */
    coap_queue_t *nextpdu;

    nextpdu = coap_peek_next(context);
    assert(nextpdu);                /* we have just inserted a node */

                                /* must set timer within the context of the retransmit process */
    PROCESS_CONTEXT_BEGIN(&coap_retransmit_process);
    etimer_set(&context->retransmit_timer, nextpdu->t);
    PROCESS_CONTEXT_END(&coap_retransmit_process);
  }
#endif /* WITH_CONTIKI */

  coap_log(LOG_DEBUG, "** %s: tid=%d added to retransmit queue (%ums)\n",
    coap_session_str(node->session), node->id,
    (unsigned)(node->t * 1000 / COAP_TICKS_PER_SECOND));

  return node->id;
}

coap_tid_t
coap_send(coap_session_t *session, coap_pdu_t *pdu) {
  uint8_t r;
  ssize_t bytes_written;

  if (!coap_pdu_encode_header(pdu, session->proto)) {
    goto error;
  }

  bytes_written = coap_send_pdu( session, pdu, NULL );

  if (bytes_written == COAP_PDU_DELAYED) {
    /* do not free pdu as it is stored with session for later use */
    return pdu->tid;
  }

  if (bytes_written < 0) {
    coap_delete_pdu(pdu);
    return (coap_tid_t)bytes_written;
  }

  if (COAP_PROTO_RELIABLE(session->proto) &&
    (size_t)bytes_written < pdu->used_size + pdu->hdr_size) {
    if (coap_session_delay_pdu(session, pdu, NULL) == COAP_PDU_DELAYED) {
      session->partial_write = (size_t)bytes_written;
      /* do not free pdu as it is stored with session for later use */
      return pdu->tid;
    } else {
      goto error;
    }
  }

  if (pdu->type != COAP_MESSAGE_CON || COAP_PROTO_RELIABLE(session->proto)) {
    coap_tid_t id = pdu->tid;
    coap_delete_pdu(pdu);
    return id;
  }

  coap_queue_t *node = coap_new_node();
  if (!node) {
    coap_log(LOG_DEBUG, "coap_wait_ack: insufficient memory\n");
    goto error;
  }

  node->id = pdu->tid;
  node->pdu = pdu;
  prng(&r, sizeof(r));
  /* add timeout in range [ACK_TIMEOUT...ACK_TIMEOUT * ACK_RANDOM_FACTOR] */
  node->timeout = coap_calc_timeout(session, r);
  return coap_wait_ack(session->context, session, node);
 error:
  coap_delete_pdu(pdu);
  return COAP_INVALID_TID;
}

coap_tid_t
coap_retransmit(coap_context_t *context, coap_queue_t *node) {
  if (!context || !node)
    return COAP_INVALID_TID;

  /* re-initialize timeout when maximum number of retransmissions are not reached yet */
  if (node->retransmit_cnt < node->session->max_retransmit) {
    ssize_t bytes_written;
    coap_tick_t now;

    node->retransmit_cnt++;
    coap_ticks(&now);
    if (context->sendqueue == NULL) {
      node->t = node->timeout << node->retransmit_cnt;
      context->sendqueue_basetime = now;
    } else {
      /* make node->t relative to context->sendqueue_basetime */
      node->t = (now - context->sendqueue_basetime) + (node->timeout << node->retransmit_cnt);
    }
    coap_insert_node(&context->sendqueue, node);
#ifdef WITH_LWIP
    if (node == context->sendqueue) /* don't bother with timer stuff if there are earlier retransmits */
      coap_retransmittimer_restart(context);
#endif

    coap_log(LOG_DEBUG, "** %s: tid=%d: retransmission #%d\n",
             coap_session_str(node->session), node->id, node->retransmit_cnt);

    if (node->session->con_active)
      node->session->con_active--;
    bytes_written = coap_send_pdu(node->session, node->pdu, node);

    if (bytes_written == COAP_PDU_DELAYED) {
      /* PDU was not retransmitted immediately because a new handshake is
         in progress. node was moved to the send queue of the session. */
      return node->id;
    }

    if (bytes_written < 0)
      return (int)bytes_written;

    return node->id;
  }

  /* no more retransmissions, remove node from system */

#ifndef WITH_CONTIKI
  coap_log(LOG_DEBUG, "** %s: tid=%d: give up after %d attempts\n",
           coap_session_str(node->session), node->id, node->retransmit_cnt);
#endif

#ifndef WITHOUT_OBSERVE
  /* Check if subscriptions exist that should be canceled after
     COAP_MAX_NOTIFY_FAILURES */
  if (node->pdu->code >= 64) {
    coap_binary_t token = { 0, NULL };

    token.length = node->pdu->token_length;
    token.s = node->pdu->token;

    coap_handle_failed_notify(context, node->session, &token);
  }
#endif /* WITHOUT_OBSERVE */
  if (node->session->con_active) {
    node->session->con_active--;
    if (node->session->state == COAP_SESSION_STATE_ESTABLISHED) {
      /*
       * As there may be another CON in a different queue entry on the same
       * session that needs to be immediately released,
       * coap_session_connected() is called.
       * However, there is the possibility coap_wait_ack() may be called for
       * this node (queue) and re-added to context->sendqueue.
       * coap_delete_node(node) called shortly will handle this and remove it.
       */
      coap_session_connected(node->session);
    }
 }

  /* And finally delete the node */
  if (node->pdu->type == COAP_MESSAGE_CON && context->nack_handler)
    context->nack_handler(context, node->session, node->pdu, COAP_NACK_TOO_MANY_RETRIES, node->id);
  coap_delete_node(node);
  return COAP_INVALID_TID;
}

#ifdef WITH_LWIP
/* WITH_LWIP, this is handled by coap_recv in a different way */
void
coap_read(coap_context_t *ctx, coap_tick_t now) {
  return;
}
#else /* WITH_LWIP */

static int
coap_handle_dgram_for_proto(coap_context_t *ctx, coap_session_t *session, coap_packet_t *packet) {
  uint8_t *data;
  size_t data_len;
  int result = -1;

  coap_packet_get_memmapped(packet, &data, &data_len);

  if (session->proto == COAP_PROTO_DTLS) {
    if (session->type == COAP_SESSION_TYPE_HELLO)
      result = coap_dtls_hello(session, data, data_len);
    else if (session->tls)
      result = coap_dtls_receive(session, data, data_len);
  } else if (session->proto == COAP_PROTO_UDP) {
    result = coap_handle_dgram(ctx, session, data, data_len);
  }
  return result;
}

static void
coap_connect_session(coap_context_t *ctx, coap_session_t *session, coap_tick_t now) {
  (void)ctx;
  if (coap_socket_connect_tcp2(&session->sock, &session->local_addr, &session->remote_addr)) {
    session->last_rx_tx = now;
    coap_handle_event(session->context, COAP_EVENT_TCP_CONNECTED, session);
    if (session->proto == COAP_PROTO_TCP) {
      coap_session_send_csm(session);
    } else if (session->proto == COAP_PROTO_TLS) {
      int connected = 0;
      session->state = COAP_SESSION_STATE_HANDSHAKE;
      session->tls = coap_tls_new_client_session(session, &connected);
      if (session->tls) {
        if (connected) {
          coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
          coap_session_send_csm(session);
        }
      } else {
        coap_handle_event(session->context, COAP_EVENT_DTLS_ERROR, session);
        coap_session_disconnected(session, COAP_NACK_TLS_FAILED);
      }
    }
  } else {
    coap_handle_event(session->context, COAP_EVENT_TCP_FAILED, session);
    coap_session_disconnected(session, COAP_NACK_NOT_DELIVERABLE);
  }
}

static void
coap_write_session(coap_context_t *ctx, coap_session_t *session, coap_tick_t now) {
  (void)ctx;
  assert(session->sock.flags & COAP_SOCKET_CONNECTED);

  while (session->delayqueue) {
    ssize_t bytes_written;
    coap_queue_t *q = session->delayqueue;
    coap_log(LOG_DEBUG, "** %s: tid=%d: transmitted after delay\n",
             coap_session_str(session), (int)q->pdu->tid);
    assert(session->partial_write < q->pdu->used_size + q->pdu->hdr_size);
    switch (session->proto) {
      case COAP_PROTO_TCP:
        bytes_written = coap_session_write(
          session,
          q->pdu->token - q->pdu->hdr_size - session->partial_write,
          q->pdu->used_size + q->pdu->hdr_size - session->partial_write
        );
        break;
      case COAP_PROTO_TLS:
        bytes_written = coap_tls_write(
          session,
          q->pdu->token - q->pdu->hdr_size - session->partial_write,
          q->pdu->used_size + q->pdu->hdr_size - session->partial_write
        );
        break;
      default:
        bytes_written = -1;
        break;
    }
    if (bytes_written > 0)
      session->last_rx_tx = now;
    if (bytes_written <= 0 || (size_t)bytes_written < q->pdu->used_size + q->pdu->hdr_size - session->partial_write) {
      if (bytes_written > 0)
        session->partial_write += (size_t)bytes_written;
      break;
    }
    session->delayqueue = q->next;
    session->partial_write = 0;
    coap_delete_node(q);
  }
}

static void
coap_read_session(coap_context_t *ctx, coap_session_t *session, coap_tick_t now) {
#if COAP_CONSTRAINED_STACK
  static coap_mutex_t s_static_mutex = COAP_MUTEX_INITIALIZER;
  static coap_packet_t s_packet;
#else /* ! COAP_CONSTRAINED_STACK */
  coap_packet_t s_packet;
#endif /* ! COAP_CONSTRAINED_STACK */
  coap_packet_t *packet = &s_packet;

#if COAP_CONSTRAINED_STACK
  coap_mutex_lock(&s_static_mutex);
#endif /* COAP_CONSTRAINED_STACK */

  assert(session->sock.flags & (COAP_SOCKET_CONNECTED | COAP_SOCKET_MULTICAST));

  if (COAP_PROTO_NOT_RELIABLE(session->proto)) {
    ssize_t bytes_read;
    coap_address_copy(&packet->src, &session->remote_addr);
    coap_address_copy(&packet->dst, &session->local_addr);
    bytes_read = ctx->network_read(&session->sock, packet);

    if (bytes_read < 0) {
      if (bytes_read == -2)
        coap_session_disconnected(session, COAP_NACK_RST);
      else
        coap_log(LOG_WARNING, "*  %s: read error\n",
                 coap_session_str(session));
    } else if (bytes_read > 0) {
      coap_log(LOG_DEBUG, "*  %s: received %zd bytes\n",
               coap_session_str(session), bytes_read);
      session->last_rx_tx = now;
      coap_packet_set_addr(packet, &session->remote_addr, &session->local_addr);
      coap_handle_dgram_for_proto(ctx, session, packet);
    }
  } else {
    ssize_t bytes_read = 0;
    const uint8_t *p;
    int retry;
    /* adjust for LWIP */
    uint8_t *buf = packet->payload;
    size_t buf_len = sizeof(packet->payload);

    do {
      if (session->proto == COAP_PROTO_TCP)
        bytes_read = coap_socket_read(&session->sock, buf, buf_len);
      else if (session->proto == COAP_PROTO_TLS)
        bytes_read = coap_tls_read(session, buf, buf_len);
      if (bytes_read > 0) {
        coap_log(LOG_DEBUG, "*  %s: received %zd bytes\n",
                 coap_session_str(session), bytes_read);
        session->last_rx_tx = now;
      }
      p = buf;
      retry = bytes_read == (ssize_t)buf_len;
      while (bytes_read > 0) {
        if (session->partial_pdu) {
          size_t len = session->partial_pdu->used_size
                     + session->partial_pdu->hdr_size
                     - session->partial_read;
          size_t n = min(len, (size_t)bytes_read);
          memcpy(session->partial_pdu->token - session->partial_pdu->hdr_size
                 + session->partial_read, p, n);
          p += n;
          bytes_read -= n;
          if (n == len) {
            if (coap_pdu_parse_header(session->partial_pdu, session->proto)
              && coap_pdu_parse_opt(session->partial_pdu)) {
              coap_dispatch(ctx, session, session->partial_pdu);
            }
            coap_delete_pdu(session->partial_pdu);
            session->partial_pdu = NULL;
            session->partial_read = 0;
          } else {
            session->partial_read += n;
          }
        } else if (session->partial_read > 0) {
          size_t hdr_size = coap_pdu_parse_header_size(session->proto,
            session->read_header);
          size_t len = hdr_size - session->partial_read;
          size_t n = min(len, (size_t)bytes_read);
          memcpy(session->read_header + session->partial_read, p, n);
          p += n;
          bytes_read -= n;
          if (n == len) {
            size_t size = coap_pdu_parse_size(session->proto, session->read_header,
              hdr_size);
            session->partial_pdu = coap_pdu_init(0, 0, 0, size);
            if (session->partial_pdu == NULL) {
              bytes_read = -1;
              break;
            }
            if (session->partial_pdu->alloc_size < size && !coap_pdu_resize(session->partial_pdu, size)) {
              bytes_read = -1;
              break;
            }
            session->partial_pdu->hdr_size = (uint8_t)hdr_size;
            session->partial_pdu->used_size = size;
            memcpy(session->partial_pdu->token - hdr_size, session->read_header, hdr_size);
            session->partial_read = hdr_size;
            if (size == 0) {
              if (coap_pdu_parse_header(session->partial_pdu, session->proto)) {
                coap_dispatch(ctx, session, session->partial_pdu);
              }
              coap_delete_pdu(session->partial_pdu);
              session->partial_pdu = NULL;
              session->partial_read = 0;
            }
          } else {
            session->partial_read += bytes_read;
          }
        } else {
          session->read_header[0] = *p++;
          bytes_read -= 1;
          if (!coap_pdu_parse_header_size(session->proto,
            session->read_header)) {
            bytes_read = -1;
            break;
          }
          session->partial_read = 1;
        }
      }
    } while (bytes_read == 0 && retry);
    if (bytes_read < 0)
      coap_session_disconnected(session, COAP_NACK_NOT_DELIVERABLE);
  }
#if COAP_CONSTRAINED_STACK
  coap_mutex_unlock(&s_static_mutex);
#endif /* COAP_CONSTRAINED_STACK */
}

static int
coap_read_endpoint(coap_context_t *ctx, coap_endpoint_t *endpoint, coap_tick_t now) {
  ssize_t bytes_read = -1;
  int result = -1;                /* the value to be returned */
#if COAP_CONSTRAINED_STACK
  static coap_mutex_t e_static_mutex = COAP_MUTEX_INITIALIZER;
  static coap_packet_t e_packet;
#else /* ! COAP_CONSTRAINED_STACK */
  coap_packet_t e_packet;
#endif /* ! COAP_CONSTRAINED_STACK */
  coap_packet_t *packet = &e_packet;

  assert(COAP_PROTO_NOT_RELIABLE(endpoint->proto));
  assert(endpoint->sock.flags & COAP_SOCKET_BOUND);

#if COAP_CONSTRAINED_STACK
  coap_mutex_lock(&e_static_mutex);
#endif /* COAP_CONSTRAINED_STACK */

  coap_address_init(&packet->src);
  coap_address_copy(&packet->dst, &endpoint->bind_addr);
  bytes_read = ctx->network_read(&endpoint->sock, packet);

  if (bytes_read < 0) {
    coap_log(LOG_WARNING, "*  %s: read failed\n", coap_endpoint_str(endpoint));
  } else if (bytes_read > 0) {
    coap_session_t *session = coap_endpoint_get_session(endpoint, packet, now);
    if (session) {
      coap_log(LOG_DEBUG, "*  %s: received %zd bytes\n",
               coap_session_str(session), bytes_read);
      result = coap_handle_dgram_for_proto(ctx, session, packet);
      if (endpoint->proto == COAP_PROTO_DTLS && session->type == COAP_SESSION_TYPE_HELLO && result == 1)
        coap_session_new_dtls_session(session, now);
    }
  }
#if COAP_CONSTRAINED_STACK
  coap_mutex_unlock(&e_static_mutex);
#endif /* COAP_CONSTRAINED_STACK */
  return result;
}

static int
coap_write_endpoint(coap_context_t *ctx, coap_endpoint_t *endpoint, coap_tick_t now) {
  (void)ctx;
  (void)endpoint;
  (void)now;
  return 0;
}

static int
coap_accept_endpoint(coap_context_t *ctx, coap_endpoint_t *endpoint,
  coap_tick_t now) {
  coap_session_t *session = coap_new_server_session(ctx, endpoint);
  if (session)
    session->last_rx_tx = now;
  return session != NULL;
}

void
coap_read(coap_context_t *ctx, coap_tick_t now) {
  coap_endpoint_t *ep, *tmp;
  coap_session_t *s, *tmp_s;

  LL_FOREACH_SAFE(ctx->endpoint, ep, tmp) {
    if ((ep->sock.flags & COAP_SOCKET_CAN_READ) != 0)
      coap_read_endpoint(ctx, ep, now);
    if ((ep->sock.flags & COAP_SOCKET_CAN_WRITE) != 0)
      coap_write_endpoint(ctx, ep, now);
    if ((ep->sock.flags & COAP_SOCKET_CAN_ACCEPT) != 0)
      coap_accept_endpoint(ctx, ep, now);
    LL_FOREACH_SAFE(ep->sessions, s, tmp_s) {
      if ((s->sock.flags & COAP_SOCKET_CAN_READ) != 0) {
        /* Make sure the session object is not deleted in one of the callbacks  */
        coap_session_reference(s);
        coap_read_session(ctx, s, now);
        coap_session_release(s);
      }
      if ((s->sock.flags & COAP_SOCKET_CAN_WRITE) != 0) {
        /* Make sure the session object is not deleted in one of the callbacks  */
        coap_session_reference(s);
        coap_write_session(ctx, s, now);
        coap_session_release(s);
      }
    }
  }

  LL_FOREACH_SAFE(ctx->sessions, s, tmp_s) {
    if ((s->sock.flags & COAP_SOCKET_CAN_CONNECT) != 0) {
      /* Make sure the session object is not deleted in one of the callbacks  */
      coap_session_reference(s);
      coap_connect_session(ctx, s, now);
      coap_session_release( s );
    }
    if ((s->sock.flags & COAP_SOCKET_CAN_READ) != 0) {
      /* Make sure the session object is not deleted in one of the callbacks  */
      coap_session_reference(s);
      coap_read_session(ctx, s, now);
      coap_session_release(s);
    }
    if ((s->sock.flags & COAP_SOCKET_CAN_WRITE) != 0) {
      /* Make sure the session object is not deleted in one of the callbacks  */
      coap_session_reference(s);
      coap_write_session(ctx, s, now);
      coap_session_release( s );
    }
  }
}

int
coap_handle_dgram(coap_context_t *ctx, coap_session_t *session,
  uint8_t *msg, size_t msg_len) {

  coap_pdu_t *pdu = NULL;

  assert(COAP_PROTO_NOT_RELIABLE(session->proto));

  pdu = coap_pdu_init(0, 0, 0, msg_len - 4);
  if (!pdu)
    goto error;

  if (!coap_pdu_parse(session->proto, msg, msg_len, pdu)) {
    coap_log(LOG_WARNING, "discard malformed PDU\n");
    goto error;
  }

  coap_dispatch(ctx, session, pdu);
  coap_delete_pdu(pdu);
  return 0;

error:
  /* FIXME: send back RST? */
  coap_delete_pdu(pdu);
  return -1;
}
#endif /* not WITH_LWIP */

int
coap_remove_from_queue(coap_queue_t **queue, coap_session_t *session, coap_tid_t id, coap_queue_t **node) {
  coap_queue_t *p, *q;

  if (!queue || !*queue)
    return 0;

  /* replace queue head if PDU's time is less than head's time */

  if (session == (*queue)->session && id == (*queue)->id) { /* found transaction */
    *node = *queue;
    *queue = (*queue)->next;
    if (*queue) {          /* adjust relative time of new queue head */
      (*queue)->t += (*node)->t;
    }
    (*node)->next = NULL;
    coap_log(LOG_DEBUG, "** %s: tid=%d: removed\n",
             coap_session_str(session), id);
    return 1;
  }

  /* search transaction to remove (only first occurence will be removed) */
  q = *queue;
  do {
    p = q;
    q = q->next;
  } while (q && (session != q->session || id != q->id));

  if (q) {                        /* found transaction */
    p->next = q->next;
    if (p->next) {                /* must update relative time of p->next */
      p->next->t += q->t;
    }
    q->next = NULL;
    *node = q;
    coap_log(LOG_DEBUG, "** %s: tid=%d: removed\n",
             coap_session_str(session), id);
    return 1;
  }

  return 0;

}

COAP_STATIC_INLINE int
token_match(const uint8_t *a, size_t alen,
  const uint8_t *b, size_t blen) {
  return alen == blen && (alen == 0 || memcmp(a, b, alen) == 0);
}

void
coap_cancel_session_messages(coap_context_t *context, coap_session_t *session,
  coap_nack_reason_t reason) {
  coap_queue_t *p, *q;

  while (context->sendqueue && context->sendqueue->session == session) {
    q = context->sendqueue;
    context->sendqueue = q->next;
    coap_log(LOG_DEBUG, "** %s: tid=%d: removed\n",
             coap_session_str(session), q->id);
    if (q->pdu->type == COAP_MESSAGE_CON && context->nack_handler)
      context->nack_handler(context, session, q->pdu, reason, q->id);
    coap_delete_node(q);
  }

  if (!context->sendqueue)
    return;

  p = context->sendqueue;
  q = p->next;

  while (q) {
    if (q->session == session) {
      p->next = q->next;
      coap_log(LOG_DEBUG, "** %s: tid=%d: removed\n",
               coap_session_str(session), q->id);
      if (q->pdu->type == COAP_MESSAGE_CON && context->nack_handler)
        context->nack_handler(context, session, q->pdu, reason, q->id);
      coap_delete_node(q);
      q = p->next;
    } else {
      p = q;
      q = q->next;
    }
  }
}

void
coap_cancel_all_messages(coap_context_t *context, coap_session_t *session,
  const uint8_t *token, size_t token_length) {
  /* cancel all messages in sendqueue that belong to session
   * and use the specified token */
  coap_queue_t *p, *q;

  while (context->sendqueue && context->sendqueue->session == session &&
    token_match(token, token_length,
      context->sendqueue->pdu->token,
      context->sendqueue->pdu->token_length)) {
    q = context->sendqueue;
    context->sendqueue = q->next;
    coap_log(LOG_DEBUG, "** %s: tid=%d: removed\n",
             coap_session_str(session), q->id);
    coap_delete_node(q);
  }

  if (!context->sendqueue)
    return;

  p = context->sendqueue;
  q = p->next;

  /* when q is not NULL, it does not match (dst, token), so we can skip it */
  while (q) {
    if (q->session == session &&
      token_match(token, token_length,
        q->pdu->token, q->pdu->token_length)) {
      p->next = q->next;
      coap_log(LOG_DEBUG, "** %s: tid=%d: removed\n",
               coap_session_str(session), q->id);
      coap_delete_node(q);
      q = p->next;
    } else {
      p = q;
      q = q->next;
    }
  }
}

coap_queue_t *
coap_find_transaction(coap_queue_t *queue, coap_session_t *session, coap_tid_t id) {
  while (queue && queue->session != session && queue->id != id)
    queue = queue->next;

  return queue;
}

coap_pdu_t *
coap_new_error_response(coap_pdu_t *request, unsigned char code,
  coap_opt_filter_t opts) {
  coap_opt_iterator_t opt_iter;
  coap_pdu_t *response;
  size_t size = request->token_length;
  unsigned char type;
  coap_opt_t *option;
  uint16_t opt_type = 0;        /* used for calculating delta-storage */

#if COAP_ERROR_PHRASE_LENGTH > 0
  const char *phrase = coap_response_phrase(code);

  /* Need some more space for the error phrase and payload start marker */
  if (phrase)
    size += strlen(phrase) + 1;
#endif

  assert(request);

  /* cannot send ACK if original request was not confirmable */
  type = request->type == COAP_MESSAGE_CON
    ? COAP_MESSAGE_ACK
    : COAP_MESSAGE_NON;

  /* Estimate how much space we need for options to copy from
   * request. We always need the Token, for 4.02 the unknown critical
   * options must be included as well. */
  coap_option_clrb(opts, COAP_OPTION_CONTENT_TYPE); /* we do not want this */

  coap_option_iterator_init(request, &opt_iter, opts);

  /* Add size of each unknown critical option. As known critical
     options as well as elective options are not copied, the delta
     value might grow.
   */
  while ((option = coap_option_next(&opt_iter))) {
    uint16_t delta = opt_iter.type - opt_type;
    /* calculate space required to encode (opt_iter.type - opt_type) */
    if (delta < 13) {
      size++;
    } else if (delta < 269) {
      size += 2;
    } else {
      size += 3;
    }

    /* add coap_opt_length(option) and the number of additional bytes
     * required to encode the option length */

    size += coap_opt_length(option);
    switch (*option & 0x0f) {
    case 0x0e:
      size++;
      /* fall through */
    case 0x0d:
      size++;
      break;
    default:
      ;
    }

    opt_type = opt_iter.type;
  }

  /* Now create the response and fill with options and payload data. */
  response = coap_pdu_init(type, code, request->tid, size);
  if (response) {
    /* copy token */
    if (!coap_add_token(response, request->token_length,
      request->token)) {
      coap_log(LOG_DEBUG, "cannot add token to error response\n");
      coap_delete_pdu(response);
      return NULL;
    }

    /* copy all options */
    coap_option_iterator_init(request, &opt_iter, opts);
    while ((option = coap_option_next(&opt_iter))) {
      coap_add_option(response, opt_iter.type,
        coap_opt_length(option),
        coap_opt_value(option));
    }

#if COAP_ERROR_PHRASE_LENGTH > 0
    /* note that diagnostic messages do not need a Content-Format option. */
    if (phrase)
      coap_add_data(response, (size_t)strlen(phrase), (const uint8_t *)phrase);
#endif
  }

  return response;
}

/**
 * Quick hack to determine the size of the resource description for
 * .well-known/core.
 */
COAP_STATIC_INLINE size_t
get_wkc_len(coap_context_t *context, coap_opt_t *query_filter) {
  unsigned char buf[1];
  size_t len = 0;

  if (coap_print_wellknown(context, buf, &len, UINT_MAX, query_filter)
    & COAP_PRINT_STATUS_ERROR) {
    coap_log(LOG_WARNING, "cannot determine length of /.well-known/core\n");
    return 0;
  }

  coap_log(LOG_DEBUG, "get_wkc_len: coap_print_wellknown() returned %zu\n", len);

  return len;
}

#define SZX_TO_BYTES(SZX) ((size_t)(1 << ((SZX) + 4)))

coap_pdu_t *
coap_wellknown_response(coap_context_t *context, coap_session_t *session,
  coap_pdu_t *request) {
  coap_pdu_t *resp;
  coap_opt_iterator_t opt_iter;
  size_t len, wkc_len;
  uint8_t buf[2];
  int result = 0;
  int need_block2 = 0;           /* set to 1 if Block2 option is required */
  coap_block_t block;
  coap_opt_t *query_filter;
  size_t offset = 0;
  uint8_t *data;

  resp = coap_pdu_init(request->type == COAP_MESSAGE_CON
    ? COAP_MESSAGE_ACK
    : COAP_MESSAGE_NON,
    COAP_RESPONSE_CODE(205),
    request->tid, coap_session_max_pdu_size(session));
  if (!resp) {
    coap_log(LOG_DEBUG, "coap_wellknown_response: cannot create PDU\n");
    return NULL;
  }

  if (!coap_add_token(resp, request->token_length, request->token)) {
    coap_log(LOG_DEBUG, "coap_wellknown_response: cannot add token\n");
    goto error;
  }

  query_filter = coap_check_option(request, COAP_OPTION_URI_QUERY, &opt_iter);
  wkc_len = get_wkc_len(context, query_filter);

  /* The value of some resources is undefined and get_wkc_len will return 0.*/
  if (wkc_len == 0) {
    coap_log(LOG_DEBUG, "coap_wellknown_response: undefined resource\n");
    /* set error code 4.00 Bad Request*/
    resp->code = COAP_RESPONSE_CODE(400);
    resp->used_size = resp->token_length;
    return resp;
  }

  /* check whether the request contains the Block2 option */
  if (coap_get_block(request, COAP_OPTION_BLOCK2, &block)) {
    coap_log(LOG_DEBUG, "create block\n");
    offset = block.num << (block.szx + 4);
    if (block.szx > 6) {  /* invalid, MUST lead to 4.00 Bad Request */
      resp->code = COAP_RESPONSE_CODE(400);
      return resp;
    } else if (block.szx > COAP_MAX_BLOCK_SZX) {
      block.szx = COAP_MAX_BLOCK_SZX;
      block.num = (unsigned int)(offset >> (block.szx + 4));
    }

    need_block2 = 1;
  }

  /* Check if there is sufficient space to add Content-Format option
   * and data. We do this before adding the Content-Format option to
   * avoid sending error responses with that option but no actual
   * content. */
  if (resp->max_size && resp->max_size <= resp->used_size + 3) {
    coap_log(LOG_DEBUG, "coap_wellknown_response: insufficient storage space\n");
    goto error;
  }

  /* Add Content-Format. As we have checked for available storage,
   * nothing should go wrong here. */
  assert(coap_encode_var_safe(buf, sizeof(buf),
    COAP_MEDIATYPE_APPLICATION_LINK_FORMAT) == 1);
  coap_add_option(resp, COAP_OPTION_CONTENT_FORMAT,
    coap_encode_var_safe(buf, sizeof(buf),
      COAP_MEDIATYPE_APPLICATION_LINK_FORMAT), buf);

  /* check if Block2 option is required even if not requested */
  if (!need_block2 && resp->max_size && resp->max_size - resp->used_size < wkc_len + 1) {
    assert(resp->used_size <= resp->max_size);
    const size_t payloadlen = resp->max_size - resp->used_size;
    /* yes, need block-wise transfer */
    block.num = 0;
    block.m = 0;      /* the M bit is set by coap_write_block_opt() */
    block.szx = COAP_MAX_BLOCK_SZX;
    while (payloadlen < SZX_TO_BYTES(block.szx) + 6) {
      if (block.szx == 0) {
        coap_log(LOG_DEBUG,
             "coap_wellknown_response: message to small even for szx == 0\n");
        goto error;
      } else {
        block.szx--;
      }
    }

    need_block2 = 1;
  }

  /* write Block2 option if necessary */
  if (need_block2) {
    if (coap_write_block_opt(&block, COAP_OPTION_BLOCK2, resp, wkc_len) < 0) {
      coap_log(LOG_DEBUG,
               "coap_wellknown_response: cannot add Block2 option\n");
      goto error;
    }
  }

  len = need_block2 ? SZX_TO_BYTES( block.szx ) :
        resp->max_size && resp->used_size + wkc_len + 1 > resp->max_size ?
        resp->max_size - resp->used_size - 1 : wkc_len;
  data = coap_add_data_after(resp, len);
  if (!data) {
    coap_log(LOG_DEBUG, "coap_wellknown_response: coap_add_data failed\n" );
    goto error;
  }

  result = coap_print_wellknown(context, data, &len, offset, query_filter);
  if ((result & COAP_PRINT_STATUS_ERROR) != 0) {
    coap_log(LOG_DEBUG, "coap_print_wellknown failed\n");
    goto error;
  }

  return resp;

error:
  /* set error code 5.03 and remove all options and data from response */
  resp->code = COAP_RESPONSE_CODE(503);
  resp->used_size = resp->token_length;
  return resp;
}

/**
 * This function cancels outstanding messages for the session and
 * token specified in @p sent. Any observation relationship for
 * sent->session and the token are removed. Calling this function is
 * required when receiving an RST message (usually in response to a
 * notification) or a GET request with the Observe option set to 1.
 *
 * This function returns @c 0 when the token is unknown with this
 * peer, or a value greater than zero otherwise.
 */
static int
coap_cancel(coap_context_t *context, const coap_queue_t *sent) {
#ifndef WITHOUT_OBSERVE
  coap_binary_t token = { 0, NULL };
  int num_cancelled = 0;    /* the number of observers cancelled */

  /* remove observer for this resource, if any
   * get token from sent and try to find a matching resource. Uh!
   */

  COAP_SET_STR(&token, sent->pdu->token_length, sent->pdu->token);

  RESOURCES_ITER(context->resources, r) {
    num_cancelled += coap_delete_observer(r, sent->session, &token);
    coap_cancel_all_messages(context, sent->session, token.s, token.length);
  }

  return num_cancelled;
#else /* WITOUT_OBSERVE */
  return 0;
#endif /* WITOUT_OBSERVE */
}

/**
 * Internal flags to control the treatment of responses (specifically
 * in presence of the No-Response option).
 */
enum respond_t { RESPONSE_DEFAULT, RESPONSE_DROP, RESPONSE_SEND };

/**
 * Checks for No-Response option in given @p request and
 * returns @c 1 if @p response should be suppressed
 * according to RFC 7967.
 *
 * The value of the No-Response option is encoded as
 * follows:
 *
 * @verbatim
 *  +-------+-----------------------+-----------------------------------+
 *  | Value | Binary Representation |          Description              |
 *  +-------+-----------------------+-----------------------------------+
 *  |   0   |      <empty>          | Interested in all responses.      |
 *  +-------+-----------------------+-----------------------------------+
 *  |   2   |      00000010         | Not interested in 2.xx responses. |
 *  +-------+-----------------------+-----------------------------------+
 *  |   8   |      00001000         | Not interested in 4.xx responses. |
 *  +-------+-----------------------+-----------------------------------+
 *  |  16   |      00010000         | Not interested in 5.xx responses. |
 *  +-------+-----------------------+-----------------------------------+
 * @endverbatim
 *
 * @param request  The CoAP request to check for the No-Response option.
 *                 This parameter must not be NULL.
 * @param response The response that is potentially suppressed.
 *                 This parameter must not be NULL.
 * @return RESPONSE_DEFAULT when no special treatment is requested,
 *         RESPONSE_DROP    when the response must be discarded, or
 *         RESPONSE_SEND    when the response must be sent.
 */
static enum respond_t
no_response(coap_pdu_t *request, coap_pdu_t *response) {
  coap_opt_t *nores;
  coap_opt_iterator_t opt_iter;
  unsigned int val = 0;

  assert(request);
  assert(response);

  if (COAP_RESPONSE_CLASS(response->code) > 0) {
    nores = coap_check_option(request, COAP_OPTION_NORESPONSE, &opt_iter);

    if (nores) {
      val = coap_decode_var_bytes(coap_opt_value(nores), coap_opt_length(nores));

      /* The response should be dropped when the bit corresponding to
       * the response class is set (cf. table in function
       * documentation). When a No-Response option is present and the
       * bit is not set, the sender explicitly indicates interest in
       * this response. */
      if (((1 << (COAP_RESPONSE_CLASS(response->code) - 1)) & val) > 0) {
        return RESPONSE_DROP;
      } else {
        return RESPONSE_SEND;
      }
    }
  }

  /* Default behavior applies when we are not dealing with a response
   * (class == 0) or the request did not contain a No-Response option.
   */
  return RESPONSE_DEFAULT;
}

static coap_str_const_t coap_default_uri_wellknown =
          { sizeof(COAP_DEFAULT_URI_WELLKNOWN)-1,
           (const uint8_t *)COAP_DEFAULT_URI_WELLKNOWN };

static void
handle_request(coap_context_t *context, coap_session_t *session, coap_pdu_t *pdu) {
  coap_method_handler_t h = NULL;
  coap_pdu_t *response = NULL;
  coap_opt_filter_t opt_filter;
  coap_resource_t *resource;
  /* The respond field indicates whether a response must be treated
   * specially due to a No-Response option that declares disinterest
   * or interest in a specific response class. DEFAULT indicates that
   * No-Response has not been specified. */
  enum respond_t respond = RESPONSE_DEFAULT;

  coap_option_filter_clear(opt_filter);

  /* try to find the resource from the request URI */
  coap_string_t *uri_path = coap_get_uri_path(pdu);
  if (!uri_path)
    return;
  coap_str_const_t uri_path_c = { uri_path->length, uri_path->s };
  resource = coap_get_resource_from_uri_path(context, &uri_path_c);

  if ((resource == NULL) || (resource->is_unknown == 1)) {
    /* The resource was not found or there is an unexpected match against the
     * resource defined for handling unknown URIs.
     * Check if the request URI happens to be the well-known URI, or if the
     * unknown resource handler is defined, a PUT or optionally other methods,
     * if configured, for the unknown handler.
     *
     * if well-known URI generate a default response
     *
     * else if unknown URI handler defined, call the unknown
     *  URI handler (to allow for potential generation of resource
     *  [RFC7272 5.8.3]) if the appropriate method is defined.
     *
     * else if DELETE return 2.02 (RFC7252: 5.8.4.  DELETE)
     *
     * else return 4.04 */

    if (coap_string_equal(uri_path, &coap_default_uri_wellknown)) {
      /* request for .well-known/core */
      if (pdu->code == COAP_REQUEST_GET) { /* GET */
        coap_log(LOG_INFO, "create default response for %s\n",
                 COAP_DEFAULT_URI_WELLKNOWN);
        response = coap_wellknown_response(context, session, pdu);
      } else {
        coap_log(LOG_DEBUG, "method not allowed for .well-known/core\n");
        response = coap_new_error_response(pdu, COAP_RESPONSE_CODE(405),
          opt_filter);
      }
    } else if ((context->unknown_resource != NULL) &&
               ((size_t)pdu->code - 1 <
                (sizeof(resource->handler) / sizeof(coap_method_handler_t))) &&
               (context->unknown_resource->handler[pdu->code - 1])) {
      /*
       * The unknown_resource can be used to handle undefined resources
       * for a PUT request and can support any other registered handler
       * defined for it
       * Example set up code:-
       *   r = coap_resource_unknown_init(hnd_put_unknown);
       *   coap_register_handler(r, COAP_REQUEST_POST, hnd_post_unknown);
       *   coap_register_handler(r, COAP_REQUEST_GET, hnd_get_unknown);
       *   coap_register_handler(r, COAP_REQUEST_DELETE, hnd_delete_unknown);
       *   coap_add_resource(ctx, r);
       *
       * Note: It is not possible to observe the unknown_resource, a separate
       *       resource must be created (by PUT or POST) which has a GET
       *       handler to be observed
       */
      resource = context->unknown_resource;
    } else if (pdu->code == COAP_REQUEST_DELETE) {
      /*
       * Request for DELETE on non-existant resource (RFC7252: 5.8.4.  DELETE)
       */
      coap_log(LOG_DEBUG, "request for unknown resource '%*.*s',"
                          " return 2.02\n",
                          (int)uri_path->length,
                          (int)uri_path->length,
                          uri_path->s);
      response =
        coap_new_error_response(pdu, COAP_RESPONSE_CODE(202),
          opt_filter);
    } else { /* request for any another resource, return 4.04 */

      coap_log(LOG_DEBUG, "request for unknown resource '%*.*s', return 4.04\n",
               (int)uri_path->length, (int)uri_path->length, uri_path->s);
      response =
        coap_new_error_response(pdu, COAP_RESPONSE_CODE(404),
          opt_filter);
    }

    if (!resource) {
      if (response && (no_response(pdu, response) != RESPONSE_DROP)) {
        if (coap_send(session, response) == COAP_INVALID_TID)
          coap_log(LOG_WARNING, "cannot send response for transaction %u\n",
                   pdu->tid);
      } else {
        coap_delete_pdu(response);
      }

      response = NULL;

      coap_delete_string(uri_path);
      return;
    } else {
      if (response) {
        /* Need to delete unused response - it will get re-created further on */
        coap_delete_pdu(response);
      }
    }
  }

  /* the resource was found, check if there is a registered handler */
  if ((size_t)pdu->code - 1 <
    sizeof(resource->handler) / sizeof(coap_method_handler_t))
    h = resource->handler[pdu->code - 1];

  if (h) {
    coap_string_t *query = coap_get_query(pdu);
    int owns_query = 1;
     coap_log(LOG_DEBUG, "call custom handler for resource '%*.*s'\n",
              (int)resource->uri_path->length, (int)resource->uri_path->length,
              resource->uri_path->s);
    response = coap_pdu_init(pdu->type == COAP_MESSAGE_CON
      ? COAP_MESSAGE_ACK
      : COAP_MESSAGE_NON,
      0, pdu->tid, coap_session_max_pdu_size(session));

    /* Implementation detail: coap_add_token() immediately returns 0
       if response == NULL */
    if (coap_add_token(response, pdu->token_length, pdu->token)) {
      coap_binary_t token = { pdu->token_length, pdu->token };
      coap_opt_iterator_t opt_iter;
      coap_opt_t *observe = NULL;
      int observe_action = COAP_OBSERVE_CANCEL;

      /* check for Observe option */
      if (resource->observable) {
        observe = coap_check_option(pdu, COAP_OPTION_OBSERVE, &opt_iter);
        if (observe) {
          observe_action =
            coap_decode_var_bytes(coap_opt_value(observe),
              coap_opt_length(observe));

          if ((observe_action & COAP_OBSERVE_CANCEL) == 0) {
            coap_subscription_t *subscription;
            coap_block_t block2;
            int has_block2 = 0;

            if (coap_get_block(pdu, COAP_OPTION_BLOCK2, &block2)) {
              has_block2 = 1;
            }
            subscription = coap_add_observer(resource, session, &token, query, has_block2, block2);
            owns_query = 0;
            if (subscription) {
              coap_touch_observer(context, session, &token);
            }
          } else {
            coap_delete_observer(resource, session, &token);
          }
        }
      }

      h(context, resource, session, pdu, &token, query, response);

      if (query && owns_query)
        coap_delete_string(query);

      respond = no_response(pdu, response);
      if (respond != RESPONSE_DROP) {
        if (observe && (COAP_RESPONSE_CLASS(response->code) > 2)) {
          coap_delete_observer(resource, session, &token);
        }

        /* If original request contained a token, and the registered
         * application handler made no changes to the response, then
         * this is an empty ACK with a token, which is a malformed
         * PDU */
        if ((response->type == COAP_MESSAGE_ACK)
          && (response->code == 0)) {
          /* Remove token from otherwise-empty acknowledgment PDU */
          response->token_length = 0;
          response->used_size = 0;
        }

        if ((respond == RESPONSE_SEND)
          || /* RESPOND_DEFAULT */
          (response->type != COAP_MESSAGE_NON ||
          (response->code >= 64
            && !coap_mcast_interface(&node->local_if)))) {

          if (coap_send(session, response) == COAP_INVALID_TID)
            coap_log(LOG_DEBUG, "cannot send response for message %d\n",
                     pdu->tid);
        } else {
          coap_delete_pdu(response);
        }
      } else {
        coap_delete_pdu(response);
      }
      response = NULL;
    } else {
      coap_log(LOG_WARNING, "cannot generate response\r\n");
    }
  } else {
    if (coap_string_equal(uri_path, &coap_default_uri_wellknown)) {
      /* request for .well-known/core */
      coap_log(LOG_DEBUG, "create default response for %s\n",
               COAP_DEFAULT_URI_WELLKNOWN);
      response = coap_wellknown_response(context, session, pdu);
      coap_log(LOG_DEBUG, "have wellknown response %p\n", (void *)response);
    } else
      response = coap_new_error_response(pdu, COAP_RESPONSE_CODE(405),
        opt_filter);

    if (response && (no_response(pdu, response) != RESPONSE_DROP)) {
      if (coap_send(session, response) == COAP_INVALID_TID)
        coap_log(LOG_DEBUG, "cannot send response for transaction %d\n",
                 pdu->tid);
    } else {
      coap_delete_pdu(response);
    }
    response = NULL;
  }

  assert(response == NULL);
  coap_delete_string(uri_path);
}

static void
handle_response(coap_context_t *context, coap_session_t *session,
  coap_pdu_t *sent, coap_pdu_t *rcvd) {

  coap_send_ack(session, rcvd);

  /* In a lossy context, the ACK of a separate response may have
   * been lost, so we need to stop retransmitting requests with the
   * same token.
   */
  coap_cancel_all_messages(context, session, rcvd->token, rcvd->token_length);

  /* Call application-specific response handler when available. */
  if (context->response_handler) {
    context->response_handler(context, session, sent, rcvd, rcvd->tid);
  }
}

static void
handle_signaling(coap_context_t *context, coap_session_t *session,
  coap_pdu_t *pdu) {
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;
  (void)context;

  coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);

  if (pdu->code == COAP_SIGNALING_CSM) {
    while ((option = coap_option_next(&opt_iter))) {
      if (opt_iter.type == COAP_SIGNALING_OPTION_MAX_MESSAGE_SIZE) {
        coap_session_set_mtu(session, coap_decode_var_bytes(coap_opt_value(option),
          coap_opt_length(option)));
      } else if (opt_iter.type == COAP_SIGNALING_OPTION_BLOCK_WISE_TRANSFER) {
        /* ... */
      }
    }
    if (session->state == COAP_SESSION_STATE_CSM)
      coap_session_connected(session);
  } else if (pdu->code == COAP_SIGNALING_PING) {
    coap_pdu_t *pong = coap_pdu_init(COAP_MESSAGE_CON, COAP_SIGNALING_PONG, 0, 1);
    if (context->ping_handler) {
      context->ping_handler(context, session, pdu, pdu->tid);
    }
    if (pong) {
      coap_add_option(pong, COAP_SIGNALING_OPTION_CUSTODY, 0, NULL);
      coap_send(session, pong);
    }
  } else if (pdu->code == COAP_SIGNALING_PONG) {
    session->last_pong = session->last_rx_tx;
    if (context->pong_handler) {
      context->pong_handler(context, session, pdu, pdu->tid);
    }
  } else if (pdu->code == COAP_SIGNALING_RELEASE
          || pdu->code == COAP_SIGNALING_ABORT) {
    coap_session_disconnected(session, COAP_NACK_RST);
  }
}

void
coap_dispatch(coap_context_t *context, coap_session_t *session,
  coap_pdu_t *pdu) {
  coap_queue_t *sent = NULL;
  coap_pdu_t *response;
  coap_opt_filter_t opt_filter;

#ifndef NDEBUG
  if (LOG_DEBUG <= coap_get_log_level()) {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif
    /* FIXME: get debug to work again **
    unsigned char addr[INET6_ADDRSTRLEN+8], localaddr[INET6_ADDRSTRLEN+8];
    if (coap_print_addr(remote, addr, INET6_ADDRSTRLEN+8) &&
        coap_print_addr(&packet->dst, localaddr, INET6_ADDRSTRLEN+8) )
      coap_log(LOG_DEBUG, "** received %d bytes from %s on interface %s:\n",
            (int)msg_len, addr, localaddr);

            */
    coap_show_pdu(LOG_DEBUG, pdu);
  }
#endif

  memset(opt_filter, 0, sizeof(coap_opt_filter_t));

  switch (pdu->type) {
    case COAP_MESSAGE_ACK:
      /* find transaction in sendqueue to stop retransmission */
      coap_remove_from_queue(&context->sendqueue, session, pdu->tid, &sent);

      if (session->con_active) {
        session->con_active--;
        if (session->state == COAP_SESSION_STATE_ESTABLISHED)
          /* Flush out any entries on session->delayqueue */
          coap_session_connected(session);
      }
      if (pdu->code == 0)
        goto cleanup;

      /* if sent code was >= 64 the message might have been a
       * notification. Then, we must flag the observer to be alive
       * by setting obs->fail_cnt = 0. */
      if (sent && COAP_RESPONSE_CLASS(sent->pdu->code) == 2) {
        const coap_binary_t token =
        { sent->pdu->token_length, sent->pdu->token };
        coap_touch_observer(context, sent->session, &token);
      }
      break;

    case COAP_MESSAGE_RST:
      /* We have sent something the receiver disliked, so we remove
       * not only the transaction but also the subscriptions we might
       * have. */

      coap_log(LOG_ALERT, "got RST for message %d\n", pdu->tid);

      if (session->con_active) {
        session->con_active--;
        if (session->state == COAP_SESSION_STATE_ESTABLISHED)
          /* Flush out any entries on session->delayqueue */
          coap_session_connected(session);
      }

      /* find transaction in sendqueue to stop retransmission */
      coap_remove_from_queue(&context->sendqueue, session, pdu->tid, &sent);

      if (sent) {
        coap_cancel(context, sent);

        if(sent->pdu->type==COAP_MESSAGE_CON && context->nack_handler)
          context->nack_handler(context, sent->session, sent->pdu, COAP_NACK_RST, sent->id);
      }
      goto cleanup;

    case COAP_MESSAGE_NON:        /* check for unknown critical options */
      if (coap_option_check_critical(context, pdu, opt_filter) == 0)
        goto cleanup;
      break;

    case COAP_MESSAGE_CON:        /* check for unknown critical options */
      if (coap_option_check_critical(context, pdu, opt_filter) == 0) {

        /* FIXME: send response only if we have received a request. Otherwise,
         * send RST. */
        response =
          coap_new_error_response(pdu, COAP_RESPONSE_CODE(402), opt_filter);

        if (!response) {
          coap_log(LOG_WARNING,
                   "coap_dispatch: cannot create error response\n");
        } else {
          if (coap_send(session, response) == COAP_INVALID_TID)
            coap_log(LOG_WARNING, "coap_dispatch: error sending response\n");
        }

        goto cleanup;
      }
    default: break;
  }

  /* Pass message to upper layer if a specific handler was
    * registered for a request that should be handled locally. */
  if (COAP_PDU_IS_SIGNALING(pdu))
    handle_signaling(context, session, pdu);
  else if (COAP_PDU_IS_REQUEST(pdu))
    handle_request(context, session, pdu);
  else if (COAP_PDU_IS_RESPONSE(pdu))
    handle_response(context, session, sent ? sent->pdu : NULL, pdu);
  else {
    if (COAP_PDU_IS_EMPTY(pdu)) {
      if (context->ping_handler) {
        context->ping_handler(context, session,
          pdu, pdu->tid);
      }
    }
    coap_log(LOG_DEBUG, "dropped message with invalid code (%d.%02d)\n",
             COAP_RESPONSE_CLASS(pdu->code),
      pdu->code & 0x1f);

    if (!coap_is_mcast(&session->local_addr)) {
      if (COAP_PDU_IS_EMPTY(pdu)) {
        if (session->proto != COAP_PROTO_TCP && session->proto != COAP_PROTO_TLS) {
          coap_tick_t now;
          coap_ticks(&now);
          if (session->last_tx_rst + COAP_TICKS_PER_SECOND/4 < now) {
            coap_send_message_type(session, pdu, COAP_MESSAGE_RST);
            session->last_tx_rst = now;
          }
        }
      }
      else {
        coap_send_message_type(session, pdu, COAP_MESSAGE_RST);
      }
    }
  }

cleanup:
  coap_delete_node(sent);
}

int
coap_handle_event(coap_context_t *context, coap_event_t event, coap_session_t *session) {
  coap_log(LOG_DEBUG, "***EVENT: 0x%04x\n", event);

  if (context->handle_event) {
    return context->handle_event(context, event, session);
  } else {
    return 0;
  }
}

int
coap_can_exit(coap_context_t *context) {
  coap_endpoint_t *ep;
  coap_session_t *s;
  if (!context)
    return 1;
  if (context->sendqueue)
    return 0;
  LL_FOREACH(context->endpoint, ep) {
    LL_FOREACH(ep->sessions, s) {
      if (s->delayqueue)
        return 0;
    }
  }
  LL_FOREACH(context->sessions, s) {
    if (s->delayqueue)
      return 0;
  }
  return 1;
}

static int coap_started = 0;

void coap_startup(void) {
  if (coap_started)
    return;
  coap_started = 1;
#if defined(HAVE_WINSOCK2_H)
  WORD wVersionRequested = MAKEWORD(2, 2);
  WSADATA wsaData;
  WSAStartup(wVersionRequested, &wsaData);
#endif
  coap_clock_init();
#if defined(WITH_LWIP)
  prng_init(LWIP_RAND());
#elif defined(WITH_CONTIKI)
  prng_init(0);
#elif !defined(_WIN32)
  prng_init(0);
#endif
  coap_dtls_startup();
}

void coap_cleanup(void) {
#if defined(HAVE_WINSOCK2_H)
  WSACleanup();
#endif
}

#if ! defined WITH_CONTIKI && ! defined WITH_LWIP
int
coap_join_mcast_group(coap_context_t *ctx, const char *group_name) {
  struct ipv6_mreq mreq;
  struct addrinfo   *reslocal = NULL, *resmulti = NULL, hints, *ainfo;
  int result = -1;
  coap_endpoint_t *endpoint;
  int mgroup_setup = 0;

  /* we have to resolve the link-local interface to get the interface id */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_DGRAM;

  result = getaddrinfo("::", NULL, &hints, &reslocal);
  if (result != 0) {
    coap_log(LOG_ERR,
             "coap_join_mcast_group: cannot resolve link-local interface: %s\n",
             gai_strerror(result));
    goto finish;
  }

  /* get the first suitable interface identifier */
  for (ainfo = reslocal; ainfo != NULL; ainfo = ainfo->ai_next) {
    if (ainfo->ai_family == AF_INET6) {
      mreq.ipv6mr_interface =
                ((struct sockaddr_in6 *)ainfo->ai_addr)->sin6_scope_id;
      break;
    }
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_DGRAM;

  /* resolve the multicast group address */
  result = getaddrinfo(group_name, NULL, &hints, &resmulti);

  if (result != 0) {
    coap_log(LOG_ERR,
             "coap_join_mcast_group: cannot resolve multicast address: %s\n",
             gai_strerror(result));
    goto finish;
  }

  for (ainfo = resmulti; ainfo != NULL; ainfo = ainfo->ai_next) {
    if (ainfo->ai_family == AF_INET6) {
      mreq.ipv6mr_multiaddr =
                ((struct sockaddr_in6 *)ainfo->ai_addr)->sin6_addr;
      break;
    }
  }

  LL_FOREACH(ctx->endpoint, endpoint) {
    if (endpoint->proto == COAP_PROTO_UDP ||
        endpoint->proto == COAP_PROTO_DTLS) {
      result = setsockopt(endpoint->sock.fd, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                          (char *)&mreq, sizeof(mreq));
      if (result == COAP_SOCKET_ERROR) {
        coap_log(LOG_ERR,
                 "coap_join_mcast_group: setsockopt: %s: '%s'\n",
                 coap_socket_strerror(), group_name);
      }
      else {
        mgroup_setup = 1;
      }
    }
  }
  if (!mgroup_setup) {
    result = -1;
  }

 finish:
  freeaddrinfo(resmulti);
  freeaddrinfo(reslocal);

  return result;
}
#else /* defined WITH_CONTIKI || defined WITH_LWIP */
int
coap_join_mcast_group(coap_context_t *ctx, const char *group_name) {
  (void)ctx;
  (void)group_name;
  return -1;
}
#endif /* defined WITH_CONTIKI || defined WITH_LWIP */

#ifdef WITH_CONTIKI

/*---------------------------------------------------------------------------*/
/* CoAP message retransmission */
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(coap_retransmit_process, ev, data) {
  coap_tick_t now;
  coap_queue_t *nextpdu;

  PROCESS_BEGIN();

  coap_log(LOG_DEBUG, "Started retransmit process\n");

  while (1) {
    PROCESS_YIELD();
    if (ev == PROCESS_EVENT_TIMER) {
      if (etimer_expired(&the_coap_context.retransmit_timer)) {

        nextpdu = coap_peek_next(&the_coap_context);

        coap_ticks(&now);
        while (nextpdu && nextpdu->t <= now) {
          coap_retransmit(&the_coap_context, coap_pop_next(&the_coap_context));
          nextpdu = coap_peek_next(&the_coap_context);
        }

        /* need to set timer to some value even if no nextpdu is available */
        etimer_set(&the_coap_context.retransmit_timer,
          nextpdu ? nextpdu->t - now : 0xFFFF);
      }
#ifndef WITHOUT_OBSERVE
      if (etimer_expired(&the_coap_context.notify_timer)) {
        coap_check_notify(&the_coap_context);
        etimer_reset(&the_coap_context.notify_timer);
      }
#endif /* WITHOUT_OBSERVE */
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/

#endif /* WITH_CONTIKI */

#ifdef WITH_LWIP
/* FIXME: retransmits that are not required any more due to incoming packages
 * do *not* get cleared at the moment, the wakeup when the transmission is due
 * is silently accepted. this is mainly due to the fact that the required
 * checks are similar in two places in the code (when receiving ACK and RST)
 * and that they cause more than one patch chunk, as it must be first checked
 * whether the sendqueue item to be dropped is the next one pending, and later
 * the restart function has to be called. nothing insurmountable, but it can
 * also be implemented when things have stabilized, and the performance
 * penality is minimal
 *
 * also, this completely ignores COAP_RESOURCE_CHECK_TIME.
 * */

static void coap_retransmittimer_execute(void *arg) {
  coap_context_t *ctx = (coap_context_t*)arg;
  coap_tick_t now;
  coap_tick_t elapsed;
  coap_queue_t *nextinqueue;

  ctx->timer_configured = 0;

  coap_ticks(&now);

  elapsed = now - ctx->sendqueue_basetime; /* that's positive for sure, and unless we haven't been called for a complete wrapping cycle, did not wrap */

  nextinqueue = coap_peek_next(ctx);
  while (nextinqueue != NULL) {
    if (nextinqueue->t > elapsed) {
      nextinqueue->t -= elapsed;
      break;
    } else {
      elapsed -= nextinqueue->t;
      coap_retransmit(ctx, coap_pop_next(ctx));
      nextinqueue = coap_peek_next(ctx);
    }
  }

  ctx->sendqueue_basetime = now;

  coap_retransmittimer_restart(ctx);
}

static void coap_retransmittimer_restart(coap_context_t *ctx) {
  coap_tick_t now, elapsed, delay;

  if (ctx->timer_configured) {
    printf("clearing\n");
    sys_untimeout(coap_retransmittimer_execute, (void*)ctx);
    ctx->timer_configured = 0;
  }
  if (ctx->sendqueue != NULL) {
    coap_ticks(&now);
    elapsed = now - ctx->sendqueue_basetime;
    if (ctx->sendqueue->t >= elapsed) {
      delay = ctx->sendqueue->t - elapsed;
    } else {
      /* a strange situation, but not completely impossible.
       *
       * this happens, for example, right after
       * coap_retransmittimer_execute, when a retransmission
       * was *just not yet* due, and the clock ticked before
       * our coap_ticks was called.
       *
       * not trying to retransmit anything now, as it might
       * cause uncontrollable recursion; let's just try again
       * with the next main loop run.
       * */
      delay = 0;
    }

    printf("scheduling for %d ticks\n", delay);
    sys_timeout(delay, coap_retransmittimer_execute, (void*)ctx);
    ctx->timer_configured = 1;
  }
}
#endif
/*
 * option.c -- helpers for handling options in CoAP PDUs
 *
 * Copyright (C) 2010-2013 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */


#include "coap_config.h"

#if defined(HAVE_ASSERT_H) && !defined(assert)
# include <assert.h>
#endif

#include <stdio.h>
#include <string.h>

#include "libcoap.h"
#include "option.h"
#include "encode.h"                /* for coap_fls() */
#include "coap_debug.h"
#include "mem.h"
#include "utlist.h"

#define ADVANCE_OPT(o,e,step) if ((e) < step) {           \
    coap_log(LOG_DEBUG, "cannot advance opt past end\n"); \
    return 0;                                             \
  } else {                                                \
    (e) -= step;                                          \
    (o) = ((o)) + step;                                   \
  }

/*
 * Used to prevent access to *opt when pointing to after end of buffer
 * after doing a ADVANCE_OPT()
 */
#define ADVANCE_OPT_CHECK(o,e,step) do { \
    ADVANCE_OPT(o,e,step);               \
    if ((e) < 1)                         \
      return 0;                          \
  } while (0)

size_t
coap_opt_parse(const coap_opt_t *opt, size_t length, coap_option_t *result) {

  const coap_opt_t *opt_start = opt; /* store where parsing starts  */

  assert(opt); assert(result);

  if (length < 1)
    return 0;

  result->delta = (*opt & 0xf0) >> 4;
  result->length = *opt & 0x0f;

  switch(result->delta) {
  case 15:
    if (*opt != COAP_PAYLOAD_START) {
      coap_log(LOG_DEBUG, "ignored reserved option delta 15\n");
    }
    return 0;
  case 14:
    /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
     * After that, the option pointer is advanced to the LSB which is handled
     * just like case delta == 13. */
    ADVANCE_OPT_CHECK(opt,length,1);
    result->delta = ((*opt & 0xff) << 8) + 269;
    if (result->delta < 269) {
      coap_log(LOG_DEBUG, "delta too large\n");
      return 0;
    }
    /* fall through */
  case 13:
    ADVANCE_OPT_CHECK(opt,length,1);
    result->delta += *opt & 0xff;
    break;

  default:
    ;
  }

  switch(result->length) {
  case 15:
    coap_log(LOG_DEBUG, "found reserved option length 15\n");
    return 0;
  case 14:
    /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
     * After that, the option pointer is advanced to the LSB which is handled
     * just like case delta == 13. */
    ADVANCE_OPT_CHECK(opt,length,1);
    result->length = ((*opt & 0xff) << 8) + 269;
    /* fall through */
  case 13:
    ADVANCE_OPT_CHECK(opt,length,1);
    result->length += *opt & 0xff;
    break;

  default:
    ;
  }

  /* ADVANCE_OPT() is correct here */
  ADVANCE_OPT(opt,length,1);
  /* opt now points to value, if present */

  result->value = opt;
  if (length < result->length) {
    coap_log(LOG_DEBUG, "invalid option length\n");
    return 0;
  }

#undef ADVANCE_OPT
#undef ADVANCE_OPT_CHECK

  return (opt + result->length) - opt_start;
}

coap_opt_iterator_t *
coap_option_iterator_init(const coap_pdu_t *pdu, coap_opt_iterator_t *oi,
                          const coap_opt_filter_t filter) {
  assert(pdu);
  assert(pdu->token);
  assert(oi);

  memset(oi, 0, sizeof(coap_opt_iterator_t));

  oi->next_option = pdu->token + pdu->token_length;
  if (pdu->token + pdu->used_size <= oi->next_option) {
    oi->bad = 1;
    return NULL;
  }

  oi->length = pdu->used_size - pdu->token_length;

  if (filter) {
    memcpy(oi->filter, filter, sizeof(coap_opt_filter_t));
    oi->filtered = 1;
  }
  return oi;
}

COAP_STATIC_INLINE int
opt_finished(coap_opt_iterator_t *oi) {
  assert(oi);

  if (oi->bad || oi->length == 0 ||
      !oi->next_option || *oi->next_option == COAP_PAYLOAD_START) {
    oi->bad = 1;
  }

  return oi->bad;
}

coap_opt_t *
coap_option_next(coap_opt_iterator_t *oi) {
  coap_option_t option;
  coap_opt_t *current_opt = NULL;
  size_t optsize;
  int b;                   /* to store result of coap_option_getb() */

  assert(oi);

  if (opt_finished(oi))
    return NULL;

  while (1) {
    /* oi->option always points to the next option to deliver; as
     * opt_finished() filters out any bad conditions, we can assume that
     * oi->option is valid. */
    current_opt = oi->next_option;

    /* Advance internal pointer to next option, skipping any option that
     * is not included in oi->filter. */
    optsize = coap_opt_parse(oi->next_option, oi->length, &option);
    if (optsize) {
      assert(optsize <= oi->length);

      oi->next_option += optsize;
      oi->length -= optsize;

      oi->type += option.delta;
    } else {                        /* current option is malformed */
      oi->bad = 1;
      return NULL;
    }

    /* Exit the while loop when:
     *   - no filtering is done at all
     *   - the filter matches for the current option
     *   - the filter is too small for the current option number
     */
    if (!oi->filtered ||
        (b = coap_option_getb(oi->filter, oi->type)) > 0)
      break;
    else if (b < 0) {                /* filter too small, cannot proceed */
      oi->bad = 1;
      return NULL;
    }
  }

  return current_opt;
}

coap_opt_t *
coap_check_option(coap_pdu_t *pdu, uint16_t type,
                  coap_opt_iterator_t *oi) {
  coap_opt_filter_t f;

  coap_option_filter_clear(f);
  coap_option_setb(f, type);

  coap_option_iterator_init(pdu, oi, f);

  return coap_option_next(oi);
}

uint16_t
coap_opt_delta(const coap_opt_t *opt) {
  uint16_t n;

  n = (*opt++ & 0xf0) >> 4;

  switch (n) {
  case 15: /* error */
    coap_log(LOG_WARNING, "coap_opt_delta: illegal option delta\n");

    /* This case usually should not happen, hence we do not have a
     * proper way to indicate an error. */
    return 0;
  case 14:
    /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
     * After that, the option pointer is advanced to the LSB which is handled
     * just like case delta == 13. */
    n = ((*opt++ & 0xff) << 8) + 269;
    /* fall through */
  case 13:
    n += *opt & 0xff;
    break;
  default: /* n already contains the actual delta value */
    ;
  }

  return n;
}

uint16_t
coap_opt_length(const coap_opt_t *opt) {
  uint16_t length;

  length = *opt & 0x0f;
  switch (*opt & 0xf0) {
  case 0xf0:
    coap_log(LOG_DEBUG, "illegal option delta\n");
    return 0;
  case 0xe0:
    ++opt;
    /* fall through */
    /* to skip another byte */
  case 0xd0:
    ++opt;
    /* fall through */
    /* to skip another byte */
  default:
    ++opt;
  }

  switch (length) {
  case 0x0f:
    coap_log(LOG_DEBUG, "illegal option length\n");
    return 0;
  case 0x0e:
    length = (*opt++ << 8) + 269;
    /* fall through */
  case 0x0d:
    length += *opt++;
    break;
  default:
    ;
  }
  return length;
}

const uint8_t *
coap_opt_value(const coap_opt_t *opt) {
  size_t ofs = 1;

  switch (*opt & 0xf0) {
  case 0xf0:
    coap_log(LOG_DEBUG, "illegal option delta\n");
    return 0;
  case 0xe0:
    ++ofs;
    /* fall through */
  case 0xd0:
    ++ofs;
    break;
  default:
    ;
  }

  switch (*opt & 0x0f) {
  case 0x0f:
    coap_log(LOG_DEBUG, "illegal option length\n");
    return 0;
  case 0x0e:
    ++ofs;
    /* fall through */
  case 0x0d:
    ++ofs;
    break;
  default:
    ;
  }

  return (const uint8_t *)opt + ofs;
}

size_t
coap_opt_size(const coap_opt_t *opt) {
  coap_option_t option;

  /* we must assume that opt is encoded correctly */
  return coap_opt_parse(opt, (size_t)-1, &option);
}

size_t
coap_opt_setheader(coap_opt_t *opt, size_t maxlen,
                   uint16_t delta, size_t length) {
  size_t skip = 0;

  assert(opt);

  if (maxlen == 0)                /* need at least one byte */
    return 0;

  if (delta < 13) {
    opt[0] = (coap_opt_t)(delta << 4);
  } else if (delta < 269) {
    if (maxlen < 2) {
      coap_log(LOG_DEBUG, "insufficient space to encode option delta %d\n",
               delta);
      return 0;
    }

    opt[0] = 0xd0;
    opt[++skip] = (coap_opt_t)(delta - 13);
  } else {
    if (maxlen < 3) {
      coap_log(LOG_DEBUG, "insufficient space to encode option delta %d\n",
               delta);
      return 0;
    }

    opt[0] = 0xe0;
    opt[++skip] = ((delta - 269) >> 8) & 0xff;
    opt[++skip] = (delta - 269) & 0xff;
  }

  if (length < 13) {
    opt[0] |= length & 0x0f;
  } else if (length < 269) {
    if (maxlen < skip + 2) {
      coap_log(LOG_DEBUG, "insufficient space to encode option length %zu\n",
               length);
      return 0;
    }

    opt[0] |= 0x0d;
    opt[++skip] = (coap_opt_t)(length - 13);
  } else {
    if (maxlen < skip + 3) {
      coap_log(LOG_DEBUG, "insufficient space to encode option delta %d\n",
               delta);
      return 0;
    }

    opt[0] |= 0x0e;
    opt[++skip] = ((length - 269) >> 8) & 0xff;
    opt[++skip] = (length - 269) & 0xff;
  }

  return skip + 1;
}

size_t
coap_opt_encode_size(uint16_t delta, size_t length) {
  size_t n = 1;

  if (delta >= 13) {
    if (delta < 269)
      n += 1;
    else
      n += 2;
  }

  if (length >= 13) {
    if (length < 269)
      n += 1;
    else
      n += 2;
  }

  return n + length;
}

size_t
coap_opt_encode(coap_opt_t *opt, size_t maxlen, uint16_t delta,
                const uint8_t *val, size_t length) {
  size_t l = 1;

  l = coap_opt_setheader(opt, maxlen, delta, length);
  assert(l <= maxlen);

  if (!l) {
    coap_log(LOG_DEBUG, "coap_opt_encode: cannot set option header\n");
    return 0;
  }

  maxlen -= l;
  opt += l;

  if (maxlen < length) {
    coap_log(LOG_DEBUG, "coap_opt_encode: option too large for buffer\n");
    return 0;
  }

  if (val)                        /* better be safe here */
    memcpy(opt, val, length);

  return l + length;
}

/* coap_opt_filter_t has the following internal structure: */
typedef struct {
  uint16_t mask;

#define LONG_MASK ((1 << COAP_OPT_FILTER_LONG) - 1)
#define SHORT_MASK \
  (~LONG_MASK & ((1 << (COAP_OPT_FILTER_LONG + COAP_OPT_FILTER_SHORT)) - 1))

  uint16_t long_opts[COAP_OPT_FILTER_LONG];
  uint8_t short_opts[COAP_OPT_FILTER_SHORT];
} opt_filter;

/** Returns true iff @p type denotes an option type larger than 255. */
COAP_STATIC_INLINE int
is_long_option(uint16_t type) { return type > 255; }

/** Operation specifiers for coap_filter_op(). */
enum filter_op_t { FILTER_SET, FILTER_CLEAR, FILTER_GET };

/**
 * Applies @p op on @p filter with respect to @p type. The following
 * operations are defined:
 *
 * FILTER_SET: Store @p type into an empty slot in @p filter. Returns
 * @c 1 on success, or @c 0 if no spare slot was available.
 *
 * FILTER_CLEAR: Remove @p type from filter if it exists.
 *
 * FILTER_GET: Search for @p type in @p filter. Returns @c 1 if found,
 * or @c 0 if not found.
 *
 * @param filter The filter object.
 * @param type   The option type to set, get or clear in @p filter.
 * @param op     The operation to apply to @p filter and @p type.
 *
 * @return 1 on success, and 0 when FILTER_GET yields no
 * hit or no free slot is available to store @p type with FILTER_SET.
 */
static int
coap_option_filter_op(coap_opt_filter_t filter,
                      uint16_t type,
                      enum filter_op_t op) {
  size_t lindex = 0;
  opt_filter *of = (opt_filter *)filter;
  uint16_t nr, mask = 0;

  if (is_long_option(type)) {
    mask = LONG_MASK;

    for (nr = 1; lindex < COAP_OPT_FILTER_LONG; nr <<= 1, lindex++) {

      if (((of->mask & nr) > 0) && (of->long_opts[lindex] == type)) {
        if (op == FILTER_CLEAR) {
          of->mask &= ~nr;
        }

        return 1;
      }
    }
  } else {
    mask = SHORT_MASK;

    for (nr = 1 << COAP_OPT_FILTER_LONG; lindex < COAP_OPT_FILTER_SHORT;
         nr <<= 1, lindex++) {

      if (((of->mask & nr) > 0) && (of->short_opts[lindex] == (type & 0xff))) {
        if (op == FILTER_CLEAR) {
          of->mask &= ~nr;
        }

        return 1;
      }
    }
  }

  /* type was not found, so there is nothing to do if op is CLEAR or GET */
  if ((op == FILTER_CLEAR) || (op == FILTER_GET)) {
    return 0;
  }

  /* handle FILTER_SET: */

  lindex = coap_fls(~of->mask & mask);
  if (!lindex) {
    return 0;
  }

  if (is_long_option(type)) {
    of->long_opts[lindex - 1] = type;
  } else {
    of->short_opts[lindex - COAP_OPT_FILTER_LONG - 1] = (uint8_t)type;
  }

  of->mask |= 1 << (lindex - 1);

  return 1;
}

int
coap_option_filter_set(coap_opt_filter_t filter, uint16_t type) {
  return coap_option_filter_op(filter, type, FILTER_SET);
}

int
coap_option_filter_unset(coap_opt_filter_t filter, uint16_t type) {
  return coap_option_filter_op(filter, type, FILTER_CLEAR);
}

int
coap_option_filter_get(coap_opt_filter_t filter, uint16_t type) {
  /* Ugly cast to make the const go away (FILTER_GET wont change filter
   * but as _set and _unset do, the function does not take a const). */
  return coap_option_filter_op((uint16_t *)filter, type, FILTER_GET);
}

coap_optlist_t *
coap_new_optlist(uint16_t number,
                          size_t length,
                          const uint8_t *data
) {
  coap_optlist_t *node;

  node = coap_malloc_type(COAP_OPTLIST, sizeof(coap_optlist_t) + length);

  if (node) {
    memset(node, 0, (sizeof(coap_optlist_t) + length));
    node->number = number;
    node->length = length;
    node->data = (uint8_t *)&node[1];
    memcpy(node->data, data, length);
  } else {
    coap_log(LOG_WARNING, "coap_new_optlist: malloc failure\n");
  }

  return node;
}

static int
order_opts(void *a, void *b) {
  coap_optlist_t *o1 = (coap_optlist_t *)a;
  coap_optlist_t *o2 = (coap_optlist_t *)b;

  if (!a || !b)
    return a < b ? -1 : 1;

  return (int)(o1->number - o2->number);
}

int
coap_add_optlist_pdu(coap_pdu_t *pdu, coap_optlist_t** options) {
  coap_optlist_t *opt;

  if (options && *options) {
    /* sort options for delta encoding */
    LL_SORT((*options), order_opts);

    LL_FOREACH((*options), opt) {
      coap_add_option(pdu, opt->number, opt->length, opt->data);
    }
    return 1;
  }
  return 0;
}

int
coap_insert_optlist(coap_optlist_t **head, coap_optlist_t *node) {
  if (!node) {
    coap_log(LOG_DEBUG, "optlist not provided\n");
  } else {
    /* must append at the list end to avoid re-ordering of
     * options during sort */
    LL_APPEND((*head), node);
  }

  return node != NULL;
}

static int
coap_internal_delete(coap_optlist_t *node) {
  if (node) {
    coap_free_type(COAP_OPTLIST, node);
  }
  return 1;
}

void
coap_delete_optlist(coap_optlist_t *queue) {
  coap_optlist_t *elt, *tmp;

  if (!queue)
    return;

  LL_FOREACH_SAFE(queue, elt, tmp) {
    coap_internal_delete(elt);
  }
}

/* pdu.c -- CoAP message structure
 *
 * Copyright (C) 2010--2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_config.h"

#if defined(HAVE_ASSERT_H) && !defined(assert)
# include <assert.h>
#endif

#if defined(HAVE_LIMITS_H)
#include <limits.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#include "libcoap.h"
#include "coap_debug.h"
#include "pdu.h"
#include "option.h"
#include "encode.h"
#include "mem.h"
#include "coap_session.h"

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif

void
coap_pdu_clear(coap_pdu_t *pdu, size_t size) {
  assert(pdu);
  assert(pdu->token);
  assert(pdu->max_hdr_size >= COAP_PDU_MAX_UDP_HEADER_SIZE);
  if (pdu->alloc_size > size)
    pdu->alloc_size = size;
  pdu->type = 0;
  pdu->code = 0;
  pdu->hdr_size = 0;
  pdu->token_length = 0;
  pdu->tid = 0;
  pdu->max_delta = 0;
  pdu->max_size = size;
  pdu->used_size = 0;
  pdu->data = NULL;
}

#ifdef WITH_LWIP
coap_pdu_t *
coap_pdu_from_pbuf( struct pbuf *pbuf )
{
  coap_pdu_t *pdu;

  if (pbuf == NULL) return NULL;

  LWIP_ASSERT("Can only deal with contiguous PBUFs", pbuf->tot_len == pbuf->len);
  LWIP_ASSERT("coap_read needs to receive an exclusive copy of the incoming pbuf", pbuf->ref == 1);

  pdu = coap_malloc_type(COAP_PDU, sizeof(coap_pdu_t) );
  if (!pdu) {
    pbuf_free(pbuf);
    return NULL;
  }

  pdu->max_hdr_size = COAP_PDU_MAX_UDP_HEADER_SIZE;
  pdu->pbuf = pbuf;
  pdu->token = (uint8_t *)pbuf->payload + pdu->max_hdr_size;
  pdu->alloc_size = pbuf->tot_len - pdu->max_hdr_size;
  coap_pdu_clear(pdu, pdu->alloc_size);

  return pdu;
}
#endif

coap_pdu_t *
coap_pdu_init(uint8_t type, uint8_t code, uint16_t tid, size_t size) {
  coap_pdu_t *pdu;

  pdu = coap_malloc_type(COAP_PDU, sizeof(coap_pdu_t));
  if (!pdu) return NULL;

#if defined(WITH_CONTIKI) || defined(WITH_LWIP)
  assert(size <= COAP_MAX_MESSAGE_SIZE_TCP16 + 4);
  if (size > COAP_MAX_MESSAGE_SIZE_TCP16 + 4)
    return NULL;
  pdu->max_hdr_size = COAP_PDU_MAX_UDP_HEADER_SIZE;
#else
  pdu->max_hdr_size = COAP_PDU_MAX_TCP_HEADER_SIZE;
#endif

#ifdef WITH_LWIP
  pdu->pbuf = pbuf_alloc(PBUF_TRANSPORT, size + pdu->max_hdr_size, PBUF_RAM);
  if (pdu->pbuf == NULL) {
    coap_free_type(COAP_PDU, pdu);
    return NULL;
  }
  pdu->token = (uint8_t *)pdu->pbuf->payload + pdu->max_hdr_size;
#else /* WITH_LWIP */
  uint8_t *buf;
  pdu->alloc_size = min(size, 256);
  buf = coap_malloc_type(COAP_PDU_BUF, pdu->alloc_size + pdu->max_hdr_size);
  if (buf == NULL) {
    coap_free_type(COAP_PDU, pdu);
    return NULL;
  }
  pdu->token = buf + pdu->max_hdr_size;
#endif /* WITH_LWIP */
  coap_pdu_clear(pdu, size);
  pdu->tid = tid;
  pdu->type = type;
  pdu->code = code;
  return pdu;
}

coap_pdu_t *
coap_new_pdu(const struct coap_session_t *session) {
  coap_pdu_t *pdu = coap_pdu_init(0, 0, 0, coap_session_max_pdu_size(session));
#ifndef NDEBUG
  if (!pdu)
    coap_log(LOG_CRIT, "coap_new_pdu: cannot allocate memory for new PDU\n");
#endif
  return pdu;
}

void
coap_delete_pdu(coap_pdu_t *pdu) {
  if (pdu != NULL) {
#ifdef WITH_LWIP
    pbuf_free(pdu->pbuf);
#else
    if (pdu->token != NULL)
      coap_free_type(COAP_PDU_BUF, pdu->token - pdu->max_hdr_size);
#endif
    coap_free_type(COAP_PDU, pdu);
  }
}

int
coap_pdu_resize(coap_pdu_t *pdu, size_t new_size) {
  if (new_size > pdu->alloc_size) {
#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI)
    uint8_t *new_hdr;
    size_t offset;
#endif
    if (pdu->max_size && new_size > pdu->max_size) {
      coap_log(LOG_WARNING, "coap_pdu_resize: pdu too big\n");
      return 0;
    }
#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI)
    if (pdu->data != NULL) {
      assert(pdu->data > pdu->token);
      offset = pdu->data - pdu->token;
    } else {
      offset = 0;
    }
    new_hdr = (uint8_t*)realloc(pdu->token - pdu->max_hdr_size, new_size + pdu->max_hdr_size);
    if (new_hdr == NULL) {
      coap_log(LOG_WARNING, "coap_pdu_resize: realloc failed\n");
      return 0;
    }
    pdu->token = new_hdr + pdu->max_hdr_size;
    if (offset > 0)
      pdu->data = pdu->token + offset;
    else
      pdu->data = NULL;
#endif
  }
  pdu->alloc_size = new_size;
  return 1;
}

static int
coap_pdu_check_resize(coap_pdu_t *pdu, size_t size) {
  if (size > pdu->alloc_size) {
    size_t new_size = max(256, pdu->alloc_size * 2);
    while (size > new_size)
      new_size *= 2;
    if (pdu->max_size && new_size > pdu->max_size) {
      new_size = pdu->max_size;
      if (new_size < size)
        return 0;
    }
    if (!coap_pdu_resize(pdu, new_size))
      return 0;
  }
  return 1;
}

int
coap_add_token(coap_pdu_t *pdu, size_t len, const uint8_t *data) {
  /* must allow for pdu == NULL as callers may rely on this */
  if (!pdu || len > 8)
    return 0;

  if (pdu->used_size) {
    coap_log(LOG_WARNING,
             "coap_add_token: The token must defined first. Token ignored\n");
    return 0;
  }
  if (!coap_pdu_check_resize(pdu, len))
    return 0;
  pdu->token_length = (uint8_t)len;
  if (len)
    memcpy(pdu->token, data, len);
  pdu->max_delta = 0;
  pdu->used_size = len;
  pdu->data = NULL;

  return 1;
}

/* FIXME: de-duplicate code with coap_add_option_later */
size_t
coap_add_option(coap_pdu_t *pdu, uint16_t type, size_t len, const uint8_t *data) {
  size_t optsize;
  coap_opt_t *opt;

  assert(pdu);
  pdu->data = NULL;

  if (type < pdu->max_delta) {
    coap_log(LOG_WARNING,
             "coap_add_option: options are not in correct order\n");
    return 0;
  }

  if (!coap_pdu_check_resize(pdu,
      pdu->used_size + coap_opt_encode_size(type - pdu->max_delta, len)))
    return 0;

  opt = pdu->token + pdu->used_size;

  /* encode option and check length */
  optsize = coap_opt_encode(opt, pdu->alloc_size - pdu->used_size,
                            type - pdu->max_delta, data, len);

  if (!optsize) {
    coap_log(LOG_WARNING, "coap_add_option: cannot add option\n");
    /* error */
    return 0;
  } else {
    pdu->max_delta = type;
    pdu->used_size += optsize;
  }

  return optsize;
}

/* FIXME: de-duplicate code with coap_add_option */
uint8_t*
coap_add_option_later(coap_pdu_t *pdu, uint16_t type, size_t len) {
  size_t optsize;
  coap_opt_t *opt;

  assert(pdu);
  pdu->data = NULL;

  if (type < pdu->max_delta) {
    coap_log(LOG_WARNING,
             "coap_add_option: options are not in correct order\n");
    return NULL;
  }

  if (!coap_pdu_check_resize(pdu,
      pdu->used_size + coap_opt_encode_size(type - pdu->max_delta, len)))
    return 0;

  opt = pdu->token + pdu->used_size;

  /* encode option and check length */
  optsize = coap_opt_encode(opt, pdu->alloc_size - pdu->used_size,
                            type - pdu->max_delta, NULL, len);

  if (!optsize) {
    coap_log(LOG_WARNING, "coap_add_option: cannot add option\n");
    /* error */
    return NULL;
  } else {
    pdu->max_delta = type;
    pdu->used_size += (uint16_t)optsize;
  }

  return opt + optsize - len;
}

int
coap_add_data(coap_pdu_t *pdu, size_t len, const uint8_t *data) {
  if (len == 0) {
    return 1;
  } else {
    uint8_t *payload = coap_add_data_after(pdu, len);
    if (payload != NULL)
      memcpy(payload, data, len);
    return payload != NULL;
  }
}

uint8_t *
coap_add_data_after(coap_pdu_t *pdu, size_t len) {
  assert(pdu);
  assert(pdu->data == NULL);

  pdu->data = NULL;

  if (len == 0)
    return NULL;

  if (!coap_pdu_resize(pdu, pdu->used_size + len + 1))
    return 0;
  pdu->token[pdu->used_size++] = COAP_PAYLOAD_START;
  pdu->data = pdu->token + pdu->used_size;
  pdu->used_size += len;
  return pdu->data;
}

int
coap_get_data(const coap_pdu_t *pdu, size_t *len, uint8_t **data) {
  assert(pdu);
  assert(len);
  assert(data);

  *data = pdu->data;
  if(pdu->data == NULL) {
     *len = 0;
     return 0;
  }

  *len = pdu->used_size - (pdu->data - pdu->token);

  return 1;
}

#ifndef SHORT_ERROR_RESPONSE
typedef struct {
  unsigned char code;
  const char *phrase;
} error_desc_t;

/* if you change anything here, make sure, that the longest string does not
 * exceed COAP_ERROR_PHRASE_LENGTH. */
error_desc_t coap_error[] = {
  { COAP_RESPONSE_CODE(201), "Created" },
  { COAP_RESPONSE_CODE(202), "Deleted" },
  { COAP_RESPONSE_CODE(203), "Valid" },
  { COAP_RESPONSE_CODE(204), "Changed" },
  { COAP_RESPONSE_CODE(205), "Content" },
  { COAP_RESPONSE_CODE(231), "Continue" },
  { COAP_RESPONSE_CODE(400), "Bad Request" },
  { COAP_RESPONSE_CODE(401), "Unauthorized" },
  { COAP_RESPONSE_CODE(402), "Bad Option" },
  { COAP_RESPONSE_CODE(403), "Forbidden" },
  { COAP_RESPONSE_CODE(404), "Not Found" },
  { COAP_RESPONSE_CODE(405), "Method Not Allowed" },
  { COAP_RESPONSE_CODE(406), "Not Acceptable" },
  { COAP_RESPONSE_CODE(408), "Request Entity Incomplete" },
  { COAP_RESPONSE_CODE(412), "Precondition Failed" },
  { COAP_RESPONSE_CODE(413), "Request Entity Too Large" },
  { COAP_RESPONSE_CODE(415), "Unsupported Content-Format" },
  { COAP_RESPONSE_CODE(500), "Internal Server Error" },
  { COAP_RESPONSE_CODE(501), "Not Implemented" },
  { COAP_RESPONSE_CODE(502), "Bad Gateway" },
  { COAP_RESPONSE_CODE(503), "Service Unavailable" },
  { COAP_RESPONSE_CODE(504), "Gateway Timeout" },
  { COAP_RESPONSE_CODE(505), "Proxying Not Supported" },
  { 0, NULL }                        /* end marker */
};

const char *
coap_response_phrase(unsigned char code) {
  int i;
  for (i = 0; coap_error[i].code; ++i) {
    if (coap_error[i].code == code)
      return coap_error[i].phrase;
  }
  return NULL;
}
#endif

/**
 * Advances *optp to next option if still in PDU. This function
 * returns the number of bytes opt has been advanced or @c 0
 * on error.
 */
static size_t
next_option_safe(coap_opt_t **optp, size_t *length) {
  coap_option_t option;
  size_t optsize;

  assert(optp); assert(*optp);
  assert(length);

  optsize = coap_opt_parse(*optp, *length, &option);
  if (optsize) {
    assert(optsize <= *length);

    *optp += optsize;
    *length -= optsize;
  }

  return optsize;
}

size_t
coap_pdu_parse_header_size(coap_proto_t proto,
                           const uint8_t *data) {
  assert(data);
  size_t header_size = 0;

  if (proto == COAP_PROTO_TCP || proto==COAP_PROTO_TLS) {
    uint8_t len = *data >> 4;
    if (len < 13)
      header_size = 2;
    else if (len==13)
      header_size = 3;
    else if (len==14)
      header_size = 4;
    else
      header_size = 6;
  } else if (proto == COAP_PROTO_UDP || proto==COAP_PROTO_DTLS) {
    header_size = 4;
  }

  return header_size;
}

size_t
coap_pdu_parse_size(coap_proto_t proto,
                    const uint8_t *data,
                    size_t length) {
  assert(data);
  assert(proto == COAP_PROTO_TCP || proto == COAP_PROTO_TLS);
  assert(coap_pdu_parse_header_size(proto, data) <= length );

  size_t size = 0;

  if ((proto == COAP_PROTO_TCP || proto==COAP_PROTO_TLS) && length >= 1) {
    uint8_t len = *data >> 4;
    if (len < 13) {
      size = len;
    } else if (length >= 2) {
      if (len==13) {
        size = (size_t)data[1] + COAP_MESSAGE_SIZE_OFFSET_TCP8;
      } else if (length >= 3) {
        if (len==14) {
          size = ((size_t)data[1] << 8) + data[2] + COAP_MESSAGE_SIZE_OFFSET_TCP16;
        } else if (length >= 5) {
          size = ((size_t)data[1] << 24) + ((size_t)data[2] << 16)
               + ((size_t)data[3] << 8) + data[4] + COAP_MESSAGE_SIZE_OFFSET_TCP32;
        }
      }
    }
    size += data[0] & 0x0f;
  }

  return size;
}

int
coap_pdu_parse_header(coap_pdu_t *pdu, coap_proto_t proto) {
  uint8_t *hdr = pdu->token - pdu->hdr_size;
  if (proto == COAP_PROTO_UDP || proto == COAP_PROTO_DTLS) {
    assert(pdu->hdr_size == 4);
    if ((hdr[0] >> 6) != COAP_DEFAULT_VERSION) {
      coap_log(LOG_DEBUG, "coap_pdu_parse: UDP version not supported\n");
      return 0;
    }
    pdu->type = (hdr[0] >> 4) & 0x03;
    pdu->token_length = hdr[0] & 0x0f;
    pdu->code = hdr[1];
    pdu->tid = (uint16_t)hdr[2] << 8 | hdr[3];
  } else if (proto == COAP_PROTO_TCP || proto == COAP_PROTO_TLS) {
    assert(pdu->hdr_size >= 2 && pdu->hdr_size <= 6);
    pdu->type = COAP_MESSAGE_CON;
    pdu->token_length = hdr[0] & 0x0f;
    pdu->code = hdr[pdu->hdr_size-1];
    pdu->tid = 0;
  } else {
    coap_log(LOG_DEBUG, "coap_pdu_parse: unsupported protocol\n");
    return 0;
  }
  if (pdu->token_length > pdu->alloc_size) {
    /* Invalid PDU provided - not wise to assert here though */
    coap_log(LOG_DEBUG, "coap_pdu_parse: PDU header token size broken\n");
    pdu->token_length = (uint8_t)pdu->alloc_size;
    return 0;
  }
  return 1;
}

int
coap_pdu_parse_opt(coap_pdu_t *pdu) {

  /* sanity checks */
  if (pdu->code == 0) {
    if (pdu->used_size != 0 || pdu->token_length) {
      coap_log(LOG_DEBUG, "coap_pdu_parse: empty message is not empty\n");
      return 0;
    }
  }

  if (pdu->token_length > pdu->used_size || pdu->token_length > 8) {
    coap_log(LOG_DEBUG, "coap_pdu_parse: invalid Token\n");
    return 0;
  }

  if (pdu->code == 0) {
    /* empty packet */
    pdu->used_size = 0;
    pdu->data = NULL;
  } else {
    /* skip header + token */
    coap_opt_t *opt = pdu->token + pdu->token_length;
    size_t length = pdu->used_size - pdu->token_length;

    while (length > 0 && *opt != COAP_PAYLOAD_START) {
      if ( !next_option_safe( &opt, (size_t *)&length ) ) {
        coap_log(LOG_DEBUG, "coap_pdu_parse: missing payload start code\n");
        return 0;
      }
    }

    if (length > 0) {
      assert(*opt == COAP_PAYLOAD_START);
      opt++; length--;

      if (length == 0) {
        coap_log(LOG_DEBUG,
                 "coap_pdu_parse: message ending in payload start marker\n");
        return 0;
      }
    }
    if (length > 0)
                pdu->data = (uint8_t*)opt;
    else
      pdu->data = NULL;
  }

  return 1;
}

int
coap_pdu_parse(coap_proto_t proto,
               const uint8_t *data,
               size_t length,
               coap_pdu_t *pdu)
{
  size_t hdr_size;

  if (length == 0)
    return 0;
  hdr_size = coap_pdu_parse_header_size(proto, data);
  if (!hdr_size || hdr_size > length)
    return 0;
  if (hdr_size > pdu->max_hdr_size)
    return 0;
  if (!coap_pdu_resize(pdu, length - hdr_size))
    return 0;
#ifndef WITH_LWIP
  memcpy(pdu->token - hdr_size, data, length);
#endif
  pdu->hdr_size = (uint8_t)hdr_size;
  pdu->used_size = length - hdr_size;
  return coap_pdu_parse_header(pdu, proto) && coap_pdu_parse_opt(pdu);
}

size_t
coap_pdu_encode_header(coap_pdu_t *pdu, coap_proto_t proto) {
  if (proto == COAP_PROTO_UDP || proto == COAP_PROTO_DTLS) {
    assert(pdu->max_hdr_size >= 4);
    if (pdu->max_hdr_size < 4) {
      coap_log(LOG_WARNING,
           "coap_pdu_encode_header: not enough space for UDP-style header\n");
      return 0;
    }
    pdu->token[-4] = COAP_DEFAULT_VERSION << 6
                   | pdu->type << 4
                   | pdu->token_length;
    pdu->token[-3] = pdu->code;
    pdu->token[-2] = (uint8_t)(pdu->tid >> 8);
    pdu->token[-1] = (uint8_t)(pdu->tid);
    pdu->hdr_size = 4;
  } else if (proto == COAP_PROTO_TCP || proto == COAP_PROTO_TLS) {
    size_t len;
    assert(pdu->used_size >= pdu->token_length);
    if (pdu->used_size < pdu->token_length) {
      coap_log(LOG_WARNING, "coap_pdu_encode_header: corrupted PDU\n");
      return 0;
    }
    len = pdu->used_size - pdu->token_length;
    if (len <= COAP_MAX_MESSAGE_SIZE_TCP0) {
      assert(pdu->max_hdr_size >= 2);
      if (pdu->max_hdr_size < 2) {
        coap_log(LOG_WARNING,
              "coap_pdu_encode_header: not enough space for TCP0 header\n");
        return 0;
      }
      pdu->token[-2] = (uint8_t)len << 4
                     | pdu->token_length;
      pdu->token[-1] = pdu->code;
      pdu->hdr_size = 2;
    } else if (len <= COAP_MAX_MESSAGE_SIZE_TCP8) {
      assert(pdu->max_hdr_size >= 3);
      if (pdu->max_hdr_size < 3) {
        coap_log(LOG_WARNING,
              "coap_pdu_encode_header: not enough space for TCP8 header\n");
        return 0;
      }
      pdu->token[-3] = 13 << 4 | pdu->token_length;
      pdu->token[-2] = (uint8_t)(len - COAP_MESSAGE_SIZE_OFFSET_TCP8);
      pdu->token[-1] = pdu->code;
      pdu->hdr_size = 3;
    } else if (len <= COAP_MAX_MESSAGE_SIZE_TCP16) {
      assert(pdu->max_hdr_size >= 4);
      if (pdu->max_hdr_size < 4) {
        coap_log(LOG_WARNING,
              "coap_pdu_encode_header: not enough space for TCP16 header\n");
        return 0;
      }
      pdu->token[-4] = 14 << 4 | pdu->token_length;
      pdu->token[-3] = (uint8_t)((len - COAP_MESSAGE_SIZE_OFFSET_TCP16) >> 8);
      pdu->token[-2] = (uint8_t)(len - COAP_MESSAGE_SIZE_OFFSET_TCP16);
      pdu->token[-1] = pdu->code;
      pdu->hdr_size = 4;
    } else {
      assert(pdu->max_hdr_size >= 6);
      if (pdu->max_hdr_size < 6) {
        coap_log(LOG_WARNING,
              "coap_pdu_encode_header: not enough space for TCP32 header\n");
        return 0;
      }
      pdu->token[-6] = 15 << 4 | pdu->token_length;
      pdu->token[-5] = (uint8_t)((len - COAP_MESSAGE_SIZE_OFFSET_TCP32) >> 24);
      pdu->token[-4] = (uint8_t)((len - COAP_MESSAGE_SIZE_OFFSET_TCP32) >> 16);
      pdu->token[-3] = (uint8_t)((len - COAP_MESSAGE_SIZE_OFFSET_TCP32) >> 8);
      pdu->token[-2] = (uint8_t)(len - COAP_MESSAGE_SIZE_OFFSET_TCP32);
      pdu->token[-1] = pdu->code;
      pdu->hdr_size = 6;
    }
  } else {
    coap_log(LOG_WARNING, "coap_pdu_encode_header: unsupported protocol\n");
  }
  return pdu->hdr_size;
}
/* resource.c -- generic resource handling
 *
 * Copyright (C) 2010--2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include <stdio.h>
#include "coap_config.h"
#include "coap.h"
#include "coap_debug.h"
#include "mem.h"
#include "net.h"
#include "resource.h"
#include "subscribe.h"
#include "utlist.h"

#if defined(WITH_LWIP)
/* mem.h is only needed for the string free calls for
 * COAP_ATTR_FLAGS_RELEASE_NAME / COAP_ATTR_FLAGS_RELEASE_VALUE /
 * COAP_RESOURCE_FLAGS_RELEASE_URI. not sure what those lines should actually
 * do on lwip. */

#include <lwip/memp.h>

#define COAP_MALLOC_TYPE(Type) \
  ((coap_##Type##_t *)memp_malloc(MEMP_COAP_##Type))
#define COAP_FREE_TYPE(Type, Object) memp_free(MEMP_COAP_##Type, Object)

#elif defined(WITH_CONTIKI)
#include "memb.h"

#define COAP_MALLOC_TYPE(Type) \
  ((coap_##Type##_t *)memb_alloc(&(Type##_storage)))
#define COAP_FREE_TYPE(Type, Object) memb_free(&(Type##_storage), (Object))

MEMB(subscription_storage, coap_subscription_t, COAP_MAX_SUBSCRIBERS);

void
coap_resources_init() {
  memb_init(&subscription_storage);
}

COAP_STATIC_INLINE coap_subscription_t *
coap_malloc_subscription() {
  return memb_alloc(&subscription_storage);
}

COAP_STATIC_INLINE void
coap_free_subscription(coap_subscription_t *subscription) {
  memb_free(&subscription_storage, subscription);
}

#else
#define COAP_MALLOC_TYPE(Type) \
  ((coap_##Type##_t *)coap_malloc(sizeof(coap_##Type##_t)))
#define COAP_FREE_TYPE(Type, Object) coap_free(Object)
#endif

#define COAP_PRINT_STATUS_MAX (~COAP_PRINT_STATUS_MASK)

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

/* Helper functions for conditional output of character sequences into
 * a given buffer. The first Offset characters are skipped.
 */

/**
 * Adds Char to Buf if Offset is zero. Otherwise, Char is not written
 * and Offset is decremented.
 */
#define PRINT_WITH_OFFSET(Buf,Offset,Char)                \
  if ((Offset) == 0) {                                        \
    (*(Buf)++) = (Char);                                \
  } else {                                                \
    (Offset)--;                                                \
  }                                                        \

/**
 * Adds Char to Buf if Offset is zero and Buf is less than Bufend.
 */
#define PRINT_COND_WITH_OFFSET(Buf,Bufend,Offset,Char,Result) {                \
    if ((Buf) < (Bufend)) {                                                \
      PRINT_WITH_OFFSET(Buf,Offset,Char);                                \
    }                                                                        \
    (Result)++;                                                                \
  }

/**
 * Copies at most Length characters of Str to Buf. The first Offset
 * characters are skipped. Output may be truncated to Bufend - Buf
 * characters.
 */
#define COPY_COND_WITH_OFFSET(Buf,Bufend,Offset,Str,Length,Result) {        \
    size_t i;                                                                \
    for (i = 0; i < (Length); i++) {                                        \
      PRINT_COND_WITH_OFFSET((Buf), (Bufend), (Offset), (Str)[i], (Result)); \
    }                                                                        \
  }

static int
match(const coap_str_const_t *text, const coap_str_const_t *pattern, int match_prefix,
  int match_substring
) {
  assert(text); assert(pattern);

  if (text->length < pattern->length)
    return 0;

  if (match_substring) {
    const uint8_t *next_token = text->s;
    size_t remaining_length = text->length;
    while (remaining_length) {
      size_t token_length;
      const uint8_t *token = next_token;
      next_token = (unsigned char *)memchr(token, ' ', remaining_length);

      if (next_token) {
        token_length = next_token - token;
        remaining_length -= (token_length + 1);
        next_token++;
      } else {
        token_length = remaining_length;
        remaining_length = 0;
      }

      if ((match_prefix || pattern->length == token_length) &&
            memcmp(token, pattern->s, pattern->length) == 0)
        return 1;
    }
    return 0;
  }

  return (match_prefix || pattern->length == text->length) &&
    memcmp(text->s, pattern->s, pattern->length) == 0;
}

/**
 * Prints the names of all known resources to @p buf. This function
 * sets @p buflen to the number of bytes actually written and returns
 * @c 1 on succes. On error, the value in @p buflen is undefined and
 * the return value will be @c 0.
 *
 * @param context The context with the resource map.
 * @param buf     The buffer to write the result.
 * @param buflen  Must be initialized to the maximum length of @p buf and will be
 *                set to the length of the well-known response on return.
 * @param offset  The offset in bytes where the output shall start and is
 *                shifted accordingly with the characters that have been
 *                processed. This parameter is used to support the block
 *                option.
 * @param query_filter A filter query according to <a href="http://tools.ietf.org/html/draft-ietf-core-link-format-11#section-4.1">Link Format</a>
 *
 * @return COAP_PRINT_STATUS_ERROR on error. Otherwise, the lower 28 bits are
 *         set to the number of bytes that have actually been written to
 *         @p buf. COAP_PRINT_STATUS_TRUNC is set when the output has been
 *         truncated.
 */
#if defined(__GNUC__) && defined(WITHOUT_QUERY_FILTER)
coap_print_status_t
coap_print_wellknown(coap_context_t *context, unsigned char *buf, size_t *buflen,
                size_t offset,
                coap_opt_t *query_filter __attribute__ ((unused))) {
#else /* not a GCC */
coap_print_status_t
coap_print_wellknown(coap_context_t *context, unsigned char *buf, size_t *buflen,
                size_t offset, coap_opt_t *query_filter) {
#endif /* GCC */
  size_t output_length = 0;
  unsigned char *p = buf;
  const uint8_t *bufend = buf + *buflen;
  size_t left, written = 0;
  coap_print_status_t result;
  const size_t old_offset = offset;
  int subsequent_resource = 0;
#ifndef WITHOUT_QUERY_FILTER
  coap_str_const_t resource_param = { 0, NULL }, query_pattern = { 0, NULL };
  int flags = 0; /* MATCH_SUBSTRING, MATCH_PREFIX, MATCH_URI */
#define MATCH_URI       0x01
#define MATCH_PREFIX    0x02
#define MATCH_SUBSTRING 0x04
  static const coap_str_const_t _rt_attributes[] = {
    {2, (const uint8_t *)"rt"},
    {2, (const uint8_t *)"if"},
    {3, (const uint8_t *)"rel"},
    {0, NULL}};
#endif /* WITHOUT_QUERY_FILTER */

#ifndef WITHOUT_QUERY_FILTER
  /* split query filter, if any */
  if (query_filter) {
    resource_param.s = coap_opt_value(query_filter);
    while (resource_param.length < coap_opt_length(query_filter)
           && resource_param.s[resource_param.length] != '=')
      resource_param.length++;

    if (resource_param.length < coap_opt_length(query_filter)) {
      const coap_str_const_t *rt_attributes;
      if (resource_param.length == 4 &&
          memcmp(resource_param.s, "href", 4) == 0)
        flags |= MATCH_URI;

      for (rt_attributes = _rt_attributes; rt_attributes->s; rt_attributes++) {
        if (resource_param.length == rt_attributes->length &&
            memcmp(resource_param.s, rt_attributes->s, rt_attributes->length) == 0) {
          flags |= MATCH_SUBSTRING;
          break;
        }
      }

      /* rest is query-pattern */
      query_pattern.s =
        coap_opt_value(query_filter) + resource_param.length + 1;

      assert((resource_param.length + 1) <= coap_opt_length(query_filter));
      query_pattern.length =
        coap_opt_length(query_filter) - (resource_param.length + 1);

     if ((query_pattern.s[0] == '/') && ((flags & MATCH_URI) == MATCH_URI)) {
       query_pattern.s++;
       query_pattern.length--;
      }

      if (query_pattern.length &&
          query_pattern.s[query_pattern.length-1] == '*') {
        query_pattern.length--;
        flags |= MATCH_PREFIX;
      }
    }
  }
#endif /* WITHOUT_QUERY_FILTER */

  RESOURCES_ITER(context->resources, r) {

#ifndef WITHOUT_QUERY_FILTER
    if (resource_param.length) { /* there is a query filter */

      if (flags & MATCH_URI) {        /* match resource URI */
        if (!match(r->uri_path, &query_pattern, (flags & MATCH_PREFIX) != 0,
            (flags & MATCH_SUBSTRING) != 0))
          continue;
      } else {                        /* match attribute */
        coap_attr_t *attr;
        coap_str_const_t unquoted_val;
        attr = coap_find_attr(r, &resource_param);
        if (!attr || !attr->value) continue;
        unquoted_val = *attr->value;
        if (attr->value->s[0] == '"') {          /* if attribute has a quoted value, remove double quotes */
          unquoted_val.length -= 2;
          unquoted_val.s += 1;
        }
        if (!(match(&unquoted_val, &query_pattern,
                    (flags & MATCH_PREFIX) != 0,
                    (flags & MATCH_SUBSTRING) != 0)))
          continue;
      }
    }
#endif /* WITHOUT_QUERY_FILTER */

    if (!subsequent_resource) {        /* this is the first resource  */
      subsequent_resource = 1;
    } else {
      PRINT_COND_WITH_OFFSET(p, bufend, offset, ',', written);
    }

    left = bufend - p; /* calculate available space */
    result = coap_print_link(r, p, &left, &offset);

    if (result & COAP_PRINT_STATUS_ERROR) {
      break;
    }

    /* coap_print_link() returns the number of characters that
     * where actually written to p. Now advance to its end. */
    p += COAP_PRINT_OUTPUT_LENGTH(result);
    written += left;
  }

  *buflen = written;
  output_length = p - buf;

  if (output_length > COAP_PRINT_STATUS_MAX) {
    return COAP_PRINT_STATUS_ERROR;
  }

  result = (coap_print_status_t)output_length;

  if (result + old_offset - offset < *buflen) {
    result |= COAP_PRINT_STATUS_TRUNC;
  }
  return result;
}

static coap_str_const_t *null_path = coap_make_str_const("");

coap_resource_t *
coap_resource_init(coap_str_const_t *uri_path, int flags) {
  coap_resource_t *r;

  r = (coap_resource_t *)coap_malloc_type(COAP_RESOURCE, sizeof(coap_resource_t));
  if (r) {
    memset(r, 0, sizeof(coap_resource_t));

    if (!(flags & COAP_RESOURCE_FLAGS_RELEASE_URI)) {
      /* Need to take a copy if caller is not providing a release request */
      if (uri_path)
        uri_path = coap_new_str_const(uri_path->s, uri_path->length);
      else
        uri_path = coap_new_str_const(null_path->s, null_path->length);
    }
    else if (!uri_path) {
      /* Do not expecte this, but ... */
      uri_path = coap_new_str_const(null_path->s, null_path->length);
    }

    if (uri_path)
      r->uri_path = uri_path;

    r->flags = flags;
  } else {
    coap_log(LOG_DEBUG, "coap_resource_init: no memory left\n");
  }

  return r;
}

static const uint8_t coap_unknown_resource_uri[] =
                       "- Unknown -";

coap_resource_t *
coap_resource_unknown_init(coap_method_handler_t put_handler) {
  coap_resource_t *r;

  r = (coap_resource_t *)coap_malloc_type(COAP_RESOURCE, sizeof(coap_resource_t));
  if (r) {
    memset(r, 0, sizeof(coap_resource_t));
    r->is_unknown = 1;
    /* Something unlikely to be used, but it shows up in the logs */
    r->uri_path = coap_new_str_const(coap_unknown_resource_uri, sizeof(coap_unknown_resource_uri)-1);
    coap_register_handler(r, COAP_REQUEST_PUT, put_handler);
  } else {
    coap_log(LOG_DEBUG, "coap_resource_unknown_init: no memory left\n");
  }

  return r;
}

coap_attr_t *
coap_add_attr(coap_resource_t *resource,
              coap_str_const_t *name,
              coap_str_const_t *val,
              int flags) {
  coap_attr_t *attr;

  if (!resource || !name)
    return NULL;

  attr = (coap_attr_t *)coap_malloc_type(COAP_RESOURCEATTR, sizeof(coap_attr_t));

  if (attr) {
    if (!(flags & COAP_ATTR_FLAGS_RELEASE_NAME)) {
      /* Need to take a copy if caller is not providing a release request */
      name = coap_new_str_const(name->s, name->length);
    }
    attr->name = name;
    if (val) {
      if (!(flags & COAP_ATTR_FLAGS_RELEASE_VALUE)) {
        /* Need to take a copy if caller is not providing a release request */
        val = coap_new_str_const(val->s, val->length);
      }
    }
    attr->value = val;

    attr->flags = flags;

    /* add attribute to resource list */
    LL_PREPEND(resource->link_attr, attr);
  } else {
    coap_log(LOG_DEBUG, "coap_add_attr: no memory left\n");
  }

  return attr;
}

coap_attr_t *
coap_find_attr(coap_resource_t *resource,
               coap_str_const_t *name) {
  coap_attr_t *attr;

  if (!resource || !name)
    return NULL;

  LL_FOREACH(resource->link_attr, attr) {
    if (attr->name->length == name->length &&
        memcmp(attr->name->s, name->s, name->length) == 0)
      return attr;
  }

  return NULL;
}

void
coap_delete_attr(coap_attr_t *attr) {
  if (!attr)
    return;
  coap_delete_str_const(attr->name);
  if (attr->value) {
    coap_delete_str_const(attr->value);
  }

#ifdef WITH_LWIP
  memp_free(MEMP_COAP_RESOURCEATTR, attr);
#endif
#ifndef WITH_LWIP
  coap_free_type(COAP_RESOURCEATTR, attr);
#endif
}

static void
coap_free_resource(coap_resource_t *resource) {
  coap_attr_t *attr, *tmp;
  coap_subscription_t *obs, *otmp;

  assert(resource);

  /* delete registered attributes */
  LL_FOREACH_SAFE(resource->link_attr, attr, tmp) coap_delete_attr(attr);

  /* Either the application provided or libcoap copied - need to delete it */
  coap_delete_str_const(resource->uri_path);

  /* free all elements from resource->subscribers */
  LL_FOREACH_SAFE( resource->subscribers, obs, otmp ) {
    coap_session_release( obs->session );
    if (obs->query)
      coap_delete_string(obs->query);
    COAP_FREE_TYPE( subscription, obs );
  }

#ifdef WITH_LWIP
  memp_free(MEMP_COAP_RESOURCE, resource);
#endif
#ifndef WITH_LWIP
  coap_free_type(COAP_RESOURCE, resource);
#endif /* WITH_CONTIKI */
}

void
coap_add_resource(coap_context_t *context, coap_resource_t *resource) {
  if (resource->is_unknown) {
    if (context->unknown_resource)
      coap_free_resource(context->unknown_resource);
    context->unknown_resource = resource;
  }
  else {
    coap_resource_t *r = coap_get_resource_from_uri_path(context,
                                                         resource->uri_path);

    if (r) {
      coap_log(LOG_WARNING,
        "coap_add_resource: Duplicate uri_path '%*.*s', old resource deleted\n",
              (int)resource->uri_path->length, (int)resource->uri_path->length,
              resource->uri_path->s);
      coap_delete_resource(context, r);
    }
    RESOURCES_ADD(context->resources, resource);
  }
}

int
coap_delete_resource(coap_context_t *context, coap_resource_t *resource) {
  if (!context || !resource)
    return 0;

  if (resource->is_unknown && (context->unknown_resource == resource)) {
    coap_free_resource(context->unknown_resource);
    context->unknown_resource = NULL;
    return 1;
  }

  /* remove resource from list */
  RESOURCES_DELETE(context->resources, resource);

  /* and free its allocated memory */
  coap_free_resource(resource);

  return 1;
}

void
coap_delete_all_resources(coap_context_t *context) {
  coap_resource_t *res;
  coap_resource_t *rtmp;

  /* Cannot call RESOURCES_ITER because coap_free_resource() releases
   * the allocated storage. */

  HASH_ITER(hh, context->resources, res, rtmp) {
    HASH_DELETE(hh, context->resources, res);
    coap_free_resource(res);
  }

  context->resources = NULL;

  if (context->unknown_resource) {
    coap_free_resource(context->unknown_resource);
    context->unknown_resource = NULL;
  }
}

coap_resource_t *
coap_get_resource_from_uri_path(coap_context_t *context, coap_str_const_t *uri_path) {
  coap_resource_t *result;

  RESOURCES_FIND(context->resources, uri_path, result);

  return result;
}

coap_print_status_t
coap_print_link(const coap_resource_t *resource,
                unsigned char *buf, size_t *len, size_t *offset) {
  unsigned char *p = buf;
  const uint8_t *bufend = buf + *len;
  coap_attr_t *attr;
  coap_print_status_t result = 0;
  size_t output_length = 0;
  const size_t old_offset = *offset;

  *len = 0;
  PRINT_COND_WITH_OFFSET(p, bufend, *offset, '<', *len);
  PRINT_COND_WITH_OFFSET(p, bufend, *offset, '/', *len);

  COPY_COND_WITH_OFFSET(p, bufend, *offset,
                        resource->uri_path->s, resource->uri_path->length, *len);

  PRINT_COND_WITH_OFFSET(p, bufend, *offset, '>', *len);

  LL_FOREACH(resource->link_attr, attr) {

    PRINT_COND_WITH_OFFSET(p, bufend, *offset, ';', *len);

    COPY_COND_WITH_OFFSET(p, bufend, *offset,
                          attr->name->s, attr->name->length, *len);

    if (attr->value && attr->value->s) {
      PRINT_COND_WITH_OFFSET(p, bufend, *offset, '=', *len);

      COPY_COND_WITH_OFFSET(p, bufend, *offset,
                            attr->value->s, attr->value->length, *len);
    }

  }
  if (resource->observable) {
    COPY_COND_WITH_OFFSET(p, bufend, *offset, ";obs", 4, *len);
  }

  output_length = p - buf;

  if (output_length > COAP_PRINT_STATUS_MAX) {
    return COAP_PRINT_STATUS_ERROR;
  }

  result = (coap_print_status_t)output_length;

  if (result + old_offset - *offset < *len) {
    result |= COAP_PRINT_STATUS_TRUNC;
  }

  return result;
}

void
coap_register_handler(coap_resource_t *resource,
                      unsigned char method,
                      coap_method_handler_t handler) {
  assert(resource);
  assert(method > 0 && (size_t)(method-1) < sizeof(resource->handler)/sizeof(coap_method_handler_t));
  resource->handler[method-1] = handler;
}

#ifndef WITHOUT_OBSERVE
coap_subscription_t *
coap_find_observer(coap_resource_t *resource, coap_session_t *session,
                     const coap_binary_t *token) {
  coap_subscription_t *s;

  assert(resource);
  assert(session);

  LL_FOREACH(resource->subscribers, s) {
    if (s->session == session
        && (!token || (token->length == s->token_length
                       && memcmp(token->s, s->token, token->length) == 0)))
      return s;
  }

  return NULL;
}

static coap_subscription_t *
coap_find_observer_query(coap_resource_t *resource, coap_session_t *session,
                     const coap_string_t *query) {
  coap_subscription_t *s;

  assert(resource);
  assert(session);

  LL_FOREACH(resource->subscribers, s) {
    if (s->session == session
        && ((!query && !s->query)
             || (query && s->query && coap_string_equal(query, s->query))))
      return s;
  }

  return NULL;
}

coap_subscription_t *
coap_add_observer(coap_resource_t *resource,
                  coap_session_t *session,
                  const coap_binary_t *token,
                  coap_string_t *query,
                  int has_block2,
                  coap_block_t block2) {
  coap_subscription_t *s;

  assert( session );

  /* Check if there is already a subscription for this peer. */
  s = coap_find_observer(resource, session, token);
  if (!s) {
    /*
     * Cannot allow a duplicate to be created for the same query as application
     * may not be cleaning up duplicates.  If duplicate found, then original
     * observer is deleted and a new one created with the new token
     */
    s = coap_find_observer_query(resource, session, query);
    if (s) {
      /* Delete old entry with old token */
      coap_binary_t tmp_token = { s->token_length, s->token };
      coap_delete_observer(resource, session, &tmp_token);
      s = NULL;
    }
  }

  /* We are done if subscription was found. */
  if (s) {
    if (s->query)
      coap_delete_string(s->query);
    s->query = query;
    return s;
  }

  /* s points to a different subscription, so we have to create
   * another one. */
  s = COAP_MALLOC_TYPE(subscription);

  if (!s) {
    if (query)
      coap_delete_string(query);
    return NULL;
  }

  coap_subscription_init(s);
  s->session = coap_session_reference( session );

  if (token && token->length) {
    s->token_length = token->length;
    memcpy(s->token, token->s, min(s->token_length, 8));
  }

  s->query = query;

  s->has_block2 = has_block2;
  s->block2 = block2;

  /* add subscriber to resource */
  LL_PREPEND(resource->subscribers, s);

  coap_log(LOG_DEBUG, "create new subscription\n");

  return s;
}

void
coap_touch_observer(coap_context_t *context, coap_session_t *session,
                    const coap_binary_t *token) {
  coap_subscription_t *s;

  RESOURCES_ITER(context->resources, r) {
    s = coap_find_observer(r, session, token);
    if (s) {
      s->fail_cnt = 0;
    }
  }
}

int
coap_delete_observer(coap_resource_t *resource, coap_session_t *session,
                     const coap_binary_t *token) {
  coap_subscription_t *s;

  s = coap_find_observer(resource, session, token);

  if ( s && coap_get_log_level() >= LOG_DEBUG ) {
    char outbuf[2 * 8 + 1] = "";
    unsigned int i;
    for ( i = 0; i < s->token_length; i++ )
      snprintf( &outbuf[2 * i], 3, "%02x", s->token[i] );
    coap_log(LOG_DEBUG, "removed observer tid %s\n", outbuf);
  }

  if (resource->subscribers && s) {
    LL_DELETE(resource->subscribers, s);
    coap_session_release( session );
    if (s->query)
      coap_delete_string(s->query);
    COAP_FREE_TYPE(subscription,s);
  }

  return s != NULL;
}

void
coap_delete_observers(coap_context_t *context, coap_session_t *session) {
  RESOURCES_ITER(context->resources, resource) {
    coap_subscription_t *s, *tmp;
    LL_FOREACH_SAFE(resource->subscribers, s, tmp) {
      if (s->session == session) {
        LL_DELETE(resource->subscribers, s);
        coap_session_release(session);
        if (s->query)
          coap_delete_string(s->query);
        COAP_FREE_TYPE(subscription, s);
      }
    }
  }
}

static void
coap_notify_observers(coap_context_t *context, coap_resource_t *r) {
  coap_method_handler_t h;
  coap_subscription_t *obs;
  coap_binary_t token;
  coap_pdu_t *response;

  if (r->observable && (r->dirty || r->partiallydirty)) {
    r->partiallydirty = 0;

    /* retrieve GET handler, prepare response */
    h = r->handler[COAP_REQUEST_GET - 1];
    assert(h);                /* we do not allow subscriptions if no
                         * GET handler is defined */

    LL_FOREACH(r->subscribers, obs) {
      if (r->dirty == 0 && obs->dirty == 0)
        /*
         * running this resource due to partiallydirty, but this observation's
         * notification was already enqueued
         */
        continue;
      if (obs->session->con_active >= COAP_DEFAULT_NSTART &&
          ((r->flags & COAP_RESOURCE_FLAGS_NOTIFY_CON) ||
           (obs->non_cnt >= COAP_OBS_MAX_NON)))
        continue;

      coap_tid_t tid = COAP_INVALID_TID;
      obs->dirty = 0;
      /* initialize response */
      response = coap_pdu_init(COAP_MESSAGE_CON, 0, 0, coap_session_max_pdu_size(obs->session));
      if (!response) {
        obs->dirty = 1;
        r->partiallydirty = 1;
        coap_log(LOG_DEBUG,
                 "coap_check_notify: pdu init failed, resource stays "
                 "partially dirty\n");
        continue;
      }

      if (!coap_add_token(response, obs->token_length, obs->token)) {
        obs->dirty = 1;
        r->partiallydirty = 1;
        coap_log(LOG_DEBUG,
                 "coap_check_notify: cannot add token, resource stays "
                 "partially dirty\n");
        coap_delete_pdu(response);
        continue;
      }

      token.length = obs->token_length;
      token.s = obs->token;

      response->tid = coap_new_message_id(obs->session);
      if ((r->flags & COAP_RESOURCE_FLAGS_NOTIFY_CON) == 0
          && obs->non_cnt < COAP_OBS_MAX_NON) {
        response->type = COAP_MESSAGE_NON;
      } else {
        response->type = COAP_MESSAGE_CON;
      }
      /* fill with observer-specific data */
      h(context, r, obs->session, NULL, &token, obs->query, response);

      /* TODO: do not send response and remove observer when
       *  COAP_RESPONSE_CLASS(response->hdr->code) > 2
       */
      if (response->type == COAP_MESSAGE_CON) {
        obs->non_cnt = 0;
      } else {
        obs->non_cnt++;
      }

      tid = coap_send( obs->session, response );

      if (COAP_INVALID_TID == tid) {
        coap_log(LOG_DEBUG,
                 "coap_check_notify: sending failed, resource stays "
                 "partially dirty\n");
        obs->dirty = 1;
        r->partiallydirty = 1;
      }

    }
  }
  r->dirty = 0;
}

int
coap_resource_set_dirty(coap_resource_t *r, const coap_string_t *query) {
  return coap_resource_notify_observers(r, query);
}

int
coap_resource_notify_observers(coap_resource_t *r, const coap_string_t *query) {
  if (!r->observable)
    return 0;
  if (query) {
    coap_subscription_t *obs;
    int found = 0;
    LL_FOREACH(r->subscribers, obs) {
      if (obs->query
       && obs->query->length==query->length
       && memcmp(obs->query->s, query->s, query->length)==0 ) {
        found = 1;
        if (!r->dirty && !obs->dirty) {
          obs->dirty = 1;
          r->partiallydirty = 1;
        }
      }
    }
    if (!found)
      return 0;
  } else {
    if ( !r->subscribers )
      return 0;
    r->dirty = 1;
  }

  /* Increment value for next Observe use. Observe value must be < 2^24 */
  r->observe = (r->observe + 1) & 0xFFFFFF;

  return 1;
}

void
coap_check_notify(coap_context_t *context) {

  RESOURCES_ITER(context->resources, r) {
    coap_notify_observers(context, r);
  }
}

/**
 * Checks the failure counter for (peer, token) and removes peer from
 * the list of observers for the given resource when COAP_OBS_MAX_FAIL
 * is reached.
 *
 * @param context  The CoAP context to use
 * @param resource The resource to check for (peer, token)
 * @param session  The observer's session
 * @param token    The token that has been used for subscription.
 */
static void
coap_remove_failed_observers(coap_context_t *context,
                             coap_resource_t *resource,
                             coap_session_t *session,
                             const coap_binary_t *token) {
  coap_subscription_t *obs, *otmp;

  LL_FOREACH_SAFE(resource->subscribers, obs, otmp) {
    if ( obs->session == session &&
        token->length == obs->token_length &&
        memcmp(token->s, obs->token, token->length) == 0) {

      /* count failed notifies and remove when
       * COAP_MAX_FAILED_NOTIFY is reached */
      if (obs->fail_cnt < COAP_OBS_MAX_FAIL)
        obs->fail_cnt++;
      else {
        LL_DELETE(resource->subscribers, obs);
        obs->fail_cnt = 0;

#ifndef NDEBUG
        if (LOG_DEBUG <= coap_get_log_level()) {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif
          unsigned char addr[INET6_ADDRSTRLEN+8];

          if (coap_print_addr(&obs->session->remote_addr, addr, INET6_ADDRSTRLEN+8))
            coap_log(LOG_DEBUG, "** removed observer %s\n", addr);
        }
#endif
        coap_cancel_all_messages(context, obs->session,
                                 obs->token, obs->token_length);
        coap_session_release( obs->session );
        if (obs->query)
          coap_delete_string(obs->query);
        COAP_FREE_TYPE(subscription, obs);
      }
      break;                        /* break loop if observer was found */
    }
  }
}

void
coap_handle_failed_notify(coap_context_t *context,
                          coap_session_t *session,
                          const coap_binary_t *token) {

  RESOURCES_ITER(context->resources, r) {
        coap_remove_failed_observers(context, r, session, token);
  }
}
#endif /* WITHOUT_NOTIFY */
/* str.c -- strings to be used in the CoAP library
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_config.h"

#include <stdio.h>

#include "libcoap.h"
#include "coap_debug.h"
#include "mem.h"
#include "str.h"

coap_string_t *coap_new_string(size_t size) {
  coap_string_t *s =
            (coap_string_t *)coap_malloc_type(COAP_STRING, sizeof(coap_string_t) + size + 1);
  if ( !s ) {
#ifndef NDEBUG
    coap_log(LOG_CRIT, "coap_new_string: malloc\n");
#endif
    return NULL;
  }

  memset(s, 0, sizeof(coap_string_t));
  s->s = ((unsigned char *)s) + sizeof(coap_string_t);
  s->s[size] = '\000';
  return s;
}

void coap_delete_string(coap_string_t *s) {
  coap_free_type(COAP_STRING, s);
}

coap_str_const_t *coap_new_str_const(const uint8_t *data, size_t size) {
  coap_string_t *s = coap_new_string(size);
  if (!s)
    return NULL;
  memcpy (s->s, data, size);
  s->length = size;
  return (coap_str_const_t *)s;
}

void coap_delete_str_const(coap_str_const_t *s) {
  coap_free_type(COAP_STRING, s);
}

/* subscribe.c -- subscription handling for CoAP
 *                see draft-ietf-coap-observe-16
 *
 * Copyright (C) 2010--2013,2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_config.h"
#include "coap.h"

#if defined(HAVE_ASSERT_H) && !defined(assert)
# include <assert.h>
#endif

#include "subscribe.h"

void
coap_subscription_init(coap_subscription_t *s) {
  assert(s);
  memset(s, 0, sizeof(coap_subscription_t));
}
/* uri.c -- helper functions for URI treatment
 *
 * Copyright (C) 2010--2012,2015-2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_config.h"

#if defined(HAVE_ASSERT_H) && !defined(assert)
# include <assert.h>
#endif

#if defined(HAVE_LIMITS_H)
#include <limits.h>
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "libcoap.h"
#include "mem.h"
#include "coap_debug.h"
#include "pdu.h"
#include "option.h"
#include "uri.h"

/**
 * A length-safe version of strchr(). This function returns a pointer
 * to the first occurrence of @p c  in @p s, or @c NULL if not found.
 *
 * @param s   The string to search for @p c.
 * @param len The length of @p s.
 * @param c   The character to search.
 *
 * @return A pointer to the first occurence of @p c, or @c NULL
 * if not found.
 */
COAP_STATIC_INLINE const uint8_t *
strnchr(const uint8_t *s, size_t len, unsigned char c) {
  while (len && *s++ != c)
    --len;

  return len ? s : NULL;
}

#define ISEQUAL_CI(a,b) \
  ((a) == (b) || (islower(b) && ((a) == ((b) - 0x20))))

int
coap_split_uri(const uint8_t *str_var, size_t len, coap_uri_t *uri) {
  const uint8_t *p, *q;
  int res = 0;

  if (!str_var || !uri)
    return -1;

  memset(uri, 0, sizeof(coap_uri_t));
  uri->port = COAP_DEFAULT_PORT;

  /* search for scheme */
  p = str_var;
  if (*p == '/') {
    q = p;
    goto path;
  }

  q = (const uint8_t *)COAP_DEFAULT_SCHEME;
  while (len && *q && ISEQUAL_CI(*p, *q)) {
    ++p; ++q; --len;
  }

  /* If q does not point to the string end marker '\0', the schema
   * identifier is wrong. */
  if (*q) {
    res = -1;
    goto error;
  }

  /* There might be an additional 's', indicating the secure version: */
  if (len && (*p == 's')) {
    ++p; --len;
    uri->scheme = COAP_URI_SCHEME_COAPS;
    uri->port = COAPS_DEFAULT_PORT;
  } else {
    uri->scheme = COAP_URI_SCHEME_COAP;
  }

  /* There might be and addition "+tcp", indicating reliable transport: */
  if (len>=4 && p[0] == '+' && p[1] == 't' && p[2] == 'c' && p[3] == 'p' ) {
    p += 4;
    len -= 4;
    if (uri->scheme == COAP_URI_SCHEME_COAPS)
      uri->scheme = COAP_URI_SCHEME_COAPS_TCP;
    else
      uri->scheme = COAP_URI_SCHEME_COAP_TCP;
  }
  q = (const uint8_t *)"://";
  while (len && *q && *p == *q) {
    ++p; ++q; --len;
  }

  if (*q) {
    res = -2;
    goto error;
  }

  /* p points to beginning of Uri-Host */
  q = p;
  if (len && *p == '[') {        /* IPv6 address reference */
    ++p;

    while (len && *q != ']') {
      ++q; --len;
    }

    if (!len || *q != ']' || p == q) {
      res = -3;
      goto error;
    }

    COAP_SET_STR(&uri->host, q - p, p);
    ++q; --len;
  } else {                        /* IPv4 address or FQDN */
    while (len && *q != ':' && *q != '/' && *q != '?') {
      ++q;
      --len;
    }

    if (p == q) {
      res = -3;
      goto error;
    }

    COAP_SET_STR(&uri->host, q - p, p);
  }

  /* check for Uri-Port */
  if (len && *q == ':') {
    p = ++q;
    --len;

    while (len && isdigit(*q)) {
      ++q;
      --len;
    }

    if (p < q) {                /* explicit port number given */
      int uri_port = 0;

      while (p < q)
              uri_port = uri_port * 10 + (*p++ - '0');

      /* check if port number is in allowed range */
      if (uri_port > 65535) {
              res = -4;
              goto error;
      }

      uri->port = (uint16_t)uri_port;
    }
  }

 path:                 /* at this point, p must point to an absolute path */

  if (!len)
    goto end;

  if (*q == '/') {
    p = ++q;
    --len;

    while (len && *q != '?') {
      ++q;
      --len;
    }

    if (p < q) {
      COAP_SET_STR(&uri->path, q - p, p);
      p = q;
    }
  }

  /* Uri_Query */
  if (len && *p == '?') {
    ++p;
    --len;
    COAP_SET_STR(&uri->query, len, p);
    len = 0;
  }

  end:
  return len ? -1 : 0;

  error:
  return res;
}

/**
 * Calculates decimal value from hexadecimal ASCII character given in
 * @p c. The caller must ensure that @p c actually represents a valid
 * heaxdecimal character, e.g. with isxdigit(3).
 *
 * @hideinitializer
 */
#define hexchar_to_dec(c) ((c) & 0x40 ? ((c) & 0x0F) + 9 : ((c) & 0x0F))

/**
 * Decodes percent-encoded characters while copying the string @p seg
 * of size @p length to @p buf. The caller of this function must
 * ensure that the percent-encodings are correct (i.e. the character
 * '%' is always followed by two hex digits. and that @p buf provides
 * sufficient space to hold the result. This function is supposed to
 * be called by make_decoded_option() only.
 *
 * @param seg     The segment to decode and copy.
 * @param length  Length of @p seg.
 * @param buf     The result buffer.
 */
static void
decode_segment(const uint8_t *seg, size_t length, unsigned char *buf) {

  while (length--) {

    if (*seg == '%') {
      *buf = (hexchar_to_dec(seg[1]) << 4) + hexchar_to_dec(seg[2]);

      seg += 2; length -= 2;
    } else {
      *buf = *seg;
    }

    ++buf; ++seg;
  }
}

/**
 * Runs through the given path (or query) segment and checks if
 * percent-encodings are correct. This function returns @c 0 on success
 * and @c -1 on error.
 */
static int
check_segment(const uint8_t *s, size_t length, size_t *segment_size) {
  size_t n = 0;

  while (length) {
    if (*s == '%') {
      if (length < 2 || !(isxdigit(s[1]) && isxdigit(s[2])))
              return -1;

      s += 2;
      length -= 2;
    }

    ++s; ++n; --length;
  }

  *segment_size = n;

  return 0;
}

/**
 * Writes a coap option from given string @p s to @p buf. @p s should
 * point to a (percent-encoded) path or query segment of a coap_uri_t
 * object.  The created option will have type @c 0, and the length
 * parameter will be set according to the size of the decoded string.
 * On success, this function returns @c 0 and sets @p optionsize to the option's
 * size. On error the function returns a value less than zero. This function
 * must be called from coap_split_path_impl() only.
 *
 * @param s           The string to decode.
 * @param length      The size of the percent-encoded string @p s.
 * @param buf         The buffer to store the new coap option.
 * @param buflen      The maximum size of @p buf.
 * @param optionsize  The option's size.
 *
 * @return @c 0 on success and @c -1 on error.
 *
 * @bug This function does not split segments that are bigger than 270
 * bytes.
 */
static int
make_decoded_option(const uint8_t *s, size_t length,
                    unsigned char *buf, size_t buflen, size_t* optionsize) {
  int res;
  size_t segmentlen;
  size_t written;

  if (!buflen) {
    coap_log(LOG_DEBUG, "make_decoded_option(): buflen is 0!\n");
    return -1;
  }

  res = check_segment(s, length, &segmentlen);
  if (res < 0)
    return -1;

  /* write option header using delta 0 and length res */
  written = coap_opt_setheader(buf, buflen, 0, segmentlen);

  assert(written <= buflen);

  if (!written)                        /* encoding error */
    return -1;

  buf += written;                /* advance past option type/length */
  buflen -= written;

  if (buflen < segmentlen) {
    coap_log(LOG_DEBUG, "buffer too small for option\n");
    return -1;
  }

  decode_segment(s, length, buf);

  *optionsize = written + segmentlen;

  return 0;
}


#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

typedef void (*segment_handler_t)(const uint8_t *, size_t, void *);

/**
 * Checks if path segment @p s consists of one or two dots.
 */
COAP_STATIC_INLINE int
dots(const uint8_t *s, size_t len) {
  return len && *s == '.' && (len == 1 || (len == 2 && *(s+1) == '.'));
}

/**
 * Splits the given string into segments. You should call one of the
 * macros coap_split_path() or coap_split_query() instead.
 *
 * @param s      The URI string to be tokenized.
 * @param length The length of @p s.
 * @param h      A handler that is called with every token.
 * @param data   Opaque data that is passed to @p h when called.
 *
 * @return The number of characters that have been parsed from @p s.
 */
static size_t
coap_split_path_impl(const uint8_t *s, size_t length,
                     segment_handler_t h, void *data) {

  const uint8_t *p, *q;

  p = q = s;
  while (length > 0 && !strnchr((const uint8_t *)"?#", 2, *q)) {
    if (*q == '/') {                /* start new segment */

      if (!dots(p, q - p)) {
        h(p, q - p, data);
      }

      p = q + 1;
    }

    q++;
    length--;
  }

  /* write last segment */
  if (!dots(p, q - p)) {
    h(p, q - p, data);
  }

  return q - s;
}

struct cnt_str {
  coap_string_t buf;
  int n;
};

static void
write_option(const uint8_t *s, size_t len, void *data) {
  struct cnt_str *state = (struct cnt_str *)data;
  int res;
  size_t optionsize;
  assert(state);

  res = make_decoded_option(s, len, state->buf.s, state->buf.length, &optionsize);
  if (res == 0) {
    state->buf.s += optionsize;
    state->buf.length -= optionsize;
    state->n++;
  }
}

int
coap_split_path(const uint8_t *s, size_t length,
                unsigned char *buf, size_t *buflen) {
  struct cnt_str tmp = { { *buflen, buf }, 0 };

  coap_split_path_impl(s, length, write_option, &tmp);

  *buflen = *buflen - tmp.buf.length;

  return tmp.n;
}

int
coap_split_query(const uint8_t *s, size_t length,
                unsigned char *buf, size_t *buflen) {
  struct cnt_str tmp = { { *buflen, buf }, 0 };
  const uint8_t *p;

  p = s;
  while (length > 0 && *s != '#') {
    if (*s == '&') {                /* start new query element */
      write_option(p, s - p, &tmp);
      p = s + 1;
    }

    s++;
    length--;
  }

  /* write last query element */
  write_option(p, s - p, &tmp);

  *buflen = *buflen - tmp.buf.length;
  return tmp.n;
}

#define URI_DATA(uriobj) ((unsigned char *)(uriobj) + sizeof(coap_uri_t))

coap_uri_t *
coap_new_uri(const uint8_t *uri, unsigned int length) {
  unsigned char *result;

  result = (unsigned char*)coap_malloc(length + 1 + sizeof(coap_uri_t));

  if (!result)
    return NULL;

  memcpy(URI_DATA(result), uri, length);
  URI_DATA(result)[length] = '\0'; /* make it zero-terminated */

  if (coap_split_uri(URI_DATA(result), length, (coap_uri_t *)result) < 0) {
    coap_free(result);
    return NULL;
  }
  return (coap_uri_t *)result;
}

coap_uri_t *
coap_clone_uri(const coap_uri_t *uri) {
  coap_uri_t *result;
  uint8_t *p;

  if ( !uri )
    return  NULL;

  result = (coap_uri_t *)coap_malloc( uri->query.length + uri->host.length +
                                      uri->path.length + sizeof(coap_uri_t) + 1);

  if ( !result )
    return NULL;

  memset( result, 0, sizeof(coap_uri_t) );

  result->port = uri->port;

  if ( uri->host.length ) {
    result->host.s = p = URI_DATA(result);
    result->host.length = uri->host.length;

    memcpy(p, uri->host.s, uri->host.length);
  }

  if ( uri->path.length ) {
    result->path.s = p = URI_DATA(result) + uri->host.length;
    result->path.length = uri->path.length;

    memcpy(p, uri->path.s, uri->path.length);
  }

  if ( uri->query.length ) {
    result->query.s = p = URI_DATA(result) + uri->host.length + uri->path.length;
    result->query.length = uri->query.length;

    memcpy (p, uri->query.s, uri->query.length);
  }

  return result;
}

COAP_STATIC_INLINE int
is_unescaped_in_path(const uint8_t c) {
  return ( c >= 'A' && c <= 'Z' ) || ( c >= 'a' && c <= 'z' )
      || ( c >= '0' && c <= '9' ) || c == '-' || c == '.' || c == '_'
      || c == '~' || c == '!' || c == '$' || c == '\'' || c == '('
      || c == ')' || c == '*' || c == '+' || c == ',' || c == ';' || c=='='
      || c==':' || c=='@' || c == '&';
}

COAP_STATIC_INLINE int
is_unescaped_in_query(const uint8_t c) {
  return is_unescaped_in_path(c) || c=='/' || c=='?';
}

coap_string_t *coap_get_query(const coap_pdu_t *request) {
  coap_opt_iterator_t opt_iter;
  coap_opt_filter_t f;
  coap_opt_t *q;
  coap_string_t *query = NULL;
  size_t length = 0;
  static const uint8_t hex[] = "0123456789ABCDEF";

  coap_option_filter_clear(f);
  coap_option_filter_set(f, COAP_OPTION_URI_QUERY);
  coap_option_iterator_init(request, &opt_iter, f);
  while ((q = coap_option_next(&opt_iter))) {
    uint16_t seg_len = coap_opt_length(q), i;
    const uint8_t *seg= coap_opt_value(q);
    for (i = 0; i < seg_len; i++) {
      if (is_unescaped_in_query(seg[i]))
        length += 1;
      else
        length += 3;
    }
    length += 1;
  }
  if (length > 0)
    length -= 1;
  if (length > 0) {
    query = coap_new_string(length);
    if (query) {
      query->length = length;
      unsigned char *s = query->s;
      coap_option_iterator_init(request, &opt_iter, f);
      while ((q = coap_option_next(&opt_iter))) {
        if (s != query->s)
          *s++ = '&';
        uint16_t seg_len = coap_opt_length(q), i;
        const uint8_t *seg= coap_opt_value(q);
        for (i = 0; i < seg_len; i++) {
          if (is_unescaped_in_query(seg[i])) {
            *s++ = seg[i];
          } else {
            *s++ = '%';
            *s++ = hex[seg[i]>>4];
            *s++ = hex[seg[i]&0x0F];
          }
        }
      }
    }
  }
  return query;
}

coap_string_t *coap_get_uri_path(const coap_pdu_t *request) {
  coap_opt_iterator_t opt_iter;
  coap_opt_filter_t f;
  coap_opt_t *q;
  coap_string_t *uri_path = NULL;
  size_t length = 0;
  static const uint8_t hex[] = "0123456789ABCDEF";

  coap_option_filter_clear(f);
  coap_option_filter_set(f, COAP_OPTION_URI_PATH);
  coap_option_iterator_init(request, &opt_iter, f);
  while ((q = coap_option_next(&opt_iter))) {
    uint16_t seg_len = coap_opt_length(q), i;
    const uint8_t *seg= coap_opt_value(q);
    for (i = 0; i < seg_len; i++) {
      if (is_unescaped_in_path(seg[i]))
        length += 1;
      else
        length += 3;
    }
    /* bump for the leading "/" */
    length += 1;
  }
  /* The first entry does not have a leading "/" */
  if (length > 0)
    length -= 1;

  /* if 0, either no URI_PATH Option, or the first one was empty */
  uri_path = coap_new_string(length);
  if (uri_path) {
    uri_path->length = length;
    unsigned char *s = uri_path->s;
    int n = 0;
    coap_option_iterator_init(request, &opt_iter, f);
    while ((q = coap_option_next(&opt_iter))) {
      if (n++) {
        *s++ = '/';
      }
      uint16_t seg_len = coap_opt_length(q), i;
      const uint8_t *seg= coap_opt_value(q);
      for (i = 0; i < seg_len; i++) {
        if (is_unescaped_in_path(seg[i])) {
          *s++ = seg[i];
        } else {
          *s++ = '%';
          *s++ = hex[seg[i]>>4];
          *s++ = hex[seg[i]&0x0F];
        }
      }
    }
  }
  return uri_path;
}

#endif /*CURL_DISABLE_COAP*/
