/*
 * key.c
 *
 * key usage limits enforcement
 * 
 * David A. Mcgrew
 * Cisco Systems, Inc.
 */
/*
 *	
 * Copyright (c) 2001-2006 Cisco Systems, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 * 
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "key.h"

#define soft_limit 0x50/*0x10000*/

err_status_t
key_limit_set(key_limit_t key, const xtd_seq_num_t s) {
#ifdef NO_64BIT_MATH
  if (high32(s) == 0 && low32(s) < soft_limit)
    return err_status_bad_param;
#else
  if (s < soft_limit)
    return err_status_bad_param;
#endif
  key->num_left = soft_limit+50;/*s;*/
  key->state = key_state_normal;
  return err_status_ok;
}

err_status_t
key_limit_clone(key_limit_t original, key_limit_t *new_key) {
  if (original == NULL)
    return err_status_bad_param;
  *new_key = original;
  return err_status_ok;
}

err_status_t
key_limit_check(const key_limit_t key) {
  if (key->state == key_state_expired)
    return err_status_key_expired;
  return err_status_ok;
}

key_event_t
key_limit_update(key_limit_t key) {
#ifdef NO_64BIT_MATH
  if (low32(key->num_left) == 0)
  {
	  // carry
	  key->num_left = make64(high32(key->num_left)-1,low32(key->num_left) - 1);
  }
  else
  {
	  // no carry
	  key->num_left = make64(high32(key->num_left),low32(key->num_left) - 1);
  }
  if (high32(key->num_left) != 0 || low32(key->num_left) >= soft_limit) {
    return key_event_normal;   /* we're above the soft limit */
  }
#else
  key->num_left--;
  if (key->num_left >= soft_limit) {
    return key_event_normal;   /* we're above the soft limit */
  }
#endif
  if (key->state == key_state_normal) {
    /* we just passed the soft limit, so change the state */
    key->state = key_state_past_soft_limit;
  }
#ifdef NO_64BIT_MATH
  if (low32(key->num_left) == 0 && high32(key->num_left == 0))
#else
  if (key->num_left < 1)
#endif
  { /* we just hit the hard limit */
    key->state = key_state_expired;
    return key_event_hard_limit;
  }
   return key_event_soft_limit;
}

