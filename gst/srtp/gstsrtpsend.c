/*
 * GStreamer
 * Copyright (C) 2005 Thomas Vander Stichele <thomas@apestaart.org>
 * Copyright (C) 2005 Ronald S. Bultje <rbultje@ronald.bitfreak.net>
 * Copyright (C) 2009 Gabriel Millaire <millaire.gabriel@gmail.com>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Alternatively, the contents of this file may be used under the
 * GNU Lesser General Public License Version 2.1 (the "LGPL"), in
 * which case the following provisions apply instead of the ones
 * mentioned above:
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/**
 * SECTION:element-srtpsend
 *
 * gstrtpsend acts as an encoder that adds security to RTP and RTCP
 * packets in the form of encryption and authentication. It outs SRTP
 * and SRTCP.
 * 
 * An application can request multiple RTP and RTCP pads to protect,
 * but every sink pad requested must receive packets from the same
 * source (identical SSRC). If a packet received contains a different
 * SSRC, a warning is emited and the valid SSRC is forced on the packet.
 *
 * This element uses libsrtp library. When receiving the first packet,
 * the library is initialized with a new stream (based on the SSRC). It
 * uses the default RTP and RTCP encryption and authentication mechanisms,
 * unless the user has set the relevant properties first. It also uses
 * a master key that MUST be set by property (key) at the beginning. The
 * master key must be of a maximum length of 30 characters. The
 * encryption and authentication mecanisms available are :
 *
 * Encryption (properties rtp_c and rtcp_c)
 * - AES_128_ICM (default, maximum security)
 * - STRONGHOLD_CIPHER (same as AES_128_ICM)
 * - NULL
 *
 * Authentication (properties rtp_a and rtcp_a)
 * - HMAC_SHA1 (default, maximum protection)
 * - STRONGHOLD_AUTH (same as HMAC_SHA1)
 * - NULL
 *
 * Note that for SRTP protection, authentication is mandatory (non-null)
 * if encryption is used (non-null).
 * 
 * When requested to create a sink pad, a linked source pad is created.
 * Each packet received is first analysed (checked for valid SSRC) then
 * its buffer is protected with libsrtp, then pushed on the source pad.
 * If protection failed or the stream could not be created, the buffer
 * is dropped and a warning is emitted. The packets pushed on the source
 * pad are of type 'application/x-srtp' or 'application/x-srtcp'.
 *
 * When the maximum usage of the master key is reached, a soft-limit
 * signal is sent to the user. The user must then set a new master key
 * by property. If the hard limit is reached, a flag is set and every
 * subsequent packet is dropped, until a new key is set and the stream
 * has been updated.
 *
 *
 *
 * 
 *
 *
 *
 *
 * 
 *
 *
 *
 *
 * 
 *
 *
 *
 *
 *
 * <refsect2>
 * <title>Example pipeline</title>
 * |[
 * gst-launch-0.10 --gst-debug=srtp*:5 audiotestsrc ! speexenc ! rtpspeexpay ! srtpsend key=bafbafbaf ! udpsink port=33333
 * ]| Send SPEEX RTP packets through srtpsend using default protection
 * and costum master key, and out on UDP port 33333.
 * </refsect2>
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <gst/gst.h>
#include <gst/rtp/gstrtpbuffer.h>
#include <gst/rtp/gstrtcpbuffer.h>
#include <string.h>

#include "gstsrtp-marshal.h"

#include "gstsrtpsend.h"

GST_DEBUG_CATEGORY_STATIC (gst_srtp_send_debug);
#define GST_CAT_DEFAULT gst_srtp_send_debug

/* Filter signals and args */
enum
{
  SIGNAL_SOFT_LIMIT,
  SIGNAL_HARD_LIMIT,
  LAST_SIGNAL
};

enum
{
  PROP_0,
  PROP_USE_RAND_KEY,
  PROP_MKEY,
  PROP_RTP_CIPHER,
  PROP_RTP_AUTH,
  PROP_RTCP_CIPHER,
  PROP_RTCP_AUTH,
  PROP_USE_CAPS
};

/* the capabilities of the inputs and outputs.
 *
 * describe the real formats here.
 */
static GstStaticPadTemplate rtp_sink_template =
GST_STATIC_PAD_TEMPLATE ("rtp_sink_%d",
    GST_PAD_SINK,
    GST_PAD_REQUEST,
    GST_STATIC_CAPS ("application/x-rtp")
    );

static GstStaticPadTemplate rtp_src_template =
GST_STATIC_PAD_TEMPLATE ("rtp_src_%d",
    GST_PAD_SRC,
    GST_PAD_SOMETIMES,
    GST_STATIC_CAPS ("application/x-srtp")
    );

static GstStaticPadTemplate rtcp_sink_template =
GST_STATIC_PAD_TEMPLATE ("rtcp_sink_%d",
    GST_PAD_SINK,
    GST_PAD_REQUEST,
    GST_STATIC_CAPS ("application/x-rtcp")
    );

static GstStaticPadTemplate rtcp_src_template =
GST_STATIC_PAD_TEMPLATE ("rtcp_src_%d",
    GST_PAD_SRC,
    GST_PAD_SOMETIMES,
    GST_STATIC_CAPS ("application/x-srtcp")
    );

GST_BOILERPLATE (GstSrtpSend, gst_srtp_send, GstElement, GST_TYPE_ELEMENT);

static guint gst_srtp_send_signals[LAST_SIGNAL] = { 0 };

static void gst_srtp_send_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec);
static void gst_srtp_send_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec);

static gboolean gst_srtp_send_sink_setcaps_rtp (GstPad * pad, GstCaps * caps);
static gboolean gst_srtp_send_sink_setcaps_rtcp (GstPad * pad, GstCaps * caps);
static gboolean gst_srtp_send_sink_setcaps (GstPad * pad, GstCaps * caps,
    gboolean is_rtcp, gboolean ask_setcaps);

static GstCaps *gst_srtp_send_sink_getcaps_rtp (GstPad * pad);
static GstCaps *gst_srtp_send_sink_getcaps_rtcp (GstPad * pad);
static GstCaps *gst_srtp_send_sink_getcaps (GstPad * pad, gboolean is_rtcp);

static GstIterator *gst_srtp_send_iterate_internal_links_rtp (GstPad * pad);
static GstIterator *gst_srtp_send_iterate_internal_links_rtcp (GstPad * pad);
static GstIterator *gst_srtp_send_iterate_internal_links (GstPad * pad,
    gboolean is_rtcp);

static GstFlowReturn gst_srtp_send_chain_rtp (GstPad * pad, GstBuffer * buf);
static GstFlowReturn gst_srtp_send_chain_rtcp (GstPad * pad, GstBuffer * buf);
static GstFlowReturn gst_srtp_send_chain (GstPad * pad, GstBuffer * buf,
    gboolean is_rtcp);

static GstStateChangeReturn gst_srtp_send_change_state (GstElement * element,
    GstStateChange transition);

static GstPad *gst_srtp_send_request_new_pad (GstElement * element,
    GstPadTemplate * templ, const gchar * name);

static void gst_srtp_send_release_pad (GstElement * element, GstPad * pad);

static GstSrtpSend *srtp_filter;

struct _GstSrtpSendPads
{
  GstPad *sinkpad;
  GstPad *srcpad;
};

static void
gst_srtp_send_base_init (gpointer gclass)
{
  GstElementClass *element_class = GST_ELEMENT_CLASS (gclass);

  static const GstElementDetails srtpsend_details =
      GST_ELEMENT_DETAILS ("SrtpSend",
      "Filter/Network/SRTP",
      "Implement an RTP to SRTP filter",
      "Gabriel Millaire <millaire.gabriel@gmail.com>");

  gst_element_class_set_details (element_class, &srtpsend_details);

  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&rtp_src_template));
  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&rtp_sink_template));
  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&rtcp_src_template));
  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&rtcp_sink_template));
}

/* initialize the srtpsend's class
 */
static void
gst_srtp_send_class_init (GstSrtpSendClass * klass)
{
  GObjectClass *gobject_class;
  GstElementClass *gstelement_class;

  gobject_class = (GObjectClass *) klass;
  gstelement_class = (GstElementClass *) klass;

  /* Install callbacks */
  gobject_class->set_property = gst_srtp_send_set_property;
  gobject_class->get_property = gst_srtp_send_get_property;
  gstelement_class->request_new_pad = gst_srtp_send_request_new_pad;
  gstelement_class->release_pad = GST_DEBUG_FUNCPTR (gst_srtp_send_release_pad);
  gstelement_class->change_state =
      GST_DEBUG_FUNCPTR (gst_srtp_send_change_state);

  /* Install properties */
  g_object_class_install_property (gobject_class, PROP_USE_RAND_KEY,
      g_param_spec_boolean ("use_rand_key", "Use_Rand_Key", "Use random key?",
          FALSE, G_PARAM_READWRITE));
  g_object_class_install_property (gobject_class, PROP_MKEY,
      g_param_spec_string ("key", "Key", "Master key", "", G_PARAM_READWRITE));
  g_object_class_install_property (gobject_class, PROP_RTP_CIPHER,
      g_param_spec_string ("rtp_c", "RTP_Cipher", "RTP Cipher",
          "AES_128_ICM", G_PARAM_READWRITE));
  g_object_class_install_property (gobject_class, PROP_RTP_AUTH,
      g_param_spec_string ("rtp_a", "RTP_Auth", "RTP Authentication",
          "HMAC_SHA1", G_PARAM_READWRITE));
  g_object_class_install_property (gobject_class, PROP_RTCP_CIPHER,
      g_param_spec_string ("rtcp_c", "RTCP_Cipher", "RTCP Cipher",
          "AES_128_ICM", G_PARAM_READWRITE));
  g_object_class_install_property (gobject_class, PROP_RTCP_AUTH,
      g_param_spec_string ("rtcp_a", "RTCP_Auth", "RTCP Authentication",
          "HMAC_SHA1", G_PARAM_READWRITE));
  g_object_class_install_property (gobject_class, PROP_USE_CAPS,
      g_param_spec_boolean ("use_caps", "Use_caps",
          "Use caps instead of signals?", FALSE, G_PARAM_READWRITE));

  /* Install signals */
  gst_srtp_send_signals[SIGNAL_SOFT_LIMIT] =
      g_signal_new ("soft-limit", G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (GstSrtpSendClass,
          soft_limit), NULL, NULL, gst_srtp_marshal_VOID__UINT,
      G_TYPE_NONE, 1, G_TYPE_UINT);

  gst_srtp_send_signals[SIGNAL_HARD_LIMIT] =
      g_signal_new ("hard-limit", G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (GstSrtpSendClass,
          hard_limit), NULL, NULL, gst_srtp_marshal_VOID__UINT,
      G_TYPE_NONE, 1, G_TYPE_UINT);
}

/* initialize the new element
 */
static void
gst_srtp_send_init (GstSrtpSend * filter, GstSrtpSendClass * gclass)
{
  srtp_filter = filter;

  filter->limit_reached = FALSE;
  filter->rtppads_num = 0;
  filter->rtcppads_num = 0;
  filter->use_caps = FALSE;
  filter->use_rand_key = FALSE;
  filter->ask_setcaps = FALSE;
  filter->first_session = TRUE;
  filter->key = NULL;
  filter->rtp_cipher = AES_128_ICM;
  filter->rtp_auth = HMAC_SHA1;
  filter->rtcp_cipher = AES_128_ICM;
  filter->rtcp_auth = HMAC_SHA1;
}

/* Returns the cipher type from a string; NULL if unrecognized
 */
static guint
get_rtp_cipher_property (const gchar * prop)
{
  guint ret = NULL_CIPHER;

  if (g_strcmp0 (prop, "AES_128_ICM") == 0)
    ret = AES_128_ICM;
/*  else if (g_strcmp0 (prop, "SEAL") == 0)
    ret = SEAL;
  else if (g_strcmp0 (prop, "AES_128_CBC") == 0)
    ret = AES_128_CBC;
*/
  else if (g_strcmp0 (prop, "STRONGHOLD_CIPHER") == 0)
    ret = STRONGHOLD_CIPHER;

  return ret;
}

/* Returns the authentication type from a string; NULL if unrecognized
 */
static guint
get_rtp_auth_property (const gchar * prop)
{
  guint ret = NULL_AUTH;

  if (g_strcmp0 (prop, "HMAC_SHA1") == 0)
    ret = HMAC_SHA1;
/*  else if (g_strcmp0 (prop, "UST_AES_128_XMAC") == 0)
    ret = UST_AES_128_XMAC;
  else if (g_strcmp0 (prop, "UST_TMMHv2") == 0)
    ret = UST_TMMHv2;
*/
  else if (g_strcmp0 (prop, "STRONGHOLD_AUTH") == 0)
    ret = STRONGHOLD_AUTH;

  return ret;
}

/* Returns the cipher name from a guint; NULL if unrecognized
 */
static void
set_rtp_cipher_property (GValue * value, const guint prop)
{
  switch (prop) {
    case AES_128_ICM:
      g_value_set_string (value, "AES_128_ICM");        /* STRONGHOLD */
      break;
/*  case SEAL:
      g_value_set_string (value, "SEAL");
      break;
    case AES_128_CBC:
      g_value_set_string (value, "AES_128_CBC");
      break;
*/
    default:
      g_value_set_string (value, "NULL_CIPHER");
  }
}

/* Returns the authentication name from a guint; NULL if unrecognized
 */
static void
set_rtp_auth_property (GValue * value, const guint prop)
{
  switch (prop) {
    case HMAC_SHA1:
      g_value_set_string (value, "HMAC_SHA1");  /* STRONGHOLD */
      break;
/*  case UST_AES_128_XMAC:
      g_value_set_string (value, "UST_AES_128_XMAC");
      break;
    case UST_TMMHv2:
      g_value_set_string (value, "UST_TMMHv2");
      break;
*/
    default:
      g_value_set_string (value, "NULL_AUTH");
  }
}

/* Sets the policy (cipher, authentication)
 */
static void
set_crypto_policy_cipher_auth (GstSrtpSend * filter, crypto_policy_t * policy)
{
  if (filter->rtp_cipher == AES_128_ICM) {
    if (filter->rtp_auth == HMAC_SHA1) {
      crypto_policy_set_aes_cm_128_hmac_sha1_80 (policy);
      GST_LOG_OBJECT (filter, "Policy set to AES_128_ICM and HMAC_SHA1");
    } else {
      crypto_policy_set_aes_cm_128_null_auth (policy);
      GST_LOG_OBJECT (filter,
          "Policy set to AES_128_ICM and NULL authentication");
    }
  } else {
    if (filter->rtp_auth == HMAC_SHA1) {
      crypto_policy_set_null_cipher_hmac_sha1_80 (policy);
      GST_LOG_OBJECT (filter, "Policy set to NULL cipher and HMAC_SHA1");
    } else {
      policy->cipher_type = NULL_CIPHER;
      policy->cipher_key_len = 0;
      policy->auth_type = NULL_AUTH;
      policy->auth_key_len = 0;
      policy->auth_tag_len = 0;
      policy->sec_serv = sec_serv_none;
      GST_LOG_OBJECT (filter,
          "Policy set to NULL cipher and NULL authentication");
    }
  }
}

/* Make a random key of length len using readable characters
 */
static gboolean
get_random_key (gchar * key, guint32 len)
{
  gboolean ret = FALSE;
  gint32 tmp;
  int i;
  GRand *r = g_rand_new ();

  for (i = 0; i < len; i++) {
    tmp = g_rand_int_range (r, 33, 127);
    key[i] = tmp;
  }
  return ret;
}

/* Check if SSRC in buffer is valid
 */
static ssrc_state_t
validate_ssrc (GstSrtpSend * filter, guint32 ssrc)
{
  ssrc_state_t ret;

  if (filter->first_session) {  /* New session, create stream */
    ret = ssrc_new;
    filter->ssrc = ssrc;
  } else if (filter->ask_setcaps) {     /* Property or caps changed, update stream */
    ret = ssrc_new;
    srtp_remove_stream (filter->session, ssrc);
  } else if (ssrc == filter->ssrc) {    /* SSRC is valid */
    ret = ssrc_valid;
  } else {                      /* SSRC is invalid : force */
    ret = ssrc_invalid;
  }

  return ret;
}

/* Get SSRC from buffer
 */
static guint32
get_ssrc_from_buffer (GstBuffer * buf, gboolean is_rtcp)
{
  gboolean ret;
  GstRTCPPacket *packet = NULL;
  guint32 ssrc = 0;
  /* RTCP only */
  guint64 ntptime;
  guint32 rtptime;
  guint32 packet_count;
  guint32 octet_count;

  if (is_rtcp) {                /* Get SSRC from RR or SR packet (RTCP) */
    for (ret = gst_rtcp_buffer_get_first_packet (buf, packet);
        ret && ssrc == 0; ret = gst_rtcp_packet_move_to_next (packet)) {
      switch (gst_rtcp_packet_get_type (packet)) {
        case GST_RTCP_TYPE_RR:
          ssrc = gst_rtcp_packet_rr_get_ssrc (packet);
          break;
        case GST_RTCP_TYPE_SR:
          gst_rtcp_packet_sr_get_sender_info (packet, &ssrc, &ntptime, &rtptime,
              &packet_count, &octet_count);
          break;
        default:
          break;
      }
    }
  } else {                      /* Get SSRC from buffer (RTP) */
    ssrc = gst_rtp_buffer_get_ssrc (buf);
  }

  return ssrc;
}

/* Force SSRC on buffer
 */
static void
force_ssrc_on_buffer (GstBuffer * buf, guint32 ssrc, gboolean is_rtcp)
{
  gboolean ret;
  GstRTCPPacket *packet = NULL;
  guint32 ssrc2 = 0;
  /* RTCP only */
  guint64 ntptime;
  guint32 rtptime;
  guint32 packet_count;
  guint32 octet_count;

  if (is_rtcp) {                /* RTCP */
    for (ret = gst_rtcp_buffer_get_first_packet (buf, packet);
        ret; ret = gst_rtcp_packet_move_to_next (packet)) {
      switch (gst_rtcp_packet_get_type (packet)) {
        case GST_RTCP_TYPE_RR:
          gst_rtcp_packet_rr_set_ssrc (packet, ssrc);
          break;
        case GST_RTCP_TYPE_SR:
          gst_rtcp_packet_sr_get_sender_info (packet, &ssrc2, &ntptime,
              &rtptime, &packet_count, &octet_count);
          gst_rtcp_packet_sr_set_sender_info (packet, ssrc, ntptime, rtptime,
              packet_count, octet_count);
          break;
        default:
          /* Should have an RR or SR packet in first position (RFC 3550) */
          return;
      }
    }
  } else {                      /* RTP */
    gst_rtp_buffer_set_ssrc (buf, ssrc);
  }
}

/* Create stream
 */
static err_status_t
init_new_stream (GstSrtpSend * filter, guint32 ssrc)
{
  err_status_t ret;
  srtp_policy_t policy;

  /* RTCP authentication can't be NULL if encryption is not NULL (RFC 3711) */
  if ((filter->rtcp_cipher != NULL_CIPHER)
      && (filter->rtcp_auth == NULL_CIPHER)) {
    filter->rtcp_auth = STRONGHOLD_AUTH;
    GST_LOG_OBJECT (filter, "Setting RTCP authentication to HMAC_SHA1");
  }

  GST_LOG_OBJECT (filter, "Setting RTP policy...");
  set_crypto_policy_cipher_auth (filter, &policy.rtp);
  GST_LOG_OBJECT (filter, "Setting RTCP policy...");
  set_crypto_policy_cipher_auth (filter, &policy.rtcp);

  policy.ssrc.value = ssrc;
  policy.ssrc.type = ssrc_specific;
  policy.key = (guchar *) filter->key;
  policy.next = NULL;

  /* If it is the first stream, create the session 
   * If not, add the stream to the session
   */
  if (filter->first_session)
    ret = srtp_create (&filter->session, &policy);
  else
    ret = srtp_add_stream (filter->session, &policy);

  return ret;
}

/* Validate the received buffer
 * Check SSRC, create new stream if needed
 */
static GstFlowReturn
validate_buffer (GstSrtpSend * filter, GstBuffer * buf, gboolean is_rtcp)
{
  guint32 ssrc = 0;
  err_status_t err;
  GstFlowReturn ret;
  ssrc_state_t state;

  ssrc = get_ssrc_from_buffer (buf, is_rtcp);

  if (ssrc != 0) {
    state = validate_ssrc (filter, ssrc);
  } else {                      /* No SSRC found in buffer */
    state = ssrc_invalid;
  }

  if (state == ssrc_new) {
    /* New session (or property/caps changed) : create stream */

    /* Check if key is valid */
    if (!filter->key) {
      if (filter->use_rand_key) {       /* For testing only */
        filter->key = g_new0 (gchar, 30);
        get_random_key (filter->key, 30);
        GST_LOG_OBJECT (filter, "Setting random key for SSRC %d : [%30s]",
            filter->ssrc, filter->key);
      } else {
        GST_ERROR_OBJECT (filter, "No master key specified");
        GST_ELEMENT_ERROR (GST_ELEMENT_CAST (filter), LIBRARY, SETTINGS,
            (NULL), ("No master key property specified"));
        return GST_FLOW_ERROR;
      }
    }

    err = init_new_stream (filter, filter->ssrc);

    if (err != err_status_ok) {
      GST_WARNING_OBJECT (filter,
          "Could not set stream for SSRC %d (error code %d)", filter->ssrc,
          err);
      ret = GST_FLOW_CUSTOM_ERROR;      /* Will drop buffer but continue */
    } else {
      GST_LOG_OBJECT (filter, "Stream set for SSRC %d", filter->ssrc);
      filter->first_session = FALSE;
      ret = GST_FLOW_OK;
    }
  } else if (state == ssrc_invalid) {   /* Wrong SSRC */
    GST_WARNING_OBJECT (filter, "Wrong SSRC in stream (%d). Forcing SSRC to %d",
        ssrc, filter->ssrc);

    /* Force SSRC on buffer */
    force_ssrc_on_buffer (buf, filter->ssrc, is_rtcp);
    ret = GST_FLOW_OK;
  } else {                      /* state = ssrc_valid */
    ret = GST_FLOW_OK;
  }

  return ret;
}

/* Release ressources and set default values
 */
static void
gst_srtp_send_reset (GstElement * element)
{
  GSList *walk;
  GstSrtpSendPads *pads;
  GstSrtpSend *filter;

  filter = GST_SRTPSEND (element);
  GST_OBJECT_LOCK (filter);
  GST_LOG_OBJECT (element, "Releasing ressources");

  if (!filter->first_session)
    srtp_dealloc (filter->session);

  filter->rtppads_num = 0;
  filter->rtcppads_num = 0;
  filter->ask_setcaps = TRUE;
  filter->first_session = TRUE;
  filter->limit_reached = TRUE;

  /* Properties */
  filter->rtp_cipher = AES_128_ICM;
  filter->rtcp_cipher = AES_128_ICM;
  filter->rtp_auth = HMAC_SHA1;
  filter->rtcp_auth = HMAC_SHA1;
  g_free (filter->key);
  filter->key = NULL;

  /* RTP */
  while ((walk = filter->rtp_pads)) {
    pads = (GstSrtpSendPads *) walk->data;

    /* deactivate from source to sink */
    gst_pad_set_active (pads->srcpad, FALSE);
    gst_pad_set_active (pads->sinkpad, FALSE);

    /* remove pads */
    GST_OBJECT_UNLOCK (filter);
    gst_element_remove_pad (element, pads->sinkpad);
    gst_element_remove_pad (element, pads->srcpad);
    GST_OBJECT_LOCK (filter);

    pads->sinkpad = NULL;
    pads->srcpad = NULL;
    g_slice_free (GstSrtpSendPads, pads);
    filter->rtp_pads = g_slist_delete_link (filter->rtp_pads, walk);
  }

  /* RTCP */
  while ((walk = filter->rtcp_pads)) {
    pads = (GstSrtpSendPads *) walk->data;

    /* deactivate from source to sink */
    gst_pad_set_active (pads->srcpad, FALSE);
    gst_pad_set_active (pads->sinkpad, FALSE);

    /* remove pads */
    GST_OBJECT_UNLOCK (filter);
    gst_element_remove_pad (element, pads->sinkpad);
    gst_element_remove_pad (element, pads->srcpad);
    GST_OBJECT_LOCK (filter);

    pads->sinkpad = NULL;
    pads->srcpad = NULL;
    g_slice_free (GstSrtpSendPads, pads);
    filter->rtcp_pads = g_slist_delete_link (filter->rtcp_pads, walk);
  }

  filter->limit_reached = FALSE;
  GST_OBJECT_UNLOCK (filter);
}

/* Create sinkpad to receive RTP packets from senders
 * and a srcpad for the RTP packets
 */
static GstPad *
create_rtp_sink (GstSrtpSend * filter)
{
  gchar *padname;
  GstSrtpSendPads *rtppad;

  rtppad = g_slice_new0 (GstSrtpSendPads);

  GST_OBJECT_LOCK (filter);

  padname = g_strdup_printf ("rtp_sink_%03d", filter->rtppads_num);
  GST_DEBUG_OBJECT (filter, "creating RTP sink pad %s", padname);
  rtppad->sinkpad =
      gst_pad_new_from_static_template (&rtp_sink_template, padname);
  g_free (padname);

  padname = g_strdup_printf ("rtp_src_%03d", filter->rtppads_num);
  GST_DEBUG_OBJECT (filter, "creating RTP source pad %s", padname);
  rtppad->srcpad =
      gst_pad_new_from_static_template (&rtp_src_template, padname);
  g_free (padname);

  filter->rtppads_num++;
  GST_OBJECT_UNLOCK (filter);

  gst_pad_set_setcaps_function (rtppad->sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_sink_setcaps_rtp));
  gst_pad_set_getcaps_function (rtppad->sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_sink_getcaps_rtp));
  gst_pad_set_iterate_internal_links_function (rtppad->sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_iterate_internal_links_rtp));
  gst_pad_set_chain_function (rtppad->sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_chain_rtp));
  gst_pad_set_active (rtppad->sinkpad, TRUE);
  gst_element_add_pad (GST_ELEMENT_CAST (filter), rtppad->sinkpad);


  gst_pad_set_getcaps_function (rtppad->srcpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_sink_getcaps_rtp));
  gst_pad_set_iterate_internal_links_function (rtppad->srcpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_iterate_internal_links_rtp));
  gst_pad_set_active (rtppad->srcpad, TRUE);
  gst_element_add_pad (GST_ELEMENT_CAST (filter), rtppad->srcpad);

  GST_OBJECT_LOCK (filter);
  filter->rtp_pads = g_slist_prepend (filter->rtp_pads, rtppad);
  GST_OBJECT_UNLOCK (filter);

  return rtppad->sinkpad;
}

/* Create sinkpad to receive RTCP packets from senders
 * and a srcpad for the RTCP packets
 */
static GstPad *
create_rtcp_sink (GstSrtpSend * filter)
{
  gchar *padname;
  GstSrtpSendPads *rtcppad;

  rtcppad = g_slice_new0 (GstSrtpSendPads);

  GST_OBJECT_LOCK (filter);

  padname = g_strdup_printf ("rtcp_sink_%03d", filter->rtcppads_num);
  GST_DEBUG_OBJECT (filter, "creating RTCP sink pad %s", padname);
  rtcppad->sinkpad =
      gst_pad_new_from_static_template (&rtcp_sink_template, padname);
  g_free (padname);

  padname = g_strdup_printf ("rtcp_src_%03d", filter->rtcppads_num);
  GST_DEBUG_OBJECT (filter, "creating RTCP source pad %s", padname);
  rtcppad->srcpad =
      gst_pad_new_from_static_template (&rtcp_src_template, padname);
  g_free (padname);

  filter->rtcppads_num++;
  GST_OBJECT_UNLOCK (filter);

  gst_pad_set_setcaps_function (rtcppad->sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_sink_setcaps_rtcp));
  gst_pad_set_getcaps_function (rtcppad->sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_sink_getcaps_rtcp));
  gst_pad_set_iterate_internal_links_function (rtcppad->sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_iterate_internal_links_rtcp));
  gst_pad_set_chain_function (rtcppad->sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_chain_rtcp));
  gst_pad_set_active (rtcppad->sinkpad, TRUE);
  gst_element_add_pad (GST_ELEMENT_CAST (filter), rtcppad->sinkpad);


  gst_pad_set_getcaps_function (rtcppad->srcpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_sink_getcaps_rtcp));
  gst_pad_set_iterate_internal_links_function (rtcppad->srcpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_iterate_internal_links_rtcp));
  gst_pad_set_active (rtcppad->srcpad, TRUE);
  gst_element_add_pad (GST_ELEMENT_CAST (filter), rtcppad->srcpad);

  GST_OBJECT_LOCK (filter);
  filter->rtcp_pads = g_slist_prepend (filter->rtcp_pads, rtcppad);
  GST_OBJECT_UNLOCK (filter);

  return rtcppad->sinkpad;
}

/* Handling new pad request
 */
static GstPad *
gst_srtp_send_request_new_pad (GstElement * element,
    GstPadTemplate * templ, const gchar * name)
{
  GstElementClass *klass;
  GstSrtpSend *filter;
  GstPad *pad = NULL;

  filter = GST_SRTPSEND (element);
  klass = GST_ELEMENT_GET_CLASS (element);

  GST_LOG_OBJECT (element, "New pad requested");

  if (templ == gst_element_class_get_pad_template (klass, "rtp_sink_%d"))
    pad = create_rtp_sink (filter);
  else if (templ == gst_element_class_get_pad_template (klass, "rtcp_sink_%d"))
    pad = create_rtcp_sink (filter);
  else {
    GST_ERROR_OBJECT (element, "Wrong template");
    GST_ELEMENT_ERROR (element, CORE, PAD, (NULL),
        ("Could not find specified template"));
  }

  return pad;
}

/* Set property
 */
static void
gst_srtp_send_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  const gchar *key;
  guint len;
  GstSrtpSend *filter = GST_SRTPSEND (object);
  GST_OBJECT_LOCK (filter);

  filter->ask_setcaps = TRUE;

  switch (prop_id) {
    case PROP_USE_CAPS:
      filter->use_caps = g_value_get_boolean (value);
      GST_LOG_OBJECT (object, "Set property: use_caps=%d", filter->use_caps);
      break;
    case PROP_USE_RAND_KEY:
      filter->use_rand_key = g_value_get_boolean (value);
      GST_LOG_OBJECT (object, "Set property: use random key=%d",
          filter->use_rand_key);
      break;
    case PROP_MKEY:
      g_free (filter->key);
      filter->key = g_new0 (gchar, 30);
      key = g_value_get_string (value);
      len = strlen (key);
      if (len > 30)
        len = 30;
      memcpy ((void *) filter->key, (void *) key, len);
      GST_LOG_OBJECT (object, "Set property: key=[%30s]", filter->key);
      filter->limit_reached = FALSE;
      break;
    case PROP_RTP_CIPHER:
      filter->rtp_cipher = get_rtp_cipher_property (g_value_get_string (value));
      GST_LOG_OBJECT (object, "Set property: rtp cipher=%d",
          filter->rtp_cipher);
      break;
    case PROP_RTP_AUTH:
      filter->rtp_auth = get_rtp_auth_property (g_value_get_string (value));
      GST_LOG_OBJECT (object, "Set property: rtp auth=%d", filter->rtp_auth);
      break;
    case PROP_RTCP_CIPHER:
      filter->rtcp_cipher =
          get_rtp_cipher_property (g_value_get_string (value));
      GST_LOG_OBJECT (object, "Set property: rtcp cipher=%d",
          filter->rtcp_cipher);
      if ((filter->rtcp_cipher != NULL_CIPHER)
          && (filter->rtcp_auth == NULL_AUTH))
        filter->rtcp_auth = STRONGHOLD_AUTH;
      break;
    case PROP_RTCP_AUTH:
      filter->rtcp_auth = get_rtp_auth_property (g_value_get_string (value));
      GST_LOG_OBJECT (object, "Set property: rtcp auth=%d", filter->rtcp_auth);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }

  GST_OBJECT_UNLOCK (filter);
}

/* Get property
 */
static void
gst_srtp_send_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  GstSrtpSend *filter = GST_SRTPSEND (object);
  GST_OBJECT_LOCK (filter);

  switch (prop_id) {
    case PROP_USE_CAPS:
      g_value_set_boolean (value, filter->use_caps);
      break;
    case PROP_USE_RAND_KEY:
      g_value_set_boolean (value, filter->use_rand_key);
      break;
    case PROP_MKEY:
      g_value_set_string (value, filter->key);
      break;
    case PROP_RTP_CIPHER:
      set_rtp_cipher_property (value, filter->rtp_cipher);
      break;
    case PROP_RTCP_CIPHER:
      set_rtp_cipher_property (value, filter->rtcp_cipher);
      break;
    case PROP_RTP_AUTH:
      set_rtp_auth_property (value, filter->rtp_auth);
      break;
    case PROP_RTCP_AUTH:
      set_rtp_auth_property (value, filter->rtcp_auth);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }

  GST_OBJECT_UNLOCK (filter);
}

/* Returns the source pad linked with the sink pad
 */
static GstPad *
get_rtp_other_pad (GstSrtpSend * filter, GstPad * pad, gboolean is_rtcp)
{
  GSList *walk;
  GstSrtpSendPads *pads;
  GstPad *otherpad = NULL;

  if (is_rtcp)
    walk = filter->rtcp_pads;
  else
    walk = filter->rtp_pads;

  for (; walk; walk = g_slist_next (walk)) {
    pads = (GstSrtpSendPads *) walk->data;

    if (pads->sinkpad == pad) {
      otherpad = pads->srcpad;
      break;
    } else if (pads->srcpad == pad) {
      otherpad = pads->sinkpad;
      break;
    }
  }

  return otherpad;
}

/* Release a sink pad and it's linked source pad
 */
static void
gst_srtp_send_release_pad (GstElement * element, GstPad * pad)
{
  GstSrtpSend *filter = NULL;
  GSList *walk;
  GstSrtpSendPads *pads = NULL;
  GstPad *otherpad = NULL;
  gboolean is_rtcp;
  gchar *name;

  filter = GST_SRTPSEND (element);
  GST_OBJECT_LOCK (filter);

  name = gst_pad_get_name (pad);
  GST_LOG_OBJECT (element, "Releasing pad %s:%s", GST_DEBUG_PAD_NAME (pad));

  /* Check first in the RTP list */
  for (walk = filter->rtp_pads; walk; walk = g_slist_next (walk)) {
    pads = (GstSrtpSendPads *) walk->data;

    if (pads->sinkpad == pad) {
      otherpad = pads->srcpad;
      is_rtcp = FALSE;
      break;
    }
  }

  /* If not found, check in the RTCP list */
  if (!otherpad) {
    for (walk = filter->rtcp_pads; walk; walk = g_slist_next (walk)) {
      pads = (GstSrtpSendPads *) walk->data;

      if (pads->sinkpad == pad) {
        otherpad = pads->srcpad;
        is_rtcp = TRUE;
        break;
      }
    }
  }
  GST_OBJECT_UNLOCK (filter);

  if (otherpad) {
    /* deactivate from source to sink */
    gst_pad_set_active (otherpad, FALSE);
    gst_pad_set_active (pad, FALSE);

    /* remove pads */
    gst_element_remove_pad (element, pad);
    gst_element_remove_pad (element, otherpad);
    g_slice_free (GstSrtpSendPads, pads);
    otherpad = NULL;
    pad = NULL;

    /* remove from list */
    GST_OBJECT_LOCK (filter);
    if (is_rtcp) {
      filter->rtcp_pads = g_slist_delete_link (filter->rtcp_pads, walk);
      filter->rtcppads_num--;
    } else {
      filter->rtp_pads = g_slist_delete_link (filter->rtp_pads, walk);
      filter->rtppads_num--;
    }
    GST_OBJECT_UNLOCK (filter);

  } else {
    GST_WARNING_OBJECT (element, "Could not release pad %s (not found)", name);
  }

  g_free (name);
}

/* RTP pad setcaps function
 */
static gboolean
gst_srtp_send_sink_setcaps_rtp (GstPad * pad, GstCaps * caps)
{
  return gst_srtp_send_sink_setcaps (pad, caps, FALSE, TRUE);
}

/* RTCP pad setcaps function
 */
static gboolean
gst_srtp_send_sink_setcaps_rtcp (GstPad * pad, GstCaps * caps)
{
  return gst_srtp_send_sink_setcaps (pad, caps, TRUE, TRUE);
}

/* Common setcaps function
 * Handles the link with other elements
 */
static gboolean
gst_srtp_send_sink_setcaps (GstPad * pad, GstCaps * caps, gboolean is_rtcp,
    gboolean ask_setcaps)
{
  GstSrtpSend *filter = NULL;
  GstCaps *othercaps = NULL;
  GstPad *otherpad = NULL;
  GstStructure *ps = NULL;
  gboolean ret = FALSE;

  filter = GST_SRTPSEND (gst_pad_get_parent (pad));

  if ((othercaps = gst_caps_copy (caps))) {

    if ((ps = gst_caps_get_structure (othercaps, 0))) {
      GST_DEBUG_OBJECT (pad, "Sink caps: %" GST_PTR_FORMAT, othercaps);

      if (is_rtcp)
        gst_structure_set_name (ps, "application/x-srtcp");
      else
        gst_structure_set_name (ps, "application/x-srtp");

      GST_OBJECT_LOCK (filter);
      if (filter->use_caps) {
        /* For testing purpose, add srtp-specific params to source caps */
        gst_structure_set (ps, "mkey", G_TYPE_STRING, filter->key,
            "rtp_c", G_TYPE_UINT, filter->rtp_cipher,
            "rtp_a", G_TYPE_UINT, filter->rtp_auth,
            "rtcp_c", G_TYPE_UINT, filter->rtcp_cipher,
            "rtcp_a", G_TYPE_UINT, filter->rtcp_auth, NULL);
      }
      GST_OBJECT_UNLOCK (filter);

      GST_DEBUG_OBJECT (pad, "Source caps: %" GST_PTR_FORMAT, othercaps);

      /* Set caps on source pad */
      if ((otherpad = get_rtp_other_pad (filter, pad, is_rtcp))) {

        if (!(ret = gst_pad_set_caps (otherpad, othercaps))) {
          GST_ERROR_OBJECT (pad,
              "Unable to set caps on source pad (gst_pad_set_caps failed)");
          GST_ELEMENT_ERROR (GST_ELEMENT_CAST (filter), CORE, CAPS, (NULL),
              ("Unable to set caps on source pad (gst_pad_set_caps failed)"));
        }
      } else {                  /* get_other_pad */
        GST_ERROR_OBJECT (pad, "Unable to get source pad");
      }

    } else {                    /* gst_caps_get_structure */
      GST_ERROR_OBJECT (pad, "Unable to set caps (gst_get_structure failed)");
      GST_ELEMENT_ERROR (GST_ELEMENT_CAST (filter), CORE, CAPS, (NULL),
          ("Unable to set caps on source pad (gst_get_structure failed)"));
    }

    gst_caps_unref (othercaps);

  } else {                      /* gst_caps_copy */
    GST_ERROR_OBJECT (pad, "Unable to set caps (gst_caps_copy failed)");
    GST_ELEMENT_ERROR (GST_ELEMENT_CAST (filter), CORE, CAPS, (NULL),
        ("Unable to set caps on source pad (gst_caps_copy failed)"));
  }

  gst_object_unref (filter);

  return ret;
}

/* RTP pad getcaps function
 */
static GstCaps *
gst_srtp_send_sink_getcaps_rtp (GstPad * pad)
{
  return gst_srtp_send_sink_getcaps (pad, FALSE);
}

/* RTCP pad getcaps function
 */
static GstCaps *
gst_srtp_send_sink_getcaps_rtcp (GstPad * pad)
{
  return gst_srtp_send_sink_getcaps (pad, TRUE);
}

/* Common getcaps function
 * Handles the link with other elements
 */
static GstCaps *
gst_srtp_send_sink_getcaps (GstPad * pad, gboolean is_rtcp)
{
  GstCaps *template1, *template2, *othercaps;
  GstSrtpSend *filter = NULL;
  filter = GST_SRTPSEND (gst_pad_get_parent (pad));

  if (is_rtcp) {
    template1 = gst_caps_new_simple ("application/x-rtcp", NULL);
    template2 = gst_caps_new_simple ("application/x-srtcp", NULL);
  } else {
    template1 = gst_caps_new_simple ("application/x-rtp", NULL);
    template2 = gst_caps_new_simple ("application/x-srtp", NULL);
  }

  othercaps =
      gst_caps_intersect (gst_pad_get_pad_template_caps (pad), template1);

  if (gst_caps_is_empty (othercaps)) {
    gst_caps_unref (othercaps);
    othercaps =
        gst_caps_intersect (gst_pad_get_pad_template_caps (pad), template2);

    if (gst_caps_is_empty (othercaps)) {
      gst_caps_unref (othercaps);
      othercaps = NULL;
      GST_ERROR_OBJECT (filter, "Could not find caps");
      GST_ELEMENT_ERROR (GST_ELEMENT_CAST (filter), CORE, CAPS, (NULL),
          ("Could not find suitable caps"));
    }
  }

  gst_caps_unref (template1);
  gst_caps_unref (template2);

  gst_object_unref (filter);

  return othercaps;
}

/* RTP pad internal_links function
 */
static GstIterator *
gst_srtp_send_iterate_internal_links_rtp (GstPad * pad)
{
  return gst_srtp_send_iterate_internal_links (pad, FALSE);
}

/* RTCP pad internal_links function
 */
static GstIterator *
gst_srtp_send_iterate_internal_links_rtcp (GstPad * pad)
{
  return gst_srtp_send_iterate_internal_links (pad, TRUE);
}

/* Common internal_links function
 * Returns the list of element linked to the pad
 */
static GstIterator *
gst_srtp_send_iterate_internal_links (GstPad * pad, gboolean is_rtcp)
{
  GstPad *otherpad;
  GstIterator *it = NULL;
  GstSrtpSend *filter = NULL;

  filter = GST_SRTPSEND (gst_pad_get_parent (pad));
  GST_OBJECT_LOCK (filter);

  otherpad = get_rtp_other_pad (filter, pad, is_rtcp);

  GST_OBJECT_UNLOCK (filter);

  if (otherpad)
    it = gst_iterator_new_single (GST_TYPE_PAD, otherpad,
        (GstCopyFunction) gst_object_ref, (GFreeFunc) gst_object_unref);
  else
    GST_ELEMENT_ERROR (GST_ELEMENT_CAST (filter), CORE, PAD, (NULL),
        ("Unable to get linked pad"));

  gst_object_unref (filter);

  return it;
}

/* RTP chain function
 */
static GstFlowReturn
gst_srtp_send_chain_rtp (GstPad * pad, GstBuffer * buf)
{
  return gst_srtp_send_chain (pad, buf, FALSE);
}

/* RTCP chain function
 */
static GstFlowReturn
gst_srtp_send_chain_rtcp (GstPad * pad, GstBuffer * buf)
{
  return gst_srtp_send_chain (pad, buf, TRUE);
}

/* Chain function
 * This function does the actual processing
 */
static GstFlowReturn
gst_srtp_send_chain (GstPad * pad, GstBuffer * buf, gboolean is_rtcp)
{
  GstSrtpSend *filter;
  GstFlowReturn ret = GST_FLOW_CUSTOM_ERROR;
  GstPad *otherpad = NULL;
  err_status_t err;

  filter = GST_SRTPSEND (gst_pad_get_parent (pad));
  GST_OBJECT_LOCK (filter);

  if (!(otherpad = get_rtp_other_pad (filter, pad, is_rtcp))) {
    GST_OBJECT_UNLOCK (filter);
    GST_ERROR_OBJECT (pad, "Unable to get source pad");
    GST_ELEMENT_ERROR (GST_ELEMENT_CAST (filter), CORE, PAD, (NULL),
        ("Unable to get linked pad"));
    return GST_FLOW_ERROR;
  }

  /* Validate buffer SSRC (if key hard limit is not reached) */
  if (!filter->limit_reached)
    ret = validate_buffer (filter, buf, is_rtcp);

  if (ret == GST_FLOW_OK) {
    guint size = GST_BUFFER_SIZE (buf);
    guint size2 = size + SRTP_MAX_TRAILER_LEN;
    gint size_p = size;
    guint8 *srtpbuf;
    ret = GST_FLOW_OK;

    /* For testing : update source caps if asked */
    if (filter->use_caps && filter->ask_setcaps) {
      GST_DEBUG_OBJECT (pad, "Asked to set caps...");
      filter->ask_setcaps = FALSE;
      GST_OBJECT_UNLOCK (filter);

      if (!gst_srtp_send_sink_setcaps (pad, GST_PAD_CAPS (pad), is_rtcp, FALSE)) {
        /* Could not set caps on source pad as asked */
        ret = GST_FLOW_CUSTOM_ERROR;
      }
    } else {
      filter->ask_setcaps = FALSE;
      GST_OBJECT_UNLOCK (filter);
    }

    if (ret == GST_FLOW_OK) {
      ret = GST_FLOW_CUSTOM_ERROR;

      /* Create a bigger buffer to add protection */
      srtpbuf = g_malloc0 (size2);
      memcpy (srtpbuf, GST_BUFFER_DATA (buf), size);

      GST_OBJECT_LOCK (filter);

      if (is_rtcp)
        err = srtp_protect_rtcp (filter->session, srtpbuf, &size_p);
      else
        err = srtp_protect (filter->session, srtpbuf, &size_p);

      GST_OBJECT_UNLOCK (filter);

      if (err == err_status_ok) {
        GST_LOG_OBJECT (pad, "Buffer protected with size %d", size_p);
        gst_buffer_set_data (buf, srtpbuf, size_p);

        /* Set buffer caps as source caps (srtp or srtcp) */
        gst_buffer_set_caps (buf, GST_PAD_CAPS (otherpad));

        /* Push buffer to source pad */
        ret = gst_pad_push (otherpad, buf);

        if (ret != GST_FLOW_OK) {
          GST_ELEMENT_ERROR (GST_ELEMENT_CAST (filter), CORE, PAD, (NULL),
              ("Unable to push buffer on source pad"));
        }

      } else {                  /* srtp_protect failed */
        g_free (srtpbuf);
        GST_WARNING_OBJECT (pad,
            "Unable to protect buffer (protect failed) code %d", err);
      }
    }
  } else {
    GST_OBJECT_UNLOCK (filter);
  }

  /* Drop buffer, except if
   * - gst_pad_push returned OK or an error
   * - validate_buffer returned an error
   */
  if (ret == GST_FLOW_CUSTOM_ERROR) {
    GST_WARNING_OBJECT (pad, "Dropping buffer");
    gst_buffer_unref (buf);
    ret = GST_FLOW_OK;
  }

  gst_object_unref (filter);

  return ret;
}

/* srtp_event_reporter is an event handler function that
 * reports the events that are reported by the libsrtp callbacks
 */
void
srtp_send_event_reporter (srtp_event_data_t * data)
{
  GstSrtpSend *filter = srtp_filter;
  guint32 ssrc = ntohl (data->stream->ssrc);

  if (!GST_IS_SRTPSEND (filter)) {
    GST_WARNING ("Cannot report SRTP event to user (filter invalid)");
    filter = NULL;
  }

  switch (data->event) {
    case event_ssrc_collision:
      GST_WARNING_OBJECT (filter, "SSRC collision on stream %d", ssrc);
      break;
    case event_key_soft_limit:
      GST_WARNING_OBJECT (filter, "Key usage soft limit reached on stream %d",
          ssrc);
      if (filter)
        g_signal_emit (filter, gst_srtp_send_signals[SIGNAL_SOFT_LIMIT], 0,
            ssrc);
      break;
    case event_key_hard_limit:
      GST_WARNING_OBJECT (filter, "Key usage hard limit reached on stream %d",
          ssrc);
      /* Activate flag to drop buffers from now on */
      if (filter) {
        filter->limit_reached = TRUE;
        g_signal_emit (filter, gst_srtp_send_signals[SIGNAL_HARD_LIMIT], 0,
            ssrc);
      }
      break;
    case event_packet_index_limit:
      GST_WARNING_OBJECT (filter, "Packet index limit reached on stream %d",
          ssrc);
      break;
    default:
      GST_WARNING_OBJECT (filter,
          "Unknown event reported to handler on stream %d", ssrc);
  }
}

/* Change state
 */
static GstStateChangeReturn
gst_srtp_send_change_state (GstElement * element, GstStateChange transition)
{
  GstStateChangeReturn res;
  GstSrtpSend *filter;

  filter = GST_SRTPSEND (element);
  GST_OBJECT_LOCK (filter);

  switch (transition) {
    case GST_STATE_CHANGE_NULL_TO_READY:
      srtp_init ();
      filter->first_session = TRUE;
      srtp_install_event_handler (srtp_send_event_reporter);
      break;
    case GST_STATE_CHANGE_READY_TO_PAUSED:
      break;
    case GST_STATE_CHANGE_PAUSED_TO_PLAYING:
      break;
    case GST_STATE_CHANGE_PLAYING_TO_PAUSED:
    case GST_STATE_CHANGE_PAUSED_TO_READY:
      break;
    default:
      break;
  }

  GST_OBJECT_UNLOCK (filter);

  res = parent_class->change_state (element, transition);

  switch (transition) {
    case GST_STATE_CHANGE_PAUSED_TO_PLAYING:
      break;
    case GST_STATE_CHANGE_PLAYING_TO_PAUSED:
      break;
    case GST_STATE_CHANGE_PAUSED_TO_READY:
      break;
    case GST_STATE_CHANGE_READY_TO_NULL:
      gst_srtp_send_reset (element);
      break;
    default:
      break;
  }

  return res;
}

/* entry point to initialize the plug-in
 * initialize the plug-in itself
 * register the element factories and other features
 */
gboolean
gst_srtp_send_plugin_init (GstPlugin * srtpsend)
{
  GST_DEBUG_CATEGORY_INIT (gst_srtp_send_debug, "srtpsend", 0, "SRTP Send");

  return gst_element_register (srtpsend, "srtpsend", GST_RANK_NONE,
      GST_TYPE_SRTPSEND);
}

/* PACKAGE: this is usually set by autotools depending on some _INIT macro
 * in configure.ac and then written into and defined in config.h, but we can
 * just set it ourselves here in case someone doesn't use autotools to
 * compile this code. GST_PLUGIN_DEFINE needs PACKAGE to be defined.
 */
#ifndef PACKAGE
#define PACKAGE "srtpsend"
#endif
