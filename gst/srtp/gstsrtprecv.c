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
 * SECTION:element-srtprecv
 *
 * gstrtprecv acts as a decoder that removes security from SRTP and SRTCP
 * packets (encryption and authentication) and out RTP and RTCP. It
 * receives packet of type 'application/x-srtp' or 'application/x-srtcp'
 * on its sink pad, and outs packets of type 'application/x-rtp' or
 * 'application/x-rtcp' on its sink pad.
 *
 * For each packet received, it checks if the internal SSRC is in the list
 * of streams already in use. If this is not the case, it sends a signal to
 * the user to get the needed parameters to create a new stream : master
 * key, encryption and authentication mecanisms for both RTP and RTCP. If
 * the user can't provide those parameters, the buffer is dropped and a
 * warning is emitted.
 *
 * This element uses libsrtp library. The encryption and authentication
 * mecanisms available are :
 *
 * Encryption
 * - AES_128_ICM (default, maximum security)
 * - STRONGHOLD_CIPHER (same as AES_128_ICM)
 * - NULL
 *
 * Authentication
 * - HMAC_SHA1 (default, maximum protection)
 * - STRONGHOLD_AUTH (same as HMAC_SHA1)
 * - NULL
 *
 * Note that for SRTP protection, authentication is mandatory (non-null)
 * if encryption is used (non-null).
 * 
 * Each packet received is first analysed (checked for valid SSRC) then
 * its buffer is unprotected with libsrtp, then pushed on the source pad.
 * If protection failed or the stream could not be created, the buffer
 * is dropped and a warning is emitted.
 *
 * When the maximum usage of the master key is reached, a soft-limit
 * signal is sent to the user, and new parameters (master key) are needed
 * in return. If the hard limit is reached, a flag is set and every
 * subsequent packet is dropped, until a new key is set and the stream
 * has been updated.
 *
 * <refsect2>
 * <title>Example pipeline</title>
 * |[
 * gst-launch-0.10 udpsrc port=33333 caps="application/x-rtp,mkey=(string)bafbafbaf,..." ! srtprecv use_caps=TRUE ! rtpspeexdepay ! speexdec ! alsasink
 * ]| Receive SPEEX SRTP or SRTCP packets through UDP using caps to specify
 * master key and protection. It outs RTP or SRTP packets.
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

#include "gstsrtprecv.h"

GST_DEBUG_CATEGORY_STATIC (gst_srtp_recv_debug);
#define GST_CAT_DEFAULT gst_srtp_recv_debug

/* Filter signals and args */
enum
{
  SIGNAL_GET_CAPS,
  SIGNAL_CLEAR_STREAMS,
  SIGNAL_SOFT_LIMIT,
  SIGNAL_HARD_LIMIT,
  LAST_SIGNAL
};

enum
{
  PROP_0,
  PROP_USE_CAPS
};

/* the capabilities of the inputs and outputs.
 *
 * describe the real formats here.
 */
static GstStaticPadTemplate rtp_sink_template =
GST_STATIC_PAD_TEMPLATE ("rtp_sink",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("application/x-srtp")
    );

static GstStaticPadTemplate rtp_src_template =
GST_STATIC_PAD_TEMPLATE ("rtp_src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("application/x-rtp")
    );

static GstStaticPadTemplate rtcp_sink_template =
GST_STATIC_PAD_TEMPLATE ("rtcp_sink",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("application/x-srtcp")
    );

static GstStaticPadTemplate rtcp_src_template =
GST_STATIC_PAD_TEMPLATE ("rtcp_src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("application/x-rtcp")
    );

static guint gst_srtp_recv_signals[LAST_SIGNAL] = { 0 };

GST_BOILERPLATE (GstSrtpRecv, gst_srtp_recv, GstElement, GST_TYPE_ELEMENT);

static void gst_srtp_recv_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec);
static void gst_srtp_recv_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec);

static void gst_srtp_recv_clear_streams (GstSrtpRecv * filter);

static gboolean gst_srtp_recv_sink_setcaps_rtp (GstPad * pad, GstCaps * caps);
static gboolean gst_srtp_recv_sink_setcaps_rtcp (GstPad * pad, GstCaps * caps);
static gboolean gst_srtp_recv_sink_setcaps (GstPad * pad, GstCaps * caps,
    gboolean is_rtcp);

static GstCaps *gst_srtp_recv_sink_getcaps_rtp (GstPad * pad);
static GstCaps *gst_srtp_recv_sink_getcaps_rtcp (GstPad * pad);
static GstCaps *gst_srtp_recv_sink_getcaps (GstPad * pad, gboolean is_rtcp);

static GstIterator *gst_srtp_recv_iterate_internal_links_rtp (GstPad * pad);
static GstIterator *gst_srtp_recv_iterate_internal_links_rtcp (GstPad * pad);
static GstIterator *gst_srtp_recv_iterate_internal_links (GstPad * pad,
    gboolean is_rtcp);

static GstFlowReturn gst_srtp_recv_chain_rtp (GstPad * pad, GstBuffer * buf);
static GstFlowReturn gst_srtp_recv_chain_rtcp (GstPad * pad, GstBuffer * buf);
static GstFlowReturn gst_srtp_recv_chain (GstPad * pad, GstBuffer * buf,
    gboolean is_rtcp);

static GstStateChangeReturn gst_srtp_recv_change_state (GstElement * element,
    GstStateChange transition);

static GstSrtpRecv *srtp_filter;

struct _GstSrtpRecvSsrcStream
{
  guint32 ssrc;
  gchar *key;
  guint rtp_cipher;
  guint rtp_auth;
  guint rtcp_cipher;
  guint rtcp_auth;
  gboolean limit_reached;
};

static void
gst_srtp_recv_base_init (gpointer gclass)
{
  GstElementClass *element_class = GST_ELEMENT_CLASS (gclass);

  static const GstElementDetails srtprecv_details =
      GST_ELEMENT_DETAILS ("SrtpRecv",
      "Filter/Network/SrtpRecv",
      "Implement an SRTP to RTP filter",
      "Gabriel Millaire <millaire.gabriel@gmail.com>");

  gst_element_class_set_details (element_class, &srtprecv_details);

  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&rtp_src_template));
  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&rtp_sink_template));
  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&rtcp_src_template));
  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&rtcp_sink_template));
}

/* initialize the srtprecv's class */
static void
gst_srtp_recv_class_init (GstSrtpRecvClass * klass)
{
  GObjectClass *gobject_class;
  GstElementClass *gstelement_class;

  gobject_class = (GObjectClass *) klass;
  gstelement_class = (GstElementClass *) klass;

  gobject_class->set_property = gst_srtp_recv_set_property;
  gobject_class->get_property = gst_srtp_recv_get_property;
  gstelement_class->change_state =
      GST_DEBUG_FUNCPTR (gst_srtp_recv_change_state);
  klass->clear_streams = GST_DEBUG_FUNCPTR (gst_srtp_recv_clear_streams);

  /* Install properties */
  g_object_class_install_property (gobject_class, PROP_USE_CAPS,
      g_param_spec_boolean ("use_caps", "Use_caps",
          "Use caps instead of signals?", FALSE, G_PARAM_READWRITE));

  /* Install signals */
  gst_srtp_recv_signals[SIGNAL_GET_CAPS] =
      g_signal_new ("get-caps", G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (GstSrtpRecvClass,
          get_caps), NULL, NULL, gst_srtp_marshal_BOXED__UINT,
      GST_TYPE_CAPS, 1, G_TYPE_UINT);

  gst_srtp_recv_signals[SIGNAL_CLEAR_STREAMS] =
      g_signal_new ("clear-streams", G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
      G_STRUCT_OFFSET (GstSrtpRecvClass, clear_streams), NULL, NULL,
      g_cclosure_marshal_VOID__VOID, G_TYPE_NONE, 0, G_TYPE_NONE);

  gst_srtp_recv_signals[SIGNAL_SOFT_LIMIT] =
      g_signal_new ("soft-limit", G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (GstSrtpRecvClass,
          soft_limit), NULL, NULL, gst_srtp_marshal_BOXED__UINT,
      GST_TYPE_CAPS, 1, G_TYPE_UINT);

  gst_srtp_recv_signals[SIGNAL_HARD_LIMIT] =
      g_signal_new ("hard-limit", G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (GstSrtpRecvClass,
          hard_limit), NULL, NULL, gst_srtp_marshal_BOXED__UINT,
      GST_TYPE_CAPS, 1, G_TYPE_UINT);
}

/* initialize the new element
 * instantiate pads and add them to element
 * set pad calback functions
 * initialize instance structure
 */
static void
gst_srtp_recv_init (GstSrtpRecv * filter, GstSrtpRecvClass * gclass)
{
  filter->rtp_sinkpad =
      gst_pad_new_from_static_template (&rtp_sink_template, "rtp_sink");
  gst_pad_set_setcaps_function (filter->rtp_sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_recv_sink_setcaps_rtp));
  gst_pad_set_getcaps_function (filter->rtp_sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_recv_sink_getcaps_rtp));
  gst_pad_set_iterate_internal_links_function (filter->rtp_sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_recv_iterate_internal_links_rtp));
  gst_pad_set_chain_function (filter->rtp_sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_recv_chain_rtp));

  filter->rtp_srcpad =
      gst_pad_new_from_static_template (&rtp_src_template, "rtp_src");
  gst_pad_set_getcaps_function (filter->rtp_srcpad,
      GST_DEBUG_FUNCPTR (gst_srtp_recv_sink_getcaps_rtp));
  gst_pad_set_iterate_internal_links_function (filter->rtp_srcpad,
      GST_DEBUG_FUNCPTR (gst_srtp_recv_iterate_internal_links_rtp));

  gst_element_add_pad (GST_ELEMENT (filter), filter->rtp_sinkpad);
  gst_element_add_pad (GST_ELEMENT (filter), filter->rtp_srcpad);


  filter->rtcp_sinkpad =
      gst_pad_new_from_static_template (&rtcp_sink_template, "rtcp_sink");
  gst_pad_set_setcaps_function (filter->rtcp_sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_recv_sink_setcaps_rtcp));
  gst_pad_set_getcaps_function (filter->rtcp_sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_recv_sink_getcaps_rtcp));
  gst_pad_set_iterate_internal_links_function (filter->rtcp_sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_recv_iterate_internal_links_rtcp));
  gst_pad_set_chain_function (filter->rtcp_sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_recv_chain_rtcp));

  filter->rtcp_srcpad =
      gst_pad_new_from_static_template (&rtcp_src_template, "rtcp_src");
  gst_pad_set_getcaps_function (filter->rtcp_srcpad,
      GST_DEBUG_FUNCPTR (gst_srtp_recv_sink_getcaps_rtcp));
  gst_pad_set_iterate_internal_links_function (filter->rtcp_srcpad,
      GST_DEBUG_FUNCPTR (gst_srtp_recv_iterate_internal_links_rtcp));

  gst_element_add_pad (GST_ELEMENT (filter), filter->rtcp_sinkpad);
  gst_element_add_pad (GST_ELEMENT (filter), filter->rtcp_srcpad);

  filter->use_caps = FALSE;
  filter->ask_update = FALSE;
  srtp_filter = filter;
}

/* Find a stream structure for a given SSRC
 */
static GstSrtpRecvSsrcStream *
find_filter_stream_for_ssrc (GstSrtpRecv * filter, guint32 ssrc,
    gboolean ask_update)
{
  GSList *walk;
  GstSrtpRecvSsrcStream *stream = NULL;

  for (walk = filter->streams; walk; walk = g_slist_next (walk)) {
    stream = (GstSrtpRecvSsrcStream *) walk->data;

    if (stream->ssrc == ssrc) {
      /* If asked, remove stream and leave to create a new one */
      if (ask_update) {
        srtp_remove_stream (filter->session, ssrc);
        g_free (stream->key);
        stream->key = NULL;
        filter->streams = g_slist_delete_link (filter->streams, walk);
      } else {
        GST_DEBUG_OBJECT (filter, "Pad found for SSRC %d", ssrc);
      }
      return stream;
    }
  }

  return NULL;
}

/* Set the limit_reached flag on the stream structure with SSRC
 */
static gboolean
set_stream_key_limit (GstSrtpRecv * filter, guint32 ssrc,
    gboolean limit_reached)
{
  gboolean ret = TRUE;
  GstSrtpRecvSsrcStream *stream =
      find_filter_stream_for_ssrc (filter, ssrc, FALSE);
  if (stream)
    stream->limit_reached = limit_reached;
  else
    ret = FALSE;

  return ret;
}

/* get info from buffer caps
 */
static GstSrtpRecvSsrcStream *
get_stream_from_caps (GstCaps * caps, guint32 ssrc)
{
  GstSrtpRecvSsrcStream *stream;
  GstStructure *ps;
  const gchar *key = NULL;
  guint len = 0;

  /* Create new stream structure and set default values */
  stream = g_slice_new0 (GstSrtpRecvSsrcStream);
  stream->ssrc = ssrc;
  stream->key = g_new0 (gchar, 30);
  stream->rtp_cipher = AES_128_ICM;
  stream->rtp_auth = HMAC_SHA1;
  stream->rtcp_cipher = AES_128_ICM;
  stream->rtcp_auth = HMAC_SHA1;
  stream->limit_reached = FALSE;

  /* Get info from caps */
  if ((ps = gst_caps_get_structure (caps, 0)) &&
      (key = gst_structure_get_string (ps, "mkey"))) {

    if ((len = strlen (key)) > 30)
      len = 30;

    memcpy ((void *) stream->key, (void *) key, len);
    gst_structure_get_uint (ps, "rtp_c", &(stream->rtp_cipher));
    gst_structure_get_uint (ps, "rtp_a", &(stream->rtp_auth));
    gst_structure_get_uint (ps, "rtcp_c", &(stream->rtcp_cipher));
    gst_structure_get_uint (ps, "rtcp_a", &(stream->rtcp_auth));
  }

  if (len == 0) {
    g_free (stream->key);
    g_free (stream);
    stream = NULL;
  }

  gst_caps_unref (caps);

  return stream;
}

/* Sets the policy (cipher, authentication)
*/
static void
set_crypto_policy_cipher_auth (GstSrtpRecvSsrcStream * stream,
    crypto_policy_t * policy)
{
  if (stream->rtp_cipher == AES_128_ICM) {
    if (stream->rtp_auth == HMAC_SHA1) {
      crypto_policy_set_aes_cm_128_hmac_sha1_80 (policy);
      GST_LOG ("Policy set to AES_128_ICM and HMAC_SHA1");
    } else {
      crypto_policy_set_aes_cm_128_null_auth (policy);
      GST_LOG ("Policy set to AES_128_ICM and NULL authentication");
    }
  } else {
    if (stream->rtp_auth == HMAC_SHA1) {
      crypto_policy_set_null_cipher_hmac_sha1_80 (policy);
      GST_LOG ("Policy set to NULL cipher and HMAC_SHA1");
    } else {
      policy->cipher_type = NULL_CIPHER;
      policy->cipher_key_len = 0;
      policy->auth_type = NULL_AUTH;
      policy->auth_key_len = 0;
      policy->auth_tag_len = 0;
      policy->sec_serv = sec_serv_none;
      GST_LOG ("Policy set to NULL cipher and NULL authentication");
    }
  }
}

/* Get SRTP params by signal
 */
static GstCaps *
signal_get_srtp_params (GstSrtpRecv * filter, guint32 ssrc, guint signal)
{
  GstCaps *caps = NULL;
  GValue caps_ret = { 0 };
  GValue args[2] = { {0}, {0} };

  g_value_init (&args[0], GST_TYPE_ELEMENT);
  g_value_set_object (&args[0], filter);
  g_value_init (&args[1], G_TYPE_UINT);
  g_value_set_uint (&args[1], ssrc);

  g_value_init (&caps_ret, GST_TYPE_CAPS);
  g_value_set_boxed (&caps_ret, NULL);

  g_signal_emitv (args, gst_srtp_recv_signals[signal], 0, &caps_ret);

  g_value_unset (&args[0]);
  g_value_unset (&args[1]);
  caps = (GstCaps *) g_value_dup_boxed (&caps_ret);
  g_value_unset (&caps_ret);

  return caps;
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

/* Create a stream in the session
 */
static err_status_t
init_session_stream (GstSrtpRecv * filter, guint32 ssrc,
    GstSrtpRecvSsrcStream * stream)
{
  err_status_t ret;
  srtp_policy_t policy;

  if (!stream)
    return err_status_bad_param;

  GST_LOG_OBJECT (filter, "Setting RTP policy...");
  set_crypto_policy_cipher_auth (stream, &policy.rtp);
  GST_LOG_OBJECT (filter, "Setting RTCP policy...");
  set_crypto_policy_cipher_auth (stream, &policy.rtcp);

  policy.ssrc.value = ssrc;
  policy.ssrc.type = ssrc_specific;
  policy.key = (guchar *) stream->key;
  policy.next = NULL;

  /* If it is the first stream, create the session 
   * If not, add the stream policy to the session
   */
  if (filter->first_session)
    ret = srtp_create (&filter->session, &policy);
  else
    ret = srtp_add_stream (filter->session, &policy);

  if (ret == err_status_ok) {
    filter->first_session = FALSE;
    filter->streams = g_slist_prepend (filter->streams, stream);
  }

  return ret;
}

/* Return a stream structure for a given buffer
 */
static GstSrtpRecvSsrcStream *
validate_buffer (GstSrtpRecv * filter, GstBuffer * buf, gboolean is_rtcp)
{
  guint32 ssrc;
  GstCaps *caps;
  err_status_t err;
  GstSrtpRecvSsrcStream *stream = NULL;

  /* Try to find SSRC in local table */
  ssrc = get_ssrc_from_buffer (buf, is_rtcp);

  if (ssrc == 0) {
    GST_WARNING_OBJECT (filter, "No SSRC found in buffer");
  } else {
    stream = find_filter_stream_for_ssrc (filter, ssrc, filter->ask_update);
    filter->ask_update = FALSE;

    if (!stream) {
      /* Policy not found or caps has changed */

      if (!filter->use_caps) {
        /* Emit signal to get srtp-specific params from user */
        GST_LOG_OBJECT (filter, "Using signal for srtp-specific parameters");
        caps = signal_get_srtp_params (filter, ssrc, SIGNAL_GET_CAPS);
      } else {
        /* For testing purpose, get srtp-specific params from caps */
        GST_LOG_OBJECT (filter, "Using caps for srtp-specific parameters");
        caps = gst_buffer_get_caps (buf);
      }

      if (caps)
        stream = get_stream_from_caps (caps, ssrc);

      if (!stream) {
        /* Signal returned empty or invalid caps : drop buffer */
        GST_WARNING_OBJECT (filter,
            "Could not set stream with SSRC %d (no caps or wrong caps)", ssrc);
      } else {                  /* caps are OK */
        err = init_session_stream (filter, ssrc, stream);

        if (err != err_status_ok) {
          g_free (stream->key);
          g_free (stream);
          stream = NULL;
          GST_WARNING_OBJECT (filter,
              "Could not set stream with SSRC %d (error code %d)", ssrc, err);
        } else {
          GST_LOG_OBJECT (filter, "Stream set with SSRC %d and key [%30s]",
              ssrc, stream->key);
        }
      }
    }
  }

  return stream;
}

/* Create new stream from params in caps
 */
static gboolean
new_session_stream_from_caps (GstSrtpRecv * filter, guint32 ssrc,
    GstCaps * caps)
{
  GstSrtpRecvSsrcStream *stream = NULL;
  err_status_t err;
  gboolean ret = FALSE;

  if (!GST_IS_SRTPRECV (filter) || !caps)
    return FALSE;

  find_filter_stream_for_ssrc (filter, ssrc, TRUE);     /* Remove existing stream, if any */
  stream = get_stream_from_caps (caps, ssrc);

  if (stream) {
    err = init_session_stream (filter, ssrc, stream);   /* Create new session stream */

    if (err != err_status_ok) {
      g_free (stream->key);
      g_free (stream);
      stream = NULL;
    } else {
      ret = TRUE;
    }
  }

  return ret;
}

/* Clear the policy list
 */
static void
gst_srtp_recv_clear_streams (GstSrtpRecv * filter)
{
  GSList *walk;
  GstSrtpRecvSsrcStream *stream;
  guint nb = 0;

  GST_OBJECT_LOCK (filter);

  if (!filter->first_session)
    srtp_dealloc (filter->session);
  filter->first_session = TRUE;

  walk = filter->streams;
  while (walk) {
    stream = (GstSrtpRecvSsrcStream *) walk->data;

    if (stream) {
      g_free (stream->key);
      g_slice_free (GstSrtpRecvSsrcStream, stream);
      walk = filter->streams = g_slist_delete_link (filter->streams, walk);
      nb++;
    }
  }

  filter->streams = NULL;
  GST_OBJECT_UNLOCK (filter);
  GST_DEBUG_OBJECT (filter, "Cleared %d streams", nb);
}

/* Set property
 */
static void
gst_srtp_recv_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  GstSrtpRecv *filter = GST_SRTPRECV (object);
  GST_OBJECT_LOCK (filter);

  switch (prop_id) {
    case PROP_USE_CAPS:
      filter->use_caps = g_value_get_boolean (value);
      GST_DEBUG_OBJECT (object, "set use_caps : %d", filter->use_caps);
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
gst_srtp_recv_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  GstSrtpRecv *filter = GST_SRTPRECV (object);
  GST_OBJECT_LOCK (filter);

  switch (prop_id) {
    case PROP_USE_CAPS:
      g_value_set_boolean (value, filter->use_caps);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }

  GST_OBJECT_UNLOCK (filter);
}

/* RTP pad setcaps function
 */
static gboolean
gst_srtp_recv_sink_setcaps_rtp (GstPad * pad, GstCaps * caps)
{
  return gst_srtp_recv_sink_setcaps (pad, caps, FALSE);
}

/* RTCP pad setcaps function
 */
static gboolean
gst_srtp_recv_sink_setcaps_rtcp (GstPad * pad, GstCaps * caps)
{
  return gst_srtp_recv_sink_setcaps (pad, caps, TRUE);
}


/* Common setcaps function
 * Handles the link with other elements
 */
static gboolean
gst_srtp_recv_sink_setcaps (GstPad * pad, GstCaps * caps, gboolean is_rtcp)
{
  GstSrtpRecv *filter;
  GstPad *otherpad;
  GstCaps *othercaps;
  GstStructure *ps;
  gboolean ret = FALSE;

  filter = GST_SRTPRECV (gst_pad_get_parent (pad));

  if ((othercaps = gst_caps_copy (caps))) {
    /* Remove srtp params before setting caps on src */
    ps = gst_caps_get_structure (othercaps, 0);
    GST_DEBUG_OBJECT (pad, "Caps: %" GST_PTR_FORMAT, othercaps);

    gst_structure_remove_field (ps, "mkey");
    gst_structure_remove_field (ps, "rtp_c");
    gst_structure_remove_field (ps, "rtp_a");
    gst_structure_remove_field (ps, "rtcp_c");
    gst_structure_remove_field (ps, "rtcp_a");

    if (is_rtcp)
      gst_structure_set_name (ps, "application/x-rtcp");
    else
      gst_structure_set_name (ps, "application/x-rtp");

    GST_OBJECT_LOCK (filter);

    if (is_rtcp)
      otherpad = filter->rtcp_srcpad;
    else
      otherpad = filter->rtp_srcpad;

    GST_OBJECT_UNLOCK (filter);

    if (gst_pad_set_caps (otherpad, othercaps))
      ret = TRUE;

    gst_caps_unref (othercaps);
  }

  if (!ret) {
    GST_ERROR_OBJECT (pad, "Could not set caps on source pad");
    GST_ELEMENT_ERROR (GST_ELEMENT_CAST (filter), CORE, CAPS, (NULL),
        ("Could not set caps on source pad"));
  }

  gst_object_unref (filter);

  return ret;
}

/* RTP pad getcaps function
 */
static GstCaps *
gst_srtp_recv_sink_getcaps_rtp (GstPad * pad)
{
  return gst_srtp_recv_sink_getcaps (pad, FALSE);
}

/* RTCP pad getcaps function
 */
static GstCaps *
gst_srtp_recv_sink_getcaps_rtcp (GstPad * pad)
{
  return gst_srtp_recv_sink_getcaps (pad, TRUE);
}

/* Common getcaps function
 * Handles the link with other elements
 */
static GstCaps *
gst_srtp_recv_sink_getcaps (GstPad * pad, gboolean is_rtcp)
{
  GstCaps *othercaps = NULL;
  GstSrtpRecv *filter = NULL;

  filter = GST_SRTPRECV (gst_pad_get_parent (pad));
  GST_OBJECT_LOCK (filter);

  if (pad == filter->rtp_sinkpad)
    othercaps = gst_caps_new_simple ("application/x-srtp", NULL);
  else if (pad == filter->rtp_srcpad)
    othercaps = gst_caps_new_simple ("application/x-rtp", NULL);
  else if (pad == filter->rtcp_sinkpad)
    othercaps = gst_caps_new_simple ("application/x-srtcp", NULL);
  else if (pad == filter->rtcp_srcpad)
    othercaps = gst_caps_new_simple ("application/x-rtcp", NULL);
  else {
    GST_ERROR_OBJECT (pad, "Could not find suitable caps");
    GST_ELEMENT_ERROR (GST_ELEMENT_CAST (filter), CORE, CAPS, (NULL),
        ("Could not find suitable caps"));
  }

  GST_OBJECT_UNLOCK (filter);
  gst_object_unref (filter);

  return othercaps;
}

/* RTP pad internal_links function
 */
static GstIterator *
gst_srtp_recv_iterate_internal_links_rtp (GstPad * pad)
{
  return gst_srtp_recv_iterate_internal_links (pad, FALSE);
}

/* RTCP pad internal_links function
 */
static GstIterator *
gst_srtp_recv_iterate_internal_links_rtcp (GstPad * pad)
{
  return gst_srtp_recv_iterate_internal_links (pad, TRUE);
}

/* Common internal_links function
 * Returns the list of element linked to the pad
 */
static GstIterator *
gst_srtp_recv_iterate_internal_links (GstPad * pad, gboolean is_rtcp)
{
  GstSrtpRecv *filter = NULL;
  GstPad *otherpad = NULL;
  GstIterator *it = NULL;

  filter = GST_SRTPRECV (gst_pad_get_parent (pad));
  GST_OBJECT_LOCK (filter);

  if (is_rtcp) {
    if (pad == filter->rtcp_sinkpad)
      otherpad = filter->rtcp_srcpad;
    else if (pad == filter->rtcp_srcpad)
      otherpad = filter->rtcp_sinkpad;
  } else {
    if (pad == filter->rtp_sinkpad)
      otherpad = filter->rtp_srcpad;
    else if (pad == filter->rtp_srcpad)
      otherpad = filter->rtp_sinkpad;
  }

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
gst_srtp_recv_chain_rtp (GstPad * pad, GstBuffer * buf)
{
  return gst_srtp_recv_chain (pad, buf, FALSE);
}

/* RTCP chain function
 */
static GstFlowReturn
gst_srtp_recv_chain_rtcp (GstPad * pad, GstBuffer * buf)
{
  return gst_srtp_recv_chain (pad, buf, TRUE);
}

/* Chain function
 * This function does the actual processing
 */
static GstFlowReturn
gst_srtp_recv_chain (GstPad * pad, GstBuffer * buf, gboolean is_rtcp)
{
  GstSrtpRecv *filter;
  GstCaps *caps;
  GstPad *otherpad;
  err_status_t err;
  GstSrtpRecvSsrcStream *stream = NULL;
  GstFlowReturn ret = GST_FLOW_CUSTOM_ERROR;
  gint signal = -1;

  filter = GST_SRTPRECV (gst_pad_get_parent (pad));

  GST_LOG_OBJECT (pad, "Received buffer of size %d", GST_BUFFER_SIZE (buf));
  GST_OBJECT_LOCK (filter);

  /* Check if this stream exists, if not create a new stream */
  stream = validate_buffer (filter, buf, is_rtcp);

  if (stream) {
    if (!stream->limit_reached) {       /* Drop buffer if flag is set */
      guint size = GST_BUFFER_SIZE (buf);
      gint size_p = size;

      /* Change buffer to remove protection */
      buf = gst_buffer_make_writable (buf);

      if (is_rtcp) {
        otherpad = filter->rtcp_srcpad;
        err =
            srtp_unprotect_rtcp (filter->session, GST_BUFFER_DATA (buf),
            &size_p);
      } else {
        otherpad = filter->rtp_srcpad;
        err = srtp_unprotect (filter->session, GST_BUFFER_DATA (buf), &size_p);
      }

      GST_OBJECT_UNLOCK (filter);

      if (err == err_status_ok) {
        GST_LOG_OBJECT (pad, "Buffer unprotected with size %d", size_p);
        GST_BUFFER_SIZE (buf) = size_p;

        /* Remove srtp-specific caps from buffer */
        gst_buffer_set_caps (buf, GST_PAD_CAPS (otherpad));

        /* Push buffer to source pad */
        ret = gst_pad_push (otherpad, buf);

        if (ret != GST_FLOW_OK) {
          GST_ELEMENT_ERROR (GST_ELEMENT_CAST (filter), CORE, PAD, (NULL),
              ("Unable to push buffer on source pad"));
        }

      } else {                  /* srtp_unprotect failed */
        GST_WARNING_OBJECT (pad,
            "Unable to unprotect buffer (unprotect failed) code %d", err);

        /* Signal user depending on type of error */
        switch (err) {
          case err_status_key_expired:
            /* Signal already sent in event_reporter */
            /*signal = SIGNAL_HARD_LIMIT; */
            break;
          case err_status_auth_fail:
          case err_status_cipher_fail:
            signal = SIGNAL_GET_CAPS;
            break;
          default:
            signal = -1;
        }
      }
    } else {                    /* Hard limit reached */
      /* Ask the user for caps at a regular interval */
      signal = SIGNAL_HARD_LIMIT;
      GST_OBJECT_UNLOCK (filter);
    }
  } else {                      /* Could not find or create stream */
    GST_OBJECT_UNLOCK (filter);
  }

  /* Drop buffer, except if gst_pad_push returned OK or an error */
  if (ret == GST_FLOW_CUSTOM_ERROR) {
    GST_WARNING_OBJECT (pad, "Dropping buffer");
    gst_buffer_unref (buf);
    ret = GST_FLOW_OK;

    if (signal != -1) {
      GST_DEBUG_OBJECT (pad, "Sending signal %d to user", signal);
      GST_OBJECT_LOCK (filter);

      caps = signal_get_srtp_params (filter, stream->ssrc, signal);

      if (caps) {
        if (new_session_stream_from_caps (filter, stream->ssrc, caps))
          GST_LOG_OBJECT (filter, "New stream set with SSRC %d", stream->ssrc);
        else
          GST_WARNING_OBJECT (filter, "Could not set stream with SSRC %d",
              stream->ssrc);

        set_stream_key_limit (filter, stream->ssrc, FALSE);
      } else {
        GST_DEBUG_OBJECT (pad, "No answer to signal %d", signal);
      }

      GST_OBJECT_UNLOCK (filter);
    }
  } else if (ret == GST_FLOW_OK) {
    signal = -1;
  }

  gst_object_unref (filter);

  return ret;
}

/* srtp_event_reporter is an event handler function that
 * reports the events that are reported by the libsrtp callbacks
 */
void
srtp_recv_event_reporter (srtp_event_data_t * data)
{
  GstSrtpRecv *filter = srtp_filter;
  GstCaps *caps;
  guint32 ssrc = ntohl (data->stream->ssrc);

  if (!GST_IS_SRTPRECV (filter)) {
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

      if (filter) {
        caps = signal_get_srtp_params (filter, ssrc, SIGNAL_SOFT_LIMIT);

        if (caps) {
          if (new_session_stream_from_caps (filter, ssrc, caps)) {
            GST_LOG_OBJECT (filter, "Stream set with SSRC %d", ssrc);
          } else {
            GST_WARNING_OBJECT (filter, "Could not set stream with SSRC %d",
                ssrc);
          }
        }                       /* No answer from user : no problem for now, just wait */
      }
      break;
    case event_key_hard_limit:
      GST_WARNING_OBJECT (filter, "Key usage hard limit reached on stream %d",
          ssrc);

      if (filter) {
        set_stream_key_limit (filter, ssrc, TRUE);
        caps = signal_get_srtp_params (filter, ssrc, SIGNAL_HARD_LIMIT);

        if (caps) {
          if (new_session_stream_from_caps (filter, ssrc, caps))
            GST_LOG_OBJECT (filter, "Stream set with SSRC %d", ssrc);
          else
            GST_WARNING_OBJECT (filter, "Could not set stream with SSRC %d",
                ssrc);
        } else {
          /* No answer from user : limit_reached flag is activated for this stream 
           * This will drop every buffer on that stream from now on
           */
          GST_WARNING_OBJECT (filter,
              "No answer from user, dropping buffers on stream %d", ssrc);
        }
      }
      break;
    case event_packet_index_limit:
      GST_WARNING_OBJECT (filter, "Packet index limit reached on stream %d",
          data->stream->ssrc);
      break;
    default:
      GST_WARNING_OBJECT (filter,
          "Unknown event reported to handler on stream %d", data->stream->ssrc);
  }
}

/* Change state
 */
static GstStateChangeReturn
gst_srtp_recv_change_state (GstElement * element, GstStateChange transition)
{
  GstStateChangeReturn res;
  GstSrtpRecv *filter;

  filter = GST_SRTPRECV (element);
  GST_OBJECT_LOCK (filter);

  switch (transition) {
    case GST_STATE_CHANGE_NULL_TO_READY:
      srtp_init ();
      srtp_install_event_handler (srtp_recv_event_reporter);
      filter->first_session = TRUE;
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
      gst_srtp_recv_clear_streams (filter);
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
gst_srtp_recv_plugin_init (GstPlugin * srtprecv)
{
  GST_DEBUG_CATEGORY_INIT (gst_srtp_recv_debug, "srtprecv", 0, "SRTP recv");

  return gst_element_register (srtprecv, "srtprecv", GST_RANK_NONE,
      GST_TYPE_SRTPRECV);
}

/* PACKAGE: this is usually set by autotools depending on some _INIT macro
 * in configure.ac and then written into and defined in config.h, but we can
 * just set it ourselves here in case someone doesn't use autotools to
 * compile this code. GST_PLUGIN_DEFINE needs PACKAGE to be defined.
 */
#ifndef PACKAGE
#define PACKAGE "srtprecv"
#endif
