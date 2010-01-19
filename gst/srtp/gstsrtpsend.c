/*
 * GStreamer - GStreamer SRTP encoder
 *
 * Copyright 2009 Collabora Ltd.
 *  @author: Gabriel Millaire <gabriel.millaire@collabora.co.uk>
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
 * Encryption (properties rtp-cipher and rtcp-cipher)
 * - AES_128_ICM (default, maximum security)
 * - STRONGHOLD_CIPHER (same as AES_128_ICM)
 * - NULL
 *
 * Authentication (properties rtp-auth and rtcp-auth)
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
#include "gstsrtp-enumtypes.h"
#include "gstsrtpsend.h"

GST_DEBUG_CATEGORY_STATIC (gst_srtp_send_debug);
#define GST_CAT_DEFAULT gst_srtp_send_debug

/* Properties default values */
#define DEFAULT_MASTER_KEY      NULL
#define DEFAULT_RTP_CIPHER_STR  "AES_128_ICM"
#define DEFAULT_RTP_AUTH_STR    "HMAC_SHA1"
#define DEFAULT_RTCP_CIPHER_STR DEFAULT_RTP_CIPHER_STR
#define DEFAULT_RTCP_AUTH_STR   DEFAULT_RTP_AUTH_STR
#define DEFAULT_RTP_CIPHER      GST_SRTP_CIPHER_AES_128_ICM
#define DEFAULT_RTP_AUTH        GST_SRTP_AUTH_HMAC_SHA1
#define DEFAULT_RTCP_CIPHER     DEFAULT_RTP_CIPHER
#define DEFAULT_RTCP_AUTH       DEFAULT_RTP_AUTH

#define OBJECT_LOCK(arg)  {GST_DEBUG("Locking"); GST_OBJECT_LOCK(arg);}
#define OBJECT_UNLOCK(arg)  {GST_DEBUG("Unlocking"); GST_OBJECT_UNLOCK(arg);}

/* Filter signals and args */
enum
{
  SIGNAL_SOFT_LIMIT,
  SIGNAL_HARD_LIMIT,
  SIGNAL_INDEX_LIMIT,
  LAST_SIGNAL
};

enum
{
  PROP_0,
  PROP_MKEY,
  PROP_RTP_CIPHER,
  PROP_RTP_AUTH,
  PROP_RTCP_CIPHER,
  PROP_RTCP_AUTH
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

static void gst_srtp_send_dispose (GObject * object);

static void gst_srtp_send_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec);
static void gst_srtp_send_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec);

static gboolean gst_srtp_send_sink_setcaps_rtp (GstPad * pad, GstCaps * caps);
static gboolean gst_srtp_send_sink_setcaps_rtcp (GstPad * pad, GstCaps * caps);
static gboolean gst_srtp_send_sink_setcaps (GstPad * pad, GstCaps * caps,
    gboolean is_rtcp);

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

static gboolean gst_srtp_send_sink_event_rtp (GstPad * pad, GstEvent * event);
static gboolean gst_srtp_send_sink_event_rtcp (GstPad * pad, GstEvent * event);
static gboolean gst_srtp_send_sink_event (GstPad * pad, GstEvent * event,
    gboolean is_rtcp);

static gboolean gst_srtp_send_src_event_rtp (GstPad * pad, GstEvent * event);
static gboolean gst_srtp_send_src_event_rtcp (GstPad * pad, GstEvent * event);
static gboolean gst_srtp_send_src_event (GstPad * pad, GstEvent * event,
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
/*
enum
{
  GST_SRTP_CIPHER_NULL = 0,
  GST_SRTP_CIPHER_AES_128_ICM
};

enum
{
  GST_SRTP_AUTH_NULL = 0,
  GST_SRTP_AUTH_HMAC_SHA1 = 3
};

#define GST_SRTP_CIPHER_TYPE (gst_srtp_cipher_get_type())
static GType
gst_srtp_cipher_get_type (void)
{
  static GType type = 0;

  static const GEnumValue types[] = {
    {GST_SRTP_CIPHER_NULL, "NULL_CIPHER", "NULL_CIPHER"},
    {GST_SRTP_CIPHER_AES_128_ICM, "AES_128_ICM", "AES_128_ICM"},
    {0, NULL, NULL}
  };

  if (!type) {
    type = g_enum_register_static ("GstSrtpCipher", types);
  }
  return type;
}

#define GST_SRTP_AUTH_TYPE (gst_srtp_auth_get_type())
static GType
gst_srtp_auth_get_type (void)
{
  static GType type = 0;

  static const GEnumValue types[] = {
    {GST_SRTP_AUTH_NULL, "NULL_AUTH", "NULL_AUTH"},
    {GST_SRTP_AUTH_HMAC_SHA1, "HMAC_SHA1", "HMAC_SHA1"},
    {0, NULL, NULL}
  };

  if (!type) {
    type = g_enum_register_static ("GstSrtpAuth", types);
  }
  return type;
}
*/
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
  gobject_class->dispose = gst_srtp_send_dispose;
  gstelement_class->request_new_pad =
      GST_DEBUG_FUNCPTR (gst_srtp_send_request_new_pad);
  gstelement_class->release_pad = GST_DEBUG_FUNCPTR (gst_srtp_send_release_pad);
  gstelement_class->change_state =
      GST_DEBUG_FUNCPTR (gst_srtp_send_change_state);

  /* Install properties */
  g_object_class_install_property (gobject_class, PROP_MKEY,
      g_param_spec_pointer ("key", "Key", "Master key",
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (gobject_class, PROP_RTP_CIPHER,
      g_param_spec_enum ("rtp-cipher", "RTP Cipher", "RTP Cipher",
          GST_TYPE_SRTP_CIPHER_TYPE, DEFAULT_RTP_CIPHER,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (gobject_class, PROP_RTP_AUTH,
      g_param_spec_enum ("rtp-auth", "RTP Authentication",
          "RTP Authentication", GST_TYPE_SRTP_AUTH_TYPE, DEFAULT_RTP_AUTH,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (gobject_class, PROP_RTCP_CIPHER,
      g_param_spec_enum ("rtcp-cipher", "RTCP Cipher",
          "RTCP Cipher", GST_TYPE_SRTP_CIPHER_TYPE, DEFAULT_RTCP_CIPHER,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (gobject_class, PROP_RTCP_AUTH,
      g_param_spec_enum ("rtcp-auth", "RTCP Authentication",
          "RTCP Authentication", GST_TYPE_SRTP_AUTH_TYPE, DEFAULT_RTCP_AUTH,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  /**
   * GstSrtpSend::soft-limit:
   * @gstsrtpsend: the element on which the signal is emitted
   * @ssrc: The unique SSRC of the stream
   *
   * Signal emited when the stream with @ssrc has reached the
   * soft limit of utilisation of it's master encryption key.
   * User should provide a new key by setting the corresponding
   * property.
   */
  gst_srtp_send_signals[SIGNAL_SOFT_LIMIT] =
      g_signal_new ("soft-limit", G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, 0, NULL, NULL, gst_srtp_marshal_VOID__UINT,
      G_TYPE_NONE, 1, G_TYPE_UINT);

  /**
   * GstSrtpSend::hard-limit:
   * @gstsrtpsend: the element on which the signal is emitted
   * @ssrc: The unique SSRC of the stream
   *
   * Signal emited when the stream with @ssrc has reached the
   * hard limit of utilisation of it's master encryption key.
   * User should provide a new key by setting the corresponding
   * property, then return TRUE. If user could not set a new key
   * or signal is not answered, the element will abort execution.
   */
  gst_srtp_send_signals[SIGNAL_HARD_LIMIT] =
      g_signal_new ("hard-limit", G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, 0, NULL, NULL, gst_srtp_marshal_UINT__UINT,
      G_TYPE_UINT, 1, G_TYPE_UINT);

  /**
   * GstSrtpSend::index-limit:
   * @gstsrtpsend: the element on which the signal is emitted
   * @ssrc: The unique SSRC of the stream
   *
   * Signal emited when the stream with @ssrc has reached the
   * index limit of paquet. User should provide a new key and,
   * optionnaly, new RTP and RTCP encryption ciphers and
   * authentication by setting the corresponding properties,
   * then return TRUE. If user could not set a new key
   * or signal is not answered, the element will abort execution.
   */
  gst_srtp_send_signals[SIGNAL_INDEX_LIMIT] =
      g_signal_new ("index-limit", G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, 0, NULL, NULL, gst_srtp_marshal_UINT__UINT,
      G_TYPE_UINT, 1, G_TYPE_UINT);
}

/* initialize the new element
 */
static void
gst_srtp_send_init (GstSrtpSend * filter, GstSrtpSendClass * gclass)
{
  srtp_init ();
  srtp_filter = filter;

  filter->limit_reached = FALSE;
  filter->wait_change = FALSE;
  filter->ask_setcaps = FALSE;
  filter->first_session = TRUE;
  filter->key = DEFAULT_MASTER_KEY;
  filter->rtp_cipher = DEFAULT_RTP_CIPHER;
  filter->rtp_auth = DEFAULT_RTP_AUTH;
  filter->rtcp_cipher = DEFAULT_RTCP_CIPHER;
  filter->rtcp_auth = DEFAULT_RTCP_AUTH;
}

/* Sets the policy (cipher, authentication)
 */
static void
set_crypto_policy_cipher_auth (guint cipher, guint auth,
    crypto_policy_t * policy)
{
  if (cipher == GST_SRTP_CIPHER_AES_128_ICM) {
    if (auth == GST_SRTP_AUTH_HMAC_SHA1) {
      crypto_policy_set_aes_cm_128_hmac_sha1_80 (policy);
      GST_DEBUG ("Policy set to AES_128_ICM and HMAC_SHA1");
    } else {
      crypto_policy_set_aes_cm_128_null_auth (policy);
      GST_DEBUG ("Policy set to AES_128_ICM and NULL authentication");
    }
  } else {
    if (auth == GST_SRTP_AUTH_HMAC_SHA1) {
      crypto_policy_set_null_cipher_hmac_sha1_80 (policy);
      GST_DEBUG ("Policy set to NULL cipher and HMAC_SHA1");
    } else {
      policy->cipher_type = NULL_CIPHER;
      policy->cipher_key_len = 0;
      policy->auth_type = NULL_AUTH;
      policy->auth_key_len = 0;
      policy->auth_tag_len = 0;
      policy->sec_serv = sec_serv_none;
      GST_DEBUG ("Policy set to NULL cipher and NULL authentication");
    }
  }
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

    if (filter->rtcp_cipher != NULL_CIPHER && filter->rtcp_auth == NULL_AUTH) {
      /* RTCP authentication can't be NULL if encryption is not NULL (RFC 3711) */
      srtp_remove_stream (filter->session, ssrc);
      ret = ssrc_new;
    } else {
      ret = ssrc_valid;
    }

  } else {                      /* SSRC is invalid */
    ret = ssrc_invalid;
  }

  return ret;
}

/* Get SSRC from buffer
 */
static gboolean
get_ssrc_from_buffer (GstBuffer * buf, guint32 * ssrc, gboolean is_rtcp)
{
  gboolean ret = FALSE;
  GstRTCPPacket packet;
  /* RTCP only */
  guint64 ntptime;
  guint32 rtptime;
  guint32 packet_count;
  guint32 octet_count;

  if (is_rtcp) {                /* Get SSRC from RR or SR packet (RTCP) */
    if (gst_rtcp_buffer_get_first_packet (buf, &packet)) {
      do {
        switch (gst_rtcp_packet_get_type (&packet)) {
          case GST_RTCP_TYPE_RR:
            *ssrc = gst_rtcp_packet_rr_get_ssrc (&packet);
            ret = TRUE;
            break;
          case GST_RTCP_TYPE_SR:
            gst_rtcp_packet_sr_get_sender_info (&packet, ssrc, &ntptime,
                &rtptime, &packet_count, &octet_count);
            ret = TRUE;
            break;
          default:
            break;
        }
      } while (gst_rtcp_packet_move_to_next (&packet) && ret == FALSE);
    }
  } else {                      /* Get SSRC from buffer (RTP) */
    *ssrc = gst_rtp_buffer_get_ssrc (buf);
    ret = TRUE;
  }

  return ret;
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
      && (filter->rtcp_auth == NULL_AUTH)) {
    filter->rtcp_auth = HMAC_SHA1;
    GST_WARNING_OBJECT (filter,
        "RTCP authentication can't be NULL if encryption is not NULL. Setting RTCP authentication to HMAC_SHA1.");
  }

  GST_INFO_OBJECT (filter, "Setting RTP policy...");
  set_crypto_policy_cipher_auth (filter->rtp_cipher, filter->rtp_auth,
      &policy.rtp);
  GST_INFO_OBJECT (filter, "Setting RTCP policy...");
  set_crypto_policy_cipher_auth (filter->rtcp_cipher, filter->rtcp_auth,
      &policy.rtcp);

  policy.ssrc.value = ssrc;
  policy.ssrc.type = ssrc_specific;
  policy.key = (guchar *) GST_BUFFER_DATA (filter->key);
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
static buffer_state_t
validate_buffer (GstSrtpSend * filter, GstBuffer * buf, gboolean is_rtcp)
{
  guint32 ssrc = 0;
  err_status_t err;
  gboolean gret;
  buffer_state_t ret;
  ssrc_state_t state;

  gret = get_ssrc_from_buffer (buf, &ssrc, is_rtcp);

  if (gret == TRUE) {
    state = validate_ssrc (filter, ssrc);

    if (state == ssrc_new) {
      /* New session (or property/caps changed) : create stream */

      /* Check if key is valid */
      if (!filter->key) {
        GST_ELEMENT_ERROR (GST_ELEMENT_CAST (filter), LIBRARY, SETTINGS,
            (NULL), ("No master key property specified"));
        return buffer_drop_fail;
      }

      err = init_new_stream (filter, filter->ssrc);

      if (err != err_status_ok) {
        GST_ELEMENT_ERROR (GST_ELEMENT_CAST (filter), LIBRARY, SETTINGS,
            (NULL), ("Could not init new stream"));
        /* Will drop buffer and fail */
        ret = buffer_drop_fail;

      } else {
        GST_INFO_OBJECT (filter, "Stream set for SSRC %d", filter->ssrc);
        filter->first_session = FALSE;
        ret = buffer_valid;
      }

    } else if (state == ssrc_invalid) { /* Wrong SSRC */
      GST_WARNING_OBJECT (filter, "Wrong SSRC in stream (%d)", ssrc);

      /* Will drop buffer but continue */
      ret = buffer_drop_continue;
    } else {                    /* state = ssrc_valid */
      ret = buffer_valid;
    }
  } else {
    /* Will drop buffer but continue */
    ret = buffer_drop_continue;
  }

  return ret;
}

/* Release ressources and set default values
 */
static void
gst_srtp_send_reset (GstSrtpSend * filter)
{
  GST_INFO_OBJECT (filter, "Releasing ressources");

  GST_OBJECT_LOCK (filter);

  if (!filter->first_session)
    srtp_dealloc (filter->session);

  filter->ask_setcaps = TRUE;
  filter->limit_reached = FALSE;
  filter->wait_change = FALSE;
  filter->first_session = TRUE;

  GST_OBJECT_UNLOCK (filter);
}

/* Create sinkpad to receive RTP packets from senders
 * and a srcpad for the RTP packets
 */
static GstPad *
create_rtp_sink (GstSrtpSend * filter, const gchar * name)
{
  gchar *sinkpadname, *srcpadname;
  gint nb = 0;
  GstSrtpSendPads *rtppad;

  rtppad = g_slice_new0 (GstSrtpSendPads);

  GST_DEBUG_OBJECT (filter, "creating RTP sink pad");
  rtppad->sinkpad = gst_pad_new_from_static_template (&rtp_sink_template, name);

  sinkpadname = gst_pad_get_name (rtppad->sinkpad);
  sscanf (sinkpadname, "rtp_sink_%d", &nb);
  srcpadname = g_strdup_printf ("rtp_src_%d", nb);

  GST_DEBUG_OBJECT (filter, "creating RTP source pad");
  rtppad->srcpad =
      gst_pad_new_from_static_template (&rtp_src_template, srcpadname);
  g_free (srcpadname);
  g_free (sinkpadname);

  gst_pad_set_element_private (rtppad->sinkpad, rtppad->srcpad);
  gst_pad_set_element_private (rtppad->srcpad, rtppad->sinkpad);

  gst_pad_set_setcaps_function (rtppad->sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_sink_setcaps_rtp));
  gst_pad_set_getcaps_function (rtppad->sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_sink_getcaps_rtp));
  gst_pad_set_iterate_internal_links_function (rtppad->sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_iterate_internal_links_rtp));
  gst_pad_set_chain_function (rtppad->sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_chain_rtp));
  gst_pad_set_event_function (rtppad->sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_sink_event_rtp));
  gst_pad_set_active (rtppad->sinkpad, TRUE);
  gst_element_add_pad (GST_ELEMENT_CAST (filter), rtppad->sinkpad);

  gst_pad_set_iterate_internal_links_function (rtppad->srcpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_iterate_internal_links_rtp));
  gst_pad_set_event_function (rtppad->srcpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_src_event_rtp));
  gst_pad_set_active (rtppad->srcpad, TRUE);
  gst_element_add_pad (GST_ELEMENT_CAST (filter), rtppad->srcpad);

  return rtppad->sinkpad;
}

/* Create sinkpad to receive RTCP packets from senders
 * and a srcpad for the RTCP packets
 */
static GstPad *
create_rtcp_sink (GstSrtpSend * filter, const gchar * name)
{
  gchar *sinkpadname, *srcpadname;
  GstSrtpSendPads *rtcppad;
  gint nb = 0;

  rtcppad = g_slice_new0 (GstSrtpSendPads);

  GST_DEBUG_OBJECT (filter, "creating RTCP sink pad");
  rtcppad->sinkpad =
      gst_pad_new_from_static_template (&rtcp_sink_template, name);

  sinkpadname = gst_pad_get_name (rtcppad->sinkpad);
  sscanf (sinkpadname, "rtcp_sink_%d", &nb);
  srcpadname = g_strdup_printf ("rtcp_src_%d", nb);

  GST_DEBUG_OBJECT (filter, "creating RTCP source pad");
  rtcppad->srcpad =
      gst_pad_new_from_static_template (&rtcp_src_template, srcpadname);
  g_free (srcpadname);
  g_free (sinkpadname);

  gst_pad_set_element_private (rtcppad->sinkpad, rtcppad->srcpad);
  gst_pad_set_element_private (rtcppad->srcpad, rtcppad->sinkpad);

  gst_pad_set_setcaps_function (rtcppad->sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_sink_setcaps_rtcp));
  gst_pad_set_getcaps_function (rtcppad->sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_sink_getcaps_rtcp));
  gst_pad_set_iterate_internal_links_function (rtcppad->sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_iterate_internal_links_rtcp));
  gst_pad_set_chain_function (rtcppad->sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_chain_rtcp));
  gst_pad_set_event_function (rtcppad->sinkpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_sink_event_rtcp));
  gst_pad_set_active (rtcppad->sinkpad, TRUE);
  gst_element_add_pad (GST_ELEMENT_CAST (filter), rtcppad->sinkpad);

  gst_pad_set_iterate_internal_links_function (rtcppad->srcpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_iterate_internal_links_rtcp));
  gst_pad_set_event_function (rtcppad->srcpad,
      GST_DEBUG_FUNCPTR (gst_srtp_send_src_event_rtcp));
  gst_pad_set_active (rtcppad->srcpad, TRUE);
  gst_element_add_pad (GST_ELEMENT_CAST (filter), rtcppad->srcpad);

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

  GST_INFO_OBJECT (element, "New pad requested");

  if (templ == gst_element_class_get_pad_template (klass, "rtp_sink_%d")) {
    pad = create_rtp_sink (filter, name);
  } else if (templ == gst_element_class_get_pad_template (klass,
          "rtcp_sink_%d")) {
    pad = create_rtcp_sink (filter, name);
  } else {
    GST_ELEMENT_ERROR (element, CORE, PAD, (NULL),
        ("Could not find specified template"));
  }

  return pad;
}

/* Dispose
 */
static void
gst_srtp_send_dispose (GObject * object)
{
  GstSrtpSend *filter = GST_SRTPSEND (object);
  GstIterator *it;
  GstPad *pad;

  GST_DEBUG_OBJECT (object, "Dispose...");

  filter->limit_reached = TRUE;
  it = gst_element_iterate_sink_pads (GST_ELEMENT_CAST (object));

  while (gst_iterator_next (it, (gpointer *) & pad) == GST_ITERATOR_OK) {
    gst_srtp_send_release_pad (GST_ELEMENT_CAST (object), pad);
    gst_iterator_resync (it);
  }

  gst_buffer_unref (filter->key);

  GST_CALL_PARENT (G_OBJECT_CLASS, dispose, (object));
}

/* Set property
 */
static void
gst_srtp_send_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  GstBuffer *buf;
  /*gchar *tmp2; */

  GstSrtpSend *filter = GST_SRTPSEND (object);

  GST_OBJECT_LOCK (filter);

  filter->ask_setcaps = TRUE;

  switch (prop_id) {
    case PROP_MKEY:
      gst_buffer_unref (filter->key);
      buf = (GstBuffer *) g_value_get_pointer (value);
      filter->key = gst_buffer_new_and_alloc (GST_BUFFER_SIZE (buf));
      memcpy ((void *) GST_BUFFER_DATA (filter->key),
          (void *) GST_BUFFER_DATA (buf), GST_BUFFER_SIZE (buf));

      /* This code is to test the key = "baf" */
      /* tmp2 = g_new0 (gchar, 10);
         sprintf (tmp2, "baf");
         gst_buffer_unref (filter->key);
         filter->key = gst_buffer_new_and_alloc (3);
         memcpy ((void *) GST_BUFFER_DATA (filter->key), (void *) tmp2, 3);
         memcpy ((void *) tmp2, (void *) GST_BUFFER_DATA (filter->key), 3);
         tmp2[3] = '\0'; */

      GST_DEBUG ("%p", GST_BUFFER_DATA (filter->key));
      GST_INFO_OBJECT (object, "Set property: key=[%s]",
          GST_BUFFER_DATA (filter->key));
      filter->limit_reached = FALSE;
      break;

    case PROP_RTP_CIPHER:
      filter->rtp_cipher = g_value_get_enum (value);
      GST_INFO_OBJECT (object, "Set property: rtp cipher=%d",
          filter->rtp_cipher);
      break;
    case PROP_RTP_AUTH:
      filter->rtp_auth = g_value_get_enum (value);
      GST_INFO_OBJECT (object, "Set property: rtp auth=%d", filter->rtp_auth);
      break;

    case PROP_RTCP_CIPHER:
      filter->rtcp_cipher = g_value_get_enum (value);
      GST_INFO_OBJECT (object, "Set property: rtcp cipher=%d",
          filter->rtcp_cipher);
      break;

    case PROP_RTCP_AUTH:
      filter->rtcp_auth = g_value_get_enum (value);
      GST_INFO_OBJECT (object, "Set property: rtcp auth=%d", filter->rtcp_auth);
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
    case PROP_MKEY:
      g_value_set_pointer (value, filter->key);
      break;
    case PROP_RTP_CIPHER:
      g_value_set_enum (value, filter->rtp_cipher);
      break;
    case PROP_RTCP_CIPHER:
      g_value_set_enum (value, filter->rtcp_cipher);
      break;
    case PROP_RTP_AUTH:
      g_value_set_enum (value, filter->rtp_auth);
      break;
    case PROP_RTCP_AUTH:
      g_value_set_enum (value, filter->rtcp_auth);
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
get_rtp_other_pad (GstPad * pad)
{
  return gst_pad_get_element_private (pad);
}

/* Release a sink pad and it's linked source pad
 */
static void
gst_srtp_send_release_pad (GstElement * element, GstPad * sinkpad)
{
  GstPad *srcpad = NULL;

  GST_INFO_OBJECT (element, "Releasing pad %s:%s",
      GST_DEBUG_PAD_NAME (sinkpad));

  srcpad = gst_pad_get_element_private (sinkpad);

  if (srcpad) {
    /* deactivate from source to sink */
    gst_pad_set_active (srcpad, FALSE);
    gst_pad_set_active (sinkpad, FALSE);

    /* remove pads */
    gst_element_remove_pad (element, srcpad);
    gst_element_remove_pad (element, sinkpad);

    srcpad = NULL;
    sinkpad = NULL;

  } else {
    GST_WARNING_OBJECT (element, "Could not release pad (source not found)");
  }
}

/* RTP pad setcaps function
 */
static gboolean
gst_srtp_send_sink_setcaps_rtp (GstPad * pad, GstCaps * caps)
{
  return gst_srtp_send_sink_setcaps (pad, caps, FALSE);
}

/* RTCP pad setcaps function
 */
static gboolean
gst_srtp_send_sink_setcaps_rtcp (GstPad * pad, GstCaps * caps)
{
  return gst_srtp_send_sink_setcaps (pad, caps, TRUE);
}

/* Common setcaps function
 * Handles the link with other elements
 */
static gboolean
gst_srtp_send_sink_setcaps (GstPad * pad, GstCaps * caps, gboolean is_rtcp)
{
  GstSrtpSend *filter = NULL;
  GstPad *otherpad = NULL;
  GstStructure *ps = NULL;

  filter = GST_SRTPSEND (gst_pad_get_parent (pad));

  caps = gst_caps_make_writable (caps);

  if (!(ps = gst_caps_get_structure (caps, 0)))
    goto error_caps;

  GST_DEBUG_OBJECT (pad, "Sink caps: %" GST_PTR_FORMAT, caps);

  if (is_rtcp)
    gst_structure_set_name (ps, "application/x-srtcp");
  else
    gst_structure_set_name (ps, "application/x-srtp");

  GST_OBJECT_LOCK (filter);

  /* Add srtp-specific params to source caps */
  gst_structure_set (ps, "mkey", GST_TYPE_BUFFER, filter->key,
      "rtp-cipher", G_TYPE_UINT, filter->rtp_cipher,
      "rtp-auth", G_TYPE_UINT, filter->rtp_auth,
      "rtcp-cipher", G_TYPE_UINT, filter->rtcp_cipher,
      "rtcp-auth", G_TYPE_UINT, filter->rtcp_auth, NULL);

  GST_OBJECT_UNLOCK (filter);

  GST_DEBUG_OBJECT (pad, "Source caps: %" GST_PTR_FORMAT, caps);

  /* Set caps on source pad */
  otherpad = get_rtp_other_pad (pad);

  if (!gst_pad_set_caps (otherpad, caps))
    goto error_caps;

  gst_object_unref (filter);

  return TRUE;

error_caps:
  GST_ELEMENT_ERROR (GST_ELEMENT_CAST (filter), CORE, CAPS, (NULL),
      ("Unable to set caps on source pad"));
  return GST_FLOW_NOT_NEGOTIATED;
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
  GstPad *otherpad;
  GstStructure *ps = NULL;
  GstCaps *ret = NULL;

  otherpad = (GstPad *) gst_pad_get_element_private (pad);

  if (!(ret = gst_pad_get_allowed_caps (otherpad))) {
    ret = gst_caps_copy (gst_pad_get_pad_template_caps (pad));
  } else {

    if (!(ps = gst_caps_get_structure (ret, 0))) {
      gst_caps_unref (ret);
      ret = gst_caps_copy (gst_pad_get_pad_template_caps (pad));
    } else {
      if (is_rtcp)
        gst_structure_set_name (ps, "application/x-rtcp");
      else
        gst_structure_set_name (ps, "application/x-rtp");
    }
  }

  return ret;
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

  otherpad = get_rtp_other_pad (pad);

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
  GstFlowReturn ret = GST_FLOW_OK;
  GstPad *otherpad = NULL;
  err_status_t err = err_status_ok;
  gint size_before, size_max, size_after;
  buffer_state_t bufstate = buffer_drop_continue;
  GstBuffer *buf2 = NULL;

  filter = GST_SRTPSEND (gst_pad_get_parent (pad));

  /* Check if key hard limit is reached */
  while (filter->wait_change);

  if (filter->limit_reached) {
    GST_OBJECT_UNLOCK (filter);
    GST_ELEMENT_ERROR (GST_ELEMENT_CAST (filter), LIBRARY, FAILED, (NULL),
        ("Unable to protect buffer (hard limit reached)"));
    ret = GST_FLOW_ERROR;
    goto drop_fail;
  }

  GST_OBJECT_LOCK (filter);

  /* Get linked source pad */
  if (!(otherpad = get_rtp_other_pad (pad))) {
    GST_OBJECT_UNLOCK (filter);
    GST_ELEMENT_ERROR (GST_ELEMENT_CAST (filter), CORE, PAD, (NULL),
        ("Unable to get linked pad"));
    ret = GST_FLOW_ERROR;
    goto drop_fail;
  }

unprotect:
  /* Validate buffer SSRC */
  bufstate = validate_buffer (filter, buf, is_rtcp);

  if (bufstate != buffer_valid) {
    GST_OBJECT_UNLOCK (filter);
    goto invalid;
  }

  size_before = GST_BUFFER_SIZE (buf);
  size_max = size_before + SRTP_MAX_TRAILER_LEN + 10;
  size_after = size_before;

  /* Update source caps if asked */
  if (filter->ask_setcaps) {
    GST_DEBUG_OBJECT (pad, "Asked to set caps...");
    filter->ask_setcaps = FALSE;
    GST_OBJECT_UNLOCK (filter);

    if (!gst_srtp_send_sink_setcaps (pad, GST_PAD_CAPS (pad), is_rtcp)) {
      ret = GST_FLOW_NOT_NEGOTIATED;
      goto drop_fail;
    }

    GST_OBJECT_LOCK (filter);

  } else {
    filter->ask_setcaps = FALSE;
  }

  /* Create a bigger buffer to add protection */
  ret = gst_pad_alloc_buffer_and_set_caps (otherpad, 0, size_max,
      GST_PAD_CAPS (otherpad), &buf2);

  if (ret != GST_FLOW_OK) {
    GST_OBJECT_UNLOCK (filter);
    GST_ELEMENT_ERROR (GST_ELEMENT_CAST (filter), RESOURCE, FAILED, (NULL),
        ("Unable to allocate new buffer"));
    goto drop_fail;
  }

  memcpy (GST_BUFFER_DATA (buf2), GST_BUFFER_DATA (buf), size_before);

  if (is_rtcp)
    err = srtp_protect_rtcp (filter->session, GST_BUFFER_DATA (buf2),
        &size_after);
  else
    err = srtp_protect (filter->session, GST_BUFFER_DATA (buf2), &size_after);

  if (err == err_status_ok) {
    /* Buffer protected */
    GST_BUFFER_SIZE (buf2) = size_after;
    gst_buffer_copy_metadata (buf2, buf,
        GST_BUFFER_COPY_FLAGS | GST_BUFFER_COPY_TIMESTAMPS);
    gst_buffer_unref (buf);
    buf = NULL;

    GST_LOG_OBJECT (pad, "Sending %s buffer of size %d",
        is_rtcp ? "RTCP" : "RTP", size_after);

    /* Push buffer to source pad */
    GST_OBJECT_UNLOCK (filter);
    ret = gst_pad_push (otherpad, buf2);

    if (ret != GST_FLOW_OK) {
      GST_ELEMENT_ERROR (GST_ELEMENT_CAST (filter), CORE, PAD, (NULL),
          ("Unable to push buffer on source pad"));
      goto drop_fail;
    }

  } else if (err == err_status_key_expired) {

    if (filter->limit_reached == FALSE) {
      GST_DEBUG_OBJECT (pad, "Trying to unprotect again");
      goto unprotect;
    } else {
      GST_OBJECT_UNLOCK (filter);
      GST_ELEMENT_ERROR (GST_ELEMENT_CAST (filter), LIBRARY, FAILED, (NULL),
          ("Unable to protect buffer (hard limit reached)"));
      filter->limit_reached = FALSE;
      ret = GST_FLOW_ERROR;
      goto drop_fail;
    }

  } else {                      /* srtp_protect failed */
    GST_OBJECT_UNLOCK (filter);
    GST_WARNING_OBJECT (pad,
        "Unable to protect buffer (protect failed) code %d", err);
    bufstate = buffer_drop_continue;
  }

  /* Drop buffer, continue or fail */
invalid:
  if (bufstate != buffer_valid) {

    GST_WARNING_OBJECT (pad, "Dropping buffer");

    if (buf)
      gst_buffer_unref (buf);
    if (buf2)
      gst_buffer_unref (buf2);

    if (bufstate == buffer_drop_continue)
      ret = GST_FLOW_OK;
  }

  gst_object_unref (filter);

  return ret;

drop_fail:
  gst_buffer_unref (buf);
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
  guint ret = 0;

  if (!GST_IS_SRTPSEND (filter)) {
    GST_WARNING ("Cannot report SRTP event to user (filter invalid)");
    filter = NULL;
  }

  switch (data->event) {
    case event_ssrc_collision:
      break;

    case event_key_soft_limit:
      GST_WARNING_OBJECT (filter, "Key usage soft limit reached on stream %d",
          ssrc);
      if (filter) {
        GST_OBJECT_UNLOCK (filter);
        g_signal_emit (filter, gst_srtp_send_signals[SIGNAL_SOFT_LIMIT], 0,
            ssrc);
        GST_OBJECT_LOCK (filter);
      }
      break;

    case event_key_hard_limit:
      GST_WARNING_OBJECT (filter, "Key usage hard limit reached on stream %d",
          ssrc);

      if (filter) {
        /* Activate flag to drop buffers from now on */
        filter->limit_reached = TRUE;
        filter->wait_change = TRUE;

        /* Leave the door open for property change */
        GST_OBJECT_UNLOCK (filter);

        g_signal_emit (filter, gst_srtp_send_signals[SIGNAL_HARD_LIMIT], 0,
            ssrc, &ret);
        filter->wait_change = FALSE;

        GST_OBJECT_LOCK (filter);

        if (ret == 0)
          GST_ERROR_OBJECT (filter, "No answer to hard-limit signal");
      }
      break;

    case event_packet_index_limit:
      GST_WARNING_OBJECT (filter, "Packet index limit reached on stream %d",
          ssrc);

      if (filter) {
        /* Activate flag to drop buffers from now on */
        filter->limit_reached = TRUE;

        /* Leave the door open for property change */
        GST_OBJECT_UNLOCK (filter);

        g_signal_emit (filter, gst_srtp_send_signals[SIGNAL_INDEX_LIMIT], 0,
            ssrc, &ret);

        GST_OBJECT_LOCK (filter);

        if (ret == 0)
          GST_ERROR_OBJECT (filter, "No answer to index-limit signal");
      }
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

  switch (transition) {
    case GST_STATE_CHANGE_NULL_TO_READY:
      srtp_install_event_handler (srtp_send_event_reporter);
      if (!filter->first_session)
        gst_srtp_send_reset (filter);
      break;
    case GST_STATE_CHANGE_READY_TO_PAUSED:
      break;
    case GST_STATE_CHANGE_PAUSED_TO_PLAYING:
      break;
    default:
      break;
  }

  res = parent_class->change_state (element, transition);

  switch (transition) {
    case GST_STATE_CHANGE_PLAYING_TO_PAUSED:
      break;
    case GST_STATE_CHANGE_PAUSED_TO_READY:
      gst_srtp_send_reset (filter);
      filter->limit_reached = TRUE;
      break;
    case GST_STATE_CHANGE_READY_TO_NULL:
      break;
    default:
      break;
  }

  return res;
}

static gboolean
gst_srtp_send_sink_event_rtp (GstPad * pad, GstEvent * event)
{
  return gst_srtp_send_sink_event (pad, event, FALSE);
}

static gboolean
gst_srtp_send_sink_event_rtcp (GstPad * pad, GstEvent * event)
{
  return gst_srtp_send_sink_event (pad, event, TRUE);
}

static gboolean
gst_srtp_send_sink_event (GstPad * pad, GstEvent * event, gboolean is_rtcp)
{
  GstSrtpSend *filter;
  gboolean ret;
  GstPad *otherpad;

  filter = GST_SRTPSEND (gst_pad_get_parent (pad));
  otherpad = get_rtp_other_pad (pad);

  switch (GST_EVENT_TYPE (event)) {
    case GST_EVENT_NEWSEGMENT:
      GST_DEBUG_OBJECT (pad, "Sending event New segment (%d)",
          GST_EVENT_TYPE (event));
      ret = gst_pad_push_event (otherpad, event);
      break;
    case GST_EVENT_EOS:
      GST_DEBUG_OBJECT (pad, "Sending event EOS (%d)", GST_EVENT_TYPE (event));
      ret = gst_pad_push_event (otherpad, event);
      break;
    case GST_EVENT_FLUSH_STOP:
      GST_DEBUG_OBJECT (pad, "Sending event Flush stop (%d)",
          GST_EVENT_TYPE (event));
      gst_srtp_send_reset (filter);
      ret = gst_pad_push_event (otherpad, event);
      break;
    default:
      GST_DEBUG_OBJECT (pad, "Sending event default (%d)",
          GST_EVENT_TYPE (event));
      ret = gst_pad_push_event (otherpad, event);
      break;
  }

  gst_object_unref (filter);
  return ret;
}

static gboolean
gst_srtp_send_src_event_rtp (GstPad * pad, GstEvent * event)
{
  return gst_srtp_send_src_event (pad, event, FALSE);
}

static gboolean
gst_srtp_send_src_event_rtcp (GstPad * pad, GstEvent * event)
{
  return gst_srtp_send_src_event (pad, event, TRUE);
}

static gboolean
gst_srtp_send_src_event (GstPad * pad, GstEvent * event, gboolean is_rtcp)
{
  GstSrtpSend *filter;
  GstPad *otherpad;

  GST_DEBUG_OBJECT (pad, "Sending event upstream (%d)", GST_EVENT_TYPE (event));
  filter = GST_SRTPSEND (gst_pad_get_parent (pad));
  otherpad = get_rtp_other_pad (pad);
  gst_object_unref (filter);

  return gst_pad_push_event (otherpad, event);
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
