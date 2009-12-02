/* GStreamer
 * Copyright (C) 2009 Wim Taymans <wim.taymans@gmail.com>
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

#include <string.h>
#include <math.h>

#include <gst/gst.h>
#include <srtp/crypto_types.h>

/*
 * A simple SRTP receiver
 *
 *  receives alaw encoded RTP audio on port 5001, RTCP is received on  port 5004.
 *  the receiver RTCP reports are sent to port 5008
 *
 *             .-------.      .------------.    .----------.     .---------.   .-------.   .--------.
 *  RTP        |udpsrc |      |  srtprecv  |    | rtpbin   |     |pcmadepay|   |alawdec|   |alsasink|
 *  port=5001  |      src->rtp_sink  rtp_src->recv_rtp recv_rtp->sink     src->sink   src->sink     |
 *             '-------'      |            |    |          |     '---------'   '-------'   '--------'
 *                            |            |    |          |
 *                            |            |    |          |     .-------.
 *                            |            |    |          |     |udpsink|  RTCP
 *                            |            |    |    send_rtcp->sink     | port=5008
 *             .-------.      |            |    |          |     '-------' sync=false
 *  RTCP       |udpsrc |      |            |    |          |               async=false
 *  port=5004  |    src->rtcp_sink rtcp_src->recv_rtcp     |
 *             '-------'      '------------'    '----------'
 */

/* the caps of the sender RTP stream. This is usually negotiated out of band with
 * SDP or RTSP. */
#define AUDIO_CAPS "application/x-srtp,media=(string)audio,clock-rate=(int)8000,encoding-name=(string)PCMA"

#define AUDIO_DEPAY "rtppcmadepay"
#define AUDIO_DEC   "alawdec"
#define AUDIO_SINK  "autoaudiosink"

/* the destination machine to send RTCP to. This is the address of the sender and
 * is used to send back the RTCP reports of this receiver. If the data is sent
 * from another machine, change this address. */
#define DEST_HOST "127.0.0.1"

struct SrtpRecvCaps
{
  guint ssrc;
  gchar *key;
  int rtp_cipher;
  int rtp_auth;
  int rtcp_cipher;
  int rtcp_auth;
};

static int
get_auth_property (char *prop)
{
  int ret = HMAC_SHA1;

  if (g_strcmp0 (prop, "HMAC_SHA1") == 0)
    ret = HMAC_SHA1;
  else if (g_strcmp0 (prop, "NULL_AUTH") == 0)
    ret = NULL_AUTH;
  else if (g_strcmp0 (prop, "STRONGHOLD_AUTH") == 0)
    ret = STRONGHOLD_AUTH;

  return ret;
}

static int
get_cipher_property (char *prop)
{
  int ret = AES_128_ICM;

  if (g_strcmp0 (prop, "AES_128_ICM") == 0)
    ret = AES_128_ICM;
  else if (g_strcmp0 (prop, "NULL_CIPHER") == 0)
    ret = NULL_CIPHER;
  else if (g_strcmp0 (prop, "STRONGHOLD_CIPHER") == 0)
    ret = STRONGHOLD_CIPHER;

  return ret;
}

static int
get_user_input (gchar * input, int len)
{
  if (input == NULL || len < 1)
    return -1;

  fgets (input, len, stdin);

  if (input[0] == '\n') {
    return 0;
  }

  if (strlen (input) == (len - 1)) {
    if (input[len - 2] == '\n')
      input[len - 2] = '\0';
  } else {
    input[strlen (input) - 1] = '\0';
  }

  return 1;
}

static int
new_srtp_recv_caps (SrtpRecvCaps * caps)
{
  int ret;
  gchar *input;

  if (caps == NULL)
    return 0;

  input = g_new0 (gchar, 81);

  caps->key = g_new0 (gchar, 30);
  caps->rtp_cipher = AES_128_ICM;
  caps->rtp_auth = HMAC_SHA1;
  caps->rtcp_cipher = AES_128_ICM;
  caps->rtcp_auth = HMAC_SHA1;

  /* Ask for the master key */
  g_print ("Please enter the master key for SSRC %d: ", caps->ssrc);
  ret = get_user_input (input, 31);

  if (ret < 1) {
    g_print ("You failed to specify a master key\n\n");
    g_free (input);
    g_free (caps->key);
    return 0;
  }

  memcpy ((void *) caps->key, (void *) input, strlen (input));

  /* Ask for the RTP cipher */
  g_print ("Please enter the RTP cipher for SSRC %d: ", caps->ssrc);
  ret = get_user_input (input, 18);

  if (ret < 1) {
    g_print
        ("You failed to specify an RTP cipher. Using default AES_128_ICM\n\n");
  } else {
    caps->rtp_cipher = get_cipher_property (input);
  }

  /* Ask for the RTP auth */
  g_print ("Please enter the RTP authentication for SSRC %d: ", caps->ssrc);
  ret = get_user_input (input, 16);

  if (ret < 1) {
    g_print
        ("You failed to specify an RTP authentication. Using default HMAC_SHA1\n\n");
  } else {
    caps->rtp_auth = get_auth_property (input);
  }

  /* Ask for the RTCP cipher */
  g_print ("Please enter the RTCP cipher for SSRC %d: ", caps->ssrc);
  ret = get_user_input (input, 18);

  if (ret < 1) {
    g_print
        ("You failed to specify an RTCP cipher. Using default AES_128_ICM\n\n");
  } else {
    caps->rtcp_cipher = get_cipher_property (input);
  }

  /* Ask for the RTCP auth */
  g_print ("Please enter the RTCP authentication for SSRC %d: ", caps->ssrc);
  ret = get_user_input (input, 16);

  if (ret < 1) {
    g_print
        ("You failed to specify an RTCP authentication. Using default HMAC_SHA1\n\n");
  } else {
    caps->rtcp_auth = get_auth_property (input);
  }

  g_free (input);

  return 1;
}

static void
empty_stream_list (GSList ** streams)
{
  GSList *walk;
  SrtpRecvCaps *recvcaps = NULL;

  while ((walk = *streams)) {
    recvcaps = (SrtpRecvCaps *) walk->data;
    g_free (recvcaps->key);
    recvcaps->key = NULL;
    g_slice_free (recvcaps);
    recvcaps = NULL;
    *streams = g_slist_delete (*streams, walk);
  }
}

static SrtpRecvCaps *
get_srtp_recv_caps_by_ssrc (guint ssrc, GSList ** streams, gboolean del)
{
  GSList *walk;
  SrtpRecvCaps *recvcaps = NULL;

  for (walk = *streams; walk; walk = g_slist_next (walk)) {
    recvcaps = (SrtpRecvCaps *) walk->data;

    if (recvcaps->ssrc == ssrc) {
      if (del) {
        g_free (recvcaps->key);
        recvcaps->key = NULL;
        g_slice_free (recvcaps);
        recvcaps = NULL;
        *streams = g_slist_delete (*streams, walk);
      } else {
        return recvcaps;
      }
    }
  }

  /* SSRC not found in list, create new caps */
  recvcaps = g_slice_new0 (SrtpRecvCaps);
  recvcaps->ssrc = ssrc;

  if (new_srtp_recv_caps (recvcaps) == 0) {
    g_slice_free (recvcaps);
    recvcaps = NULL;
  } else {
    /* Add to list */
    *streams = g_slist_prepend (*streams, recvcaps);
  }

  return recvcaps;
}

/* will be called when rtpbin has validated a payload that we can depayload */
static void
pad_added_cb (GstElement * rtpbin, GstPad * new_pad, GstElement * depay)
{
  GstPad *sinkpad;
  GstPadLinkReturn lres;

  g_print ("new payload on pad: %s\n", GST_PAD_NAME (new_pad));

  sinkpad = gst_element_get_static_pad (depay, "sink");
  g_assert (sinkpad);

  lres = gst_pad_link (new_pad, sinkpad);
  g_assert (lres == GST_PAD_LINK_OK);
  gst_object_unref (sinkpad);
}

/* will be called when srtprecv needs parameters */
static GstCaps *
get_caps_cb (GstElement * srtpdec, guint ssrc, GSList ** streams)
{
  GstCaps *caps = NULL;
  SrtpRecvCaps *recvcaps = NULL;

  g_print ("Asked to send caps\n");
  recvcaps = get_srtp_recv_caps_by_ssrc (ssrc, streams, FALSE);

  if (recvcaps == NULL || recvcaps->key == NULL) {
    g_print ("-> Invalid parameters\n");
  } else {
    caps = gst_caps_new_simple ("application/x-srtp", "mkey", G_TYPE_STRING,
        recvcaps->key, "rtp_c", G_TYPE_UINT, recvcaps->rtp_cipher, "rtp_a",
        G_TYPE_UINT, recvcaps->rtp_auth, "rtcp_c", G_TYPE_UINT,
        recvcaps->rtcp_cipher, "rtcp_a", G_TYPE_UINT, recvcaps->rtcp_auth,
        NULL);
  }

  return caps;
}

/* will be called when srtprecv reached the hard limit on its master key */
static GstCaps *
hard_limit_cb (GstElement * srtpdec, guint ssrc, GSList ** streams)
{
  GstCaps *caps = NULL;
  gchar input[31];
  SrtpRecvCaps *recvcaps = NULL;

  g_print ("Asked to send caps after hard limit\n");
  recvcaps = get_srtp_recv_caps_by_ssrc (ssrc, streams, TRUE);

  if (recvcaps == NULL || recvcaps->key == NULL) {
    g_print ("-> Invalid parameters\n");
  } else {
    caps = gst_caps_new_simple ("application/x-srtp", "mkey", G_TYPE_STRING,
        recvcaps->key, "rtp_c", G_TYPE_UINT, recvcaps->rtp_cipher, "rtp_a",
        G_TYPE_UINT, recvcaps->rtp_auth, "rtcp_c", G_TYPE_UINT,
        recvcaps->rtcp_cipher, "rtcp_a", G_TYPE_UINT, recvcaps->rtcp_auth,
        NULL);
  }

  return caps;
}

/* build a pipeline equivalent to:
 *
 * gst-launch -v gstrtpbin name=rtpbin                       \
 *      udpsrc caps=$AUDIO_CAPS port=5002 ! rtpbin.recv_rtp_sink_0              \
 *        rtpbin. ! rtppcmadepay ! alawdec ! audioconvert ! audioresample ! alsasink \
 *      udpsrc port=5003 ! rtpbin.recv_rtcp_sink_0                              \
 *        rtpbin.send_rtcp_src_0 ! udpsink port=5007 host=$DEST sync=false async=false
 */
int
main (int argc, char *argv[])
{
  GstElement *srtpdec, *rtpbin, *rtpsrc, *rtcpsrc, *rtcpsink;
  GstElement *audiodepay, *audiodec, *audiores, *audioconv, *audiosink;
  GstElement *pipeline;
  GMainLoop *loop;
  GstCaps *caps;
  gboolean res;
  GstPadLinkReturn lres;
  GstPad *srcpad, *sinkpad;
  GSList *streams;

  /* always init first */
  gst_init (&argc, &argv);

  /* the pipeline to hold everything */
  pipeline = gst_pipeline_new (NULL);
  g_assert (pipeline);

  /* the udp src and sink we will use for RTP and RTCP */
  rtpsrc = gst_element_factory_make ("udpsrc", "rtpsrc");
  g_assert (rtpsrc);
  g_object_set (rtpsrc, "port", 5001, NULL);
  /* we need to set caps on the udpsrc for the RTP data */
  caps = gst_caps_from_string (AUDIO_CAPS);
  g_object_set (rtpsrc, "caps", caps, NULL);
  gst_caps_unref (caps);

  rtcpsrc = gst_element_factory_make ("udpsrc", "rtcpsrc");
  g_assert (rtcpsrc);
  g_object_set (rtcpsrc, "port", 5004, NULL);
  /* we need to set caps on the udpsrc for the RTCP data */
  caps = gst_caps_new_simple ("application/x-srtcp", NULL);
  g_object_set (rtcpsrc, "caps", caps, NULL);
  gst_caps_unref (caps);

  rtcpsink = gst_element_factory_make ("udpsink", "rtcpsink");
  g_assert (rtcpsink);
  g_object_set (rtcpsink, "port", 5008, "host", DEST_HOST, NULL);
  /* no need for synchronisation or preroll on the RTCP sink */
  g_object_set (rtcpsink, "async", FALSE, "sync", FALSE, NULL);

  gst_bin_add_many (GST_BIN (pipeline), rtpsrc, rtcpsrc, rtcpsink, NULL);

  /* the depayloading and decoding */
  audiodepay = gst_element_factory_make (AUDIO_DEPAY, "audiodepay");
  g_assert (audiodepay);
  audiodec = gst_element_factory_make (AUDIO_DEC, "audiodec");
  g_assert (audiodec);
  /* the audio playback and format conversion */
  audioconv = gst_element_factory_make ("audioconvert", "audioconv");
  g_assert (audioconv);
  audiores = gst_element_factory_make ("audioresample", "audiores");
  g_assert (audiores);
  audiosink = gst_element_factory_make (AUDIO_SINK, "audiosink");
  g_assert (audiosink);

  /* add depayloading and playback to the pipeline and link */
  gst_bin_add_many (GST_BIN (pipeline), audiodepay, audiodec, audioconv,
      audiores, audiosink, NULL);

  res = gst_element_link_many (audiodepay, audiodec, audioconv, audiores,
      audiosink, NULL);
  g_assert (res == TRUE);

  /* the srtprecv element */
  srtpdec = gst_element_factory_make ("srtprecv", "srtpdec");
  g_assert (srtpdec);

  gst_bin_add (GST_BIN (pipeline), srtpdec);

  /* the rtpbin element */
  rtpbin = gst_element_factory_make ("gstrtpbin", "rtpbin");
  g_assert (rtpbin);

  gst_bin_add (GST_BIN (pipeline), rtpbin);

  /* now link all to the srtpdec */
  /* start by getting an RTP sinkpad */
  srcpad = gst_element_get_static_pad (rtpsrc, "src");
  sinkpad = gst_element_get_static_pad (srtpdec, "rtp_sink");
  lres = gst_pad_link (srcpad, sinkpad);
  g_assert (lres == GST_PAD_LINK_OK);
  gst_object_unref (srcpad);
  gst_object_unref (sinkpad);

  /* get an RTCP sinkpad */
  srcpad = gst_element_get_static_pad (rtcpsrc, "src");
  sinkpad = gst_element_get_static_pad (srtpdec, "rtcp_sink");
  lres = gst_pad_link (srcpad, sinkpad);
  g_assert (lres == GST_PAD_LINK_OK);
  gst_object_unref (srcpad);
  gst_object_unref (sinkpad);

  /* now link the srtpdec to the rtpbin */
  /* start by getting an RTP sinkpad for session 0 */
  srcpad = gst_element_get_static_pad (srtpdec, "rtp_src");
  sinkpad = gst_element_get_request_pad (rtpbin, "recv_rtp_sink_0");
  lres = gst_pad_link (srcpad, sinkpad);
  g_assert (lres == GST_PAD_LINK_OK);
  gst_object_unref (srcpad);

  /* get an RTCP sinkpad in session 0 */
  srcpad = gst_element_get_static_pad (srtpdec, "rtcp_src");
  sinkpad = gst_element_get_request_pad (rtpbin, "recv_rtcp_sink_0");
  lres = gst_pad_link (srcpad, sinkpad);
  g_assert (lres == GST_PAD_LINK_OK);
  gst_object_unref (srcpad);

  /* get an RTCP srcpad for sending RTCP back to the sender */
  srcpad = gst_element_get_request_pad (rtpbin, "send_rtcp_src_0");
  sinkpad = gst_element_get_static_pad (rtcpsink, "sink");
  lres = gst_pad_link (srcpad, sinkpad);
  g_assert (lres == GST_PAD_LINK_OK);
  gst_object_unref (sinkpad);

  /* the RTP pad that we have to connect to the depayloader will be created
   * dynamically so we connect to the pad-added signal, pass the depayloader as
   * user_data so that we can link to it. */
  g_signal_connect (rtpbin, "pad-added", G_CALLBACK (pad_added_cb), audiodepay);

  g_signal_connect (srtpdec, "get-caps", G_CALLBACK (get_caps_cb), &streams);
  g_signal_connect (srtpdec, "hard-limit", G_CALLBACK (hard_limit_cb),
      &streams);

  /* set the pipeline to playing */
  g_print ("starting receiver pipeline\n");
  gst_element_set_state (pipeline, GST_STATE_PLAYING);

  /* we need to run a GLib main loop to get the messages */
  loop = g_main_loop_new (NULL, FALSE);
  g_main_loop_run (loop);

  g_print ("stopping receiver pipeline\n");
  gst_element_set_state (pipeline, GST_STATE_NULL);

  /* Empty stream list */
  empty_stream_list (&streams);

  gst_object_unref (pipeline);

  return 0;
}
