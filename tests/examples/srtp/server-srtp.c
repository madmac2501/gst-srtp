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

/*
 * A simple RTP server
 *  sends the output of alsasrc as alaw encoded RTP on port 5001, RTCP is sent on
 *  port 5004. The destination is 127.0.0.1.
 *  the receiver RTCP reports are received on port 5008
 *
 * .-------.    .-------.    .-------.      .----------.     .------------.      .-------.
 * |alsasrc|    |alawenc|    |pcmapay|      | rtpbin   |     |  srtpsend  |      |udpsink|  RTP
 * |      src->sink    src->sink    src->send_rtp send_rtp->rtp_sink   rtp_src->sink     | port=5001
 * '-------'    '-------'    '-------'      |          |     |            |      '-------'
 *                                          |          |     |            |
 *                                          |          |     |            |      .-------.
 *                                          |          |     |            |      |udpsink|  RTCP
 *                                          |    send_rtcp->rtcp_sink rtcp_src->sink     | port=5004
 *                           .-------.      |          |     '------------'      '-------' sync=false
 *                RTCP       |udpsrc |      |          |                                   async=false
 *              port=5008    |     src->recv_rtcp      |
 *                           '-------'      '----------'
 */

/* change this to send the RTP data and RTCP to another host */
#define DEST_HOST "127.0.0.1"

/* #define AUDIO_SRC  "alsasrc" */
#define AUDIO_SRC  "audiotestsrc"

/* the encoder and payloader elements */
#define AUDIO_ENC  "alawenc"
#define AUDIO_PAY  "rtppcmapay"

struct SrtpRecvCaps
{
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

  if (g_strcmp0 (prop, "HMAC_SHA1") == 0) {
    g_print ("HMAC_SHA1\n");
    ret = HMAC_SHA1;
  } else if (g_strcmp0 (prop, "NULL_AUTH") == 0) {
    g_print ("NULL_AUTH\n");
    ret = NULL_AUTH;
  } else if (g_strcmp0 (prop, "STRONGHOLD_AUTH") == 0) {
    g_print ("STRONGHOLD_AUTH\n");
    ret = STRONGHOLD_AUTH;
  } else {
    g_print ("(default) HMAC_SHA1\n");
  }

  return ret;
}

static int
get_cipher_property (char *prop)
{
  int ret = AES_128_ICM;

  if (g_strcmp0 (prop, "AES_128_ICM") == 0) {
    g_print ("AES_128_ICM\n");
    ret = AES_128_ICM;
  } else if (g_strcmp0 (prop, "NULL_CIPHER") == 0) {
    g_print ("NULL_CIPHER\n");
    ret = NULL_CIPHER;
  } else if (g_strcmp0 (prop, "STRONGHOLD_CIPHER") == 0) {
    g_print ("STRONGHOLD_CIPHER\n");
    ret = STRONGHOLD_CIPHER;
  } else {
    g_print ("(default) AES_128_ICM\n");
  }

  return ret;
}

/* print the stats of a source */
static void
print_source_stats (GObject * source)
{
  GstStructure *stats;
  gchar *str;

  /* get the source stats */
  g_object_get (source, "stats", &stats, NULL);

  /* simply dump the stats structure */
  str = gst_structure_to_string (stats);
  g_print ("source stats: %s\n", str);

  gst_structure_free (stats);
  g_free (str);
}

/* this function is called every second and dumps the RTP manager stats */
static gboolean
print_stats (GstElement * rtpbin)
{
  GObject *session;
  GValueArray *arr;
  GValue *val;
  guint i;

  g_print ("***********************************\n");

  /* get session 0 */
  g_signal_emit_by_name (rtpbin, "get-internal-session", 0, &session);

  /* print all the sources in the session, this includes the internal source */
  g_object_get (session, "sources", &arr, NULL);

  for (i = 0; i < arr->n_values; i++) {
    GObject *source;

    val = g_value_array_get_nth (arr, i);
    source = g_value_get_object (val);

    print_source_stats (source);
  }
  g_value_array_free (arr);

  g_object_unref (session);

  return TRUE;
}

/* Get an input from stdin and remove trailing newline
 */
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

/* Ask user for new parameters
 */
static int
get_srtp_recv_caps (guint ssrc, SrtpRecvCaps * recvcaps, gboolean key_only)
{
  int ret;
  gchar *input;

  if (recvcaps == NULL)
    return 0;

  input = g_new0 (gchar, 81);

  g_free (recvcaps->key);
  recvcaps->key = g_new0 (gchar, 30);

  /* Ask for the master key */
  g_print ("Please enter the master key for SSRC %d: ", ssrc);
  ret = get_user_input (input, 31);

  if (ret < 1) {
    g_print ("You failed to specify a master key\n\n");
    g_free (input);
    g_free (recvcaps->key);
    return 0;
  }

  memcpy ((void *) recvcaps->key, (void *) input, strlen (input));

  /* Ask for other parameters, unless asked not to */
  if (key_only == FALSE) {

    /* Ask for the RTP cipher */
    g_print ("Please enter the RTP cipher for SSRC %d: ", ssrc);
    ret = get_user_input (input, 18);

    if (ret < 1) {
      g_print
          ("You failed to specify an RTP cipher. Using default AES_128_ICM\n\n");
      recvcaps->rtp_cipher = AES_128_ICM;
    } else {
      recvcaps->rtp_cipher = get_cipher_property (input);
    }

    /* Ask for the RTP auth */
    g_print ("Please enter the RTP authentication for SSRC %d: ", ssrc);
    ret = get_user_input (input, 16);

    if (ret < 1) {
      g_print
          ("You failed to specify an RTP authentication. Using default HMAC_SHA1\n\n");
      recvcaps->rtp_auth = HMAC_SHA1;
    } else {
      recvcaps->rtp_auth = get_auth_property (input);
    }

    /* Ask for the RTCP cipher */
    g_print ("Please enter the RTCP cipher for SSRC %d: ", ssrc);
    ret = get_user_input (input, 18);

    if (ret < 1) {
      g_print
          ("You failed to specify an RTCP cipher. Using default AES_128_ICM\n\n");
      recvcaps->rtcp_cipher = AES_128_ICM;
    } else {
      recvcaps->rtcp_cipher = get_cipher_property (input);
    }

    /* Ask for the RTCP auth */
    g_print ("Please enter the RTCP authentication for SSRC %d: ", ssrc);
    ret = get_user_input (input, 16);

    if (ret < 1) {
      g_print
          ("You failed to specify an RTCP authentication. Using default HMAC_SHA1\n\n");
      recvcaps->rtcp_auth = HMAC_SHA1;
    } else {
      recvcaps->rtcp_auth = get_auth_property (input);
    }
  }

  g_free (input);

  return 1;
}

/* will be called when srtprecv reached the hard limit on its master key
 */
static GstCaps *
hard_limit_cb (GstElement * srtpenc, guint ssrc, SrtpRecvCaps * recvcaps)
{
  GstCaps *caps = NULL;
  gchar input[31];
  int ret;

  g_print ("Asked to change master key after hard limit\n");
  ret = get_srtp_recv_caps (ssrc, recvcaps, TRUE);

  if (ret == 0) {
    g_print ("-> Invalid parameters\n");
  } else {
    /* Set properties on srtpenc */
    g_object_set (rtpsrc, "key", recvpads->key, "rtp_c", recvpads->rtp_cipher,
        "rtp_a", recvpads->rtp_auth, "rtcp_c", recvpads->rtcp_cipher, "rtcp_a",
        recvpads->rtcp_auth, NULL);
  }

  return caps;
}

/* Check arguments on command line to get parameters
 */
static int
check_args (int argc, char *argv[], SrtpRecvCaps * recvcaps)
{
  int len;

  if (recvcaps == NULL)
    return 0;

  if (argc < 2) {
    g_print ("\nInvalid call to %s : first argument is mandatory.\n\n",
        argv[0]);
    g_print
        ("%s  master_key  [rtp_cipher]  [rtp_auth]  [rtcp_cipher]  [rtcp_auth]\n\n",
        argv[0]);
    g_print
        ("- master_key  : Key used for encryption and decryption (mandatory)\n");
    g_print ("- rtp_cipher  : Encryption mecanism used for RTP\n");
    g_print ("- rtp_auth    : Authentication mecanism used for RTP\n");
    g_print ("- rtcp_cipher : Encryption mecanism used for RTCP\n");
    g_print ("- rtcp_cipher : Authentication mecanism used for RTCP\n\n");
    g_print ("Encryption mecanisms:\n- AES_128_ICM\n- NULL\n");
    g_print ("Authentication mecanisms:\n- HMAC_SHA1\n- NULL\n\n");
    g_print
        ("NOTE: For RTCP, authentication mecanism cannot be NULL if cipher is non-NULL.\n\n");

    return 0;
  } else {
    recvcaps->rtp_cipher = AES_128_ICM;
    recvcaps->rtp_auth = HMAC_SHA1;
    recvcaps->rtcp_cipher = AES_128_ICM;
    recvcaps->rtcp_auth = HMAC_SHA1;

    /* copy key to structure */
    recvcaps->key = g_new0 (gchar, 30);
    len = strlen (argv[1]);
    if (len > 30) {
      g_print
          ("\nWarning: master key too long, truncating to 30 characters\n\n");
      len = 30;
    }

    memcpy ((void *) recvcaps->key, (void *) argv[1], len);
    g_print ("\nMaster key: %s\n\n", recvcaps->key);

    /* get cipher and auth */
    if (argc > 2) {
      g_print ("RTP cipher : ");
      recvcaps->rtp_cipher = get_cipher_property (argv[2]);
    } else {
      g_print ("RTP cipher : (default) HMAC_SHA1\n");
    }

    if (argc > 3) {
      g_print ("RTP authentication : ");
      recvcaps->rtp_auth = get_auth_property (argv[3]);
    } else {
      g_print ("RTP authentication : (default) AES_128_ICM\n");
    }

    if (argc > 4) {
      g_print ("RTCP cipher : ");
      recvcaps->rtcp_cipher = get_cipher_property (argv[4]);
    } else {
      g_print ("RTCP cipher : (default) HMAC_SHA1\n");
    }

    if (argc > 5) {
      g_print ("RTCP authentication : ");
      recvcaps->rtcp_auth = get_auth_property (argv[5]);
    } else {
      g_print ("RTCP authentication : (default) AES_128_ICM\n");
    }

    return argc;
  }
}

/* build a pipeline equivalent to:
 *
 * gst-launch -v gstrtpbin name=rtpbin \
 *    $AUDIO_SRC ! audioconvert ! audioresample ! $AUDIO_ENC ! $AUDIO_PAY ! rtpbin.send_rtp_sink_0  \
 *           rtpbin.send_rtp_src_0 ! udpsink port=5002 host=$DEST                      \
 *           rtpbin.send_rtcp_src_0 ! udpsink port=5003 host=$DEST sync=false async=false \
 *        udpsrc port=5007 ! rtpbin.recv_rtcp_sink_0
 */
int
main (int argc, char *argv[])
{
  GstElement *audiosrc, *audioconv, *audiores, *audioenc, *audiopay;
  GstElement *rtpbin, *srtpenc, *rtpsink, *rtcpsink, *rtcpsrc;
  GstElement *pipeline;
  GMainLoop *loop;
  gboolean res;
  GstPadLinkReturn lres;
  GstPad *srcpad, *sinkpad;
  SrtpRecvCaps *recvcaps;

  recvcaps->key = NULL;
  if (check_args (argc, argv, recvcaps) == 0)
    return 0;

  /* always init first */
  gst_init (&argc, &argv);

  /* the pipeline to hold everything */
  pipeline = gst_pipeline_new (NULL);
  g_assert (pipeline);

  /* the audio capture and format conversion */
  audiosrc = gst_element_factory_make (AUDIO_SRC, "audiosrc");
  g_assert (audiosrc);
  audioconv = gst_element_factory_make ("audioconvert", "audioconv");
  g_assert (audioconv);
  audiores = gst_element_factory_make ("audioresample", "audiores");
  g_assert (audiores);
  /* the encoding and payloading */
  audioenc = gst_element_factory_make (AUDIO_ENC, "audioenc");
  g_assert (audioenc);
  audiopay = gst_element_factory_make (AUDIO_PAY, "audiopay");
  g_assert (audiopay);

  /* add capture and payloading to the pipeline and link */
  gst_bin_add_many (GST_BIN (pipeline), audiosrc, audioconv, audiores,
      audioenc, audiopay, NULL);

  res = gst_element_link_many (audiosrc, audioconv, audiores, audioenc,
      audiopay, NULL);
  g_assert (res == TRUE);

  /* the rtpbin element */
  rtpbin = gst_element_factory_make ("gstrtpbin", "rtpbin");
  g_assert (rtpbin);

  gst_bin_add (GST_BIN (pipeline), rtpbin);

  /* the srtpsend element */
  srtpenc = gst_element_factory_make ("srtpsend", "srtpenc");
  g_assert (srtpenc);
  g_object_set (rtpsrc, "key", recvpads->key, "rtp_c", recvpads->rtp_cipher,
      "rtp_a", recvpads->rtp_auth, "rtcp_c", recvpads->rtcp_cipher, "rtcp_a",
      recvpads->rtcp_auth, NULL);

  gst_bin_add (GST_BIN (pipeline), srtpenc);

  /* the udp sinks and source we will use for RTP and RTCP */
  rtpsink = gst_element_factory_make ("udpsink", "rtpsink");
  g_assert (rtpsink);
  g_object_set (rtpsink, "port", 5001, "host", DEST_HOST, NULL);

  rtcpsink = gst_element_factory_make ("udpsink", "rtcpsink");
  g_assert (rtcpsink);
  g_object_set (rtcpsink, "port", 5004, "host", DEST_HOST, NULL);
  /* no need for synchronisation or preroll on the RTCP sink */
  g_object_set (rtcpsink, "async", FALSE, "sync", FALSE, NULL);

  rtcpsrc = gst_element_factory_make ("udpsrc", "rtcpsrc");
  g_assert (rtcpsrc);
  g_object_set (rtcpsrc, "port", 5008, NULL);

  gst_bin_add_many (GST_BIN (pipeline), rtpsink, rtcpsink, rtcpsrc, NULL);

  /* now link all to the rtpbin, start by getting an RTP sinkpad for session 0 */
  sinkpad = gst_element_get_request_pad (rtpbin, "send_rtp_sink_0");
  srcpad = gst_element_get_static_pad (audiopay, "src");
  lres = gst_pad_link (srcpad, sinkpad);
  g_assert (lres == GST_PAD_LINK_OK);
  gst_object_unref (srcpad);

  /* get the RTP srcpad that was created when we requested the sinkpad above and
   * link it to the srtpenc sinkpad */
  srcpad = gst_element_get_static_pad (rtpbin, "send_rtp_src_0");
  sinkpad = gst_element_get_request_pad (srtpenc, "rtp_sink_0");
  lres = gst_pad_link (srcpad, sinkpad);
  g_assert (lres == GST_PAD_LINK_OK);
  gst_object_unref (srcpad);

  /* get the RTP srcpad that was created when we requested the sinkpad above and
   * link it to the rtpsink sinkpad*/
  srcpad = gst_element_get_static_pad (srtpenc, "rtp_src_0");
  sinkpad = gst_element_get_static_pad (rtpsink, "sink");
  lres = gst_pad_link (srcpad, sinkpad);
  g_assert (lres == GST_PAD_LINK_OK);
  gst_object_unref (srcpad);
  gst_object_unref (sinkpad);

  /* get an RTCP srcpad for sending RTCP to the srtpenc  */
  srcpad = gst_element_get_request_pad (rtpbin, "send_rtcp_src_0");
  sinkpad = gst_element_get_request_pad (srtpenc, "rtcp_sink_0");
  lres = gst_pad_link (srcpad, sinkpad);
  g_assert (lres == GST_PAD_LINK_OK);

  /* get the RTCP srcpad that was created when we requested the sinkpad above and
   * link it to the rtcpsink sinkpad*/
  srcpad = gst_element_get_request_pad (srtpenc, "rtcp_src_0");
  sinkpad = gst_element_get_static_pad (rtcpsink, "sink");
  lres = gst_pad_link (srcpad, sinkpad);
  g_assert (lres == GST_PAD_LINK_OK);
  gst_object_unref (sinkpad);

  /* we also want to receive RTCP, request an RTCP sinkpad for session 0 and
   * link it to the srcpad of the udpsrc for RTCP */
  srcpad = gst_element_get_static_pad (rtcpsrc, "src");
  sinkpad = gst_element_get_request_pad (rtpbin, "recv_rtcp_sink_0");
  lres = gst_pad_link (srcpad, sinkpad);
  g_assert (lres == GST_PAD_LINK_OK);
  gst_object_unref (srcpad);

  /* Connect to signal */
  g_signal_connect (srtpenc, "hard-limit", G_CALLBACK (hard_limit_cb),
      recvpads);

  /* set the pipeline to playing */
  g_print ("starting sender pipeline\n");
  gst_element_set_state (pipeline, GST_STATE_PLAYING);

  /* print stats every second */
  g_timeout_add (1000, (GSourceFunc) print_stats, rtpbin);

  /* we need to run a GLib main loop to get the messages */
  loop = g_main_loop_new (NULL, FALSE);
  g_main_loop_run (loop);

  g_print ("stopping sender pipeline\n");
  gst_element_set_state (pipeline, GST_STATE_NULL);

  return 0;
}
