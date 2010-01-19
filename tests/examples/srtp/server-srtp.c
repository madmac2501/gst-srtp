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

#define AES_128_ICM       1
#define NULL_CIPHER       0
#define STRONGHOLD_CIPHER 1

#define HMAC_SHA1         3
#define NULL_AUTH         0
#define STRONGHOLD_AUTH   3

struct SrtpSendCaps
{
  GstBuffer *key;
  guint rtp_cipher;
  guint rtp_auth;
  guint rtcp_cipher;
  guint rtcp_auth;
};

static guint
get_auth_property (char *prop)
{
  guint auth;

  if (g_strcmp0 (prop, "HMAC_SHA1") == 0) {
    g_print ("HMAC_SHA1\n");
    auth = 3;
  } else if (g_strcmp0 (prop, "NULL_AUTH") == 0) {
    g_print ("NULL_AUTH\n");
    auth = 0;
  } else if (g_strcmp0 (prop, "STRONGHOLD_AUTH") == 0) {
    g_print ("STRONGHOLD_AUTH\n");
    auth = 3;
  } else {
    g_print ("Unknown value, using (default) HMAC_SHA1\n");
    auth = 3;
  }

  return auth;
}

static guint
get_cipher_property (char *prop)
{
  guint cipher;

  if (g_strcmp0 (prop, "AES_128_ICM") == 0) {
    g_print ("AES_128_ICM\n");
    cipher = 1;
  } else if (g_strcmp0 (prop, "NULL_CIPHER") == 0) {
    g_print ("NULL_CIPHER\n");
    cipher = 0;
  } else if (g_strcmp0 (prop, "STRONGHOLD_CIPHER") == 0) {
    g_print ("STRONGHOLD_CIPHER\n");
    cipher = 1;
  } else {
    g_print ("Unknown value, using (default) AES_128_ICM\n");
    cipher = 1;
  }

  return cipher;
}

/* Get an input from stdin and remove trailing newline
 */
static int
get_user_input (gchar * input, int len)
{
  if (input == NULL || len < 1)
    return -1;

  input = fgets (input, len, stdin);

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
static guint
get_srtp_recv_caps (guint ssrc, struct SrtpSendCaps *sendcaps,
    gboolean key_only)
{
  int ret;
  gchar *input;

  if (sendcaps == NULL)
    return 0;

  input = g_new0 (gchar, 81);

  g_free (sendcaps->key);
  sendcaps->key = NULL;
  /*sendcaps->key = g_new0 (gchar, 30); */

  /* Ask for the master key */
  g_print ("Please enter the master key for SSRC %d: ", ssrc);
  ret = get_user_input (input, 31);

  if (ret < 1) {
    g_print ("You failed to specify a master key\n\n");
    g_free (input);
    /*g_free (sendcaps->key); */
    return 0;
  }

  /*memcpy ((void *) sendcaps->key, (void *) input, strlen (input)); */
  sendcaps->key = gst_buffer_new_and_alloc (strlen (input));
  memcpy ((void *) GST_BUFFER_DATA (sendcaps->key), (void *) input,
      strlen (input));

  /* Ask for other parameters, unless asked not to */
  if (key_only == FALSE) {

    /* Ask for the RTP cipher */
    g_print ("Please enter the RTP cipher for SSRC %d: ", ssrc);
    ret = get_user_input (input, 18);

    if (ret < 1) {
      g_print
          ("\nYou failed to specify an RTP cipher. Using default AES_128_ICM\n\n");
      sendcaps->rtp_cipher = 1;
    } else {
      sendcaps->rtp_cipher = get_cipher_property (input);
    }

    /* Ask for the RTP auth */
    g_print ("Please enter the RTP authentication for SSRC %d: ", ssrc);
    ret = get_user_input (input, 16);

    if (ret < 1) {
      g_print
          ("You failed to specify an RTP authentication. Using default HMAC_SHA1\n\n");
      sendcaps->rtp_auth = 3;
    } else {
      sendcaps->rtp_auth = get_auth_property (input);
    }

    /* Ask for the RTCP cipher */
    g_print ("Please enter the RTCP cipher for SSRC %d: ", ssrc);
    ret = get_user_input (input, 18);

    if (ret < 1) {
      g_print
          ("You failed to specify an RTCP cipher. Using default AES_128_ICM\n\n");
      sendcaps->rtcp_cipher = 1;
    } else {
      sendcaps->rtcp_cipher = get_cipher_property (input);
    }

    /* Ask for the RTCP auth */
    g_print ("Please enter the RTCP authentication for SSRC %d: ", ssrc);
    ret = get_user_input (input, 16);

    if (ret < 1) {
      g_print
          ("You failed to specify an RTCP authentication. Using default HMAC_SHA1\n\n");
      sendcaps->rtcp_auth = 3;
    } else {
      sendcaps->rtcp_auth = get_auth_property (input);
    }
  }

  g_free (input);

  return 1;
}

/* will be called when srtprecv reached the hard limit on its master key
 */
static guint
hard_limit_cb (GstElement * srtpenc, guint ssrc, struct SrtpSendCaps *sendcaps)
{
  guint ret;

  g_print ("Asked to change master key after hard limit\n");
  ret = get_srtp_recv_caps (ssrc, sendcaps, TRUE);

  if (ret == 0) {
    g_print ("-> Invalid parameters\n");
  } else {
    g_print ("Setting property on object\n");
    g_object_set (srtpenc, "key", sendcaps->key, "rtp-cipher",
        sendcaps->rtp_cipher, "rtp-auth", sendcaps->rtp_auth, "rtcp-cipher",
        sendcaps->rtcp_cipher, "rtcp-auth", sendcaps->rtcp_auth, NULL);
    ret = 1;
  }

  return ret;
}

/* will be called when srtprecv reached the index limit
 */
static guint
index_limit_cb (GstElement * srtpenc, guint ssrc, struct SrtpSendCaps *sendcaps)
{
  guint ret;

  g_print ("Asked to change parameters after index limit\n");
  ret = get_srtp_recv_caps (ssrc, sendcaps, TRUE);

  if (ret == 0) {
    g_print ("-> Invalid parameters\n");
  } else {
    /* Set properties on srtpenc */
    g_print ("Setting property on object\n");
    g_object_set (srtpenc, "key", sendcaps->key, "rtp-cipher",
        sendcaps->rtp_cipher, "rtp-auth", sendcaps->rtp_auth, "rtcp-cipher",
        sendcaps->rtcp_cipher, "rtcp-auth", sendcaps->rtcp_auth, NULL);
    ret = 1;
  }

  return ret;
}

static void
soft_limit_cb (GstElement * srtpenc, guint ssrc, struct SrtpSendCaps *sendcaps)
{
  g_print ("soft limit\n");
}

/* Check arguments on command line to get parameters
 */
static int
check_args (int argc, char *argv[], struct SrtpSendCaps *sendcaps)
{
  unsigned int len;

  if (sendcaps == NULL) {
    g_print ("\nError: NULL pointer");
    return 0;
  }

  if (argc < 2) {
    g_print ("\nInvalid call to %s : first argument is mandatory.\n\n",
        argv[0]);
    g_print
        ("Usage: %s  master_key  [rtp_cipher]  [rtp_auth]  [rtcp_cipher]  [rtcp_auth]\n\n",
        argv[0]);
    g_print
        ("- master_key  : Key used for encryption and decryption (mandatory)\n");
    g_print ("- rtp_cipher  : Encryption mecanism used for RTP\n");
    g_print ("- rtp_auth    : Authentication mecanism used for RTP\n");
    g_print ("- rtcp_cipher : Encryption mecanism used for RTCP\n");
    g_print ("- rtcp_cipher : Authentication mecanism used for RTCP\n\n");
    g_print ("Encryption mecanisms:\n- AES_128_ICM (default)\n- NULL\n");
    g_print ("Authentication mecanisms:\n- HMAC_SHA1 (default)\n- NULL\n\n");
    g_print
        ("NOTE: For RTCP, authentication mecanism cannot be NULL if cipher is non-NULL.\n\n");

    return 0;
  } else {

    /*sendcaps->key = g_new0 (gchar, 30); */

    /* copy key to structure */
    len = strlen (argv[1]);
    if (len > 30) {
      g_print
          ("\nWarning: master key too long, truncating to 30 characters\n\n");
      len = 30;
    }

    /*memcpy ((void *) sendcaps->key, (void *) argv[1], len); */
    sendcaps->key = gst_buffer_new_and_alloc (len);
    memcpy ((void *) GST_BUFFER_DATA (sendcaps->key), (void *) argv[1], len);
    /*gst_buffer_set_data (sendcaps->key, (guint8 *) argv[1], len); */

    g_print ("\nMaster key: [%s]\n", GST_BUFFER_DATA (sendcaps->key));

    /* get cipher and auth */
    if (argc > 2 && !g_str_has_prefix (argv[2], "--")) {
      g_print ("RTP cipher : ");
      sendcaps->rtp_cipher = get_cipher_property (argv[2]);
    } else {
      g_print ("RTP cipher : (default) AES_128_ICM\n");
      sendcaps->rtp_cipher = 1;
    }

    if (argc > 3 && !g_str_has_prefix (argv[3], "--")) {
      g_print ("RTP authentication : ");
      sendcaps->rtp_auth = get_auth_property (argv[3]);
    } else {
      g_print ("RTP authentication : (default) HMAC_SHA1\n");
      sendcaps->rtp_auth = 3;
    }

    if (argc > 4 && !g_str_has_prefix (argv[4], "--")) {
      g_print ("RTCP cipher : ");
      sendcaps->rtcp_cipher = get_cipher_property (argv[4]);
    } else {
      g_print ("RTCP cipher : (default) AES_128_ICM\n");
      sendcaps->rtcp_cipher = 1;
    }

    if (argc > 5 && !g_str_has_prefix (argv[5], "--")) {
      g_print ("RTCP authentication : ");
      sendcaps->rtcp_auth = get_auth_property (argv[5]);
    } else {
      g_print ("RTCP authentication : (default) HMAC_SHA1\n");
      sendcaps->rtcp_auth = 3;
    }

    return argc;
  }
}


int
main (int argc, char *argv[])
{
  GstElement *audiosrc, *audioconv, *audiores, *audioenc, *audiopay;
  GstElement *rtpbin, *srtpenc, *rtpsink, *rtcpsink, *rtcpsrc;
  GstElement *pipeline;
  GMainLoop *loop;
  gboolean res;
  GstPadLinkReturn lres;
  GstPad *srcpad, *srcpad1, *sinkpad, *sinkpad1, *sinkpad2, *sinkpad3,
      *sinkpad4;
  GstIterator *it;
  GstIteratorResult itres;
  struct SrtpSendCaps *sendcaps;

  /* always init first */
  gst_init (&argc, &argv);

  sendcaps = g_slice_new0 (struct SrtpSendCaps);

  if (check_args (argc, argv, sendcaps) == 0)
    return 0;

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

  g_object_set (srtpenc, "key", sendcaps->key, "rtp-cipher",
      sendcaps->rtp_cipher, "rtp-auth", sendcaps->rtp_auth, "rtcp-cipher",
      sendcaps->rtcp_cipher, "rtcp-auth", sendcaps->rtcp_auth, NULL);

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
  sinkpad1 = gst_element_get_request_pad (rtpbin, "send_rtp_sink_0");
  srcpad = gst_element_get_static_pad (audiopay, "src");
  lres = gst_pad_link (srcpad, sinkpad1);
  g_assert (lres == GST_PAD_LINK_OK);
  gst_object_unref (srcpad);

  /* get the RTP srcpad that was created when we requested the sinkpad above and
   * link it to the srtpenc sinkpad */
  srcpad = gst_element_get_static_pad (rtpbin, "send_rtp_src_0");
  sinkpad2 = gst_element_get_request_pad (srtpenc, "rtp_sink_0");
  lres = gst_pad_link (srcpad, sinkpad2);
  g_assert (lres == GST_PAD_LINK_OK);
  gst_object_unref (srcpad);

  /* get the RTP srcpad that was created when we requested the sinkpad above and
   * link it to the rtpsink sinkpad*/
  it = gst_pad_iterate_internal_links (sinkpad2);
  itres = gst_iterator_next (it, (gpointer *) & srcpad);
  gst_iterator_free (it);
  g_assert (itres == GST_ITERATOR_OK);

  sinkpad = gst_element_get_static_pad (rtpsink, "sink");
  lres = gst_pad_link (srcpad, sinkpad);
  g_assert (lres == GST_PAD_LINK_OK);
  gst_object_unref (srcpad);
  gst_object_unref (sinkpad);

  /* get an RTCP srcpad for sending RTCP to the srtpenc  */
  srcpad1 = gst_element_get_request_pad (rtpbin, "send_rtcp_src_0");
  sinkpad3 = gst_element_get_request_pad (srtpenc, "rtcp_sink_0");
  lres = gst_pad_link (srcpad1, sinkpad3);
  g_assert (lres == GST_PAD_LINK_OK);

  /* get the RTCP srcpad that was created when we requested the sinkpad above and
   * link it to the rtcpsink sinkpad*/
  it = gst_pad_iterate_internal_links (sinkpad3);
  itres = gst_iterator_next (it, (gpointer *) & srcpad);
  gst_iterator_free (it);
  g_assert (itres == GST_ITERATOR_OK);

  sinkpad = gst_element_get_static_pad (rtcpsink, "sink");
  lres = gst_pad_link (srcpad, sinkpad);
  g_assert (lres == GST_PAD_LINK_OK);
  gst_object_unref (srcpad);
  gst_object_unref (sinkpad);

  /* we also want to receive RTCP, request an RTCP sinkpad for session 0 and
   * link it to the srcpad of the udpsrc for RTCP */
  srcpad = gst_element_get_static_pad (rtcpsrc, "src");
  sinkpad4 = gst_element_get_request_pad (rtpbin, "recv_rtcp_sink_0");
  lres = gst_pad_link (srcpad, sinkpad4);
  g_assert (lres == GST_PAD_LINK_OK);
  gst_object_unref (srcpad);

  /* Connect to signal */
  loop = g_main_loop_new (NULL, FALSE);

  g_signal_connect (srtpenc, "hard-limit", G_CALLBACK (hard_limit_cb),
      sendcaps);
  g_signal_connect (srtpenc, "index-limit", G_CALLBACK (index_limit_cb),
      sendcaps);
  g_signal_connect (srtpenc, "soft-limit", G_CALLBACK (soft_limit_cb),
      sendcaps);

  /* set the pipeline to playing */
  g_print ("starting sender pipeline\n");
  gst_element_set_state (pipeline, GST_STATE_PLAYING);

  /* we need to run a GLib main loop to get the messages */
  g_main_loop_run (loop);

  /* clean up */
  g_print ("stopping sender pipeline\n");
  gst_element_set_state (pipeline, GST_STATE_NULL);

  g_main_loop_unref (loop);

  gst_element_release_request_pad (rtpbin, sinkpad4);
  gst_object_unref (sinkpad4);

  gst_element_release_request_pad (rtpbin, srcpad1);

  gst_element_release_request_pad (rtpbin, sinkpad1);

  gst_object_unref (pipeline);

  g_slice_free (struct SrtpSendCaps, sendcaps);

  return 0;
}
