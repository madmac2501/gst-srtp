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

#include <stdio.h>
#include <string.h>
#include <math.h>

#include <gst/gst.h>

/*
 * A simple SRTP receiver
 *
 *  Receives alaw encoded RTP audio on port 5001, RTCP is received on  port 5004.
 *  The rtpbin demux the audio through multiple audio pipeline.
 *  The receiver RTCP reports are sent to port 5008
 *
 *             .-------.      .------------.    .----------.     .---------.   .-------.   .--------.
 *  RTP        |udpsrc |      |  srtprecv  |    | rtpbin   |     |pcmadepay|   |alawdec|   |alsasink|
 *  port=5001  |      src->rtp_sink  rtp_src->recv_rtp recv_rtp->sink     src->sink   src->sink     |
 *             '-------'      |            |    |          |     '---------'   '-------'   '--------'
 *                            |            |    |          | --->
 *                            |            |    |          | --->
 *                            |            |    |          | --->
 *                            |            |    |          |
 *                            |            |    |          |     .-------.
 *             .-------.      |            |    |          |     |udpsink|  RTCP
 *  RTCP       |udpsrc |      |            |    |    send_rtcp->sink     | port=5008
 *  port=5004  |    src->rtcp_sink rtcp_src->recv_rtcp     |     '-------' sync=false
 *             '-------'      '------------'    '----------'               async=false
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

#define AES_128_ICM       1
#define NULL_CIPHER       0
#define STRONGHOLD_CIPHER 1

#define HMAC_SHA1         3
#define NULL_AUTH         0
#define STRONGHOLD_AUTH   3

struct SrtpRecvCaps
{
  guint ssrc;
  GstBuffer *key;
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

static int
new_srtp_recv_caps (struct SrtpRecvCaps *recvcaps, gboolean key_only)
{
  int ret;
  gchar *input;

  if (recvcaps == NULL)
    return 0;

  input = g_new0 (gchar, 81);
  if (recvcaps->key == NULL)
    /*recvcaps->key = g_new0 (gchar, 30); */
    recvcaps->key = gst_buffer_new ();

  /* Ask for the master key */
  g_print ("Please enter the master key for SSRC %d: ", recvcaps->ssrc);
  ret = get_user_input (input, 31);

  if (ret < 1) {
    g_print ("You failed to specify a master key\n");
    g_free (input);
    return 0;
  }

  /*memcpy ((void *) recvcaps->key, (void *) input, strlen (input)); */
  gst_buffer_set_data (recvcaps->key, (guint8 *) input, strlen (input));

  /* Ask for other parameters, unless asked not to */
  if (!key_only) {
    g_print ("asking for every parameters\n");

    /* Ask for the RTP cipher */
    g_print ("Please enter the RTP cipher for SSRC %d: ", recvcaps->ssrc);
    ret = get_user_input (input, 18);

    if (ret < 1) {
      g_print
          ("You failed to specify an RTP cipher. Using default AES_128_ICM\n");
      recvcaps->rtp_cipher = AES_128_ICM;
    } else {
      recvcaps->rtp_cipher = get_cipher_property (input);
    }

    /* Ask for the RTP auth */
    g_print ("Please enter the RTP authentication for SSRC %d: ",
        recvcaps->ssrc);
    ret = get_user_input (input, 16);

    if (ret < 1) {
      g_print
          ("You failed to specify an RTP authentication. Using default HMAC_SHA1\n");
      recvcaps->rtp_auth = HMAC_SHA1;
    } else {
      recvcaps->rtp_auth = get_auth_property (input);
    }

    /* Ask for the RTCP cipher */
    g_print ("Please enter the RTCP cipher for SSRC %d: ", recvcaps->ssrc);
    ret = get_user_input (input, 18);

    if (ret < 1) {
      g_print
          ("You failed to specify an RTCP cipher. Using default AES_128_ICM\n");
      recvcaps->rtcp_cipher = AES_128_ICM;
    } else {
      recvcaps->rtcp_cipher = get_cipher_property (input);
    }

    /* Ask for the RTCP auth */
    g_print ("Please enter the RTCP authentication for SSRC %d: ",
        recvcaps->ssrc);
    ret = get_user_input (input, 16);

    if (ret < 1) {
      g_print
          ("You failed to specify an RTCP authentication. Using default HMAC_SHA1\n");
      recvcaps->rtcp_auth = HMAC_SHA1;
    } else {
      recvcaps->rtcp_auth = get_auth_property (input);
    }
  }

  g_free (input);

  return 1;
}

static void
empty_stream_list (GSList ** streams)
{
  GSList *walk;
  struct SrtpRecvCaps *recvcaps = NULL;

  while ((walk = *streams)) {
    recvcaps = (struct SrtpRecvCaps *) walk->data;
    g_free (recvcaps->key);
    recvcaps->key = NULL;
    g_slice_free (struct SrtpRecvCaps, recvcaps);
    recvcaps = NULL;
    *streams = g_slist_delete_link (*streams, walk);
  }
}

static struct SrtpRecvCaps *
get_srtp_recv_caps_by_ssrc (guint ssrc, GSList ** streams, gboolean key_only,
    gboolean new_caps)
{
  GSList *walk;
  gboolean found = FALSE;
  struct SrtpRecvCaps *recvcaps = NULL;

  for (walk = *streams; walk; walk = g_slist_next (walk)) {
    recvcaps = (struct SrtpRecvCaps *) walk->data;

    if (recvcaps->ssrc == ssrc) {
      if (key_only) {
        found = TRUE;
        break;
      } else if (new_caps) {
        g_print ("Changing stream\n");
        g_free (recvcaps->key);
        recvcaps->key = NULL;
        g_slice_free (struct SrtpRecvCaps, recvcaps);
        recvcaps = NULL;
        *streams = g_slist_delete_link (*streams, walk);
        break;
      } else {
        g_print ("Found stream\n");
        return recvcaps;
      }
    }
  }

  /* SSRC not found in list, create new caps */
  if (!found) {
    g_print ("New stream\n");
    recvcaps = g_slice_new0 (struct SrtpRecvCaps);
    recvcaps->ssrc = ssrc;
    key_only = FALSE;

    recvcaps->rtp_cipher = AES_128_ICM;
    recvcaps->rtp_auth = HMAC_SHA1;
    recvcaps->rtcp_cipher = AES_128_ICM;
    recvcaps->rtcp_auth = HMAC_SHA1;
  }

  if (new_srtp_recv_caps (recvcaps, key_only) == 0) {
    g_print ("couldn't get new caps\n");
    if (!found)
      g_slice_free (struct SrtpRecvCaps, recvcaps);

    return NULL;
  } else {
    /* Add to list */
    g_print ("adding to list\n");
    if (!found)
      *streams = g_slist_prepend (*streams, recvcaps);
  }

  return recvcaps;
}

static GstElement *
new_audio_pipe (GstElement * pipeline)
{
  GstElement *audiodepay, *audiodec, *audiores, *audioconv, *audiosink;
  gboolean res;

  /* the depayloading and decoding */
  audiodepay = gst_element_factory_make (AUDIO_DEPAY, NULL);
  if (!audiodepay)
    return NULL;

  audiodec = gst_element_factory_make (AUDIO_DEC, NULL);
  if (!audiodec) {
    g_object_unref (audiodepay);
    return NULL;
  }

  /* the audio playback and format conversion */
  audioconv = gst_element_factory_make ("audioconvert", NULL);
  if (!audioconv) {
    g_object_unref (audiodepay);
    g_object_unref (audiodec);
    return NULL;
  }

  audiores = gst_element_factory_make ("audioresample", NULL);
  if (!audiores) {
    g_object_unref (audiodepay);
    g_object_unref (audiodec);
    g_object_unref (audioconv);
    return NULL;
  }

  audiosink = gst_element_factory_make (AUDIO_SINK, NULL);
  if (!audiosink) {
    g_object_unref (audiodepay);
    g_object_unref (audiodec);
    g_object_unref (audioconv);
    g_object_unref (audiores);
    return NULL;
  }


  /* add depayloading and playback to the pipeline and link */
  gst_bin_add_many (GST_BIN (pipeline), audiodepay, audiodec, audioconv,
      audiores, audiosink, NULL);

  res = gst_element_link_many (audiodepay, audiodec, audioconv, audiores,
      audiosink, NULL);
  if (res != TRUE) {
    gst_bin_remove_many (GST_BIN (pipeline), audiodepay, audiodec, audioconv,
        audiores, audiosink, NULL);

    audiodepay = NULL;
  } else {
    /* Audio pipeline added, start playing */
    gst_element_set_state (audiodepay, GST_STATE_PLAYING);
    gst_element_set_state (audiodec, GST_STATE_PLAYING);
    gst_element_set_state (audioconv, GST_STATE_PLAYING);
    gst_element_set_state (audiores, GST_STATE_PLAYING);
    gst_element_set_state (audiosink, GST_STATE_PLAYING);
  }

  return audiodepay;
}

/* will be called when rtpbin has validated a payload that we can depayload */
static void
pad_added_cb (GstElement * rtpbin, GstPad * new_pad, GstElement * pipeline)
{
  GstPad *sinkpad;
  GstPadLinkReturn lres;
  GstElement *depay;

  g_print ("new payload on pad: %s\n", GST_PAD_NAME (new_pad));

  depay = new_audio_pipe (pipeline);

  if (depay) {
    sinkpad = gst_element_get_static_pad (depay, "sink");
    g_assert (sinkpad);

    lres = gst_pad_link (new_pad, sinkpad);
    g_assert (lres == GST_PAD_LINK_OK);
    gst_object_unref (sinkpad);
    g_print ("New audio pipeline created\n");

  } else {
    g_print ("Could not create new audio pipeline\n");
  }
}

/* will be called when srtprecv needs parameters */
static GstCaps *
get_caps_cb (GstElement * srtpdec, guint ssrc, GSList ** streams)
{
  GstCaps *caps = NULL;
  struct SrtpRecvCaps *recvcaps = NULL;

  g_print ("Asked to send caps\n");
  recvcaps = get_srtp_recv_caps_by_ssrc (ssrc, streams, FALSE, FALSE);

  if (recvcaps == NULL || recvcaps->key == NULL) {
    g_print ("-> Invalid parameters\n");
  } else {

    caps = gst_caps_new_simple ("application/x-srtp", "mkey", GST_TYPE_BUFFER,
        recvcaps->key, "rtp-cipher", G_TYPE_UINT, recvcaps->rtp_cipher,
        "rtp-auth", G_TYPE_UINT, recvcaps->rtp_auth, "rtcp-cipher",
        G_TYPE_UINT, recvcaps->rtcp_cipher, "rtcp-auth", G_TYPE_UINT,
        recvcaps->rtcp_auth, NULL);
  }

  return caps;
}

/* will be called when srtprecv needs new parameters */
static GstCaps *
new_caps_cb (GstElement * srtpdec, guint ssrc, GSList ** streams)
{
  GstCaps *caps = NULL;
  struct SrtpRecvCaps *recvcaps = NULL;

  g_print ("Asked to get new caps\n");
  recvcaps = get_srtp_recv_caps_by_ssrc (ssrc, streams, FALSE, TRUE);

  if (recvcaps == NULL || recvcaps->key == NULL) {
    g_print ("-> Invalid parameters\n");
  } else {
    caps = gst_caps_new_simple ("application/x-srtp", "mkey", GST_TYPE_BUFFER,
        recvcaps->key, "rtp-cipher", G_TYPE_UINT, recvcaps->rtp_cipher,
        "rtp-auth", G_TYPE_UINT, recvcaps->rtp_auth, "rtcp-cipher",
        G_TYPE_UINT, recvcaps->rtcp_cipher, "rtcp-auth", G_TYPE_UINT,
        recvcaps->rtcp_auth, NULL);
  }

  return caps;
}

/* will be called when srtprecv reached the hard limit on its master key */
static GstCaps *
hard_limit_cb (GstElement * srtpdec, guint ssrc, GSList ** streams)
{
  GstCaps *caps = NULL;
  struct SrtpRecvCaps *recvcaps = NULL;

  g_print ("Asked to send caps after hard limit\n");
  recvcaps = get_srtp_recv_caps_by_ssrc (ssrc, streams, TRUE, FALSE);

  if (recvcaps == NULL || recvcaps->key == NULL) {
    g_print ("-> Invalid parameters\n");
  } else {
    caps = gst_caps_new_simple ("application/x-srtp", "mkey", GST_TYPE_BUFFER,
        recvcaps->key, "rtp-cipher", G_TYPE_UINT, recvcaps->rtp_cipher,
        "rtp-auth", G_TYPE_UINT, recvcaps->rtp_auth, "rtcp-cipher",
        G_TYPE_UINT, recvcaps->rtcp_cipher, "rtcp-auth", G_TYPE_UINT,
        recvcaps->rtcp_auth, NULL);
  }

  return caps;
}

/* will be called when srtprecv reached the soft limit on its master key */
static GstCaps *
soft_limit_cb (GstElement * srtpdec, guint ssrc, GSList ** streams)
{
  g_print ("soft limit\n");

  return NULL;
}

/* will be called when srtprecv reached the index limit */
static GstCaps *
index_limit_cb (GstElement * srtpdec, guint ssrc, GSList ** streams)
{
  GstCaps *caps = NULL;
  struct SrtpRecvCaps *recvcaps = NULL;

  g_print ("Asked to send caps after index limit\n");
  recvcaps = get_srtp_recv_caps_by_ssrc (ssrc, streams, TRUE, FALSE);

  if (recvcaps == NULL || recvcaps->key == NULL) {
    g_print ("-> Invalid parameters\n");
  } else {
    caps = gst_caps_new_simple ("application/x-srtp", "mkey", GST_TYPE_BUFFER,
        recvcaps->key, "rtp-cipher", G_TYPE_UINT, recvcaps->rtp_cipher,
        "rtp-auth", G_TYPE_UINT, recvcaps->rtp_auth, "rtcp-cipher",
        G_TYPE_UINT, recvcaps->rtcp_cipher, "rtcp-auth", G_TYPE_UINT,
        recvcaps->rtcp_auth, NULL);
  }

  return caps;
}

int
main (int argc, char *argv[])
{
  GstElement *srtpdec, *rtpbin, *rtpsrc, *rtcpsrc, *rtcpsink;
  GstElement *pipeline;
  GMainLoop *loop;
  GstCaps *caps;
  GstPadLinkReturn lres;
  GstPad *srcpad, *sinkpad;
  GSList *streams = NULL;

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
  g_signal_connect (rtpbin, "pad-added", G_CALLBACK (pad_added_cb), pipeline);

  /* we need to run a GLib main loop to get the messages */
  loop = g_main_loop_new (NULL, FALSE);

  g_signal_connect (srtpdec, "get-caps", G_CALLBACK (get_caps_cb), &streams);
  g_signal_connect (srtpdec, "new-caps", G_CALLBACK (new_caps_cb), &streams);
  g_signal_connect (srtpdec, "hard-limit", G_CALLBACK (hard_limit_cb),
      &streams);
  g_signal_connect (srtpdec, "soft-limit", G_CALLBACK (soft_limit_cb),
      &streams);
  g_signal_connect (srtpdec, "index-limit", G_CALLBACK (index_limit_cb),
      &streams);

  /* set the pipeline to playing */
  g_print ("starting receiver pipeline\n");
  gst_element_set_state (pipeline, GST_STATE_PLAYING);

  g_main_loop_run (loop);

  g_print ("stopping receiver pipeline\n");
  gst_element_set_state (pipeline, GST_STATE_NULL);

  /* Empty stream list */
  empty_stream_list (&streams);

  g_main_loop_unref (loop);
  gst_object_unref (pipeline);

  return 0;
}
