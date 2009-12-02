#!/bin/sh
#
# A simple SRTP receiver
#
#  receives alaw encoded RTP audio on port 5001, RTCP is received on  port 5004.
#  the receiver RTCP reports are sent to port 5008
#
#             .-------.      .------------.    .----------.     .---------.   .-------.   .--------.
#  RTP        |udpsrc |      |  srtprecv  |    | rtpbin   |     |pcmadepay|   |alawdec|   |alsasink|
#  port=5001  |      src->rtp_sink  rtp_src->recv_rtp recv_rtp->sink     src->sink   src->sink     |
#             '-------'      |            |    |          |     '---------'   '-------'   '--------'
#                            |            |    |          |
#                            |            |    |          |     .-------.
#                            |            |    |          |     |udpsink|  RTCP
#                            |            |    |    send_rtcp->sink     | port=5008
#             .-------.      |            |    |          |     '-------' sync=false
#  RTCP       |udpsrc |      |            |    |          |               async=false
#  port=5004  |    src->rtcp_sink rtcp_src->recv_rtcp     |
#             '-------'      '------------'    '----------'
#

# the caps of the sender RTP stream. This is usually negotiated out of band with
# SDP or RTSP.
AUDIO_CAPS="application/x-srtp,media=(string)audio,clock-rate=(int)8000,encoding-name=(string)PCMA"

# the destination machine to send RTCP to. This is the address of the sender and
# is used to send back the RTCP reports of this receiver. If the data is sent
# from another machine, change this address.
DEST=127.0.0.1

gst-launch -v gstrtpbin name=rtpbin                                                \
	   udpsrc caps=$AUDIO_CAPS port=5001 ! rtpbin.recv_rtp_sink_0              \
	         rtpbin. ! rtppcmadepay ! alawdec ! audioconvert ! audioresample ! autoaudiosink \
           udpsrc port=5004 ! rtpbin.recv_rtcp_sink_0                              \
         rtpbin.send_rtcp_src_0 ! udpsink port=5008 host=$DEST sync=false async=false
