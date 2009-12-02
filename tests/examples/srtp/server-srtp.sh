#!/bin/sh
#
# A simple RTP server
#
#  sends the output of alsasrc as alaw encoded RTP on port 5001, RTCP is sent on
#  port 5004. The destination is 127.0.0.1.
#  the receiver RTCP reports are received on port 5008
#
# .-------.    .-------.    .-------.      .----------.     .------------.      .-------.
# |alsasrc|    |alawenc|    |pcmapay|      | rtpbin   |     |  srtpsend  |      |udpsink|  RTP
# |      src->sink    src->sink    src->send_rtp send_rtp->rtp_sink   rtp_src->sink     | port=5001
# '-------'    '-------'    '-------'      |          |     |            |      '-------'
#                                          |          |     |            |
#                                          |          |     |            |      .-------.
#                                          |          |     |            |      |udpsink|  RTCP
#                                          |    send_rtcp->rtcp_sink rtcp_src->sink     | port=5004
#                           .-------.      |          |     '------------'      '-------' sync=false
#                RTCP       |udpsrc |      |          |                                   async=false
#              port=5008    |     src->recv_rtcp      |
#                           '-------'      '----------'
#

# change this to send the RTP data and RTCP to another host
DEST=127.0.0.1

#AELEM=autoaudiosrc
AELEM=audiotestsrc

# PCMA encode from an the source
ASOURCE="$AELEM ! audioconvert"
AENC="alawenc ! rtppcmapay"

gst-launch -v gstrtpbin name=rtpbin \
     $ASOURCE ! $AENC ! rtpbin.send_rtp_sink_0  \
            rtpbin.send_rtp_src_0 ! udpsink port=5001 host=$DEST                      \
            rtpbin.send_rtcp_src_0 ! udpsink port=5004 host=$DEST sync=false async=false \
         udpsrc port=5008 ! rtpbin.recv_rtcp_sink_0
