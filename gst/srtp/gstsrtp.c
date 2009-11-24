/* GStreamer
 * Copyright (C) <2009> Gabriel Millaire <millaire.gabriel@gmail.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "gstsrtpsend.h"
#include "gstsrtprecv.h"

static gboolean
plugin_init (GstPlugin * plugin)
{
  if (!gst_srtp_send_plugin_init (plugin))
    return FALSE;

  if (!gst_srtp_recv_plugin_init (plugin))
    return FALSE;

  return TRUE;
}

GST_PLUGIN_DEFINE (GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    "gstsrtp",
    "GStreamer SRTP",
    plugin_init, VERSION, "LGPL", "GStreamer", "http://gstreamer.net/")
