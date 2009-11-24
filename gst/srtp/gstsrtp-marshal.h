
#ifndef __gst_srtp_marshal_MARSHAL_H__
#define __gst_srtp_marshal_MARSHAL_H__

#include	<glib-object.h>

G_BEGIN_DECLS

/* BOXED:UINT (gstrtpbin-marshal.list:1) */
extern void gst_srtp_marshal_BOXED__UINT (GClosure     *closure,
                                          GValue       *return_value,
                                          guint         n_param_values,
                                          const GValue *param_values,
                                          gpointer      invocation_hint,
                                          gpointer      marshal_data);

/* VOID:UINT (gstrtpbin-marshal.list:2) */
extern void gst_srtp_marshal_VOID__UINT (GClosure     *closure,
                                         GValue       *return_value,
                                         guint         n_param_values,
                                         const GValue *param_values,
                                         gpointer      invocation_hint,
                                         gpointer      marshal_data);

G_END_DECLS

#endif /* __gst_srtp_marshal_MARSHAL_H__ */

