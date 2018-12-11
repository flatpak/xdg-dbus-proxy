/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 * Copyright (C) 2015 Colin Walters <walters@verbum.org>
 * 
 * GLIB - Library of useful routines for C programming
 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#pragma once

#include <gio/gio.h>

G_BEGIN_DECLS

#if !GLIB_CHECK_VERSION(2, 43, 4)

#define _GLIB_AUTOPTR_FUNC_NAME(TypeName) glib_autoptr_cleanup_##TypeName
#define _GLIB_AUTOPTR_TYPENAME(TypeName)  TypeName##_autoptr
#define _GLIB_AUTO_FUNC_NAME(TypeName)    glib_auto_cleanup_##TypeName
#define _GLIB_CLEANUP(func)               __attribute__((cleanup(func)))
#define _GLIB_DEFINE_AUTOPTR_CHAINUP(ModuleObjName, ParentName) \
  typedef ModuleObjName *_GLIB_AUTOPTR_TYPENAME(ModuleObjName);                                          \
  static inline void _GLIB_AUTOPTR_FUNC_NAME(ModuleObjName) (ModuleObjName **_ptr) {                     \
    _GLIB_AUTOPTR_FUNC_NAME(ParentName) ((ParentName **) _ptr); }                                        \


/* these macros are API */
#define G_DEFINE_AUTOPTR_CLEANUP_FUNC(TypeName, func) \
  typedef TypeName *_GLIB_AUTOPTR_TYPENAME(TypeName);                                                           \
  G_GNUC_BEGIN_IGNORE_DEPRECATIONS                                                                              \
  static inline void _GLIB_AUTOPTR_FUNC_NAME(TypeName) (TypeName **_ptr) { if (*_ptr) (func) (*_ptr); }         \
  G_GNUC_END_IGNORE_DEPRECATIONS
#define G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TypeName, func) \
  G_GNUC_BEGIN_IGNORE_DEPRECATIONS                                                                              \
  static inline void _GLIB_AUTO_FUNC_NAME(TypeName) (TypeName *_ptr) { (func) (_ptr); }                         \
  G_GNUC_END_IGNORE_DEPRECATIONS
#define G_DEFINE_AUTO_CLEANUP_FREE_FUNC(TypeName, func, none) \
  G_GNUC_BEGIN_IGNORE_DEPRECATIONS                                                                              \
  static inline void _GLIB_AUTO_FUNC_NAME(TypeName) (TypeName *_ptr) { if (*_ptr != none) (func) (*_ptr); }     \
  G_GNUC_END_IGNORE_DEPRECATIONS
#define g_autoptr(TypeName) _GLIB_CLEANUP(_GLIB_AUTOPTR_FUNC_NAME(TypeName)) _GLIB_AUTOPTR_TYPENAME(TypeName)
#define g_auto(TypeName) _GLIB_CLEANUP(_GLIB_AUTO_FUNC_NAME(TypeName)) TypeName
#define g_autofree _GLIB_CLEANUP(g_autoptr_cleanup_generic_gfree)

/**
 * g_steal_pointer:
 * @pp: a pointer to a pointer
 *
 * Sets @pp to %NULL, returning the value that was there before.
 *
 * Conceptually, this transfers the ownership of the pointer from the
 * referenced variable to the "caller" of the macro (ie: "steals" the
 * reference).
 *
 * The return value will be properly typed, according to the type of
 * @pp.
 *
 * This can be very useful when combined with g_autoptr() to prevent the
 * return value of a function from being automatically freed.  Consider
 * the following example (which only works on GCC and clang):
 *
 * |[
 * GObject *
 * create_object (void)
 * {
 *   g_autoptr(GObject) obj = g_object_new (G_TYPE_OBJECT, NULL);
 *
 *   if (early_error_case)
 *     return NULL;
 *
 *   return g_steal_pointer (&obj);
 * }
 * ]|
 *
 * It can also be used in similar ways for 'out' parameters and is
 * particularly useful for dealing with optional out parameters:
 *
 * |[
 * gboolean
 * get_object (GObject **obj_out)
 * {
 *   g_autoptr(GObject) obj = g_object_new (G_TYPE_OBJECT, NULL);
 *
 *   if (early_error_case)
 *     return FALSE;
 *
 *   if (obj_out)
 *     *obj_out = g_steal_pointer (&obj);
 *
 *   return TRUE;
 * }
 * ]|
 *
 * In the above example, the object will be automatically freed in the
 * early error case and also in the case that %NULL was given for
 * @obj_out.
 *
 * Since: 2.44
 */
static inline gpointer
(g_steal_pointer) (gpointer pp)
{
  gpointer *ptr = (gpointer *) pp;
  gpointer ref;

  ref = *ptr;
  *ptr = NULL;

  return ref;
}

/* type safety */
#define g_steal_pointer(pp) \
  (0 ? (*(pp)) : (g_steal_pointer) (pp))

static inline void
g_autoptr_cleanup_generic_gfree (void *p)
{ 
  void **pp = (void**)p;
  if (*pp)
    g_free (*pp);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(GAsyncQueue, g_async_queue_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GBookmarkFile, g_bookmark_file_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GBytes, g_bytes_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GChecksum, g_checksum_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GDateTime, g_date_time_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GDir, g_dir_close)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GError, g_error_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GHashTable, g_hash_table_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GHmac, g_hmac_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GIOChannel, g_io_channel_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GKeyFile, g_key_file_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GList, g_list_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GArray, g_array_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GPtrArray, g_ptr_array_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GMainContext, g_main_context_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GMainLoop, g_main_loop_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GSource, g_source_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GMappedFile, g_mapped_file_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GMarkupParseContext, g_markup_parse_context_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(gchar, g_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GNode, g_node_destroy)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GOptionContext, g_option_context_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GOptionGroup, g_option_group_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GPatternSpec, g_pattern_spec_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GQueue, g_queue_free)
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(GQueue, g_queue_clear)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GRand, g_rand_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GRegex, g_regex_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GMatchInfo, g_match_info_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GScanner, g_scanner_destroy)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GSequence, g_sequence_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GSList, g_slist_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GStringChunk, g_string_chunk_free)
G_DEFINE_AUTO_CLEANUP_FREE_FUNC(GStrv, g_strfreev, NULL)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GThread, g_thread_unref)
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(GMutex, g_mutex_clear)
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(GCond, g_cond_clear)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GTimer, g_timer_destroy)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GTimeZone, g_time_zone_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GTree, g_tree_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GVariant, g_variant_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GVariantBuilder, g_variant_builder_unref)
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(GVariantBuilder, g_variant_builder_clear)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GVariantIter, g_variant_iter_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GVariantDict, g_variant_dict_unref)
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(GVariantDict, g_variant_dict_clear)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GVariantType, g_variant_type_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GSubprocess, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GSubprocessLauncher, g_object_unref)

/* Add GObject-based types as needed. */
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GAsyncResult, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GCancellable, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GConverter, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GConverterOutputStream, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GDataInputStream, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GFile, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GFileEnumerator, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GFileIOStream, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GFileInfo, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GFileInputStream, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GFileMonitor, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GFileOutputStream, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GInputStream, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GMemoryInputStream, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GMemoryOutputStream, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GMount, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GOutputStream, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GSocket, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GSocketAddress, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GSubprocess, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GSubprocessLauncher, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GTask, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GTlsCertificate, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GTlsDatabase, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GTlsInteraction, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GDBusConnection, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GDBusMessage, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GVolumeMonitor, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GZlibCompressor, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GZlibDecompressor, g_object_unref)

#endif /* !GLIB_CHECK_VERSION(2, 43, 3) */

#if !GLIB_CHECK_VERSION(2, 45, 8)

static inline void
g_autoptr_cleanup_gstring_free (GString *string)
{
  if (string)
    g_string_free (string, TRUE);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(GString, g_autoptr_cleanup_gstring_free)

#endif

G_END_DECLS
