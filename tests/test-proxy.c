/*
 * Copyright © 2018 Collabora Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>
#include <glib-unix.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include "backport-autoptr.h"

#define DBUS_SERVICE_DBUS "org.freedesktop.DBus"
#define DBUS_PATH_DBUS "/org/freedesktop/DBus"
#define DBUS_INTERFACE_DBUS "org.freedesktop.DBus"
#define DBUS_INTERFACE_PEER "org.freedesktop.DBus.Peer"

#define DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER 1
#define DBUS_REQUEST_NAME_REPLY_IN_QUEUE 2
#define DBUS_REQUEST_NAME_REPLY_EXISTS 3
#define DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER 4

#define CALLER_NAME "com.example.Caller"
#define CANNOT_ACCESS_NAME "com.example.CannotAccess"
#define CAN_SEE_NAME "com.example.CanSee"
#define CAN_TALK_NAME "com.example.CanTalk"
#define CAN_OWN_NAME "com.example.CanOwn"
#define CAN_CALL_ANYTHING_NAME "com.example.CanCallAny"
#define CAN_CALL_SOME_NAME "com.example.CanCallSome"
#define CAN_RECEIVE_ANYTHING_NAME "com.example.CanReceiveAny"
#define CAN_RECEIVE_SOME_NAME "com.example.CanReceiveSome"

#define EXAMPLE_IFACE "net.example.AnyInterface"
#define EXAMPLE_METHOD "Echo"
#define EXAMPLE_SIGNAL "Shouted"
#define EXAMPLE_PATH "/path"
#define CAN_CALL_SOME_IFACE "org.example.CanCallThis"
#define CAN_CALL_SOME_METHOD "OnlyThisMethod"
#define CAN_CALL_SOME_PATH "/only/this/path"
#define CAN_RECEIVE_SOME_IFACE "org.example.CanReceiveThis"
#define CAN_RECEIVE_SOME_SIGNAL "JustThisSignal"
#define CAN_RECEIVE_SOME_PATH "/just/this/path"

#define IGNORE_IFACE "com.example.Ignore"
#define IGNORE_METHOD "Ignore"

#define MALICIOUS_IFACE "com.example.Malice"
#define MALICIOUS_MEMBER "ShouldNotBeAllowed"
#define MALICIOUS_BODY "Message containing this body should have been blocked"

static void
ready_cb (GObject *source_object,
          GAsyncResult *result,
          void *user_data)
{
  GAsyncResult **result_p = user_data;

  g_assert_nonnull (result_p);
  g_assert_null (*result_p);
  *result_p = g_object_ref (result);
}

typedef struct
{
  GDBusConnection *conn;
  const char *label;
  const char *unique_name;
  guint filter;
  int n_method_calls;       /* atomic */
  int n_unicast_signals;    /* atomic */
  int n_broadcasts;         /* atomic */
} Connection;

static void
connection_clear (Connection *self)
{
  if (self->conn != NULL)
    {
      g_autoptr(GError) error = NULL;

      if (self->filter != 0)
        {
          g_dbus_connection_remove_filter (self->conn, self->filter);
          self->filter = 0;
        }

      g_dbus_connection_close_sync (self->conn, NULL, &error);

      if (error != NULL)
        g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CLOSED);
    }

  self->unique_name = NULL;
  g_clear_object (&self->conn);
}

typedef struct
{
  Connection proxied;
  Connection caller_conn;
  Connection cannot_access_conn;
  Connection can_see_conn;
  Connection can_talk_conn;
  Connection can_own_conn;
  Connection can_call_anything_conn;
  Connection can_call_some_conn;
  Connection can_receive_anything_conn;
  Connection can_receive_some_conn;
  GHashTable *connections_by_name;
  GSubprocess *dbus_daemon;
  GSubprocess *monitor;
  GSubprocess *proxy;
  gchar *dbus_address;
  gchar *temp_directory;
  gchar *proxy_socket;
  gchar *proxy_address;
  const gchar *proxy_path;
  int sync_pipe;
} Fixture;

typedef struct
{
  int dummy;
} Config;

static GDBusMessage *
conn_filter_cb (GDBusConnection *conn,
                GDBusMessage *message,
                gboolean incoming,
                void *user_data)
{
  Connection *conn_info = user_data;

  g_assert (conn == conn_info->conn);

  if (incoming)
    {
      GDBusMessageType type = g_dbus_message_get_message_type (message);
      const char *sender = g_dbus_message_get_sender (message);
      const char *dest = g_dbus_message_get_destination (message);
      const char *path = g_dbus_message_get_path (message);
      const char *iface = g_dbus_message_get_interface (message);
      const char *member = g_dbus_message_get_member (message);

      g_test_message ("%s got message type %u, from=%s, to=%s, path=%s, %s.%s",
                      conn_info->label,
                      type,
                      sender ?: "(message bus)",
                      dest ?: "(broadcast)",
                      path ?: "(none)",
                      iface ?: "(none)",
                      member ?: "(none)");

      switch (type)
        {
          case G_DBUS_MESSAGE_TYPE_METHOD_CALL:
            g_test_message ("%s got method call", conn_info->label);
            g_atomic_int_inc (&conn_info->n_method_calls);

            if (g_strcmp0 (iface, IGNORE_IFACE) == 0 &&
                g_strcmp0 (member, IGNORE_METHOD) == 0)
              {
                g_test_message ("method call is %s.%s, ignoring",
                                iface, member);
                g_clear_object (&message);
                return NULL;
              }

            break;

          case G_DBUS_MESSAGE_TYPE_SIGNAL:
            if (sender == NULL)
              {
                g_test_message ("%s got signal from message bus, ignoring", conn_info->label);
              }
            else if (dest != NULL && dest[0] != '\0')
              {
                g_test_message ("%s got unicast signal", conn_info->label);
                g_atomic_int_inc (&conn_info->n_unicast_signals);
              }
            else
              {
                g_test_message ("%s got broadcast signal", conn_info->label);
                g_atomic_int_inc (&conn_info->n_broadcasts);
              }

            break;

          case G_DBUS_MESSAGE_TYPE_METHOD_RETURN:
          case G_DBUS_MESSAGE_TYPE_ERROR:
            if (type == G_DBUS_MESSAGE_TYPE_METHOD_RETURN)
              g_test_message ("%s got method reply", conn_info->label);
            else
              g_test_message ("%s got error reply", conn_info->label);

            if (g_str_equal (g_dbus_message_get_signature (message), "s"))
              {
                const char *s = NULL;

                g_variant_get (g_dbus_message_get_body (message), "(&s)", &s);

                if (g_str_equal (s, MALICIOUS_BODY))
                  g_error ("Forged reply received");
              }

            break;

          case G_DBUS_MESSAGE_TYPE_INVALID:
          default:
            g_assert_not_reached ();
        }
    }

  return message;
}

/*
 * Open a direct connection to the bus
 */
static void
fixture_connect (Fixture *f,
                 Connection *conn,
                 const char *name)
{
  g_autoptr(GError) error = NULL;

  g_return_if_fail (conn != NULL);
  g_return_if_fail (conn->conn == NULL);

  if (name != NULL)
    conn->label = name;
  else
    conn->label = "(unnamed connection)";

  conn->conn = g_dbus_connection_new_for_address_sync (f->dbus_address,
                                                       (G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT
                                                        | G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION),
                                                       NULL,    /* observer */
                                                       NULL,    /* cancellable */
                                                       &error);
  g_assert_no_error (error);
  g_assert_nonnull (conn->conn);
  conn->unique_name = g_dbus_connection_get_unique_name (conn->conn);

  if (name != NULL)
    {
      g_autoptr(GVariant) tuple = NULL;
      guint32 result = 0;

      tuple = g_dbus_connection_call_sync (conn->conn,
                                           DBUS_SERVICE_DBUS,
                                           DBUS_PATH_DBUS,
                                           DBUS_INTERFACE_DBUS,
                                           "RequestName",
                                           g_variant_new ("(su)",
                                                           name,
                                                           (G_BUS_NAME_OWNER_FLAGS_ALLOW_REPLACEMENT
                                                           | G_BUS_NAME_OWNER_FLAGS_REPLACE
                                                           | G_BUS_NAME_OWNER_FLAGS_DO_NOT_QUEUE)),
                                           G_VARIANT_TYPE ("(u)"),
                                           G_DBUS_CALL_FLAGS_NONE,
                                           -1,
                                           NULL,    /* cancellable */
                                           &error);
      g_assert_no_error (error);
      g_assert_nonnull (tuple);
      g_variant_get (tuple, "(u)", &result);
      g_assert_cmpuint (result, ==, DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);

      g_hash_table_replace (f->connections_by_name,
                            g_strdup (name),
                            conn);
    }

  conn->filter = g_dbus_connection_add_filter (conn->conn,
                                               conn_filter_cb,
                                               conn,
                                               NULL);
}

static void
do_round_trip (const Connection *caller,
               const Connection *destination)
{
  g_autoptr(GAsyncResult) result = NULL;
  g_autoptr(GError) error = NULL;
  g_autoptr(GVariant) tuple = NULL;

  g_dbus_connection_call (caller->conn,
                          destination->unique_name,
                          "/",
                          EXAMPLE_IFACE,
                          EXAMPLE_METHOD,
                          NULL,
                          G_VARIANT_TYPE ("()"),
                          G_DBUS_CALL_FLAGS_NONE,
                          -1,     /* timeout */
                          NULL,   /* cancellable */
                          ready_cb,
                          &result);

  while (result == NULL)
    g_main_context_iteration (NULL, TRUE);

  tuple = g_dbus_connection_call_finish (caller->conn, result, &error);

  /* For simplicity we didn't actually implement any method calls,
   * so the result should be an error. */
  g_assert_nonnull (error);
  g_assert_null (tuple);
  g_assert_cmpstr (g_quark_to_string (error->domain), ==, g_quark_to_string (G_DBUS_ERROR));

  switch (error->code)
    {
      case G_DBUS_ERROR_UNKNOWN_METHOD:
      case G_DBUS_ERROR_UNKNOWN_INTERFACE:
      case G_DBUS_ERROR_UNKNOWN_OBJECT:
        /* OK */
        break;

      default:
        g_assert_not_reached ();
    }
}

static void
setup (Fixture *f,
       gconstpointer context G_GNUC_UNUSED)
{
  g_autoptr(GSubprocessLauncher) launcher = NULL;
  g_autoptr(GError) error = NULL;
  GInputStream *address_pipe;
  gchar address_buffer[4096] = { 0 };
  g_autofree gchar *escaped = NULL;
  char *newline;

  f->sync_pipe = -1;

  launcher = g_subprocess_launcher_new (G_SUBPROCESS_FLAGS_STDOUT_PIPE);
  f->dbus_daemon = g_subprocess_launcher_spawn (launcher, &error,
                                                "dbus-daemon",
                                                "--session",
                                                "--print-address=1",
                                                "--nofork",
                                                NULL);
  g_assert_no_error (error);
  g_assert_nonnull (f->dbus_daemon);

  address_pipe = g_subprocess_get_stdout_pipe (f->dbus_daemon);

  /* Crash if it takes too long to get the address */
  alarm (30);

  while (strchr (address_buffer, '\n') == NULL)
    {
      if (strlen (address_buffer) >= sizeof (address_buffer) - 1)
        g_error ("Read %" G_GSIZE_FORMAT " bytes from dbus-daemon with "
                 "no newline",
                 sizeof (address_buffer) - 1);

      g_input_stream_read (address_pipe,
                           address_buffer + strlen (address_buffer),
                           sizeof (address_buffer) - strlen (address_buffer),
                           NULL, &error);
      g_assert_no_error (error);
    }

  /* Disable alarm */
  alarm (0);

  newline = strchr (address_buffer, '\n');
  g_assert_nonnull (newline);
  *newline = '\0';
  f->dbus_address = g_strdup (address_buffer);

  if (g_getenv ("TEST_DBUS_MONITOR") != NULL)
    {
      g_autoptr(GSubprocessLauncher) monitor_launcher = NULL;

      monitor_launcher = g_subprocess_launcher_new (G_SUBPROCESS_FLAGS_NONE);
      g_subprocess_launcher_take_stdout_fd (monitor_launcher, dup (STDERR_FILENO));
      f->monitor = g_subprocess_launcher_spawn (monitor_launcher, NULL,
                                                "dbus-monitor",
                                                "--address", f->dbus_address,
                                                NULL);
    }

  f->proxy_path = g_getenv ("DBUS_PROXY");

  if (f->proxy_path == NULL)
    f->proxy_path = BINDIR "/xdg-dbus-proxy";

  f->temp_directory = g_dir_make_tmp ("xdg-dbus-proxy-test.XXXXXX", &error);
  g_assert_no_error (error);
  f->proxy_socket = g_build_filename (f->temp_directory, "proxy", NULL);
  escaped = g_dbus_address_escape_value (f->proxy_socket);
  f->proxy_address = g_strdup_printf ("unix:path=%s", escaped);

  f->connections_by_name = g_hash_table_new_full (g_str_hash,
                                                  g_str_equal,
                                                  g_free,
                                                  NULL);

  fixture_connect (f, &f->caller_conn, CALLER_NAME);
  fixture_connect (f, &f->cannot_access_conn, CANNOT_ACCESS_NAME);
  fixture_connect (f, &f->can_see_conn, CAN_SEE_NAME);
  fixture_connect (f, &f->can_talk_conn, CAN_TALK_NAME);
  fixture_connect (f, &f->can_own_conn, CAN_OWN_NAME);
  fixture_connect (f, &f->can_call_anything_conn, CAN_CALL_ANYTHING_NAME);
  fixture_connect (f, &f->can_call_some_conn, CAN_CALL_SOME_NAME);
  fixture_connect (f, &f->can_receive_anything_conn, CAN_RECEIVE_ANYTHING_NAME);
  fixture_connect (f, &f->can_receive_some_conn, CAN_RECEIVE_SOME_NAME);
}

enum
{
  READ_END = 0,
  WRITE_END = 1,
  PIPE_FDS
};

static void
fixture_start_proxy (Fixture *f)
{
  g_autoptr(GSubprocessLauncher) launcher = NULL;
  g_autoptr(GError) error = NULL;
  g_autoptr(GVariant) tuple = NULL;
  int sync_pipe[PIPE_FDS];
  char buf;
  ssize_t bytes_read;

#if GLIB_CHECK_VERSION (2, 78, 0)
  g_unix_open_pipe (sync_pipe, O_CLOEXEC, &error);
#else
  g_unix_open_pipe (sync_pipe, FD_CLOEXEC, &error);
#endif
  g_assert_no_error (error);
  f->sync_pipe = sync_pipe[READ_END];

  launcher = g_subprocess_launcher_new (G_SUBPROCESS_FLAGS_NONE);
  g_subprocess_launcher_take_fd (launcher, dup (STDERR_FILENO), STDOUT_FILENO);
  g_subprocess_launcher_take_fd (launcher, sync_pipe[WRITE_END], 3);
  sync_pipe[WRITE_END] = -1;

  f->proxy = g_subprocess_launcher_spawn (launcher, &error,
                                          f->proxy_path,
                                          "--fd=3",
                                          f->dbus_address,
                                          f->proxy_socket,
                                          "--filter",
                                          "--log",
                                          "--see=" CAN_SEE_NAME,
                                          "--talk=" CAN_TALK_NAME,
                                          "--own=" CAN_OWN_NAME,
                                          "--call=" CAN_CALL_ANYTHING_NAME "=*",
                                          "--call=" CAN_CALL_SOME_NAME "=" CAN_CALL_SOME_IFACE "." CAN_CALL_SOME_METHOD "@" CAN_CALL_SOME_PATH,
                                          "--broadcast=" CAN_RECEIVE_ANYTHING_NAME "=*",
                                          "--broadcast=" CAN_RECEIVE_SOME_NAME "=" CAN_RECEIVE_SOME_IFACE "." CAN_RECEIVE_SOME_SIGNAL "@" CAN_RECEIVE_SOME_PATH,
                                          NULL);
  g_assert_no_error (error);
  g_assert_nonnull (f->proxy);

  /* Wait for the proxy to be ready */
  bytes_read = read (sync_pipe[READ_END], &buf, 1);
  g_assert_cmpint (bytes_read, ==, 1);

  f->proxied.label = "Sandboxed connection";
  f->proxied.conn = g_dbus_connection_new_for_address_sync (f->proxy_address,
                                                            (G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT
                                                             | G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION),
                                                            NULL,    /* observer */
                                                            NULL,    /* cancellable */
                                                            &error);
  g_assert_no_error (error);
  g_assert_nonnull (f->proxied.conn);
  f->proxied.unique_name = g_dbus_connection_get_unique_name (f->proxied.conn);
  tuple = g_dbus_connection_call_sync (f->proxied.conn,
                                       DBUS_SERVICE_DBUS,
                                       DBUS_PATH_DBUS,
                                       DBUS_INTERFACE_DBUS,
                                       "AddMatch",
                                       g_variant_new ("(s)", ""),
                                       G_VARIANT_TYPE ("()"),
                                       G_DBUS_CALL_FLAGS_NONE,
                                       -1,
                                       NULL,    /* cancellable */
                                       &error);
  g_assert_no_error (error);
  f->proxied.filter = g_dbus_connection_add_filter (f->proxied.conn,
                                                    conn_filter_cb,
                                                    &f->proxied,
                                                    NULL);
}

static void
test_basics (Fixture *f,
             gconstpointer context G_GNUC_UNUSED)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GVariant) tuple = NULL;
  g_auto(GStrv) strv = NULL;
  gsize i;
  gboolean found;

  alarm (30);

  fixture_start_proxy (f);

  tuple = g_dbus_connection_call_sync (f->proxied.conn, DBUS_SERVICE_DBUS,
                                       DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS,
                                       "ListNames", NULL,
                                       G_VARIANT_TYPE ("(as)"),
                                       G_DBUS_CALL_FLAGS_NONE, -1, NULL,
                                       &error);
  g_assert_no_error (error);
  g_assert_nonnull (tuple);
  g_variant_get (tuple, "(^as)", &strv);
  found = FALSE;

  /* As a simple test of the proxying, assert that the array contains the
   * proxied connection itself */
  for (i = 0; strv[i] != NULL; i++)
    {
      g_test_message ("ListNames(): %s", strv[i]);

      if (g_strcmp0 (strv[i], f->proxied.unique_name) == 0)
        found = TRUE;
    }

  g_assert_true (found);
}

typedef struct
{
  const char *name;
  const char *path;
  const char *iface;
  const char *method;
  gboolean can_call;
  gboolean can_see;
} CallTest;

static const CallTest call_tests[] =
{
  { CANNOT_ACCESS_NAME, EXAMPLE_PATH, EXAMPLE_IFACE, EXAMPLE_METHOD,
    .can_call = FALSE, .can_see = FALSE },
  { CAN_SEE_NAME, EXAMPLE_PATH, EXAMPLE_IFACE, EXAMPLE_METHOD,
    .can_call = FALSE, .can_see = TRUE },
  { CAN_TALK_NAME, EXAMPLE_PATH, EXAMPLE_IFACE, EXAMPLE_METHOD,
    .can_call = TRUE, .can_see = TRUE },
  { CAN_OWN_NAME, EXAMPLE_PATH, EXAMPLE_IFACE, EXAMPLE_METHOD,
    .can_call = TRUE, .can_see = TRUE },
  { CAN_RECEIVE_ANYTHING_NAME, EXAMPLE_PATH, EXAMPLE_IFACE, EXAMPLE_METHOD,
    .can_call = FALSE, .can_see = TRUE },
  { CAN_RECEIVE_SOME_NAME, EXAMPLE_PATH, EXAMPLE_IFACE, EXAMPLE_METHOD,
    .can_call = FALSE, .can_see = TRUE },

  { CAN_CALL_ANYTHING_NAME, EXAMPLE_PATH, EXAMPLE_IFACE, EXAMPLE_METHOD,
    .can_call = TRUE, .can_see = TRUE },

  { CAN_CALL_SOME_NAME, EXAMPLE_PATH, EXAMPLE_IFACE, EXAMPLE_METHOD,
    .can_call = FALSE, .can_see = TRUE },
  { CAN_CALL_SOME_NAME, CAN_CALL_SOME_PATH, CAN_CALL_SOME_IFACE, CAN_CALL_SOME_METHOD,
    .can_call = TRUE, .can_see = TRUE },
  { CAN_CALL_SOME_NAME, EXAMPLE_PATH, CAN_CALL_SOME_IFACE, CAN_CALL_SOME_METHOD,
    .can_call = FALSE, .can_see = TRUE },
  { CAN_CALL_SOME_NAME, CAN_CALL_SOME_PATH, EXAMPLE_IFACE, CAN_CALL_SOME_METHOD,
    .can_call = FALSE, .can_see = TRUE },
  { CAN_CALL_SOME_NAME, CAN_CALL_SOME_PATH, CAN_CALL_SOME_IFACE, EXAMPLE_METHOD,
    .can_call = FALSE, .can_see = TRUE },
};

static void
test_call (Fixture *f,
           gconstpointer context G_GNUC_UNUSED)
{
  alarm (30);
  fixture_start_proxy (f);

  for (size_t i = 0; i < G_N_ELEMENTS (call_tests); i++)
    {
      const CallTest *t = &call_tests[i];
      g_autoptr(GAsyncResult) result = NULL;
      g_autoptr(GError) error = NULL;
      g_autoptr(GVariant) tuple = NULL;
      const Connection *dest;
      int n_calls_before;

      g_test_message ("#%zu: sandboxed connection %s be allowed to call %s:%s.%s on %s",
                      i,
                      t->can_call ? "should" : "should not",
                      t->path,
                      t->iface,
                      t->method,
                      t->name);

      dest = g_hash_table_lookup (f->connections_by_name, t->name);
      g_assert_nonnull (dest);
      n_calls_before = g_atomic_int_get (&dest->n_method_calls);

      g_dbus_connection_call (f->proxied.conn,
                              t->name,
                              t->path,
                              t->iface,
                              t->method,
                              NULL,
                              G_VARIANT_TYPE ("()"),
                              G_DBUS_CALL_FLAGS_NONE,
                              -1,
                              NULL,    /* cancellable */
                              ready_cb,
                              &result);

      while (result == NULL)
        g_main_context_iteration (NULL, TRUE);

      tuple = g_dbus_connection_call_finish (f->proxied.conn, result, &error);
      g_assert_nonnull (error);
      g_assert_null (tuple);
      g_test_message ("-> %s", error->message);

      if (t->can_call)
        {
          /* If the method call was allowed, we just return an error,
           * because for simplicity we didn't actually implement any
           * method calls. */
          g_assert_cmpstr (g_quark_to_string (error->domain),
                           ==, g_quark_to_string (G_DBUS_ERROR));

          switch (error->code)
            {
              case G_DBUS_ERROR_UNKNOWN_METHOD:
              case G_DBUS_ERROR_UNKNOWN_INTERFACE:
              case G_DBUS_ERROR_UNKNOWN_OBJECT:
                /* OK */
                break;

              default:
                g_assert_not_reached ();
            }

          g_assert_cmpint (g_atomic_int_get (&dest->n_method_calls), ==, n_calls_before + 1);
        }
      else if (t->can_see)
        {
          g_assert_error (error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED);
          g_assert_cmpint (g_atomic_int_get (&dest->n_method_calls), ==, n_calls_before);
        }
      else
        {
          g_assert_error (error, G_DBUS_ERROR, G_DBUS_ERROR_SERVICE_UNKNOWN);
          g_assert_cmpint (g_atomic_int_get (&dest->n_method_calls), ==, n_calls_before);
        }
    }
}

typedef struct
{
  const char *name;
  gboolean can_own;
  gboolean can_see;
} OwnTest;

static const OwnTest own_tests[] =
{
  { CANNOT_ACCESS_NAME, .can_own = FALSE, .can_see = FALSE },
  { CAN_SEE_NAME, .can_own = FALSE, .can_see = TRUE },
  { CAN_TALK_NAME, .can_own = FALSE, .can_see = TRUE },
  { CAN_OWN_NAME, .can_own = TRUE, .can_see = TRUE },
  { CAN_CALL_ANYTHING_NAME, .can_own = FALSE, .can_see = TRUE },
  { CAN_CALL_SOME_NAME, .can_own = FALSE, .can_see = TRUE },
  { CAN_RECEIVE_ANYTHING_NAME, .can_own = FALSE, .can_see = TRUE },
  { CAN_RECEIVE_SOME_NAME, .can_own = FALSE, .can_see = TRUE },
};

static void
test_own (Fixture *f,
          gconstpointer context G_GNUC_UNUSED)
{
  alarm (30);
  fixture_start_proxy (f);

  for (size_t i = 0; i < G_N_ELEMENTS (own_tests); i++)
    {
      const OwnTest *t = &own_tests[i];
      g_autoptr(GError) error = NULL;
      g_autoptr(GVariant) tuple = NULL;
      const char *owner = NULL;

      g_test_message ("#%zu: sandboxed connection %s be allowed to own %s",
                      i, t->can_own ? "should" : "should not", t->name);

      tuple = g_dbus_connection_call_sync (f->proxied.conn,
                                           DBUS_SERVICE_DBUS,
                                           DBUS_PATH_DBUS,
                                           DBUS_INTERFACE_DBUS,
                                           "RequestName",
                                           g_variant_new ("(su)",
                                                           t->name,
                                                           (G_BUS_NAME_OWNER_FLAGS_ALLOW_REPLACEMENT
                                                           | G_BUS_NAME_OWNER_FLAGS_REPLACE
                                                           | G_BUS_NAME_OWNER_FLAGS_DO_NOT_QUEUE)),
                                           G_VARIANT_TYPE ("(u)"),
                                           G_DBUS_CALL_FLAGS_NONE,
                                           -1,
                                           NULL,    /* cancellable */
                                           &error);

      if (tuple != NULL)
        g_test_message ("-> Was allowed");
      else
        g_test_message ("-> Was not allowed: %s", error->message);

      if (t->can_own)
        {
          guint32 result = 0;

          g_assert_no_error (error);
          g_assert_nonnull (tuple);
          g_variant_get (tuple, "(u)", &result);
          g_assert_cmpuint (result, ==, DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
        }
      else if (t->can_see)
        {
          g_assert_error (error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED);
        }
      else
        {
          g_assert_error (error, G_DBUS_ERROR, G_DBUS_ERROR_SERVICE_UNKNOWN);
        }

      g_clear_error (&error);
      g_clear_pointer (&tuple, g_variant_unref);

      /* Use a different connection to check who actually owns the name */
      tuple = g_dbus_connection_call_sync (f->cannot_access_conn.conn,
                                           DBUS_SERVICE_DBUS,
                                           DBUS_PATH_DBUS,
                                           DBUS_INTERFACE_DBUS,
                                           "GetNameOwner",
                                           g_variant_new ("(s)", t->name),
                                           G_VARIANT_TYPE ("(s)"),
                                           G_DBUS_CALL_FLAGS_NONE,
                                           -1,
                                           NULL,    /* cancellable */
                                           NULL);

      if (tuple != NULL)
        g_variant_get (tuple, "(&s)", &owner);
      else
        owner = "";

      if (t->can_own)
        g_assert_cmpstr (owner, ==, f->proxied.unique_name);
      else
        g_assert_cmpstr (owner, !=, f->proxied.unique_name);
    }
}

typedef struct
{
  const char *name;
  const char *path;
  const char *iface;
  const char *member;
  gboolean can_receive_broadcast;
} ReceiveTest;

static const ReceiveTest receive_tests[] =
{
  { CANNOT_ACCESS_NAME, EXAMPLE_PATH, EXAMPLE_IFACE, EXAMPLE_SIGNAL, FALSE },
  { CAN_SEE_NAME, EXAMPLE_PATH, EXAMPLE_IFACE, EXAMPLE_SIGNAL, FALSE },
  { CAN_TALK_NAME, EXAMPLE_PATH, EXAMPLE_IFACE, EXAMPLE_SIGNAL, TRUE },
  { CAN_OWN_NAME, EXAMPLE_PATH, EXAMPLE_IFACE, EXAMPLE_SIGNAL, TRUE },

  /* Before GHSA-r7hp-698j-2h6c was fixed, both of these would receive the
   * broadcast, but that was unintended */
  { CAN_CALL_ANYTHING_NAME, EXAMPLE_PATH, EXAMPLE_IFACE, EXAMPLE_SIGNAL, FALSE },
  { CAN_CALL_SOME_NAME, EXAMPLE_PATH, EXAMPLE_IFACE, EXAMPLE_SIGNAL, FALSE },

  { CAN_RECEIVE_ANYTHING_NAME, EXAMPLE_PATH, EXAMPLE_IFACE, EXAMPLE_SIGNAL, TRUE },

  { CAN_RECEIVE_SOME_NAME, CAN_RECEIVE_SOME_PATH, CAN_RECEIVE_SOME_IFACE, CAN_RECEIVE_SOME_SIGNAL, TRUE },

  /* Before GHSA-r7hp-698j-2h6c was fixed, all of these would receive the broadcast,
   * but that was unintended */
  { CAN_RECEIVE_SOME_NAME, EXAMPLE_PATH, CAN_RECEIVE_SOME_IFACE, CAN_RECEIVE_SOME_SIGNAL, FALSE },
  { CAN_RECEIVE_SOME_NAME, CAN_RECEIVE_SOME_PATH, EXAMPLE_IFACE, CAN_RECEIVE_SOME_SIGNAL, FALSE },
  { CAN_RECEIVE_SOME_NAME, CAN_RECEIVE_SOME_PATH, CAN_RECEIVE_SOME_IFACE, EXAMPLE_SIGNAL, FALSE },
  { CAN_RECEIVE_SOME_NAME, EXAMPLE_PATH, EXAMPLE_IFACE, EXAMPLE_SIGNAL, FALSE },
};

static void
test_receive (Fixture *f,
              gconstpointer context G_GNUC_UNUSED)
{
  alarm (30);
  fixture_start_proxy (f);

  for (size_t i = 0; i < G_N_ELEMENTS (receive_tests); i++)
    {
      g_autoptr(GAsyncResult) result = NULL;
      g_autoptr(GVariant) tuple = NULL;
      g_autoptr(GError) error = NULL;
      const Connection *sender;
      const ReceiveTest *t = &receive_tests[i];
      int n_unicasts_before;
      int n_broadcasts_before;
      int n_calls_before;

      g_test_message ("#%zu: sandboxed connection %s be allowed to receive broadcast from %s:%s.%s on %s",
                      i,
                      t->can_receive_broadcast ? "should" : "should not",
                      t->path,
                      t->iface,
                      t->member,
                      t->name);

      sender = g_hash_table_lookup (f->connections_by_name, t->name);
      g_assert_nonnull (sender);

      n_calls_before = g_atomic_int_get (&f->proxied.n_method_calls);
      n_unicasts_before = g_atomic_int_get (&f->proxied.n_unicast_signals);
      n_broadcasts_before = g_atomic_int_get (&f->proxied.n_broadcasts);

      /* The sandboxed recipient is only sometimes allowed to receive
       * broadcasts. We do this first, because D-Bus preserves message
       * order, therefore by the time we have received the unicast signal
       * and/or the method call, it's guaranteed that this broadcast
       * has been processed (and received, or not, as appropriate). */
      g_dbus_connection_emit_signal (sender->conn,
                                     NULL,
                                     t->path,
                                     t->iface,
                                     t->member,
                                     NULL,
                                     &error);
      g_assert_no_error (error);

      /* The sandboxed recipient is always allowed to receive
       * unicast signals. */
      g_dbus_connection_emit_signal (sender->conn,
                                     f->proxied.unique_name,
                                     t->path,
                                     t->iface,
                                     t->member,
                                     NULL,
                                     &error);
      g_assert_no_error (error);

      /* The sandboxed recipient is always allowed to receive
       * method calls. */
      g_dbus_connection_call (sender->conn,
                              f->proxied.unique_name,
                              "/",
                              DBUS_INTERFACE_PEER,
                              "Ping",
                              NULL,
                              G_VARIANT_TYPE ("()"),
                              G_DBUS_CALL_FLAGS_NONE,
                              -1,
                              NULL,    /* cancellable */
                              ready_cb,
                              &result);

      while (result == NULL)
        g_main_context_iteration (NULL, TRUE);

      tuple = g_dbus_connection_call_finish (sender->conn, result, &error);
      g_assert_no_error (error);
      g_assert_nonnull (tuple);

      g_assert_cmpint (g_atomic_int_get (&f->proxied.n_method_calls), ==, n_calls_before + 1);
      g_assert_cmpint (g_atomic_int_get (&f->proxied.n_unicast_signals), ==, n_unicasts_before + 1);

      if (t->can_receive_broadcast)
        g_assert_cmpint (g_atomic_int_get (&f->proxied.n_broadcasts), ==, n_broadcasts_before + 1);
      else
        g_assert_cmpint (g_atomic_int_get (&f->proxied.n_broadcasts), ==, n_broadcasts_before);
    }
}

typedef struct
{
  const char *label;
  GDBusMessageType type;
  unsigned broadcast : 1;
  unsigned misdirected : 1;
} ReplyTest;

static const ReplyTest reply_tests[] =
{
    { "should not be able to send a unicast signal in reply",
      G_DBUS_MESSAGE_TYPE_SIGNAL },
    { "should not be able to send a broadcast signal in reply",
      G_DBUS_MESSAGE_TYPE_SIGNAL, .broadcast = TRUE },
    { "should not be able to send a unicast signal to someone else in reply",
      G_DBUS_MESSAGE_TYPE_SIGNAL, .misdirected = TRUE },
    { "should not be able to send a method call in reply",
      G_DBUS_MESSAGE_TYPE_METHOD_CALL },
    { "should not be able to send a method call to someone else in reply",
      G_DBUS_MESSAGE_TYPE_METHOD_CALL, .misdirected = TRUE },
    { "should be able to send a method return in reply",
      G_DBUS_MESSAGE_TYPE_METHOD_RETURN },
    { "should not be able to send a method return to someone else in reply",
      G_DBUS_MESSAGE_TYPE_METHOD_RETURN, .misdirected = TRUE },
    { "should be able to send an error in reply",
      G_DBUS_MESSAGE_TYPE_ERROR },
    { "should not be able to send an error to someone else in reply",
      G_DBUS_MESSAGE_TYPE_ERROR, .misdirected = TRUE },
};

static void
test_reply (Fixture *f,
            gconstpointer context G_GNUC_UNUSED)
{
  alarm (30);
  fixture_start_proxy (f);

  /* If a process outside the sandbox calls a method on the
   * sandboxed process, then the sandboxed process is allowed to reply,
   * but is not allowed to fake a "reply" that is really a method call
   * or signal. (GHSA-2cgv-pwcq-wvpq) */
  for (size_t i = 0; i < G_N_ELEMENTS (reply_tests); i++)
    {
      const ReplyTest *t = &reply_tests[i];
      g_autoptr(GDBusMessage) call = NULL;
      g_autoptr(GDBusMessage) reply = NULL;
      g_autoptr(GError) error = NULL;
      guint32 call_serial = 0;
      int caller_calls_before;
      int caller_broadcast_before;
      int caller_unicast_before;
      int other_calls_before;
      int other_broadcast_before;
      int other_unicast_before;

      g_test_message ("#%zu: %s", i, t->label);

      caller_calls_before = g_atomic_int_get (&f->caller_conn.n_method_calls);
      caller_unicast_before = g_atomic_int_get (&f->caller_conn.n_unicast_signals);
      caller_broadcast_before = g_atomic_int_get (&f->caller_conn.n_broadcasts);

      other_calls_before = g_atomic_int_get (&f->cannot_access_conn.n_method_calls);
      other_unicast_before = g_atomic_int_get (&f->cannot_access_conn.n_unicast_signals);
      other_broadcast_before = g_atomic_int_get (&f->cannot_access_conn.n_broadcasts);

      call = g_dbus_message_new_method_call (f->proxied.unique_name,
                                             "/",
                                             IGNORE_IFACE,
                                             IGNORE_METHOD);
      g_dbus_connection_send_message (f->caller_conn.conn,
                                      call,
                                      G_DBUS_SEND_MESSAGE_FLAGS_NONE,
                                      &call_serial,
                                      &error);
      g_assert_no_error (error);
      g_assert_cmpuint (call_serial, !=, 0);
      g_test_message ("Method call was serial number %u", call_serial);

      /* Do a round-trip from the caller to the sandboxed connection and back.
       * D-Bus messages are delivered sequentially, so by the time this call
       * has finished, the method call will also have passed through the
       * xdg-dbus-proxy and the dbus-daemon. */
      do_round_trip (&f->caller_conn, &f->proxied);

      switch (t->type)
        {
          case G_DBUS_MESSAGE_TYPE_SIGNAL:
            reply = g_dbus_message_new_signal ("/",
                                               MALICIOUS_IFACE,
                                               MALICIOUS_MEMBER);

            if (t->broadcast)
              {
                g_test_message ("Sending malicious broadcast signal as a reply");
              }
            else if (t->misdirected)
              {
                g_test_message ("Sending malicious unicast signal reply to wrong destination");
                g_dbus_message_set_destination (reply, f->cannot_access_conn.unique_name);
              }
            else
              {
                g_test_message ("Sending malicious unicast signal as a reply");
                g_dbus_message_set_destination (reply, f->caller_conn.unique_name);
              }

            break;

          case G_DBUS_MESSAGE_TYPE_METHOD_CALL:
            if (t->misdirected)
              {
                g_test_message ("Sending malicious method call to wrong destination");
                reply = g_dbus_message_new_method_call (f->cannot_access_conn.unique_name,
                                                        "/",
                                                        MALICIOUS_IFACE,
                                                        MALICIOUS_MEMBER);
              }
            else
              {
                g_test_message ("Sending malicious method call as a reply");
                reply = g_dbus_message_new_method_call (f->caller_conn.unique_name,
                                                        "/",
                                                        MALICIOUS_IFACE,
                                                        MALICIOUS_MEMBER);
              }
            break;

          case G_DBUS_MESSAGE_TYPE_METHOD_RETURN:
            reply = g_dbus_message_new_method_reply (call);

            if (t->misdirected)
              {
                g_test_message ("Sending malicious reply to wrong destination");
                g_dbus_message_set_destination (reply, f->cannot_access_conn.unique_name);
                g_dbus_message_set_body (reply, g_variant_new ("(s)", MALICIOUS_BODY));
              }
            else
              {
                g_test_message ("Sending legitimate reply as a reply");
              }

            break;

          case G_DBUS_MESSAGE_TYPE_ERROR:
            reply = g_dbus_message_new_method_error (call,
                                                     "com.example.No",
                                                     "That didn't work");

            if (t->misdirected)
              {
                g_test_message ("Sending malicious error to wrong destination");
                g_dbus_message_set_destination (reply, f->cannot_access_conn.unique_name);
                g_dbus_message_set_body (reply, g_variant_new ("(s)", MALICIOUS_BODY));
              }
            else
              {
                g_test_message ("Sending legitimate error as a reply");
              }

            break;

          case G_DBUS_MESSAGE_TYPE_INVALID:
          default:
            g_assert_not_reached ();
        }

      g_dbus_message_set_reply_serial (reply, call_serial);
      g_dbus_connection_send_message (f->proxied.conn, reply,
                                      G_DBUS_SEND_MESSAGE_FLAGS_NONE,
                                      NULL,   /* serial */
                                      &error);
      g_assert_no_error (error);

      /* Do another round-trip, to make sure everything has been delivered */
      do_round_trip (&f->caller_conn, &f->proxied);

      /* The caller didn't receive any extraneous messages */
      g_assert_cmpint (g_atomic_int_get (&f->caller_conn.n_method_calls), ==,
                       caller_calls_before);
      g_assert_cmpint (g_atomic_int_get (&f->caller_conn.n_unicast_signals), ==,
                       caller_unicast_before);
      g_assert_cmpint (g_atomic_int_get (&f->caller_conn.n_broadcasts), ==,
                       caller_broadcast_before);

      /* The other connection didn't receive any messages at all */
      g_assert_cmpint (g_atomic_int_get (&f->cannot_access_conn.n_method_calls), ==,
                       other_calls_before);
      g_assert_cmpint (g_atomic_int_get (&f->cannot_access_conn.n_unicast_signals), ==,
                       other_unicast_before);
      g_assert_cmpint (g_atomic_int_get (&f->cannot_access_conn.n_broadcasts), ==,
                       other_broadcast_before);
    }
}

static void
teardown (Fixture *f,
          gconstpointer context G_GNUC_UNUSED)
{
  g_autoptr(GError) error = NULL;

  if (f->monitor != NULL)
    {
      g_subprocess_send_signal (f->monitor, SIGTERM);
      g_subprocess_wait (f->monitor, NULL, &error);
      g_assert_no_error (error);
    }

  if (f->dbus_daemon != NULL)
    {
      g_subprocess_send_signal (f->dbus_daemon, SIGTERM);
      g_subprocess_wait (f->dbus_daemon, NULL, &error);
      g_assert_no_error (error);
    }

  if (f->sync_pipe >= 0)
    {
      g_close (f->sync_pipe, &error);
      g_assert_no_error (error);
      f->sync_pipe = -1;
    }

  if (f->proxy != NULL)
    {
      /* It terminates in response to us closing the sync_pipe */
      g_subprocess_wait_check (f->proxy, NULL, &error);
      g_assert_no_error (error);
    }

  connection_clear (&f->proxied);

  if (f->proxy_socket != NULL)
    {
      if (g_remove (f->proxy_socket) != 0 && errno != ENOENT)
        g_warning ("remove %s: %s", f->proxy_socket, g_strerror (errno));

      g_free (f->proxy_socket);
    }

  if (f->temp_directory != NULL)
    {
      if (g_rmdir (f->temp_directory) != 0)
        g_warning ("rmdir %s: %s", f->temp_directory, g_strerror (errno));

      g_free (f->temp_directory);
    }

  g_clear_pointer (&f->connections_by_name, g_hash_table_unref);
  g_clear_object (&f->monitor);
  g_clear_object (&f->dbus_daemon);
  g_clear_object (&f->proxy);
  g_free (f->dbus_address);
  g_free (f->proxy_address);
  alarm (0);
}

int
main (int argc,
      char **argv)
{
  g_test_init (&argc, &argv, NULL);

  g_test_add ("/basics", Fixture, NULL, setup, test_basics, teardown);
  g_test_add ("/call", Fixture, NULL, setup, test_call, teardown);
  g_test_add ("/own", Fixture, NULL, setup, test_own, teardown);
  g_test_add ("/receive", Fixture, NULL, setup, test_receive, teardown);
  g_test_add ("/reply", Fixture, NULL, setup, test_reply, teardown);

  return g_test_run ();
}
