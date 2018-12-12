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

#include <glib.h>
#include <glib-unix.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#define DBUS_SERVICE_DBUS "org.freedesktop.DBus"
#define DBUS_PATH_DBUS "/org/freedesktop/DBus"
#define DBUS_INTERFACE_DBUS "org.freedesktop.DBus"

typedef struct
{
  GDBusConnection *proxied_conn;
  GSubprocess *dbus_daemon;
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
                                                "--nosyslog",
                                                NULL);
  g_assert_no_error (error);
  g_assert_nonnull (f->dbus_daemon);

  address_pipe = g_subprocess_get_stdout_pipe (f->dbus_daemon);

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

  newline = strchr (address_buffer, '\n');
  g_assert_nonnull (newline);
  *newline = '\0';
  f->dbus_address = g_strdup (address_buffer);

  f->proxy_path = g_getenv ("DBUS_PROXY");

  if (f->proxy_path == NULL)
    f->proxy_path = BINDIR "/xdg-dbus-proxy";

  f->temp_directory = g_dir_make_tmp ("xdg-dbus-proxy-test.XXXXXX", &error);
  g_assert_no_error (error);
  f->proxy_socket = g_build_filename (f->temp_directory, "proxy", NULL);
  escaped = g_dbus_address_escape_value (f->proxy_socket);
  f->proxy_address = g_strdup_printf ("unix:path=%s", escaped);
}

enum
{
  READ_END = 0,
  WRITE_END = 1,
  PIPE_FDS
};

static void
test_basics (Fixture *f,
             gconstpointer context G_GNUC_UNUSED)
{
  g_autoptr(GSubprocessLauncher) launcher = NULL;
  g_autoptr(GError) error = NULL;
  g_autoptr(GVariant) tuple = NULL;
  g_auto(GStrv) strv = NULL;
  const char *proxied_name;
  int sync_pipe[PIPE_FDS];
  char buf;
  ssize_t bytes_read;
  gsize i;
  gboolean found;

  g_unix_open_pipe (sync_pipe, FD_CLOEXEC, &error);
  g_assert_no_error (error);
  f->sync_pipe = sync_pipe[READ_END];

  launcher = g_subprocess_launcher_new (G_SUBPROCESS_FLAGS_STDOUT_PIPE);
  g_subprocess_launcher_take_fd (launcher, sync_pipe[WRITE_END], 3);
  sync_pipe[WRITE_END] = -1;

  f->proxy = g_subprocess_launcher_spawn (launcher, &error,
                                          f->proxy_path,
                                          "--fd=3",
                                          f->dbus_address,
                                          f->proxy_socket,
                                          NULL);
  g_assert_no_error (error);
  g_assert_nonnull (f->proxy);

  /* Wait for the proxy to be ready */
  bytes_read = read (sync_pipe[READ_END], &buf, 1);
  g_assert_cmpint (bytes_read, ==, 1);

  f->proxied_conn = g_dbus_connection_new_for_address_sync (f->proxy_address,
                                                            G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT
                                                            | G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
                                                            NULL, NULL, &error);
  g_assert_no_error (error);
  g_assert_nonnull (f->proxied_conn);
  proxied_name = g_dbus_connection_get_unique_name (f->proxied_conn);

  tuple = g_dbus_connection_call_sync (f->proxied_conn, DBUS_SERVICE_DBUS,
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

      if (g_strcmp0 (strv[i], proxied_name) == 0)
        found = TRUE;
    }

  g_assert_true (found);
}

static void
teardown (Fixture *f,
          gconstpointer context G_GNUC_UNUSED)
{
  g_autoptr(GError) error = NULL;

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

  if (f->proxied_conn != NULL)
    {
      g_dbus_connection_close_sync (f->proxied_conn, NULL, &error);

      if (error != NULL)
        {
          g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CLOSED);
          g_clear_error (&error);
        }
    }

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

  g_clear_object (&f->proxied_conn);
  g_clear_object (&f->dbus_daemon);
  g_clear_object (&f->proxy);
  g_free (f->dbus_address);
  g_free (f->proxy_address);
}

int
main (int argc,
      char **argv)
{
  g_test_init (&argc, &argv, NULL);

  g_test_add ("/basics", Fixture, NULL, setup, test_basics, teardown);

  return g_test_run ();
}
