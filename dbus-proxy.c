/*
 * Copyright © 2015 Red Hat, Inc
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
 *
 * Authors:
 *       Alexander Larsson <alexl@redhat.com>
 */

#include "config.h"

#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <locale.h>

#include "flatpak-proxy.h"

static const char *argv0;
static GList *proxies;
static int sync_fd = -1;

static void
usage (int ecode, FILE *out)
{
  fprintf (out, "usage: %s [OPTIONS...] [ADDRESS PATH [OPTIONS...] ...]\n\n", argv0);

  fprintf (out,
           "Options:\n"
           "    --help                       Print this help\n"
           "    --version                    Print version\n"
           "    --fd=FD                      Stop when FD is closed\n"
           "    --args=FD                    Read arguments from FD\n\n"
           "Proxy Options:\n"
           "    --filter                     Enable filtering\n"
           "    --log                        Turn on logging\n"
           "    --sloppy-names               Report name changes for unique names\n"
           "    --see=NAME                   Set 'see' policy for NAME\n"
           "    --talk=NAME                  Set 'talk' policy for NAME\n"
           "    --own=NAME                   Set 'own' policy for NAME\n"
           "    --call=NAME=RULE             Set RULE for calls on NAME\n"
           "    --broadcast=NAME=RULE        Set RULE for broadcasts from NAME\n"
          );
  exit (ecode);
}

static GBytes *
fd_readall_bytes (int               fd,
                  GError          **error)
{
  const guint maxreadlen = 4096;
  struct stat stbuf;
  gsize buf_allocated;
  g_autofree guint8* buf = NULL;
  gsize buf_size = 0;

  if (TEMP_FAILURE_RETRY (fstat (fd, &stbuf)) != 0)
    {
      int errsv = errno;
      g_set_error_literal (error,
                           G_IO_ERROR,
                           g_io_error_from_errno (errsv),
                           g_strerror (errsv));
      return NULL;
    }

  if (S_ISREG (stbuf.st_mode) && stbuf.st_size > 0)
    buf_allocated = stbuf.st_size;
  else
    buf_allocated = 16;

  buf = g_malloc (buf_allocated);

  while (TRUE)
    {
      gsize readlen = MIN (buf_allocated - buf_size, maxreadlen);
      gssize bytes_read;

      do
        bytes_read = read (fd, buf + buf_size, readlen);
      while (G_UNLIKELY (bytes_read == -1 && errno == EINTR));

      if (G_UNLIKELY (bytes_read == -1))
        {
          int errsv = errno;
          g_set_error_literal (error,
                               G_IO_ERROR,
                               g_io_error_from_errno (errsv),
                               g_strerror (errsv));
          return NULL;
        }
      if (bytes_read == 0)
        break;

      buf_size += bytes_read;
      if (buf_allocated - buf_size < maxreadlen)
        buf = g_realloc (buf, buf_allocated *= 2);
    }

  return g_bytes_new_take (g_steal_pointer (&buf), buf_size);
}

static void
add_args (GBytes    *bytes,
          GPtrArray *args,
          int        pos)
{
  gsize data_len, remainder_len;
  const guchar *data = g_bytes_get_data (bytes, &data_len);
  guchar *s;
  const guchar *remainder;

  remainder = data;
  remainder_len = data_len;
  s = memchr (remainder, 0, remainder_len);
  while (s)
    {
      gsize len = s - remainder;
      char *arg = g_strndup ((char *) remainder, len);
      g_ptr_array_insert (args, pos++, arg);
      remainder = s + 1;
      remainder_len -= len + 1;
      s = memchr (remainder, 0, remainder_len);
    }

  if (remainder_len)
    {
      char *arg = g_strndup ((char *) remainder, remainder_len);
      g_ptr_array_insert (args, pos++, arg);
    }
}


static gboolean
parse_generic_args (GPtrArray *args, int *args_i)
{
  const char *arg = g_ptr_array_index (args, *args_i);

  if (strcmp (arg, "--help") == 0)
    {
      usage (EXIT_SUCCESS, stdout);
    }
  else if (strcmp (arg, "--version") == 0)
    {
      g_print ("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
      exit (EXIT_SUCCESS);
    }
  else if (g_str_has_prefix (arg, "--fd="))
    {
      const char *fd_s = arg + strlen ("--fd=");
      char *endptr;
      int fd;

      fd = strtol (fd_s, &endptr, 10);
      if (fd < 0 || endptr == fd_s || *endptr != 0)
        {
          g_printerr ("Invalid fd %s\n", fd_s);
          return FALSE;
        }
      sync_fd = fd;

      *args_i += 1;

      return TRUE;
    }
  else if (g_str_has_prefix (arg, "--args="))
    {
      const char *fd_s = arg + strlen ("--args=");
      char *endptr;
      int fd;
      g_autoptr(GBytes) data = NULL;
      g_autoptr(GError) error = NULL;

      fd = strtol (fd_s, &endptr, 10);
      if (fd < 0 || endptr == fd_s || *endptr != 0)
        {
          g_printerr ("Invalid --args fd %s\n", fd_s);
          return FALSE;
        }

      data = fd_readall_bytes (fd, &error);

      if (data == NULL)
        {
          g_printerr ("Failed to load --args: %s\n", error->message);
          return FALSE;
        }

      *args_i += 1;

      add_args (data, args, *args_i);

      return TRUE;
    }
  else
    {
      g_printerr ("Unknown argument %s\n", arg);
      return FALSE;
    }
}

static gboolean
start_proxy (GPtrArray *args, int *args_i)
{
  g_autoptr(FlatpakProxy) proxy = NULL;
  g_autoptr(GError) error = NULL;
  const char *bus_address, *socket_path;
  const char *arg;

  if (*args_i >= args->len || ((char *) g_ptr_array_index (args, *args_i))[0] == '-')
    {
      g_printerr ("No bus address given\n");
      return FALSE;
    }

  bus_address = g_ptr_array_index (args, *args_i);
  *args_i += 1;

  if (*args_i >= args->len || ((char *) g_ptr_array_index (args, *args_i))[0] == '-')
    {
      g_printerr ("No socket path given\n");
      return FALSE;
    }

  socket_path = g_ptr_array_index (args, *args_i);
  *args_i += 1;

  proxy = flatpak_proxy_new (bus_address, socket_path);

  while (*args_i < args->len)
    {
      arg = g_ptr_array_index (args, *args_i);

      if (arg[0] != '-')
        break;

      if (g_str_has_prefix (arg, "--see=") ||
          g_str_has_prefix (arg, "--talk=") ||
          g_str_has_prefix (arg, "--own="))
        {
          FlatpakPolicy policy = FLATPAK_POLICY_SEE;
          g_autofree char *name = g_strdup (strchr (arg, '=') + 1);
          gboolean wildcard = FALSE;

          if (arg[2] == 't')
            policy = FLATPAK_POLICY_TALK;
          else if (arg[2] == 'o')
            policy = FLATPAK_POLICY_OWN;

          if (g_str_has_suffix (name, ".*"))
            {
              name[strlen (name) - 2] = 0;
              wildcard = TRUE;
            }

          if (name[0] == ':' || !g_dbus_is_name (name))
            {
              g_printerr ("'%s' is not a valid dbus name\n", name);
              return FALSE;
            }

          flatpak_proxy_add_policy (proxy, name, wildcard, policy);

          *args_i += 1;
        }
      else if (g_str_has_prefix (arg, "--call=") ||
               g_str_has_prefix (arg, "--broadcast="))
        {
          g_autofree char *rest = g_strdup (strchr (arg, '=') + 1);
          char *name = rest;
          char *rule;
          char *name_end = strchr (rest, '=');
          gboolean wildcard = FALSE;

          if (name_end == NULL)
            {
              g_printerr ("'%s' is not a valid name + rule\n", rest);
              return FALSE;
            }

          *name_end = 0;
          rule = name_end + 1;

          if (g_str_has_suffix (name, ".*"))
            {
              name[strlen (name) - 2] = 0;
              wildcard = TRUE;
            }

          if (g_str_has_prefix (arg, "--call="))
            flatpak_proxy_add_call_rule (proxy, name, wildcard, rule);
          else
            flatpak_proxy_add_broadcast_rule (proxy, name, wildcard, rule);

          *args_i += 1;
        }
      else if (g_str_equal (arg, "--log"))
        {
          flatpak_proxy_set_log_messages (proxy, TRUE);
          *args_i += 1;
        }
      else if (g_str_equal (arg, "--filter"))
        {
          flatpak_proxy_set_filter (proxy, TRUE);
          *args_i += 1;
        }
      else if (g_str_equal (arg, "--sloppy-names"))
        {
          /* This means we're reporting the name changes for all unique names,
             which is needed for the a11y bus */
          flatpak_proxy_set_sloppy_names (proxy, TRUE);
          *args_i += 1;
        }
      else
        {
          if (!parse_generic_args (args, args_i))
            return FALSE;
        }
    }

  if (!flatpak_proxy_start (proxy, &error))
    {
      g_printerr ("Failed to start proxy for %s: %s\n", bus_address, error->message);
      return FALSE;
    }

  proxies = g_list_prepend (proxies, g_object_ref (proxy));

  return TRUE;
}

static gboolean
sync_closed_cb (GIOChannel  *source,
                GIOCondition condition,
                gpointer     data)
{
  GList *l;

  for (l = proxies; l != NULL; l = l->next)
    flatpak_proxy_stop (FLATPAK_PROXY (l->data));

  exit (0);
  return TRUE;
}

int
main (int argc, const char *argv[])
{
  g_autoptr(GPtrArray) args = NULL;
  GMainLoop *service_loop;
  int i, args_i;

  setlocale (LC_ALL, "");

  args = g_ptr_array_new_with_free_func (g_free);

  argv0 = argv[0];

  if (argc == 1)
    usage (EXIT_FAILURE, stderr);

  for (i = 1; i < argc; i++)
    g_ptr_array_add (args, g_strdup ((char *) argv[i]));

  args_i = 0;
  while (args_i < args->len)
    {
      const char *arg = g_ptr_array_index (args, args_i);
      if (arg[0] == '-')
        {
          if (!parse_generic_args (args, &args_i))
            return EXIT_FAILURE;
        }
      else
        {
          if (!start_proxy (args, &args_i))
            return EXIT_FAILURE;
        }
    }

  if (proxies == NULL)
    {
      g_printerr ("No proxies specified\n");
      return EXIT_FAILURE;
    }

  if (sync_fd >= 0)
    {
      ssize_t written;
      GIOChannel *sync_channel;
      written = write (sync_fd, "x", 1);
      if (written != 1)
        g_warning ("Can't write to sync socket");

      sync_channel = g_io_channel_unix_new (sync_fd);
      g_io_add_watch (sync_channel, G_IO_ERR | G_IO_HUP,
                      sync_closed_cb, NULL);
    }

  service_loop = g_main_loop_new (NULL, FALSE);
  g_main_loop_run (service_loop);

  g_main_loop_unref (service_loop);

  return EXIT_SUCCESS;
}
