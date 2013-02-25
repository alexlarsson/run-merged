/* -*- mode: c; tab-width: 8; indent-tabs-mode: nil -*-
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it would be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2013 Alexander Larsson <alexl@redhat.com>
 *
 * Based in part on linux-user-chroot, which is:
 *
 * Copyright 2011,2012 Colin Walters <walters@verbum.org>
 */

#define _GNU_SOURCE /* Required for e.g CLONE_NEWNS */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/fsuid.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/loop.h>
#include <linux/securebits.h>

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS     38
#endif

#ifndef MS_PRIVATE      /* May not be defined in older glibc headers */
#define MS_PRIVATE (1<<18) /* change to private */
#endif

static void fatal (const char *message, ...) __attribute__ ((noreturn)) __attribute__ ((format (printf, 1, 2)));
static void fatal_errno (const char *message) __attribute__ ((noreturn));

static void
fatal (const char *fmt,
       ...)
{
  va_list args;

  va_start (args, fmt);

  vfprintf (stderr, fmt, args);
  putc ('\n', stderr);

  va_end (args);
  exit (1);
}

static void
fatal_errno (const char *message)
{
  perror (message);
  exit (1);
}

static int
fsuid_chdir (uid_t       uid,
             const char *path)
{
  int errsv;
  int ret;
  /* Note we don't check errors here because we can't, basically */
  (void) setfsuid (uid);
  ret = chdir (path);
  errsv = errno;
  (void) setfsuid (0);
  errno = errsv;
  return ret;
}

static int
fsuid_access (uid_t       uid,
              const char *path,
              int         mode)
{
  int errsv;
  int ret;
  /* Note we don't check errors here because we can't, basically */
  (void) setfsuid (uid);
  ret = access (path, mode);
  errsv = errno;
  (void) setfsuid (0);
  errno = errsv;
  return ret;
}


static char *
strconcat (const char *s1,
           const char *s2,
           const char *s3)
{
  size_t len = 0;
  char *res;

  if (s1)
    len += strlen (s1);
  if (s2)
    len += strlen (s2);
  if (s3)
    len += strlen (s3);

  res = malloc (len + 1);
  if (res == NULL)
    fatal ("oom");

  *res = 0;
  if (s1)
    strcat (res, s1);
  if (s2)
    strcat (res, s2);
  if (s3)
    strcat (res, s3);

  return res;
}

static char *
attach_loop_device (const char *filename, int *loop_fd_out)
{
  struct loop_info64 loopinfo = { 0 };
  struct stat st;
  char buf[64];
  int i, loop_fd, fd;
  char *loopname;

  *loop_fd_out = -1;

  loop_fd = open ("/dev/loop-control", O_RDONLY);
  if (loop_fd < 0)
    fatal_errno ("open /dev/loop-control");

  i = ioctl (loop_fd, LOOP_CTL_GET_FREE);
  if (i < 0)
    fatal_errno ("LOOP_CTL_GET_FREE");

  close (loop_fd);

  if (sprintf (buf, "/dev/loop%d", i) < 0)
    fatal ("snprintf");
  loopname = strdup (buf);
  if (loopname == NULL)
    fatal ("oom");

  if (stat (loopname, &st) ||
      !S_ISBLK (st.st_mode))
    fatal ("loopback not block device");

  loop_fd = open (loopname, O_RDONLY);
  if (loop_fd < 0)
    fatal_errno ("open loop device");

  fd = open (filename, O_RDONLY);
  if (fd < 0)
    fatal_errno ("open image");

  if (ioctl (loop_fd, LOOP_SET_FD, (void *)(size_t)fd) < 0)
    fatal_errno ("LOOP_SET_FD");

  close (fd);

  strncpy((char*)loopinfo.lo_file_name, filename, LO_NAME_SIZE);
  loopinfo.lo_offset = 0;
  loopinfo.lo_flags = LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR;

  if (ioctl (loop_fd, LOOP_SET_STATUS64, &loopinfo) < 0)
    {
      ioctl (loop_fd, LOOP_CLR_FD, 0);
      fatal ("LOOP_SET_STATUS64");
    }

  *loop_fd_out = loop_fd;

  return loopname;
}

static char *
make_fs_dir (const char *root,
             const char *dir,
             mode_t mode)
{
  char *full, *start, *slash;

  while (*dir == '/')
    dir++;

  full = strconcat (root, "/", dir);

  start = full + strlen (root) + 1;

  do
    {
      slash = strchr (start, '/');

      if (slash != NULL)
        *slash = 0;

      if (mkdir (full, mode) < 0 &&
          errno != EEXIST)
        fatal ("mkdir_all %s", full);

      if (slash != NULL)
        {
          *slash = '/';
          start = slash + 1;
        }
    }
  while (slash != NULL);

  return full;
}

static char *
get_fs_mountpoint (const char *root)
{
  char filename[64];
  static int image_count = 0;

  if (snprintf (filename, sizeof (filename), "/fs%u", image_count++) < 0)
    fatal ("snprintf");

  return make_fs_dir (root, filename, 0555);
}

static char *
mount_image (const char *root, const char *image)
{
  int loop_fd;
  char *mountpoint;
  char *loopdev;

  mountpoint = get_fs_mountpoint (root);
  loopdev = attach_loop_device (image, &loop_fd);

  if (mount (loopdev, mountpoint,
             "squashfs", MS_MGC_VAL|MS_RDONLY|MS_NODEV|MS_NOSUID, NULL) < 0)
    fatal_errno ("mount loopback");

  close (loop_fd);

  return mountpoint;
}

enum {
  NO_CONFLICTS = 0,
  DIR_CONFLICT,
  NON_DIR_CONFLICT
};

static char *
get_subdir (const char *dir,  const char *filename)
{
  struct stat st;
  char *path;

  path = strconcat (dir, "/", filename);
  if (lstat (path, &st) == 0 && S_ISDIR (st.st_mode))
    return path;

  free (path);
  return NULL;
}

static int
has_conflict (char **dirs, int n_dirs, const char *filename, int except)
{
  char *path;
  int all_dirs = 1;
  int conflict = 0;
  struct stat st;
  int i;

  for (i = 0; i < n_dirs; i++)
    {
      if (dirs[i] == NULL || i == except)
        continue;

      path = strconcat (dirs[i], "/", filename);
      if (lstat (path, &st) < 0)
        continue;

      conflict = 1;
      if (!S_ISDIR (st.st_mode))
        all_dirs = 0;
    }

  if (!conflict)
    return NO_CONFLICTS;

  if (all_dirs)
    return DIR_CONFLICT;

  return NON_DIR_CONFLICT;
}

static void
bind_file (const char *src_path, const char *dest_path, struct stat *st)
{
  int fd;

  if (S_ISREG (st->st_mode))
    {
      fd = creat (dest_path, st->st_mode & 0777);
      if (fd < 0)
        fatal_errno ("create dest");
      close (fd);

      if (lchown(dest_path, st->st_uid, st->st_gid) < 0)
        fatal_errno ("lchown");

      if (mount (src_path, dest_path,
                 NULL, MS_MGC_VAL|MS_BIND|MS_NODEV|MS_NOSUID|MS_RDONLY|MS_NOATIME, NULL) != 0)
        fatal ("bind file %s", src_path);
    }
  else if (S_ISDIR (st->st_mode))
    {
      if (mkdir (dest_path, st->st_mode & 0777))
        fatal_errno ("create dest dir");

      if (lchown(dest_path, st->st_uid, st->st_gid) < 0)
        fatal_errno ("lchown");

      if (mount (src_path, dest_path,
                 NULL, MS_MGC_VAL|MS_BIND|MS_NODEV|MS_NOSUID|MS_RDONLY|MS_NOATIME, NULL) != 0)
        fatal ("bind dir %s", src_path);
    }
  else if (S_ISLNK (st->st_mode))
    {
      ssize_t res;
      char buf[1024];

      res = readlink (src_path, buf, sizeof (buf));
      if (res < 0)
        fatal_errno ("Could not read link");
      if (res >= sizeof (buf))
        fatal ("link to long");

      buf[res] = 0;

      if (symlink (buf, dest_path) < 0)
        fatal_errno ("symlink");
      chmod (dest_path, st->st_mode & 0777);
      if (lchown(dest_path, st->st_uid, st->st_gid) < 0)
        fatal_errno ("lchown");
    }
  else
    fatal ("Uknown file type %s\n", src_path);
}

static int
merge_dirs (const char *root, char **dirs, int n_dirs)
{
  DIR *dir;
  char *subdirs[n_dirs];
  struct dirent *dirent;
  struct stat st;
  char *src_path;
  char *dest_path;
  int conflict;
  int i, j;

  for (i = 0; i < n_dirs; i++)
    {
      if (dirs[i] == NULL)
        continue;

      dir = opendir (dirs[i]);
      if (dir == NULL)
        continue;

      while ((dirent = readdir (dir)) != NULL)
        {
          src_path = strconcat (dirs[i], "/", dirent->d_name);

          if (strcmp (dirent->d_name, ".") == 0 ||
              strcmp (dirent->d_name, "..") == 0)
            continue;

          dest_path = strconcat (root, "/", dirent->d_name);

          if (lstat (dest_path, &st) == 0)
            {
              free (dest_path);
              continue; /* We already copyed this file */
            }

          if (lstat (src_path, &st) < 0)
            {
              free (dest_path);
              continue;
            }

          if (S_ISCHR (st.st_mode) ||
              S_ISBLK (st.st_mode) ||
              S_ISFIFO (st.st_mode) ||
              S_ISSOCK (st.st_mode))
            {
              fprintf (stderr, "WARNING: ignoring special file %s\n", src_path);
              free (dest_path);
              continue;
            }

          conflict = has_conflict (dirs, n_dirs, dirent->d_name, i);

          if (conflict == NO_CONFLICTS)
            {
              bind_file (src_path, dest_path, &st);
            }
          else if (conflict == DIR_CONFLICT)
            {
              if (mkdir (dest_path, st.st_mode & 0777))
                fatal_errno ("create merged dir");

              if (lchown(dest_path, st.st_uid, st.st_gid) < 0)
                fatal_errno ("lchown");

              for (j = 0; j < n_dirs; j++)
                subdirs[j] = get_subdir (dirs[j], dirent->d_name);

              merge_dirs (dest_path, subdirs, n_dirs);
              for (j = 0; j < n_dirs; j++)
                {
                  if (subdirs[j])
                    free (subdirs[j]);
                }
            }
          else
            fatal ("Filename conflicts, refusing to mount\n");

          free (dest_path);
        }
    }

  return 0;
}

static void
setup_base (const char *root)
{
  char *proc_dir, *dev_dir;
  char *home, *new_home;

  proc_dir = make_fs_dir (root, "/proc", 0555);
  if (mount ("proc", proc_dir, "proc",
             MS_MGC_VAL | MS_PRIVATE, NULL) != 0)
    fatal_errno ("mount proc");
  free (proc_dir);

  dev_dir = make_fs_dir (root, "/dev", 0555);
  if (mount ("/dev", dev_dir,
             NULL, MS_MGC_VAL|MS_BIND|MS_NOSUID|MS_RDONLY, NULL) != 0)
    fatal_errno ("mount /dev");
  free (dev_dir);

  home = getenv ("HOME");
  if (home != NULL)
    {
      new_home = make_fs_dir (root, home, 0755);
      if (mount (home, new_home,
                 NULL, MS_MGC_VAL|MS_BIND|MS_NODEV|MS_NOSUID, NULL) != 0)
        fatal ("bind home");
      free (new_home);
    }
}

int
main (int argc,
      char **argv)
{
  char tempdir[] = "/tmp/approot_XXXXXX";
  char *base_os;
  char **images;
  char *root;
  int n_images;
  pid_t child;
  int child_status = 0;
  char *app_root;
  char **mountpoints;
  int n_mountpoints;
  int i;
  uid_t ruid, euid, suid;
  gid_t rgid, egid, sgid;
  char cwd_buf[PATH_MAX];
  char *cwd;

  if (argc < 2)
    fatal ("Too few arguments, need base and at least one image");

  base_os = argv[1];
  images = &argv[2];
  n_images = argc - 2;

  root = mkdtemp (tempdir);
  if (root == NULL)
    fatal ("Can't create root");

  if (getresgid (&rgid, &egid, &sgid) < 0)
    fatal_errno ("getresgid");
  if (getresuid (&ruid, &euid, &suid) < 0)
    fatal_errno ("getresuid");

  if ((child = syscall (__NR_clone, SIGCHLD | CLONE_NEWNS, NULL)) < 0)
    fatal_errno ("clone");

  if (child == 0)
    {
      /* Child */

      /* Disable setuid, new caps etc for children */
      if (prctl (PR_SET_NO_NEW_PRIVS, 1) < 0 && errno != EINVAL)
        fatal_errno ("prctl (PR_SET_NO_NEW_PRIVS)");
      else if (prctl (PR_SET_SECUREBITS,
                      SECBIT_NOROOT | SECBIT_NOROOT_LOCKED) < 0)
        fatal_errno ("prctl (SECBIT_NOROOT)");

      /* Don't leak our mounts to the parent namespace */
      if (mount (NULL, "/", "none", MS_SLAVE | MS_REC, NULL) < 0)
        fatal_errno ("mount(/, MS_SLAVE | MS_REC)");

      /* Check we're allowed to chdir into base os */
      cwd = getcwd (cwd_buf, sizeof (cwd_buf));
      if (fsuid_chdir (ruid, base_os) < 0)
        fatal_errno ("chdir");
      if (chdir (cwd) < 0)
        fatal_errno ("chdir");

      if (mount ("tmpfs", root, "tmpfs",
                 MS_MGC_VAL | MS_PRIVATE, NULL) != 0)
        fatal_errno ("execv");

      n_mountpoints = n_images + 1;
      mountpoints = calloc (n_mountpoints, sizeof (char *));
      if (mountpoints == NULL)
        fatal ("oom");

      mountpoints[0] = base_os;

      for (i = 0; i < n_images; i++)
        {
          if (fsuid_access (ruid, images[i], R_OK) < 0)
            fatal_errno ("access");

          mountpoints[i+1] = mount_image (root, images[i]);
          if (mountpoints[i+1] == NULL)
            fatal ("mount image %s\n", images[i]);
        }

      app_root = make_fs_dir (root, "/root", 0555);
      if (app_root == NULL)
        fatal ("make_fs_dir root");

      setup_base (app_root);

      merge_dirs (app_root, mountpoints, n_mountpoints);

      if (chdir (app_root) < 0)
        fatal_errno ("chdir");

      if (chroot (".") < 0)
        fatal_errno ("chroot");

      /* Switch back to the uid of our invoking process.  These calls are
       * irrevocable - see setuid(2) */
      if (setgid (rgid) < 0)
        fatal_errno ("setgid");
      if (setuid (ruid) < 0)
        fatal_errno ("setuid");

      if (execl ("/bin/sh", "/bin/sh", NULL) < 0)
        fatal_errno ("execl");
    }

  /* Parent */

  /* Let's also setuid back in the parent - there's no reason to stay uid 0, and
   * it's just better to drop privileges. */
  if (setgid (rgid) < 0)
    fatal_errno ("setgid");
  if (setuid (ruid) < 0)
    fatal_errno ("setuid");

  if (child == -1)
    fatal_errno ("clone");

  /* Ignore Ctrl-C in parent while waiting */
  signal (SIGINT, SIG_IGN);

  if (waitpid (child, &child_status, 0) < 0)
    fatal_errno ("waitpid");

  rmdir (root);

  if (WIFEXITED (child_status))
    return WEXITSTATUS (child_status);
  else
    return 1;
}
