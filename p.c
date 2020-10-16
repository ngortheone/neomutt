// gcc -I. -o p{,.c} lib{debug,maildir,hcache,compress,store,core,config,email,address,mutt}.a -lpcre2-8 -lidn2 -ltokyocabinet -lrocksdb -ltdb -llmdb -lkyotocabinet -lgdbm -lqdbm -ldb-5.3 -llz4 -lz -lzstd

#include "config.h"
#include <ctype.h>
#include <dirent.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "debug/lib.h"
#include "maildir/lib.h"
#include "copy.h"
#include "maildir/mdata.h"
#include "maildir/mdemail.h"
#include "maildir/private.h"
#include "mx.h"
#include "progress.h"
#ifdef USE_HCACHE
#include "hcache/lib.h"
#endif

struct MuttWindow;

bool C_Autocrypt = false;
bool C_FlagSafe = false;
bool C_MailCheckRecent = false;
char *HomeDir = NULL;
bool MonitorContextChanged = false;
char *ShortHostname = NULL;
SIG_ATOMIC_VOLATILE_T SigInt = 0;

const struct Mapping Fields[] = { 0 };
const struct Mapping ComposeFields[] = { 0 };

// Flags for maildir_mbox_check()
#define MMC_NO_DIRS 0        ///< No directories changed
#define MMC_NEW_DIR (1 << 0) ///< 'new' directory changed
#define MMC_CUR_DIR (1 << 1) ///< 'cur' directory changed

#define DIVIDER "--------------------------------------------------------------------------------\n"

int nm_update_filename(struct Mailbox *m, const char *old_file, const char *new_file, struct Email *e)
{
  if (!m || !old_file || !new_file || !e)
    return -1;
  return 0;
}

void mutt_encode_path(struct Buffer *buf, const char *src)
{
  char *p = mutt_str_dup(src);
  int rc = mutt_ch_convert_string(&p, C_Charset, "us-ascii", 0);
  size_t len = mutt_buffer_strcpy(buf, (rc == 0) ? NONULL(p) : NONULL(src));

  /* convert the path to POSIX "Portable Filename Character Set" */
  for (size_t i = 0; i < len; i++)
  {
    if (!isalnum(buf->data[i]) && !strchr("/.-_", buf->data[i]))
    {
      buf->data[i] = '_';
    }
  }
  FREE(&p);
}

struct MuttWindow *dialog_find(struct MuttWindow *win)
{
  if (!win)
    return NULL;
  return NULL;
}

struct Message *mx_msg_open_new(struct Mailbox *m, const struct Email *e, MsgOpenFlags flags)
{
  if (!m || !e)
    return NULL;
  if (flags)
  {
  }
  return NULL;
}

int mx_msg_close(struct Mailbox *m, struct Message **msg)
{
  if (!m || !msg || !*msg)
    return 0;

  return 0;
}

int mutt_copy_message(FILE *fp_out, struct Mailbox *m, struct Email *e, CopyMessageFlags cmflags, CopyHeaderFlags chflags, int wraplen)
{
  if (!fp_out || !m || !e)
    return -1;
  if (cmflags || chflags || wraplen)
  {
  }
  return 0;
}

void mutt_set_flag_update(struct Mailbox *m, struct Email *e, int flag, bool bf, bool upd_mbox)
{
  if (!m || !e)
    return;
  if (flag || bf | upd_mbox)
    return;
}

void nm_edata_free(void **ptr)
{
  if (ptr)
  {
  }
}

void mx_alloc_memory(struct Mailbox *m)
{
  size_t s = MAX(sizeof(struct Email *), sizeof(int));

  if ((m->email_max + 25) * s < m->email_max * s)
  {
    mutt_error(_("Out of memory"));
    mutt_exit(1);
  }

  m->email_max += 25;
  if (m->emails)
  {
    mutt_mem_realloc(&m->emails, sizeof(struct Email *) * m->email_max);
    mutt_mem_realloc(&m->v2r, sizeof(int) * m->email_max);
  }
  else
  {
    m->emails = mutt_mem_calloc(m->email_max, sizeof(struct Email *));
    m->v2r = mutt_mem_calloc(m->email_max, sizeof(int));
  }
  for (int i = m->email_max - 25; i < m->email_max; i++)
  {
    m->emails[i] = NULL;
    m->v2r[i] = -1;
  }
}

static void my_signal_handler(int sig)
{
  if (sig == SIGINT)
    SigInt = 1;
}

int mutt_autocrypt_process_autocrypt_header(struct Email *e, struct Envelope *env)
{
  if (e || env)
  {
  }
  return 0;
}

void mutt_progress_init(struct Progress *progress, const char *msg, enum ProgressType type, size_t size)
{
  if (progress || msg || type || size)
  {
  }
}

void mutt_progress_update(struct Progress *progress, size_t pos, int percent)
{
  if (progress || pos || percent)
  {
  }
}

void maildir_canon_filename2(char *name)
{
  if (!name)
    return;

  // char *u = strpbrk(name, ",:");
  char *u = strpbrk(name, ":");
  if (u)
    *u = '\0';
}

static int scan_dir(struct MdEmailArray *mda, const char *dir, struct Progress *progress)
{
  if (!mda || !dir)
    return -1;

  DIR *dirp = opendir(dir);
  if (!dirp)
  {
    mutt_perror("%s", dir);
    return -1;
  }

  mutt_debug(LL_DEBUG1, "Scanning: %s\n", dir);
  int count = 0;
  struct dirent *de = NULL;
  while ((SigInt != 1) && ((de = readdir(dirp))))
  {
    if (*de->d_name == '.')
      continue;

    mutt_debug(LL_DEBUG2, "    %s\n", de->d_name);
    mutt_progress_update(progress, ARRAY_SIZE(mda) + 1, -1);

    struct MdEmail *entry = maildir_entry_new();
    entry->canon_fname = strdup(de->d_name);
    ARRAY_ADD(mda, entry);
    count++;
  }

  closedir(dirp);

  if (SigInt == 1)
  {
    mutt_debug(LL_DEBUG1, "Scan aborted after %d files\n", count);
    SigInt = 0;
    return -2; // action aborted
  }

  mutt_debug(LL_DEBUG1, "Successfully found %d files\n", count);
  return count;
}

static int mbox_observer(struct NotifyCallback *nc)
{
  if (!nc)
    return -1;

  debug_notify_observer(nc);
  return 0;
}

int my_hcache_read(struct HeaderCache *hc, struct MdEmailArray *mda, struct Progress *progress)
{
  if (!hc)
    return 0;

  struct stat lastchanged = { 0 };
  int rc = 0;
  struct MdEmail *md = NULL;
  struct MdEmail **mdp = NULL;
  char key[PATH_MAX];
  int count = 0;

  mutt_debug(LL_DEBUG1, "Reading header cache\n");
  // update progress message + display it
  ARRAY_FOREACH(mdp, mda)
  {
    if (SigInt == 1)
    {
      SigInt = 0;
      return -2;
    }

    md = *mdp;

    mutt_str_copy(key, md->canon_fname + 3, sizeof(key));
    maildir_canon_filename2(key);
    mutt_debug(LL_DEBUG1, "    %s\n", key);

    if (C_MaildirHeaderCacheVerify) // Config: (true) (hcache) Check for maildir changes when opening mailbox
      rc = stat(key, &lastchanged);

    size_t keylen = strlen(key);
    struct HCacheEntry hce = mutt_hcache_fetch(hc, key, keylen, 0);

    if (hce.email && (rc == 0) && (lastchanged.st_mtime <= hce.uidvalidity))
    {
      hce.email->edata = maildir_edata_new();
      hce.email->edata_free = maildir_edata_free;
      hce.email->old = md->is_old;
      hce.email->path = mutt_str_dup(md->canon_fname);
      md->email = hce.email;
      maildir_parse_flags(md->email, key);
      count++;
      mutt_progress_update(progress, count, ARRAY_SIZE(mda));
    }
    else
    {
      email_free(&md->email);
    }
  }
  mutt_debug(LL_DEBUG1, "Found %d matches\n", count);

  return 0;
}

int my_maildir_read(struct Mailbox *m, struct MdEmailArray *mda, struct Progress *progress)
{
  ARRAY_SORT(mda, md_cmp_inode);

  char fn[PATH_MAX];

  // update progress message + display it
  struct MdEmail *md = NULL;
  struct MdEmail **mdp = NULL;
  int count = 0; // get from progress
  ARRAY_FOREACH(mdp, mda)
  {
    if (SigInt == 1)
    {
      SigInt = 0;
      return -2;
    }

    md = *mdp;
    if (md->email)
      continue;

    snprintf(fn, sizeof(fn), "%s/%s", mailbox_path(m), md->canon_fname);

    struct Email *e = email_new();
    e->edata = maildir_edata_new();
    e->edata_free = maildir_edata_free;
    e->old = md->is_old;
    e->path = mutt_str_dup(md->canon_fname);
    if (maildir_parse_message(m->type, fn, md->is_old, e))
    {
      md->email = e;
      md->header_parsed = true;
      mutt_progress_update(progress, count++, ARRAY_SIZE(mda));
    }
    else
      email_free(&e);
  }
  return 0;
}

int my_hcache_write(struct HeaderCache *hc, struct MdEmailArray *mda, struct Progress *progress)
{
  if (!hc)
    return 0;

  // update progress message + display it
  struct MdEmail *md = NULL;
  struct MdEmail **mdp = NULL;
  const char *key = NULL;
  size_t keylen;
  int count = 0;
  ARRAY_FOREACH(mdp, mda)
  {
    if (SigInt == 1)
    {
      SigInt = 0;
      return -2;
    }

    md = *mdp;
    if (!md->header_parsed)
      continue;

    key = md->email->path + 3;
    keylen = maildir_hcache_keylen(key);
    mutt_hcache_store(hc, key, keylen, md->email, 0);
    mutt_progress_update(progress, count++, ARRAY_SIZE(mda));
  }

  return 0;
}

int my_scan_dir(struct Mailbox *m, struct MdEmailArray *mda, struct Progress *progress)
{
  struct Buffer *dir = mutt_buffer_pool_get();

  mutt_buffer_printf(dir, "%s/cur", mailbox_path(m));

  int cur_count = scan_dir(mda, mutt_b2s(dir), progress);
  mutt_debug(LL_DEBUG1, "count = %d\n", cur_count);

  struct MdEmail *md = NULL;
  struct MdEmail **mdp = NULL;

  ARRAY_FOREACH(mdp, mda)
  {
    (*mdp)->is_old = true;
  }

  mutt_buffer_printf(dir, "%s/new", mailbox_path(m));

  int new_count = scan_dir(mda, mutt_b2s(dir), progress);
  mutt_debug(LL_DEBUG1, "count = %d\n", cur_count + new_count);

  char *rel_name = NULL;
  char *sub_dir = NULL;
  ARRAY_FOREACH(mdp, mda)
  {
    md = *mdp;

    sub_dir = md->is_old ? "cur" : "new";

    mutt_str_asprintf(&rel_name, "%s/%s", sub_dir, md->canon_fname);
    FREE(&md->canon_fname);
    md->canon_fname = rel_name;
  }

  mutt_buffer_pool_release(&dir);
  return 0;
}

static int my_mbox_open(struct Mailbox *m)
{
  int rc = 0;
  mutt_debug(LL_DEBUG1, "reading: %s\n", mailbox_path(m));
  struct Progress progress = { 0 };
  struct HeaderCache *hc = NULL;

  struct MdEmailArray mda = ARRAY_HEAD_INITIALIZER;

  mutt_progress_init(&progress, "Maildir", MUTT_PROGRESS_READ, 0);

  rc = my_scan_dir(m, &mda, &progress);
  if (rc < 0)
    goto done;

  hc = mutt_hcache_open(C_HeaderCache, mailbox_path(m), NULL);
  if (!hc)
  {
    // log but continue - need to distinguish: no cache vs error
  }

  rc = my_hcache_read(hc, &mda, &progress);
  if (rc < 0)
    goto done;

  rc = my_maildir_read(m, &mda, &progress);
  if (rc < 0)
    goto done;

  rc = my_hcache_write(hc, &mda, &progress);
  if (rc < 0)
    goto done;

  maildir_move_to_mailbox(m, &mda);
  rc = 0;

done:
  maildirarray_clear(&mda);
  mutt_hcache_close(hc);
  return rc;
}

static void maildir_check_dir2(struct Mailbox *m, const char *dir_name, bool check_new, bool check_stats)
{
  DIR *dirp = NULL;
  struct dirent *de = NULL;
  char *p = NULL;
  struct stat sb;

  struct Buffer *path = mutt_buffer_pool_get();
  struct Buffer *msgpath = mutt_buffer_pool_get();
  mutt_buffer_printf(path, "%s/%s", mailbox_path(m), dir_name);

  /* when $mail_check_recent is set, if the new/ directory hasn't been modified since
   * the user last exited the mailbox, then we know there is no recent mail.  */
  if (check_new && C_MailCheckRecent) // Config: (true) Notify the user about new mail since the last time the mailbox was opened
  {
    if ((stat(mutt_b2s(path), &sb) == 0) &&
        (mutt_file_stat_timespec_compare(&sb, MUTT_STAT_MTIME, &m->last_visited) < 0))
    {
      check_new = false;
    }
  }

  if (!check_new && !check_stats)
    goto cleanup;

  dirp = opendir(mutt_b2s(path));
  if (!dirp)
  {
    m->type = MUTT_UNKNOWN;
    goto cleanup;
  }

  while ((de = readdir(dirp)))
  {
    p = strstr(de->d_name, ":2,");
    if (!p)
      continue;

    p += 3;
    if (strchr(p, 'T')) // Trashed
      continue;

    if (check_stats)
    {
      m->msg_count++;
      if (strchr(p, 'F')) // Flagged
        m->msg_flagged++;
    }

    if (strchr(p, 'S')) // Seen
      continue;

    if (check_stats)
      m->msg_unread++;

    if (!check_new)
      continue;

    if (C_MailCheckRecent) ///< Config: Notify the user about new mail since the last time the mailbox was opened
    {
      mutt_buffer_printf(msgpath, "%s/%s", mutt_b2s(path), de->d_name);
      /* ensure this message was received since leaving this mailbox */
      if ((stat(mutt_b2s(msgpath), &sb) == 0) &&
          (mutt_file_stat_timespec_compare(&sb, MUTT_STAT_CTIME, &m->last_visited) <= 0))
      {
        continue;
      }
    }

    m->has_new = true;
    check_new = false;
    m->msg_new++;
    if (!check_stats)
      break;
  }

  closedir(dirp);

cleanup:
  mutt_buffer_pool_release(&path);
  mutt_buffer_pool_release(&msgpath);
}

static int my_check_stats(struct Mailbox *m, int flags)
{
  bool check_stats = flags;
  bool check_new = true;

  if (check_stats)
  {
    m->msg_count = 0;
    m->msg_unread = 0;
    m->msg_flagged = 0;
    m->msg_new = 0;
  }

  maildir_check_dir2(m, "new", check_new, check_stats);

  check_new = !m->has_new && C_MaildirCheckCur; // Config: (false) Check both 'new' and 'cur' directories for new mail
  if (check_new || check_stats)
    maildir_check_dir2(m, "cur", check_new, check_stats);

  return m->msg_new;
}

static int my_mbox_check(struct Mailbox *m)
{
  struct stat st_new;         /* status of the "new" subdirectory */
  struct stat st_cur;         /* status of the "cur" subdirectory */
  int changed = MMC_NO_DIRS;  /* which subdirectories have changed */
  bool occult = false;        /* messages were removed from the mailbox */
  int num_new = 0;            /* number of new messages added to the mailbox */
  bool flags_changed = false; /* message flags were changed in the mailbox */
  struct HashTable *fnames = NULL; /* hash table for quickly looking up the base filename
                                 for a maildir message */
  struct MaildirMboxData *mdata = maildir_mdata_get(m);

  /* XXX seems like this check belongs in mx_mbox_check() rather than here.  */
  if (!C_CheckNew)
    return 0;

  struct Buffer *buf = mutt_buffer_pool_get();
  mutt_buffer_printf(buf, "%s/new", mailbox_path(m));
  if (stat(mutt_b2s(buf), &st_new) == -1)
  {
    mutt_buffer_pool_release(&buf);
    return -1;
  }

  mutt_buffer_printf(buf, "%s/cur", mailbox_path(m));
  if (stat(mutt_b2s(buf), &st_cur) == -1)
  {
    mutt_buffer_pool_release(&buf);
    return -1;
  }

  /* determine which subdirectories need to be scanned */
  if (mutt_file_stat_timespec_compare(&st_new, MUTT_STAT_MTIME, &m->mtime) > 0)
    changed = MMC_NEW_DIR;
  if (mutt_file_stat_timespec_compare(&st_cur, MUTT_STAT_MTIME, &mdata->mtime_cur) > 0)
    changed |= MMC_CUR_DIR;

  if (changed == MMC_NO_DIRS)
  {
    mutt_buffer_pool_release(&buf);
    return 0; /* nothing to do */
  }

  /* Update the modification times on the mailbox.
   *
   * The monitor code notices changes in the open mailbox too quickly.
   * In practice, this sometimes leads to all the new messages not being
   * noticed during the SAME group of mtime stat updates.  To work around
   * the problem, don't update the stat times for a monitor caused check. */
#ifdef USE_INOTIFY
  if (MonitorContextChanged)
    MonitorContextChanged = false;
  else
#endif
  {
    mutt_file_get_stat_timespec(&mdata->mtime_cur, &st_cur, MUTT_STAT_MTIME);
    mutt_file_get_stat_timespec(&m->mtime, &st_new, MUTT_STAT_MTIME);
  }

  /* do a fast scan of just the filenames in
   * the subdirectories that have changed.  */
  struct MdEmailArray mda = ARRAY_HEAD_INITIALIZER;
  if (changed & MMC_NEW_DIR)
    maildir_parse_dir(m, &mda, "new", NULL);
  if (changed & MMC_CUR_DIR)
    maildir_parse_dir(m, &mda, "cur", NULL);

  /* we create a hash table keyed off the canonical (sans flags) filename
   * of each message we scanned.  This is used in the loop over the
   * existing messages below to do some correlation.  */
  fnames = mutt_hash_new(ARRAY_SIZE(&mda), MUTT_HASH_NO_FLAGS);

  struct MdEmail *md = NULL;
  struct MdEmail **mdp = NULL;
  ARRAY_FOREACH(mdp, &mda)
  {
    md = *mdp;
    maildir_canon_filename(buf, md->email->path);
    md->canon_fname = mutt_buffer_strdup(buf);
    mutt_hash_insert(fnames, md->canon_fname, md);
  }

  /* check for modifications and adjust flags */
  for (int i = 0; i < m->msg_count; i++)
  {
    struct Email *e = m->emails[i];
    if (!e)
      break;

    e->active = false;
    maildir_canon_filename(buf, e->path);
    md = mutt_hash_find(fnames, mutt_b2s(buf));
    if (md && md->email)
    {
      /* message already exists, merge flags */
      e->active = true;

      /* check to see if the message has moved to a different
       * subdirectory.  If so, update the associated filename.  */
      if (!mutt_str_equal(e->path, md->email->path))
        mutt_str_replace(&e->path, md->email->path);

      /* if the user hasn't modified the flags on this message, update
       * the flags we just detected.  */
      if (!e->changed)
        if (maildir_update_flags(m, e, md->email))
          flags_changed = true;

      if (e->deleted == e->trash)
      {
        if (e->deleted != md->email->deleted)
        {
          e->deleted = md->email->deleted;
          flags_changed = true;
        }
      }
      e->trash = md->email->trash;

      /* this is a duplicate of an existing email, so remove it */
      email_free(&md->email);
    }
    /* This message was not in the list of messages we just scanned.
     * Check to see if we have enough information to know if the
     * message has disappeared out from underneath us.  */
    else if (((changed & MMC_NEW_DIR) && mutt_strn_equal(e->path, "new/", 4)) ||
             ((changed & MMC_CUR_DIR) && mutt_strn_equal(e->path, "cur/", 4)))
    {
      /* This message disappeared, so we need to simulate a "reopen"
       * event.  We know it disappeared because we just scanned the
       * subdirectory it used to reside in.  */
      occult = true;
      e->deleted = true;
      e->purge = true;
    }
    else
    {
      /* This message resides in a subdirectory which was not
       * modified, so we assume that it is still present and
       * unchanged.  */
      e->active = true;
    }
  }

  /* destroy the file name hash */
  mutt_hash_free(&fnames);

  /* If we didn't just get new mail, update the tables. */
  if (occult)
    mailbox_changed(m, NT_MAILBOX_RESORT);

  /* do any delayed parsing we need to do. */
  maildir_delayed_parsing(m, &mda, NULL);

  /* Incorporate new messages */
  num_new = maildir_move_to_mailbox(m, &mda);
  if (num_new > 0)
  {
    mailbox_changed(m, NT_MAILBOX_INVALID);
    m->changed = true;
  }

  mutt_buffer_pool_release(&buf);

  ARRAY_FREE(&mda);
  if (occult)
    return MUTT_REOPENED;
  if (num_new > 0)
    return MUTT_NEW_MAIL;
  if (flags_changed)
    return MUTT_FLAGS;
  return 0;

}

int main(int argc, char *argv[])
{
  if (argc < 2)
    return 1;

  mutt_sig_init(my_signal_handler, NULL, NULL);

  MuttLogger = log_disp_terminal;
  // MuttLogger = log_disp_null;

  C_HeaderCache = "/home/mutt/.cache/mutt/";
  C_HeaderCacheBackend = "lmdb";
  C_Charset = "utf-8";

  struct ConfigSet *cs = cs_new(1024);
  NeoMutt = neomutt_new(cs);
  struct Account *a = account_new(NULL, NeoMutt->sub);
  neomutt_account_add(NeoMutt, a);

  mutt_debug(LL_DEBUG1, DIVIDER);
  char real[PATH_MAX];
  for (; argc > 1; argc--, argv++)
  {
    const char *dir = argv[1];

    struct Mailbox *m = mailbox_new();
    mutt_buffer_strcpy(&m->pathbuf, dir);
    mutt_str_copy(real, dir, sizeof(real));
    mutt_path_realpath(real);
    m->realpath = mutt_str_dup(real);
    m->type = MUTT_MAILDIR;
    m->verbose = true;
    notify_observer_add(m->notify, NT_MAILBOX, mbox_observer, NULL);

    account_mailbox_add(a, m);

    my_mbox_open(m);
    my_check_stats(m, true);
    // delete the new emails?
    MuttLogger = log_disp_terminal;
    my_mbox_check(m);
    MuttLogger = log_disp_null;

    struct Email *e = NULL;
    for (int i = 0; i < m->email_max; i++)
    {
      e = m->emails[i];
      if (!e)
        break;

      mutt_debug(LL_DEBUG1, "%3d %s\n", i, e->env->subject);
      // dump_graphviz_email(e, i);
    }
    mutt_debug(LL_DEBUG1, DIVIDER);
  }

  // dump_graphviz("index");
  neomutt_free(&NeoMutt);
  cs_free(&cs);

  return 0;
}
