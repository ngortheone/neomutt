int maildir_sync_mailbox_message(struct Mailbox *m, int msgno, struct HeaderCache *hc)
{
  struct Email *e = m->emails[msgno];
  if (!e)
    return -1;

  if (e->deleted && !C_MaildirTrash)
  {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", mailbox_path(m), e->path);
#ifdef USE_HCACHE
    if (hc)
    {
      const char *key = e->path + 3;
      size_t keylen = maildir_hcache_keylen(key);
      mutt_hcache_delete_record(hc, key, keylen);
    }
#endif
    unlink(path);
  }
  else if (e->changed || e->attach_del ||
           ((C_MaildirTrash || e->trash) && (e->deleted != e->trash)))
  {
    if (maildir_sync_message(m, msgno) == -1)
      return -1;
  }

#ifdef USE_HCACHE
  if (hc && e->changed)
  {
    const char *key = e->path + 3;
    size_t keylen = maildir_hcache_keylen(key);
    mutt_hcache_store(hc, key, keylen, e, 0);
  }
#endif

  return 0;
}

int maildir_mbox_sync(struct Mailbox *m)
{
  int check = maildir_mbox_check(m);
  if (check < 0)
    return check;

  struct HeaderCache *hc = NULL;
#ifdef USE_HCACHE
  if (m->type == MUTT_MAILDIR)
    hc = mutt_hcache_open(C_HeaderCache, mailbox_path(m), NULL);
#endif

  struct Progress progress;
  if (m->verbose)
  {
    char msg[PATH_MAX];
    snprintf(msg, sizeof(msg), _("Writing %s..."), mailbox_path(m));
    mutt_progress_init(&progress, msg, MUTT_PROGRESS_WRITE, m->msg_count);
  }

  for (int i = 0; i < m->msg_count; i++)
  {
    if (m->verbose)
      mutt_progress_update(&progress, i, -1);

    if (maildir_sync_mailbox_message(m, i, hc) == -1)
      goto err;
  }

#ifdef USE_HCACHE
  if (m->type == MUTT_MAILDIR)
    mutt_hcache_close(hc);
#endif

  /* XXX race condition? */

  maildir_update_mtime(m);

  /* adjust indices */

  if (m->msg_deleted)
  {
    for (int i = 0, j = 0; i < m->msg_count; i++)
    {
      struct Email *e = m->emails[i];
      if (!e)
        break;

      if (!e->deleted || C_MaildirTrash)
        e->index = j++;
    }
  }

  return check;

err:
#ifdef USE_HCACHE
  if (m->type == MUTT_MAILDIR)
    mutt_hcache_close(hc);
#endif
  return -1;
}

