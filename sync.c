int maildir_rewrite_message2(struct Mailbox *m, struct Email *e)
{
  bool restore = true;

  long old_body_offset = e->body->offset;
  long old_body_length = e->body->length;
  long old_hdr_lines = e->lines;

  struct Message *dest = mx_msg_open_new(m, e, MUTT_MSG_NO_FLAGS);
  if (!dest)
    return -1;

  int rc = mutt_copy_message(dest->fp, m, e, MUTT_CM_UPDATE, CH_UPDATE | CH_UPDATE_LEN, 0);
  if (rc == 0)
  {
    char oldpath[PATH_MAX];
    char partpath[PATH_MAX];
    snprintf(oldpath, sizeof(oldpath), "%s/%s", mailbox_path(m), e->path);
    mutt_str_copy(partpath, e->path, sizeof(partpath));

    rc = maildir_commit_message(m, dest, e);
    mx_msg_close(m, &dest);

    if (rc == 0)
    {
      unlink(oldpath);
      restore = false;
    }
  }
  else
    mx_msg_close(m, &dest);

  if ((rc == -1) && restore)
  {
    e->body->offset = old_body_offset;
    e->body->length = old_body_length;
    e->lines = old_hdr_lines;
  }

  mutt_body_free(&e->body->parts);
  return rc;
}

int maildir_sync_message2(struct Mailbox *m, struct Email *e)
{
  struct Buffer *newpath = NULL;
  struct Buffer *partpath = NULL;
  struct Buffer *fullpath = NULL;
  struct Buffer *oldpath = NULL;
  char suffix[16];
  int rc = 0;

  /* TODO: why the e->env check? */
  if (e->attach_del || (e->env && e->env->changed))
  {
    /* when doing attachment deletion/rethreading, fall back to the MH case. */
    if (maildir_rewrite_message2(m, e) != 0)
      return -1;
    /* TODO: why the env check? */
    if (e->env)
      e->env->changed = 0;
  }
  else
  {
    /* we just have to rename the file. */
    char *p = strrchr(e->path, '/');
    if (!p)
    {
      mutt_debug(LL_DEBUG1, "%s: unable to find subdir!\n", e->path);
      return -1;
    }
    p++;
    newpath = mutt_buffer_pool_get();
    partpath = mutt_buffer_pool_get();
    fullpath = mutt_buffer_pool_get();
    oldpath = mutt_buffer_pool_get();

    mutt_buffer_strcpy(newpath, p);

    /* kill the previous flags */
    p = strchr(newpath->data, ':');
    if (p)
    {
      *p = '\0';
      newpath->dptr = p; /* fix buffer up, just to be safe */
    }

    maildir_gen_flags(suffix, sizeof(suffix), e);

    mutt_buffer_printf(partpath, "%s/%s%s", (e->read || e->old) ? "cur" : "new", mutt_b2s(newpath), suffix);
    mutt_buffer_printf(fullpath, "%s/%s", mailbox_path(m), mutt_b2s(partpath));
    mutt_buffer_printf(oldpath, "%s/%s", mailbox_path(m), e->path);

    if (mutt_str_equal(mutt_b2s(fullpath), mutt_b2s(oldpath)))
      goto cleanup; // message hasn't really changed

    /* record that the message is possibly marked as trashed on disk */
    e->trash = e->deleted;

    if (rename(mutt_b2s(oldpath), mutt_b2s(fullpath)) != 0)
    {
      mutt_perror("rename");
      rc = -1;
      goto cleanup;
    }
    mutt_str_replace(&e->path, mutt_b2s(partpath));
  }

cleanup:
  mutt_buffer_pool_release(&newpath);
  mutt_buffer_pool_release(&partpath);
  mutt_buffer_pool_release(&fullpath);
  mutt_buffer_pool_release(&oldpath);

  return rc;
}

int maildir_sync_mailbox_message2(struct Mailbox *m, struct Email *e, struct HeaderCache *hc)
{
  if (e->deleted && !C_MaildirTrash)
  {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", mailbox_path(m), e->path);
    unlink(path);
  }
  else if (e->changed || e->attach_del || ((C_MaildirTrash || e->trash) && (e->deleted != e->trash)))
  {
    if (maildir_sync_message2(m, e) == -1)
      return -1;
  }

  return 0;
}

int maildir_mbox_sync(struct Mailbox *m)
{
  int check = maildir_mbox_check(m);
  if (check < 0)
    return check;

  struct HeaderCache *hc = NULL;

  struct Progress progress;
  if (m->verbose)
  {
    char msg[PATH_MAX];
    snprintf(msg, sizeof(msg), _("Writing %s..."), mailbox_path(m));
    mutt_progress_init(&progress, msg, MUTT_PROGRESS_WRITE, m->msg_count);
  }

#ifdef USE_HCACHE
  hc = mutt_hcache_open(C_HeaderCache, mailbox_path(m), NULL);
  if (hc)
  {
    for (int i = 0; i < m->msg_count; i++)
    {
      const char *key = e->path + 3;
      size_t keylen = maildir_hcache_keylen(key);
      mutt_hcache_delete_record(hc, key, keylen);
    }
  }
#endif

  for (int i = 0; i < m->msg_count; i++)
  {
    if (m->verbose)
      mutt_progress_update(&progress, i, -1);

    struct Email *e = m->emails[msgno];
    if (!e)
      goto err;

    if (maildir_sync_mailbox_message2(m, e, hc) == -1)
      goto err;
  }

#ifdef USE_HCACHE
  if (hc)
  {
    for (int i = 0; i < m->msg_count; i++)
    {
      if (e->changed)
      {
        const char *key = e->path + 3;
        size_t keylen = maildir_hcache_keylen(key);
        mutt_hcache_store(hc, key, keylen, e, 0);
      }
    }
  }
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
  mutt_hcache_close(hc);
#endif
  return -1;
}

