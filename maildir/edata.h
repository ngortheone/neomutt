/**
 * @file
 * Maildir-specific Email data
 *
 * @authors
 * Copyright (C) 2020 Richard Russon <rich@flatcap.org>
 *
 * @copyright
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef MUTT_MAILDIR_EDATA_H
#define MUTT_MAILDIR_EDATA_H

struct Email;

typedef uint8_t MaildirEmailFlags; ///< Flags for XXX, e.g. #MD_REPLIED
#define MD_NO_FLAGS        0       ///< No flags are set
#define MD_DIR_CUR   (1 << 0)      ///< Email is in 'cur' directory
#define MD_DIR_NEW   (1 << 1)      ///< Email is in 'new' directory
#define MD_FLAGGED   (1 << 2)      ///< Email is flagged
#define MD_NEW       (1 << 3)      ///< Email is new
#define MD_OLD       (1 << 4)      ///< Email is old
#define MD_REPLIED   (1 << 5)      ///< Email has been replied to
#define MD_SEEN      (1 << 6)      ///< Email has been seen, but not read
#define MD_TRASHED   (1 << 7)      ///< Email has Maildir 'trashed' flag set

/**
 * struct MaildirEmailData - Maildir-specific Email data - @extends Email
 *
 * @note Also used by MH Mailboxes
 */
struct MaildirEmailData
{
  char *maildir_flags;     ///< Unknown Maildir flags
  char *canon_fname;       ///< Canonical filename (no path, no flags)
  MaildirEmailFlags flags; ///< XXX
};

void                     maildir_edata_free(void **ptr);
struct MaildirEmailData *maildir_edata_get(struct Email *e);
struct MaildirEmailData *maildir_edata_new(void);

#endif /* MUTT_MAILDIR_EDATA_H */
