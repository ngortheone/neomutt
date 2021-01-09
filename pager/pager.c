/**
 * @file
 * GUI display a file/email/help in a viewport with paging
 *
 * @authors
 * Copyright (C) 1996-2002,2007,2010,2012-2013 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2020 R Primus <rprimus@gmail.com>
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

/**
 * @page pager_pager GUI display a file/email/help in a viewport with paging
 *
 * GUI display a file/email/help in a viewport with paging
 */

#include "config.h"
#include <ctype.h>
#include <errno.h>
#include <inttypes.h> // IWYU pragma: keep
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wchar.h>
#include "private.h"
#include "mutt/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "alias/lib.h"
#include "gui/lib.h"
#include "mutt.h"
#include "ncrypt/lib.h"
#include "pager/lib.h"
#include "send/lib.h"
#include "commands.h"
#include "context.h"
#include "format_flags.h"
#include "hdrline.h"
#include "hook.h"
#include "index.h"
#include "init.h"
#include "keymap.h"
#include "mutt_attach.h"
#include "mutt_globals.h"
#include "mutt_header.h"
#include "mutt_logging.h"
#include "mutt_mailbox.h"
#include "mutt_menu.h"
#include "muttlib.h"
#include "mx.h"
#include "opcodes.h"
#include "options.h"
#include "protos.h"
#include "recvattach.h"
#include "recvcmd.h"
#include "status.h"
#ifdef USE_SIDEBAR
#include "sidebar/lib.h"
#endif
#ifdef USE_NNTP
#include "nntp/lib.h"
#endif
#ifdef ENABLE_NLS
#include <libintl.h>
#endif

// clang-format off
typedef uint8_t AnsiFlags;      ///< Flags, e.g. #ANSI_OFF
#define ANSI_NO_FLAGS        0  ///< No flags are set
#define ANSI_OFF       (1 << 0) ///< Turn off colours and attributes
#define ANSI_BLINK     (1 << 1) ///< Blinking text
#define ANSI_BOLD      (1 << 2) ///< Bold text
#define ANSI_UNDERLINE (1 << 3) ///< Underlined text
#define ANSI_REVERSE   (1 << 4) ///< Reverse video
#define ANSI_COLOR     (1 << 5) ///< Use colours
// clang-format on

/**
 * struct QClass - Style of quoted text
 */
struct QClass
{
  size_t length;
  int index;
  int color;
  char *prefix;
  struct QClass *next, *prev;
  struct QClass *down, *up;
};

/**
 * struct TextSyntax - Highlighting for a line of text
 */
struct TextSyntax
{
  int color;
  int first;
  int last;
};

/**
 * struct Line - A line of text in the pager
 */
struct Line
{
  LOFF_T offset;
  short type;
  short continuation;
  short chunks;
  short search_cnt;
  struct TextSyntax *syntax;
  struct TextSyntax *search;
  struct QClass *quote;
  unsigned int is_cont_hdr; ///< this line is a continuation of the previous header line
};

/**
 * struct AnsiAttr - An ANSI escape sequence
 */
struct AnsiAttr
{
  AnsiFlags attr; ///< Attributes, e.g. underline, bold, etc
  int fg;         ///< Foreground colour
  int bg;         ///< Background colour
  int pair;       ///< Curses colour pair
};

/**
 * struct Resize - Keep track of screen resizing
 */
struct Resize
{
  int line;
  bool search_compiled;
  bool search_back;
};

/**
 * struct PagerRedrawData - Keep track when the pager needs redrawing
 */
struct PagerRedrawData
{
  PagerFlags flags;
  struct Pager *extra;
  int indexlen;
  int indicator; ///< the indicator line of the PI
  int oldtopline;
  int lines;
  int max_line;
  int last_line;
  int curline;
  int topline;
  bool force_redraw;
  int has_types;
  PagerFlags hide_quoted;
  int q_level;
  struct QClass *quote_list;
  LOFF_T last_pos;
  LOFF_T last_offset;
  struct Menu *menu; ///< the Pager Index (PI)
  regex_t search_re;
  bool search_compiled;
  PagerFlags search_flag;
  bool search_back;
  const char *banner;
  char *searchbuf;
  struct Line *line_info;
  FILE *fp;
  struct stat sb;
};

/* hack to return to position when returning from index to same message */
static int TopLine = 0;
static struct Email *OldEmail = NULL;

static bool InHelp = false;

static int braille_line = -1;
static int braille_col = -1;

static struct Resize *Resize = NULL;

static const char *Not_available_in_this_menu =
    N_("Not available in this menu");
static const char *Mailbox_is_read_only = N_("Mailbox is read-only");
static const char *Function_not_permitted_in_attach_message_mode =
    N_("Function not permitted in attach-message mode");

/// Help Bar for the Pager's Help Page
static const struct Mapping PagerHelp[] = {
  // clang-format off
  { N_("Exit"),          OP_EXIT },
  { N_("PrevPg"),        OP_PREV_PAGE },
  { N_("NextPg"),        OP_NEXT_PAGE },
  { N_("Help"),          OP_HELP },
  { NULL, 0 },
  // clang-format on
};

/// Help Bar for the Help Page itself
static const struct Mapping PagerHelpHelp[] = {
  // clang-format off
  { N_("Exit"),          OP_EXIT },
  { N_("PrevPg"),        OP_PREV_PAGE },
  { N_("NextPg"),        OP_NEXT_PAGE },
  { NULL, 0 },
  // clang-format on
};

/// Help Bar for the Pager of a normal Mailbox
static const struct Mapping PagerNormalHelp[] = {
  // clang-format off
  { N_("Exit"),          OP_EXIT },
  { N_("PrevPg"),        OP_PREV_PAGE },
  { N_("NextPg"),        OP_NEXT_PAGE },
  { N_("View Attachm."), OP_VIEW_ATTACHMENTS },
  { N_("Del"),           OP_DELETE },
  { N_("Reply"),         OP_REPLY },
  { N_("Next"),          OP_MAIN_NEXT_UNDELETED },
  { N_("Help"),          OP_HELP },
  { NULL, 0 },
  // clang-format on
};

#ifdef USE_NNTP
/// Help Bar for the Pager of an NNTP Mailbox
static const struct Mapping PagerNewsHelp[] = {
  // clang-format off
  { N_("Exit"),          OP_EXIT },
  { N_("PrevPg"),        OP_PREV_PAGE },
  { N_("NextPg"),        OP_NEXT_PAGE },
  { N_("Post"),          OP_POST },
  { N_("Followup"),      OP_FOLLOWUP },
  { N_("Del"),           OP_DELETE },
  { N_("Next"),          OP_MAIN_NEXT_UNDELETED },
  { N_("Help"),          OP_HELP },
  { NULL, 0 },
  // clang-format on
};
#endif

#define IS_HEADER(x) ((x) == MT_COLOR_HEADER || (x) == MT_COLOR_HDRDEFAULT)

#define IsAttach(pager) (pager && (pager)->body)
#define IsMsgAttach(pager)                                                     \
  (pager && (pager)->fp && (pager)->body && (pager)->body->email)
#define IsEmail(pager) (pager && (pager)->email && !(pager)->body)

#define NUM_SIG_LINES 4

#define CHECK_MODE(test)                                                       \
  if (!(test))                                                                 \
  {                                                                            \
    mutt_flushinp();                                                           \
    mutt_error(_(Not_available_in_this_menu));                                 \
    break;                                                                     \
  }

#define CHECK_READONLY                                                         \
  if (!Context || Context->mailbox->readonly)                                  \
  {                                                                            \
    mutt_flushinp();                                                           \
    mutt_error(_(Mailbox_is_read_only));                                       \
    break;                                                                     \
  }

#define CHECK_ATTACH                                                           \
  if (OptAttachMsg)                                                            \
  {                                                                            \
    mutt_flushinp();                                                           \
    mutt_error(_(Function_not_permitted_in_attach_message_mode));              \
    break;                                                                     \
  }

#define CHECK_ACL(aclbit, action)                                              \
  if (!Context || !(Context->mailbox->rights & aclbit))                        \
  {                                                                            \
    mutt_flushinp();                                                           \
    /* L10N: %s is one of the CHECK_ACL entries below. */                      \
    mutt_error(_("%s: Operation not permitted by ACL"), action);               \
    break;                                                                     \
  }

/**
 * cleanup_quote - Free a quote list
 * @param[out] quote_list Quote list to free
 */
static void cleanup_quote(struct QClass **quote_list)
{
  struct QClass *ptr = NULL;

  while (*quote_list)
  {
    if ((*quote_list)->down)
      cleanup_quote(&((*quote_list)->down));
    ptr = (*quote_list)->next;
    FREE(&(*quote_list)->prefix);
    FREE(quote_list);
    *quote_list = ptr;
  }
}

/**
 * up_n_lines - Reposition the pager's view up by n lines
 * @param nlines Number of lines to move
 * @param info   Line info array
 * @param cur    Current line number
 * @param hiding true if lines have been hidden
 * @retval num New current line number
 */
static int up_n_lines(int nlines, struct Line *info, int cur, bool hiding)
{
  while ((cur > 0) && (nlines > 0))
  {
    cur--;
    if (!hiding || (info[cur].type != MT_COLOR_QUOTED))
      nlines--;
  }

  return cur;
}

/**
 * mutt_clear_pager_position - Reset the pager's viewing position
 */
void mutt_clear_pager_position(void)
{
  TopLine = 0;
  OldEmail = NULL;
}

/**
 * pager_custom_redraw - Redraw the pager window - Implements Menu::custom_redraw()
 */
static void pager_custom_redraw(struct Menu *pager_menu)
{
  struct PagerRedrawData *rd = pager_menu->redraw_data;
  struct Mailbox *m = ctx_mailbox(Context);
  char buf[1024];

  if (!rd)
    return;

  if (pager_menu->redraw & REDRAW_FULL)
  {
    mutt_curses_set_color(MT_COLOR_NORMAL);
    mutt_window_clear(rd->extra->win_pager);

    if (IsEmail(rd->extra) && m && ((m->vcount + 1) < C_PagerIndexLines))
    {
      rd->indexlen = m->vcount + 1;
    }
    else
      rd->indexlen = C_PagerIndexLines;

    rd->indicator = rd->indexlen / 3;

    if (Resize)
    {
      rd->search_compiled = Resize->search_compiled;
      if (rd->search_compiled)
      {
        int flags = mutt_mb_is_lower(rd->searchbuf) ? REG_ICASE : 0;
        const int err = REG_COMP(&rd->search_re, rd->searchbuf, REG_NEWLINE | flags);
        if (err == 0)
        {
          rd->search_flag = MUTT_SEARCH;
          rd->search_back = Resize->search_back;
        }
        else
        {
          regerror(err, &rd->search_re, buf, sizeof(buf));
          mutt_error("%s", buf);
          rd->search_compiled = false;
        }
      }
      rd->lines = Resize->line;
      pager_menu->redraw |= REDRAW_FLOW;

      FREE(&Resize);
    }

    if (IsEmail(rd->extra) && (C_PagerIndexLines != 0))
    {
      if (!rd->menu)
      {
        /* only allocate the space if/when we need the index.
         * Initialise the menu as per the main index */
        rd->menu = mutt_menu_new(MENU_MAIN);
        rd->menu->make_entry = index_make_entry;
        rd->menu->color = index_color;
        rd->menu->max = Context ? m->vcount : 0;
        rd->menu->current = rd->extra->email->vnum;
        rd->menu->win_index = rd->extra->win_index;
        rd->menu->win_ibar = rd->extra->win_ibar;
      }

      mutt_curses_set_color(MT_COLOR_NORMAL);
      rd->menu->pagelen = rd->extra->win_index->state.rows;

      /* some fudge to work out whereabouts the indicator should go */
      if (rd->menu->current - rd->indicator < 0)
        rd->menu->top = 0;
      else if (rd->menu->max - rd->menu->current < rd->menu->pagelen - rd->indicator)
        rd->menu->top = rd->menu->max - rd->menu->pagelen;
      else
        rd->menu->top = rd->menu->current - rd->indicator;

      menu_redraw_index(rd->menu);
    }

    pager_menu->redraw |= REDRAW_BODY | REDRAW_INDEX | REDRAW_STATUS;
    mutt_show_error();
  }

  if (pager_menu->redraw & REDRAW_FLOW)
  {
    if (!(rd->flags & MUTT_PAGER_RETWINCH))
    {
      rd->lines = -1;
      for (int i = 0; i <= rd->topline; i++)
        if (!rd->line_info[i].continuation)
          rd->lines++;
      for (int i = 0; i < rd->max_line; i++)
      {
        rd->line_info[i].offset = 0;
        rd->line_info[i].type = -1;
        rd->line_info[i].continuation = 0;
        rd->line_info[i].chunks = 0;
        rd->line_info[i].search_cnt = -1;
        rd->line_info[i].quote = NULL;

        mutt_mem_realloc(&(rd->line_info[i].syntax), sizeof(struct TextSyntax));
        if (rd->search_compiled && rd->line_info[i].search)
          FREE(&(rd->line_info[i].search));
      }

      rd->last_line = 0;
      rd->topline = 0;
    }
    int i = -1;
    int j = -1;
    while (display_line(rd->fp, &rd->last_pos, &rd->line_info, ++i, &rd->last_line,
                        &rd->max_line, rd->has_types | rd->search_flag | (rd->flags & MUTT_PAGER_NOWRAP),
                        &rd->quote_list, &rd->q_level, &rd->force_redraw,
                        &rd->search_re, rd->extra->win_pager) == 0)
    {
      if (!rd->line_info[i].continuation && (++j == rd->lines))
      {
        rd->topline = i;
        if (!rd->search_flag)
          break;
      }
    }
  }

  if ((pager_menu->redraw & REDRAW_BODY) || (rd->topline != rd->oldtopline))
  {
    do
    {
      mutt_window_move(rd->extra->win_pager, 0, 0);
      rd->curline = rd->topline;
      rd->oldtopline = rd->topline;
      rd->lines = 0;
      rd->force_redraw = false;

      while ((rd->lines < rd->extra->win_pager->state.rows) &&
             (rd->line_info[rd->curline].offset <= rd->sb.st_size - 1))
      {
        if (display_line(rd->fp, &rd->last_pos, &rd->line_info, rd->curline,
                         &rd->last_line, &rd->max_line,
                         (rd->flags & MUTT_DISPLAYFLAGS) | rd->hide_quoted |
                             rd->search_flag | (rd->flags & MUTT_PAGER_NOWRAP),
                         &rd->quote_list, &rd->q_level, &rd->force_redraw,
                         &rd->search_re, rd->extra->win_pager) > 0)
        {
          rd->lines++;
        }
        rd->curline++;
        mutt_window_move(rd->extra->win_pager, 0, rd->lines);
      }
      rd->last_offset = rd->line_info[rd->curline].offset;
    } while (rd->force_redraw);

    mutt_curses_set_color(MT_COLOR_TILDE);
    while (rd->lines < rd->extra->win_pager->state.rows)
    {
      mutt_window_clrtoeol(rd->extra->win_pager);
      if (C_Tilde)
        mutt_window_addch('~');
      rd->lines++;
      mutt_window_move(rd->extra->win_pager, 0, rd->lines);
    }
    mutt_curses_set_color(MT_COLOR_NORMAL);

    /* We are going to update the pager status bar, so it isn't
     * necessary to reset to normal color now. */

    pager_menu->redraw |= REDRAW_STATUS; /* need to update the % seen */
  }

  if (pager_menu->redraw & REDRAW_STATUS)
  {
    struct HdrFormatInfo hfi;
    char pager_progress_str[65]; /* Lots of space for translations */

    hfi.mailbox = m;
    hfi.msg_in_pager = Context ? Context->msg_in_pager : -1;
    hfi.pager_progress = pager_progress_str;

    if (rd->last_pos < rd->sb.st_size - 1)
    {
      snprintf(pager_progress_str, sizeof(pager_progress_str), OFF_T_FMT "%%",
               (100 * rd->last_offset / rd->sb.st_size));
    }
    else
    {
      const char *msg = (rd->topline == 0) ?
                            /* L10N: Status bar message: the entire email is visible in the pager */
                            _("all") :
                            /* L10N: Status bar message: the end of the email is visible in the pager */
                            _("end");
      mutt_str_copy(pager_progress_str, msg, sizeof(pager_progress_str));
    }

    /* print out the pager status bar */
    mutt_window_move(rd->extra->win_pbar, 0, 0);
    mutt_curses_set_color(MT_COLOR_STATUS);

    if (IsEmail(rd->extra) || IsMsgAttach(rd->extra))
    {
      size_t l1 = rd->extra->win_pbar->state.cols * MB_LEN_MAX;
      size_t l2 = sizeof(buf);
      hfi.email = (IsEmail(rd->extra)) ? rd->extra->email : rd->extra->body->email;
      mutt_make_string_info(buf, (l1 < l2) ? l1 : l2, rd->extra->win_pbar->state.cols,
                            NONULL(C_PagerFormat), &hfi, MUTT_FORMAT_NO_FLAGS);
      mutt_draw_statusline(rd->extra->win_pbar->state.cols, buf, l2);
    }
    else
    {
      char bn[256];
      snprintf(bn, sizeof(bn), "%s (%s)", rd->banner, pager_progress_str);
      mutt_draw_statusline(rd->extra->win_pbar->state.cols, bn, sizeof(bn));
    }
    mutt_curses_set_color(MT_COLOR_NORMAL);
    if (C_TsEnabled && TsSupported && rd->menu)
    {
      menu_status_line(buf, sizeof(buf), rd->menu, m, NONULL(C_TsStatusFormat));
      mutt_ts_status(buf);
      menu_status_line(buf, sizeof(buf), rd->menu, m, NONULL(C_TsIconFormat));
      mutt_ts_icon(buf);
    }
  }

  if ((pager_menu->redraw & REDRAW_INDEX) && rd->menu)
  {
    /* redraw the pager_index indicator, because the
     * flags for this message might have changed. */
    if (rd->extra->win_index->state.rows > 0)
      menu_redraw_current(rd->menu);

    /* print out the index status bar */
    menu_status_line(buf, sizeof(buf), rd->menu, m, NONULL(C_StatusFormat));

    mutt_window_move(rd->extra->win_ibar, 0, 0);
    mutt_curses_set_color(MT_COLOR_STATUS);
    mutt_draw_statusline(rd->extra->win_ibar->state.cols, buf, sizeof(buf));
    mutt_curses_set_color(MT_COLOR_NORMAL);
  }

  pager_menu->redraw = REDRAW_NO_FLAGS;
}

/**
 * mutt_pager - Display a file, or help, in a window
 * @param banner Title to display in status bar
 * @param fname  Name of file to read
 * @param flags  Flags, e.g. #MUTT_SHOWCOLOR
 * @param extra  Info about email to display
 * @retval  0 Success
 * @retval -1 Error
 *
 * This pager is actually not so simple as it once was.  It now operates in two
 * modes: one for viewing messages and the other for viewing help.  These can
 * be distinguished by whether or not "email" is NULL.  The "email" arg is
 * there so that we can do operations on the current message without the need
 * to pop back out to the main-menu.
 */
int mutt_pager(const char *banner, const char *fname, PagerFlags flags, struct Pager *extra)
{
  static char searchbuf[256] = { 0 };
  char buf[1024];
  int ch = 0, rc = -1;
  bool first = true;
  int searchctx = 0;
  bool wrapped = false;

  struct Menu *pager_menu = NULL;
  int old_PagerIndexLines; /* some people want to resize it while inside the pager */
#ifdef USE_NNTP
  char *followup_to = NULL;
#endif

  struct Mailbox *m = ctx_mailbox(Context);

  if (!(flags & MUTT_SHOWCOLOR))
    flags |= MUTT_SHOWFLAT;

  int index_space = C_PagerIndexLines;
  if (extra->ctx && extra->ctx->mailbox)
    index_space = MIN(index_space, extra->ctx->mailbox->vcount);

  struct PagerRedrawData rd = { 0 };
  rd.banner = banner;
  rd.flags = flags;
  rd.extra = extra;
  rd.indexlen = index_space;
  rd.indicator = rd.indexlen / 3;
  rd.searchbuf = searchbuf;
  rd.has_types = (IsEmail(extra) || (flags & MUTT_SHOWCOLOR)) ? MUTT_TYPES : 0; /* main message or rfc822 attachment */

  rd.fp = fopen(fname, "r");
  if (!rd.fp)
  {
    mutt_perror(fname);
    return -1;
  }

  if (stat(fname, &rd.sb) != 0)
  {
    mutt_perror(fname);
    mutt_file_fclose(&rd.fp);
    return -1;
  }
  unlink(fname);

  if (rd.extra->win_index)
  {
    rd.extra->win_index->size = MUTT_WIN_SIZE_FIXED;
    rd.extra->win_index->req_rows = index_space;
    rd.extra->win_index->parent->size = MUTT_WIN_SIZE_MINIMISE;
    window_set_visible(rd.extra->win_index->parent, (index_space > 0));
  }
  window_set_visible(rd.extra->win_pager->parent, true);
  rd.extra->win_pager->size = MUTT_WIN_SIZE_MAXIMISE;
  mutt_window_reflow(dialog_find(rd.extra->win_pager));

  /* Initialize variables */

  if (Context && IsEmail(extra) && !extra->email->read)
  {
    Context->msg_in_pager = extra->email->msgno;
    mutt_set_flag(m, extra->email, MUTT_READ, true);
  }

  rd.max_line = LINES; /* number of lines on screen, from curses */
  rd.line_info = mutt_mem_calloc(rd.max_line, sizeof(struct Line));
  for (size_t i = 0; i < rd.max_line; i++)
  {
    rd.line_info[i].type = -1;
    rd.line_info[i].search_cnt = -1;
    rd.line_info[i].syntax = mutt_mem_malloc(sizeof(struct TextSyntax));
    (rd.line_info[i].syntax)[0].first = -1;
    (rd.line_info[i].syntax)[0].last = -1;
  }

  pager_menu = mutt_menu_new(MENU_PAGER);
  pager_menu->pagelen = extra->win_pager->state.rows;
  pager_menu->win_index = extra->win_pager;
  pager_menu->win_ibar = extra->win_pbar;

  pager_menu->custom_redraw = pager_custom_redraw;
  pager_menu->redraw_data = &rd;
  mutt_menu_push_current(pager_menu);

  if (IsEmail(extra))
  {
    // Viewing a Mailbox
#ifdef USE_NNTP
    if (m && (m->type == MUTT_NNTP))
      extra->win_pager->help_data = PagerNewsHelp;
    else
#endif
      extra->win_pager->help_data = PagerNormalHelp;
  }
  else
  {
    // Viewing Help
    if (InHelp)
      extra->win_pager->help_data = PagerHelpHelp;
    else
      extra->win_pager->help_data = PagerHelp;
  }
  extra->win_pager->help_menu = MENU_PAGER;
  window_set_focus(extra->win_pager);

  while (ch != -1)
  {
    mutt_curses_set_cursor(MUTT_CURSOR_INVISIBLE);

    pager_custom_redraw(pager_menu);
    window_redraw(RootWindow, true);

    if (C_BrailleFriendly)
    {
      if (braille_line != -1)
      {
        mutt_window_move_abs(0, braille_line + 1);
        braille_line = -1;
      }
    }
    else
      mutt_window_move(rd.extra->win_pbar, rd.extra->win_pager->state.cols - 1, 0);

    mutt_refresh();

    if (IsEmail(extra) && (OldEmail == extra->email) && (TopLine != rd.topline) &&
        (rd.line_info[rd.curline].offset < (rd.sb.st_size - 1)))
    {
      if ((TopLine - rd.topline) > rd.lines)
        rd.topline += rd.lines;
      else
        rd.topline = TopLine;
      continue;
    }
    else
      OldEmail = NULL;

    ch = km_dokey(MENU_PAGER);
    if (ch >= 0)
    {
      mutt_clear_error();
      mutt_debug(LL_DEBUG1, "Got op %s (%d)\n", OpStrings[ch][0], ch);
    }
    mutt_curses_set_cursor(MUTT_CURSOR_VISIBLE);

    bool do_new_mail = false;

    if (m && !OptAttachMsg)
    {
      int oldcount = m->msg_count;
      /* check for new mail */
      int check = mx_mbox_check(m);
      if (check < 0)
      {
        if (!m || mutt_buffer_is_empty(&m->pathbuf))
        {
          /* fatal error occurred */
          ctx_free(&Context);
          pager_menu->redraw = REDRAW_FULL;
          break;
        }
      }
      else if ((check == MUTT_NEW_MAIL) || (check == MUTT_REOPENED) || (check == MUTT_FLAGS))
      {
        /* notify user of newly arrived mail */
        if (check == MUTT_NEW_MAIL)
        {
          for (size_t i = oldcount; i < m->msg_count; i++)
          {
            struct Email *e = m->emails[i];

            if (e && !e->read)
            {
              mutt_message(_("New mail in this mailbox"));
              do_new_mail = true;
              break;
            }
          }
        }

        if ((check == MUTT_NEW_MAIL) || (check == MUTT_REOPENED))
        {
          if (rd.menu && m)
          {
            /* After the mailbox has been updated,
             * rd.menu->current might be invalid */
            rd.menu->current = MIN(rd.menu->current, MAX(m->msg_count - 1, 0));
            struct Email *e = mutt_get_virt_email(m, rd.menu->current);
            if (!e)
              continue;

            bool verbose = m->verbose;
            m->verbose = false;
            mutt_update_index(rd.menu, Context, check, oldcount, e);
            m->verbose = verbose;

            rd.menu->max = m->vcount;

            /* If these header pointers don't match, then our email may have
             * been deleted.  Make the pointer safe, then leave the pager.
             * This have a unpleasant behaviour to close the pager even the
             * deleted message is not the opened one, but at least it's safe. */
            e = mutt_get_virt_email(m, rd.menu->current);
            if (extra->email != e)
            {
              extra->email = e;
              break;
            }
          }

          pager_menu->redraw = REDRAW_FULL;
          OptSearchInvalid = true;
        }
      }

      if (mutt_mailbox_notify(m) || do_new_mail)
      {
        if (C_BeepNew)
          mutt_beep(true);
        if (C_NewMailCommand)
        {
          char cmd[1024];
          menu_status_line(cmd, sizeof(cmd), rd.menu, m, NONULL(C_NewMailCommand));
          if (mutt_system(cmd) != 0)
            mutt_error(_("Error running \"%s\""), cmd);
        }
      }
    }

    if (SigWinch)
    {
      SigWinch = 0;
      mutt_resize_screen();
      clearok(stdscr, true); /* force complete redraw */
      mutt_window_clearline(MessageWindow, 0);

      if (flags & MUTT_PAGER_RETWINCH)
      {
        /* Store current position. */
        rd.lines = -1;
        for (size_t i = 0; i <= rd.topline; i++)
          if (!rd.line_info[i].continuation)
            rd.lines++;

        Resize = mutt_mem_malloc(sizeof(struct Resize));

        Resize->line = rd.lines;
        Resize->search_compiled = rd.search_compiled;
        Resize->search_back = rd.search_back;

        ch = -1;
        rc = OP_REFORMAT_WINCH;
      }
      else
      {
        /* note: mutt_resize_screen() -> mutt_window_reflow() sets
         * REDRAW_FULL and REDRAW_FLOW */
        ch = 0;
      }
      continue;
    }

    if (ch < 0)
    {
      ch = 0;
      mutt_timeout_hook();
      continue;
    }

    rc = ch;

    switch (ch)
    {
      case OP_EXIT:
        rc = -1;
        ch = -1;
        break;

      case OP_QUIT:
        if (query_quadoption(C_Quit, _("Quit NeoMutt?")) == MUTT_YES)
        {
          /* avoid prompting again in the index menu */
          cs_subset_str_native_set(NeoMutt->sub, "quit", MUTT_YES, NULL);
          ch = -1;
        }
        break;

      case OP_NEXT_PAGE:
        if (rd.line_info[rd.curline].offset < (rd.sb.st_size - 1))
        {
          rd.topline = up_n_lines(C_PagerContext, rd.line_info, rd.curline, rd.hide_quoted);
        }
        else if (C_PagerStop)
        {
          /* emulate "less -q" and don't go on to the next message. */
          mutt_error(_("Bottom of message is shown"));
        }
        else
        {
          /* end of the current message, so display the next message. */
          rc = OP_MAIN_NEXT_UNDELETED;
          ch = -1;
        }
        break;

      case OP_PREV_PAGE:
        if (rd.topline == 0)
        {
          mutt_message(_("Top of message is shown"));
        }
        else
        {
          rd.topline = up_n_lines(rd.extra->win_pager->state.rows - C_PagerContext,
                                  rd.line_info, rd.topline, rd.hide_quoted);
        }
        break;

      case OP_NEXT_LINE:
        if (rd.line_info[rd.curline].offset < (rd.sb.st_size - 1))
        {
          rd.topline++;
          if (rd.hide_quoted)
          {
            while ((rd.line_info[rd.topline].type == MT_COLOR_QUOTED) &&
                   (rd.topline < rd.last_line))
            {
              rd.topline++;
            }
          }
        }
        else
          mutt_message(_("Bottom of message is shown"));
        break;

      case OP_PREV_LINE:
        if (rd.topline)
          rd.topline = up_n_lines(1, rd.line_info, rd.topline, rd.hide_quoted);
        else
          mutt_error(_("Top of message is shown"));
        break;

      case OP_PAGER_TOP:
        if (rd.topline)
          rd.topline = 0;
        else
          mutt_error(_("Top of message is shown"));
        break;

      case OP_HALF_UP:
        if (rd.topline)
        {
          rd.topline = up_n_lines(rd.extra->win_pager->state.rows / 2 +
                                      (rd.extra->win_pager->state.rows % 2),
                                  rd.line_info, rd.topline, rd.hide_quoted);
        }
        else
          mutt_error(_("Top of message is shown"));
        break;

      case OP_HALF_DOWN:
        if (rd.line_info[rd.curline].offset < (rd.sb.st_size - 1))
        {
          rd.topline = up_n_lines(rd.extra->win_pager->state.rows / 2,
                                  rd.line_info, rd.curline, rd.hide_quoted);
        }
        else if (C_PagerStop)
        {
          /* emulate "less -q" and don't go on to the next message. */
          mutt_error(_("Bottom of message is shown"));
        }
        else
        {
          /* end of the current message, so display the next message. */
          rc = OP_MAIN_NEXT_UNDELETED;
          ch = -1;
        }
        break;

      case OP_SEARCH_NEXT:
      case OP_SEARCH_OPPOSITE:
        if (rd.search_compiled)
        {
          wrapped = false;

          if (C_SearchContext < rd.extra->win_pager->state.rows)
            searchctx = C_SearchContext;
          else
            searchctx = 0;

        search_next:
          if ((!rd.search_back && (ch == OP_SEARCH_NEXT)) ||
              (rd.search_back && (ch == OP_SEARCH_OPPOSITE)))
          {
            /* searching forward */
            int i;
            for (i = wrapped ? 0 : rd.topline + searchctx + 1; i < rd.last_line; i++)
            {
              if ((!rd.hide_quoted || (rd.line_info[i].type != MT_COLOR_QUOTED)) &&
                  !rd.line_info[i].continuation && (rd.line_info[i].search_cnt > 0))
              {
                break;
              }
            }

            if (i < rd.last_line)
              rd.topline = i;
            else if (wrapped || !C_WrapSearch)
              mutt_error(_("Not found"));
            else
            {
              mutt_message(_("Search wrapped to top"));
              wrapped = true;
              goto search_next;
            }
          }
          else
          {
            /* searching backward */
            int i;
            for (i = wrapped ? rd.last_line : rd.topline + searchctx - 1; i >= 0; i--)
            {
              if ((!rd.hide_quoted ||
                   (rd.has_types && (rd.line_info[i].type != MT_COLOR_QUOTED))) &&
                  !rd.line_info[i].continuation && (rd.line_info[i].search_cnt > 0))
              {
                break;
              }
            }

            if (i >= 0)
              rd.topline = i;
            else if (wrapped || !C_WrapSearch)
              mutt_error(_("Not found"));
            else
            {
              mutt_message(_("Search wrapped to bottom"));
              wrapped = true;
              goto search_next;
            }
          }

          if (rd.line_info[rd.topline].search_cnt > 0)
          {
            rd.search_flag = MUTT_SEARCH;
            /* give some context for search results */
            if (rd.topline - searchctx > 0)
              rd.topline -= searchctx;
          }

          break;
        }
        /* no previous search pattern */
        /* fallthrough */

      case OP_SEARCH:
      case OP_SEARCH_REVERSE:
        mutt_str_copy(buf, searchbuf, sizeof(buf));
        if (mutt_get_field(((ch == OP_SEARCH) || (ch == OP_SEARCH_NEXT)) ?
                               _("Search for: ") :
                               _("Reverse search for: "),
                           buf, sizeof(buf), MUTT_CLEAR | MUTT_PATTERN) != 0)
        {
          break;
        }

        if (strcmp(buf, searchbuf) == 0)
        {
          if (rd.search_compiled)
          {
            /* do an implicit search-next */
            if (ch == OP_SEARCH)
              ch = OP_SEARCH_NEXT;
            else
              ch = OP_SEARCH_OPPOSITE;

            wrapped = false;
            goto search_next;
          }
        }

        if (buf[0] == '\0')
          break;

        mutt_str_copy(searchbuf, buf, sizeof(searchbuf));

        /* leave search_back alone if ch == OP_SEARCH_NEXT */
        if (ch == OP_SEARCH)
          rd.search_back = false;
        else if (ch == OP_SEARCH_REVERSE)
          rd.search_back = true;

        if (rd.search_compiled)
        {
          regfree(&rd.search_re);
          for (size_t i = 0; i < rd.last_line; i++)
          {
            FREE(&(rd.line_info[i].search));
            rd.line_info[i].search_cnt = -1;
          }
        }

        int rflags = mutt_mb_is_lower(searchbuf) ? REG_ICASE : 0;
        int err = REG_COMP(&rd.search_re, searchbuf, REG_NEWLINE | rflags);
        if (err != 0)
        {
          regerror(err, &rd.search_re, buf, sizeof(buf));
          mutt_error("%s", buf);
          for (size_t i = 0; i < rd.max_line; i++)
          {
            /* cleanup */
            FREE(&(rd.line_info[i].search));
            rd.line_info[i].search_cnt = -1;
          }
          rd.search_flag = 0;
          rd.search_compiled = false;
        }
        else
        {
          rd.search_compiled = true;
          /* update the search pointers */
          int line_num = 0;
          while (display_line(rd.fp, &rd.last_pos, &rd.line_info, line_num,
                              &rd.last_line, &rd.max_line,
                              MUTT_SEARCH | (flags & MUTT_PAGER_NSKIP) | (flags & MUTT_PAGER_NOWRAP),
                              &rd.quote_list, &rd.q_level, &rd.force_redraw,
                              &rd.search_re, rd.extra->win_pager) == 0)
          {
            line_num++;
          }

          if (!rd.search_back)
          {
            /* searching forward */
            int i;
            for (i = rd.topline; i < rd.last_line; i++)
            {
              if ((!rd.hide_quoted || (rd.line_info[i].type != MT_COLOR_QUOTED)) &&
                  !rd.line_info[i].continuation && (rd.line_info[i].search_cnt > 0))
              {
                break;
              }
            }

            if (i < rd.last_line)
              rd.topline = i;
          }
          else
          {
            /* searching backward */
            int i;
            for (i = rd.topline; i >= 0; i--)
            {
              if ((!rd.hide_quoted || (rd.line_info[i].type != MT_COLOR_QUOTED)) &&
                  !rd.line_info[i].continuation && (rd.line_info[i].search_cnt > 0))
              {
                break;
              }
            }

            if (i >= 0)
              rd.topline = i;
          }

          if (rd.line_info[rd.topline].search_cnt == 0)
          {
            rd.search_flag = 0;
            mutt_error(_("Not found"));
          }
          else
          {
            rd.search_flag = MUTT_SEARCH;
            /* give some context for search results */
            if (C_SearchContext < rd.extra->win_pager->state.rows)
              searchctx = C_SearchContext;
            else
              searchctx = 0;
            if (rd.topline - searchctx > 0)
              rd.topline -= searchctx;
          }
        }
        pager_menu->redraw = REDRAW_BODY;
        break;

      case OP_SEARCH_TOGGLE:
        if (rd.search_compiled)
        {
          rd.search_flag ^= MUTT_SEARCH;
          pager_menu->redraw = REDRAW_BODY;
        }
        break;

      case OP_SORT:
      case OP_SORT_REVERSE:
        CHECK_MODE(IsEmail(extra))
        if (mutt_select_sort((ch == OP_SORT_REVERSE)) == 0)
        {
          OptNeedResort = true;
          ch = -1;
          rc = OP_DISPLAY_MESSAGE;
        }
        break;

      case OP_HELP:
        if (InHelp)
        {
          /* don't let the user enter the help-menu from the help screen! */
          mutt_error(_("Help is currently being shown"));
          break;
        }

        InHelp = true;
        mutt_help(MENU_PAGER, pager_menu->win_index->state.cols);
        pager_menu->redraw = REDRAW_FULL;
        InHelp = false;
        break;

      case OP_PAGER_HIDE_QUOTED:
        if (!rd.has_types)
          break;

        rd.hide_quoted ^= MUTT_HIDE;
        if (rd.hide_quoted && (rd.line_info[rd.topline].type == MT_COLOR_QUOTED))
          rd.topline = up_n_lines(1, rd.line_info, rd.topline, rd.hide_quoted);
        else
          pager_menu->redraw = REDRAW_BODY;
        break;

      case OP_PAGER_SKIP_QUOTED:
        if (!rd.has_types)
          break;

        int dretval = 0;
        int new_topline = rd.topline;

        /* Skip all the email headers */
        if (IS_HEADER(rd.line_info[new_topline].type))
        {
          while (((new_topline < rd.last_line) ||
                  (0 == (dretval = display_line(
                             rd.fp, &rd.last_pos, &rd.line_info, new_topline, &rd.last_line,
                             &rd.max_line, MUTT_TYPES | (flags & MUTT_PAGER_NOWRAP),
                             &rd.quote_list, &rd.q_level, &rd.force_redraw,
                             &rd.search_re, rd.extra->win_pager)))) &&
                 IS_HEADER(rd.line_info[new_topline].type))
          {
            new_topline++;
          }
          rd.topline = new_topline;
          break;
        }

        while ((((new_topline + C_SkipQuotedOffset) < rd.last_line) ||
                (0 == (dretval = display_line(
                           rd.fp, &rd.last_pos, &rd.line_info, new_topline, &rd.last_line,
                           &rd.max_line, MUTT_TYPES | (flags & MUTT_PAGER_NOWRAP),
                           &rd.quote_list, &rd.q_level, &rd.force_redraw,
                           &rd.search_re, rd.extra->win_pager)))) &&
               (rd.line_info[new_topline + C_SkipQuotedOffset].type != MT_COLOR_QUOTED))
        {
          new_topline++;
        }

        if (dretval < 0)
        {
          mutt_error(_("No more quoted text"));
          break;
        }

        while ((((new_topline + C_SkipQuotedOffset) < rd.last_line) ||
                (0 == (dretval = display_line(
                           rd.fp, &rd.last_pos, &rd.line_info, new_topline, &rd.last_line,
                           &rd.max_line, MUTT_TYPES | (flags & MUTT_PAGER_NOWRAP),
                           &rd.quote_list, &rd.q_level, &rd.force_redraw,
                           &rd.search_re, rd.extra->win_pager)))) &&
               (rd.line_info[new_topline + C_SkipQuotedOffset].type == MT_COLOR_QUOTED))
        {
          new_topline++;
        }

        if (dretval < 0)
        {
          mutt_error(_("No more unquoted text after quoted text"));
          break;
        }
        rd.topline = new_topline;
        break;

      case OP_PAGER_BOTTOM: /* move to the end of the file */
        if (rd.line_info[rd.curline].offset < (rd.sb.st_size - 1))
        {
          int line_num = rd.curline;
          /* make sure the types are defined to the end of file */
          while (display_line(rd.fp, &rd.last_pos, &rd.line_info, line_num, &rd.last_line,
                              &rd.max_line, rd.has_types | (flags & MUTT_PAGER_NOWRAP),
                              &rd.quote_list, &rd.q_level, &rd.force_redraw,
                              &rd.search_re, rd.extra->win_pager) == 0)
          {
            line_num++;
          }
          rd.topline = up_n_lines(rd.extra->win_pager->state.rows, rd.line_info,
                                  rd.last_line, rd.hide_quoted);
        }
        else
          mutt_error(_("Bottom of message is shown"));
        break;

      case OP_REDRAW:
        mutt_window_reflow(NULL);
        clearok(stdscr, true);
        pager_menu->redraw = REDRAW_FULL;
        break;

      case OP_NULL:
        km_error_key(MENU_PAGER);
        break;

        /* --------------------------------------------------------------------
         * The following are operations on the current message rather than
         * adjusting the view of the message.  */

      case OP_BOUNCE_MESSAGE:
      {
        CHECK_MODE(IsEmail(extra) || IsMsgAttach(extra))
        CHECK_ATTACH;
        if (IsMsgAttach(extra))
          mutt_attach_bounce(m, extra->fp, extra->actx, extra->body);
        else
        {
          struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
          emaillist_add_email(&el, extra->email);
          ci_bounce_message(m, &el);
          emaillist_clear(&el);
        }
        break;
      }

      case OP_RESEND:
        CHECK_MODE(IsEmail(extra) || IsMsgAttach(extra))
        CHECK_ATTACH;
        if (IsMsgAttach(extra))
          mutt_attach_resend(extra->fp, extra->actx, extra->body);
        else
          mutt_resend_message(NULL, extra->ctx, extra->email, NeoMutt->sub);
        pager_menu->redraw = REDRAW_FULL;
        break;

      case OP_COMPOSE_TO_SENDER:
        CHECK_MODE(IsEmail(extra) || IsMsgAttach(extra));
        CHECK_ATTACH;
        if (IsMsgAttach(extra))
          mutt_attach_mail_sender(extra->fp, extra->email, extra->actx, extra->body);
        else
        {
          struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
          emaillist_add_email(&el, extra->email);
          mutt_send_message(SEND_TO_SENDER, NULL, NULL, extra->ctx, &el, NeoMutt->sub);
          emaillist_clear(&el);
        }
        pager_menu->redraw = REDRAW_FULL;
        break;

      case OP_CHECK_TRADITIONAL:
        CHECK_MODE(IsEmail(extra));
        if (!(WithCrypto & APPLICATION_PGP))
          break;
        if (!(extra->email->security & PGP_TRADITIONAL_CHECKED))
        {
          ch = -1;
          rc = OP_CHECK_TRADITIONAL;
        }
        break;

      case OP_CREATE_ALIAS:
        CHECK_MODE(IsEmail(extra) || IsMsgAttach(extra));
        struct AddressList *al = NULL;
        if (IsMsgAttach(extra))
          al = mutt_get_address(extra->body->email->env, NULL);
        else
          al = mutt_get_address(extra->email->env, NULL);
        alias_create(al, NeoMutt->sub);
        break;

      case OP_PURGE_MESSAGE:
      case OP_DELETE:
        CHECK_MODE(IsEmail(extra));
        CHECK_READONLY;
        /* L10N: CHECK_ACL */
        CHECK_ACL(MUTT_ACL_DELETE, _("Can't delete message"));

        mutt_set_flag(Context->mailbox, extra->email, MUTT_DELETE, true);
        mutt_set_flag(Context->mailbox, extra->email, MUTT_PURGE, (ch == OP_PURGE_MESSAGE));
        if (C_DeleteUntag)
          mutt_set_flag(Context->mailbox, extra->email, MUTT_TAG, false);
        pager_menu->redraw |= REDRAW_STATUS | REDRAW_INDEX;
        if (C_Resolve)
        {
          ch = -1;
          rc = OP_MAIN_NEXT_UNDELETED;
        }
        break;

      case OP_MAIN_SET_FLAG:
      case OP_MAIN_CLEAR_FLAG:
      {
        CHECK_MODE(IsEmail(extra));
        CHECK_READONLY;

        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        emaillist_add_email(&el, extra->email);

        if (mutt_change_flag(Context->mailbox, &el, (ch == OP_MAIN_SET_FLAG)) == 0)
          pager_menu->redraw |= REDRAW_STATUS | REDRAW_INDEX;
        if (extra->email->deleted && C_Resolve)
        {
          ch = -1;
          rc = OP_MAIN_NEXT_UNDELETED;
        }
        emaillist_clear(&el);
        break;
      }

      case OP_DELETE_THREAD:
      case OP_DELETE_SUBTHREAD:
      case OP_PURGE_THREAD:
      {
        CHECK_MODE(IsEmail(extra));
        CHECK_READONLY;
        /* L10N: CHECK_ACL */
        /* L10N: Due to the implementation details we do not know whether we
           delete zero, 1, 12, ... messages. So in English we use
           "messages". Your language might have other means to express this.  */
        CHECK_ACL(MUTT_ACL_DELETE, _("Can't delete messages"));

        int subthread = (ch == OP_DELETE_SUBTHREAD);
        int r = mutt_thread_set_flag(extra->email, MUTT_DELETE, 1, subthread);
        if (r == -1)
          break;
        if (ch == OP_PURGE_THREAD)
        {
          r = mutt_thread_set_flag(extra->email, MUTT_PURGE, true, subthread);
          if (r == -1)
            break;
        }

        if (C_DeleteUntag)
          mutt_thread_set_flag(extra->email, MUTT_TAG, 0, subthread);
        if (C_Resolve)
        {
          rc = OP_MAIN_NEXT_UNDELETED;
          ch = -1;
        }

        if (!C_Resolve && (C_PagerIndexLines != 0))
          pager_menu->redraw = REDRAW_FULL;
        else
          pager_menu->redraw |= REDRAW_STATUS | REDRAW_INDEX;

        break;
      }

      case OP_DISPLAY_ADDRESS:
        CHECK_MODE(IsEmail(extra) || IsMsgAttach(extra));
        if (IsMsgAttach(extra))
          mutt_display_address(extra->body->email->env);
        else
          mutt_display_address(extra->email->env);
        break;

      case OP_ENTER_COMMAND:
        old_PagerIndexLines = C_PagerIndexLines;

        mutt_enter_command();
        window_set_focus(rd.extra->win_pager);
        pager_menu->redraw = REDRAW_FULL;

        if (OptNeedResort)
        {
          OptNeedResort = false;
          CHECK_MODE(IsEmail(extra));
          OptNeedResort = true;
        }

        if (old_PagerIndexLines != C_PagerIndexLines)
        {
          mutt_menu_free(&rd.menu);
        }

        if ((pager_menu->redraw & REDRAW_FLOW) && (flags & MUTT_PAGER_RETWINCH))
        {
          ch = -1;
          rc = OP_REFORMAT_WINCH;
          continue;
        }

        ch = 0;
        break;

      case OP_FLAG_MESSAGE:
        CHECK_MODE(IsEmail(extra));
        CHECK_READONLY;
        /* L10N: CHECK_ACL */
        CHECK_ACL(MUTT_ACL_WRITE, "Can't flag message");

        mutt_set_flag(Context->mailbox, extra->email, MUTT_FLAG, !extra->email->flagged);
        pager_menu->redraw |= REDRAW_STATUS | REDRAW_INDEX;
        if (C_Resolve)
        {
          ch = -1;
          rc = OP_MAIN_NEXT_UNDELETED;
        }
        break;

      case OP_PIPE:
        CHECK_MODE(IsEmail(extra) || IsAttach(extra));
        if (IsAttach(extra))
          mutt_pipe_attachment_list(extra->actx, extra->fp, false, extra->body, false);
        else
        {
          struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
          el_add_tagged(&el, extra->ctx, extra->email, false);
          mutt_pipe_message(extra->ctx->mailbox, &el);
          emaillist_clear(&el);
        }
        break;

      case OP_PRINT:
        CHECK_MODE(IsEmail(extra) || IsAttach(extra));
        if (IsAttach(extra))
          mutt_print_attachment_list(extra->actx, extra->fp, false, extra->body);
        else
        {
          struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
          el_add_tagged(&el, extra->ctx, extra->email, false);
          mutt_print_message(extra->ctx->mailbox, &el);
          emaillist_clear(&el);
        }
        break;

      case OP_MAIL:
        CHECK_MODE(IsEmail(extra) && !IsAttach(extra));
        CHECK_ATTACH;
        mutt_send_message(SEND_NO_FLAGS, NULL, NULL, extra->ctx, NULL, NeoMutt->sub);
        pager_menu->redraw = REDRAW_FULL;
        break;

#ifdef USE_NNTP
      case OP_POST:
        CHECK_MODE(IsEmail(extra) && !IsAttach(extra));
        CHECK_ATTACH;
        if (extra->ctx && (extra->ctx->mailbox->type == MUTT_NNTP) &&
            !((struct NntpMboxData *) extra->ctx->mailbox->mdata)->allowed && (query_quadoption(C_PostModerated, _("Posting to this group not allowed, may be moderated. Continue?")) != MUTT_YES))
        {
          break;
        }
        mutt_send_message(SEND_NEWS, NULL, NULL, extra->ctx, NULL, NeoMutt->sub);
        pager_menu->redraw = REDRAW_FULL;
        break;

      case OP_FORWARD_TO_GROUP:
        CHECK_MODE(IsEmail(extra) || IsMsgAttach(extra));
        CHECK_ATTACH;
        if (extra->ctx && (extra->ctx->mailbox->type == MUTT_NNTP) &&
            !((struct NntpMboxData *) extra->ctx->mailbox->mdata)->allowed && (query_quadoption(C_PostModerated, _("Posting to this group not allowed, may be moderated. Continue?")) != MUTT_YES))
        {
          break;
        }
        if (IsMsgAttach(extra))
          mutt_attach_forward(extra->fp, extra->email, extra->actx, extra->body, SEND_NEWS);
        else
        {
          struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
          emaillist_add_email(&el, extra->email);
          mutt_send_message(SEND_NEWS | SEND_FORWARD, NULL, NULL, extra->ctx,
                            &el, NeoMutt->sub);
          emaillist_clear(&el);
        }
        pager_menu->redraw = REDRAW_FULL;
        break;

      case OP_FOLLOWUP:
        CHECK_MODE(IsEmail(extra) || IsMsgAttach(extra));
        CHECK_ATTACH;

        if (IsMsgAttach(extra))
          followup_to = extra->body->email->env->followup_to;
        else
          followup_to = extra->email->env->followup_to;

        if (!followup_to || !mutt_istr_equal(followup_to, "poster") ||
            (query_quadoption(C_FollowupToPoster,
                              _("Reply by mail as poster prefers?")) != MUTT_YES))
        {
          if (extra->ctx && (extra->ctx->mailbox->type == MUTT_NNTP) &&
              !((struct NntpMboxData *) extra->ctx->mailbox->mdata)->allowed && (query_quadoption(C_PostModerated, _("Posting to this group not allowed, may be moderated. Continue?")) != MUTT_YES))
          {
            break;
          }
          if (IsMsgAttach(extra))
          {
            mutt_attach_reply(extra->fp, extra->email, extra->actx, extra->body,
                              SEND_NEWS | SEND_REPLY);
          }
          else
          {
            struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
            emaillist_add_email(&el, extra->email);
            mutt_send_message(SEND_NEWS | SEND_REPLY, NULL, NULL, extra->ctx,
                              &el, NeoMutt->sub);
            emaillist_clear(&el);
          }
          pager_menu->redraw = REDRAW_FULL;
          break;
        }
#endif
      /* fallthrough */
      case OP_REPLY:
      case OP_GROUP_REPLY:
      case OP_GROUP_CHAT_REPLY:
      case OP_LIST_REPLY:
      {
        CHECK_MODE(IsEmail(extra) || IsMsgAttach(extra));
        CHECK_ATTACH;

        SendFlags replyflags = SEND_REPLY;
        if (ch == OP_GROUP_REPLY)
          replyflags |= SEND_GROUP_REPLY;
        else if (ch == OP_GROUP_CHAT_REPLY)
          replyflags |= SEND_GROUP_CHAT_REPLY;
        else if (ch == OP_LIST_REPLY)
          replyflags |= SEND_LIST_REPLY;

        if (IsMsgAttach(extra))
          mutt_attach_reply(extra->fp, extra->email, extra->actx, extra->body, replyflags);
        else
        {
          struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
          emaillist_add_email(&el, extra->email);
          mutt_send_message(replyflags, NULL, NULL, extra->ctx, &el, NeoMutt->sub);
          emaillist_clear(&el);
        }
        pager_menu->redraw = REDRAW_FULL;
        break;
      }

      case OP_RECALL_MESSAGE:
      {
        CHECK_MODE(IsEmail(extra) && !IsAttach(extra));
        CHECK_ATTACH;
        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        emaillist_add_email(&el, extra->email);
        mutt_send_message(SEND_POSTPONED, NULL, NULL, extra->ctx, &el, NeoMutt->sub);
        emaillist_clear(&el);
        pager_menu->redraw = REDRAW_FULL;
        break;
      }

      case OP_FORWARD_MESSAGE:
        CHECK_MODE(IsEmail(extra) || IsMsgAttach(extra));
        CHECK_ATTACH;
        if (IsMsgAttach(extra))
          mutt_attach_forward(extra->fp, extra->email, extra->actx, extra->body, SEND_NO_FLAGS);
        else
        {
          struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
          emaillist_add_email(&el, extra->email);
          mutt_send_message(SEND_FORWARD, NULL, NULL, extra->ctx, &el, NeoMutt->sub);
          emaillist_clear(&el);
        }
        pager_menu->redraw = REDRAW_FULL;
        break;

      case OP_DECRYPT_SAVE:
        if (!WithCrypto)
        {
          ch = -1;
          break;
        }
      /* fallthrough */
      case OP_SAVE:
        if (IsAttach(extra))
        {
          mutt_save_attachment_list(extra->actx, extra->fp, false, extra->body,
                                    extra->email, NULL);
          break;
        }
      /* fallthrough */
      case OP_COPY_MESSAGE:
      case OP_DECODE_SAVE:
      case OP_DECODE_COPY:
      case OP_DECRYPT_COPY:
      {
        if (!(WithCrypto != 0) && (ch == OP_DECRYPT_COPY))
        {
          ch = -1;
          break;
        }
        CHECK_MODE(IsEmail(extra));
        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        emaillist_add_email(&el, extra->email);

        const bool delete_original =
            (ch == OP_SAVE) || (ch == OP_DECODE_SAVE) || (ch == OP_DECRYPT_SAVE);
        const bool decode = (ch == OP_DECODE_SAVE) || (ch == OP_DECODE_COPY);
        const bool decrypt = (ch == OP_DECRYPT_SAVE) || (ch == OP_DECRYPT_COPY);

        if ((mutt_save_message(Context->mailbox, &el, delete_original, decode, decrypt) == 0) &&
            delete_original)
        {
          if (C_Resolve)
          {
            ch = -1;
            rc = OP_MAIN_NEXT_UNDELETED;
          }
          else
            pager_menu->redraw |= REDRAW_STATUS | REDRAW_INDEX;
        }
        emaillist_clear(&el);
        break;
      }

      case OP_SHELL_ESCAPE:
        if (mutt_shell_escape())
        {
          mutt_mailbox_check(ctx_mailbox(Context), MUTT_MAILBOX_CHECK_FORCE);
        }
        break;

      case OP_TAG:
        CHECK_MODE(IsEmail(extra));
        if (Context)
        {
          mutt_set_flag(Context->mailbox, extra->email, MUTT_TAG, !extra->email->tagged);
        }

        pager_menu->redraw |= REDRAW_STATUS | REDRAW_INDEX;
        if (C_Resolve)
        {
          ch = -1;
          rc = OP_NEXT_ENTRY;
        }
        break;

      case OP_TOGGLE_NEW:
        CHECK_MODE(IsEmail(extra));
        CHECK_READONLY;
        /* L10N: CHECK_ACL */
        CHECK_ACL(MUTT_ACL_SEEN, _("Can't toggle new"));

        if (extra->email->read || extra->email->old)
          mutt_set_flag(Context->mailbox, extra->email, MUTT_NEW, true);
        else if (!first)
          mutt_set_flag(Context->mailbox, extra->email, MUTT_READ, true);
        first = false;
        Context->msg_in_pager = -1;
        pager_menu->redraw |= REDRAW_STATUS | REDRAW_INDEX;
        if (C_Resolve)
        {
          ch = -1;
          rc = OP_MAIN_NEXT_UNDELETED;
        }
        break;

      case OP_UNDELETE:
        CHECK_MODE(IsEmail(extra));
        CHECK_READONLY;
        /* L10N: CHECK_ACL */
        CHECK_ACL(MUTT_ACL_DELETE, _("Can't undelete message"));

        mutt_set_flag(Context->mailbox, extra->email, MUTT_DELETE, false);
        mutt_set_flag(Context->mailbox, extra->email, MUTT_PURGE, false);
        pager_menu->redraw |= REDRAW_STATUS | REDRAW_INDEX;
        if (C_Resolve)
        {
          ch = -1;
          rc = OP_NEXT_ENTRY;
        }
        break;

      case OP_UNDELETE_THREAD:
      case OP_UNDELETE_SUBTHREAD:
      {
        CHECK_MODE(IsEmail(extra));
        CHECK_READONLY;
        /* L10N: CHECK_ACL */
        /* L10N: Due to the implementation details we do not know whether we
           undelete zero, 1, 12, ... messages. So in English we use
           "messages". Your language might have other means to express this. */
        CHECK_ACL(MUTT_ACL_DELETE, _("Can't undelete messages"));

        int r = mutt_thread_set_flag(extra->email, MUTT_DELETE, false,
                                     (ch != OP_UNDELETE_THREAD));
        if (r != -1)
        {
          r = mutt_thread_set_flag(extra->email, MUTT_PURGE, false,
                                   (ch != OP_UNDELETE_THREAD));
        }
        if (r != -1)
        {
          if (C_Resolve)
          {
            rc = (ch == OP_DELETE_THREAD) ? OP_MAIN_NEXT_THREAD : OP_MAIN_NEXT_SUBTHREAD;
            ch = -1;
          }

          if (!C_Resolve && (C_PagerIndexLines != 0))
            pager_menu->redraw = REDRAW_FULL;
          else
            pager_menu->redraw |= REDRAW_STATUS | REDRAW_INDEX;
        }
        break;
      }

      case OP_VERSION:
        mutt_message(mutt_make_version());
        break;

      case OP_MAILBOX_LIST:
        mutt_mailbox_list();
        break;

      case OP_VIEW_ATTACHMENTS:
        if (flags & MUTT_PAGER_ATTACHMENT)
        {
          ch = -1;
          rc = OP_ATTACH_COLLAPSE;
          break;
        }
        CHECK_MODE(IsEmail(extra));
        dlg_select_attachment(extra->email);
        if (Context && extra->email->attach_del)
          Context->mailbox->changed = true;
        pager_menu->redraw = REDRAW_FULL;
        break;

      case OP_MAIL_KEY:
      {
        if (!(WithCrypto & APPLICATION_PGP))
        {
          ch = -1;
          break;
        }
        CHECK_MODE(IsEmail(extra));
        CHECK_ATTACH;
        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        emaillist_add_email(&el, extra->email);
        mutt_send_message(SEND_KEY, NULL, NULL, extra->ctx, &el, NeoMutt->sub);
        emaillist_clear(&el);
        pager_menu->redraw = REDRAW_FULL;
        break;
      }

      case OP_EDIT_LABEL:
      {
        CHECK_MODE(IsEmail(extra));

        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        emaillist_add_email(&el, extra->email);
        rc = mutt_label_message(Context->mailbox, &el);
        emaillist_clear(&el);

        if (rc > 0)
        {
          Context->mailbox->changed = true;
          pager_menu->redraw = REDRAW_FULL;
          mutt_message(ngettext("%d label changed", "%d labels changed", rc), rc);
        }
        else
        {
          mutt_message(_("No labels changed"));
        }
        break;
      }

      case OP_FORGET_PASSPHRASE:
        crypt_forget_passphrase();
        break;

      case OP_EXTRACT_KEYS:
      {
        if (!WithCrypto)
        {
          ch = -1;
          break;
        }
        CHECK_MODE(IsEmail(extra));
        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        emaillist_add_email(&el, extra->email);
        crypt_extract_keys_from_messages(Context->mailbox, &el);
        emaillist_clear(&el);
        pager_menu->redraw = REDRAW_FULL;
        break;
      }

      case OP_WHAT_KEY:
        mutt_what_key();
        break;

      case OP_CHECK_STATS:
        mutt_check_stats();
        break;

#ifdef USE_SIDEBAR
      case OP_SIDEBAR_FIRST:
      case OP_SIDEBAR_LAST:
      case OP_SIDEBAR_NEXT:
      case OP_SIDEBAR_NEXT_NEW:
      case OP_SIDEBAR_PAGE_DOWN:
      case OP_SIDEBAR_PAGE_UP:
      case OP_SIDEBAR_PREV:
      case OP_SIDEBAR_PREV_NEW:
      {
        struct MuttWindow *win_sidebar =
            mutt_window_find(dialog_find(rd.extra->win_pager), WT_SIDEBAR);
        if (!win_sidebar)
          break;
        sb_change_mailbox(win_sidebar, ch);
        break;
      }

      case OP_SIDEBAR_TOGGLE_VISIBLE:
        bool_str_toggle(NeoMutt->sub, "sidebar_visible", NULL);
        mutt_window_reflow(dialog_find(rd.extra->win_pager));
        break;
#endif

      default:
        ch = -1;
        break;
    }
  }

  mutt_file_fclose(&rd.fp);
  if (IsEmail(extra))
  {
    if (Context)
      Context->msg_in_pager = -1;
    switch (rc)
    {
      case -1:
      case OP_DISPLAY_HEADERS:
        mutt_clear_pager_position();
        break;
      default:
        TopLine = rd.topline;
        OldEmail = extra->email;
        break;
    }
  }

  cleanup_quote(&rd.quote_list);

  for (size_t i = 0; i < rd.max_line; i++)
  {
    FREE(&(rd.line_info[i].syntax));
    if (rd.search_compiled && rd.line_info[i].search)
      FREE(&(rd.line_info[i].search));
  }
  if (rd.search_compiled)
  {
    regfree(&rd.search_re);
    rd.search_compiled = false;
  }
  FREE(&rd.line_info);
  mutt_menu_pop_current(pager_menu);
  mutt_menu_free(&pager_menu);
  mutt_menu_free(&rd.menu);

  if (rd.extra->win_index)
  {
    rd.extra->win_index->size = MUTT_WIN_SIZE_MAXIMISE;
    rd.extra->win_index->req_rows = MUTT_WIN_SIZE_UNLIMITED;
    rd.extra->win_index->parent->size = MUTT_WIN_SIZE_MAXIMISE;
    rd.extra->win_index->parent->req_rows = MUTT_WIN_SIZE_UNLIMITED;
    window_set_visible(rd.extra->win_index->parent, true);
  }
  window_set_visible(rd.extra->win_pager->parent, false);
  mutt_window_reflow(dialog_find(rd.extra->win_pager));

  return (rc != -1) ? rc : 0;
}
