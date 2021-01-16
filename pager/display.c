/**
 * @file
 * XXX
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

/**
 * @page pager_display XXX
 *
 * XXX
 */

#include "config.h"
#include "private.h"
#include <stdbool.h>

/**
 * check_sig - Check for an email signature
 * @param s    Text to examine
 * @param info Line info array to update
 * @param n    First line to check
 * @retval  0 Success
 * @retval -1 Error
 */
static int check_sig(const char *s, struct Line *info, int n)
{
  int count = 0;

  while ((n > 0) && (count <= NUM_SIG_LINES))
  {
    if (info[n].type != MT_COLOR_SIGNATURE)
      break;
    count++;
    n--;
  }

  if (count == 0)
    return -1;

  if (count > NUM_SIG_LINES)
  {
    /* check for a blank line */
    while (*s)
    {
      if (!IS_SPACE(*s))
        return 0;
      s++;
    }

    return -1;
  }

  return 0;
}

/**
 * comp_syntax_t - Search for a Syntax using bsearch
 * @param m1 Search key
 * @param m2 Array member
 * @retval -1 m1 precedes m2
 * @retval  0 m1 matches m2
 * @retval  1 m2 precedes m1
 */
static int comp_syntax_t(const void *m1, const void *m2)
{
  const int *cnt = (const int *) m1;
  const struct TextSyntax *stx = (const struct TextSyntax *) m2;

  if (*cnt < stx->first)
    return -1;
  if (*cnt >= stx->last)
    return 1;
  return 0;
}

/**
 * resolve_color - Set the colour for a line of text
 * @param line_info Line info array
 * @param n         Line Number (index into line_info)
 * @param cnt       If true, this is a continuation line
 * @param flags     Flags, see #PagerFlags
 * @param special   Flags, e.g. A_BOLD
 * @param a         ANSI attributes
 */
static void resolve_color(struct Line *line_info, int n, int cnt,
                          PagerFlags flags, int special, struct AnsiAttr *a)
{
  int def_color;         /* color without syntax highlight */
  int color;             /* final color */
  static int last_color; /* last color set */
  bool search = false;
  int m;
  struct TextSyntax *matching_chunk = NULL;

  if (cnt == 0)
    last_color = -1; /* force attrset() */

  if (line_info[n].continuation)
  {
    if (!cnt && C_Markers)
    {
      mutt_curses_set_color(MT_COLOR_MARKERS);
      mutt_window_addch('+');
      last_color = Colors->defs[MT_COLOR_MARKERS];
    }
    m = (line_info[n].syntax)[0].first;
    cnt += (line_info[n].syntax)[0].last;
  }
  else
    m = n;
  if (flags & MUTT_PAGER_LOGS)
  {
    def_color = Colors->defs[(line_info[n].syntax)[0].color];
  }
  else if (!(flags & MUTT_SHOWCOLOR))
    def_color = Colors->defs[MT_COLOR_NORMAL];
  else if (line_info[m].type == MT_COLOR_HEADER)
    def_color = (line_info[m].syntax)[0].color;
  else
    def_color = Colors->defs[line_info[m].type];

  if ((flags & MUTT_SHOWCOLOR) && (line_info[m].type == MT_COLOR_QUOTED))
  {
    struct QClass *qc = line_info[m].quote;

    if (qc)
    {
      def_color = qc->color;

      while (qc && (qc->length > cnt))
      {
        def_color = qc->color;
        qc = qc->up;
      }
    }
  }

  color = def_color;
  if ((flags & MUTT_SHOWCOLOR) && line_info[m].chunks)
  {
    matching_chunk = bsearch(&cnt, line_info[m].syntax, line_info[m].chunks,
                             sizeof(struct TextSyntax), comp_syntax_t);
    if (matching_chunk && (cnt >= matching_chunk->first) &&
        (cnt < matching_chunk->last))
    {
      color = matching_chunk->color;
    }
  }

  if ((flags & MUTT_SEARCH) && line_info[m].search_cnt)
  {
    matching_chunk = bsearch(&cnt, line_info[m].search, line_info[m].search_cnt,
                             sizeof(struct TextSyntax), comp_syntax_t);
    if (matching_chunk && (cnt >= matching_chunk->first) &&
        (cnt < matching_chunk->last))
    {
      color = Colors->defs[MT_COLOR_SEARCH];
      search = 1;
    }
  }

  /* handle "special" bold & underlined characters */
  if (special || a->attr)
  {
#ifdef HAVE_COLOR
    if ((a->attr & ANSI_COLOR))
    {
      if (a->pair == -1)
        a->pair = mutt_color_alloc(Colors, a->fg, a->bg);
      color = a->pair;
      if (a->attr & ANSI_BOLD)
        color |= A_BOLD;
    }
    else
#endif
        if ((special & A_BOLD) || (a->attr & ANSI_BOLD))
    {
      if (Colors->defs[MT_COLOR_BOLD] && !search)
        color = Colors->defs[MT_COLOR_BOLD];
      else
        color ^= A_BOLD;
    }
    if ((special & A_UNDERLINE) || (a->attr & ANSI_UNDERLINE))
    {
      if (Colors->defs[MT_COLOR_UNDERLINE] && !search)
        color = Colors->defs[MT_COLOR_UNDERLINE];
      else
        color ^= A_UNDERLINE;
    }
    else if (a->attr & ANSI_REVERSE)
    {
      color ^= A_REVERSE;
    }
    else if (a->attr & ANSI_BLINK)
    {
      color ^= A_BLINK;
    }
    else if (a->attr == ANSI_OFF)
    {
      a->attr = 0;
    }
  }

  if (color != last_color)
  {
    mutt_curses_set_attr(color);
    last_color = color;
  }
}

/**
 * append_line - Add a new Line to the array
 * @param line_info Array of Line info
 * @param n         Line number to add
 * @param cnt       true, if line is a continuation
 */
static void append_line(struct Line *line_info, int n, int cnt)
{
  int m;

  line_info[n + 1].type = line_info[n].type;
  (line_info[n + 1].syntax)[0].color = (line_info[n].syntax)[0].color;
  line_info[n + 1].continuation = 1;

  /* find the real start of the line */
  for (m = n; m >= 0; m--)
    if (line_info[m].continuation == 0)
      break;

  (line_info[n + 1].syntax)[0].first = m;
  (line_info[n + 1].syntax)[0].last =
      (line_info[n].continuation) ? cnt + (line_info[n].syntax)[0].last : cnt;
}

/**
 * class_color_new - Create a new quoting colour
 * @param[in]     qc      Class of quoted text
 * @param[in,out] q_level Quote level
 */
static void class_color_new(struct QClass *qc, int *q_level)
{
  qc->index = (*q_level)++;
  qc->color = Colors->quotes[qc->index % Colors->quotes_used];
}

/**
 * shift_class_colors - Insert a new quote colour class into a list
 * @param[in]     quote_list List of quote colours
 * @param[in]     new_class  New quote colour to inset
 * @param[in]     index      Index to insert at
 * @param[in,out] q_level    Quote level
 */
static void shift_class_colors(struct QClass *quote_list,
                               struct QClass *new_class, int index, int *q_level)
{
  struct QClass *q_list = quote_list;
  new_class->index = -1;

  while (q_list)
  {
    if (q_list->index >= index)
    {
      q_list->index++;
      q_list->color = Colors->quotes[q_list->index % Colors->quotes_used];
    }
    if (q_list->down)
      q_list = q_list->down;
    else if (q_list->next)
      q_list = q_list->next;
    else
    {
      while (!q_list->next)
      {
        q_list = q_list->up;
        if (!q_list)
          break;
      }
      if (q_list)
        q_list = q_list->next;
    }
  }

  new_class->index = index;
  new_class->color = Colors->quotes[index % Colors->quotes_used];
  (*q_level)++;
}

/**
 * classify_quote - Find a style for a string
 * @param[out] quote_list   List of quote colours
 * @param[in]  qptr         String to classify
 * @param[in]  length       Length of string
 * @param[out] force_redraw Set to true if a screen redraw is needed
 * @param[out] q_level      Quoting level
 * @retval ptr Quoting style
 */
static struct QClass *classify_quote(struct QClass **quote_list, const char *qptr,
                                     size_t length, bool *force_redraw, int *q_level)
{
  struct QClass *q_list = *quote_list;
  struct QClass *qc = NULL, *tmp = NULL, *ptr = NULL, *save = NULL;
  const char *tail_qptr = NULL;
  int offset, tail_lng;
  int index = -1;

  if (Colors->quotes_used <= 1)
  {
    /* not much point in classifying quotes... */

    if (!*quote_list)
    {
      qc = mutt_mem_calloc(1, sizeof(struct QClass));
      qc->color = Colors->quotes[0];
      *quote_list = qc;
    }
    return *quote_list;
  }

  /* classify quoting prefix */
  while (q_list)
  {
    if (length <= q_list->length)
    {
      /* case 1: check the top level nodes */

      if (mutt_strn_equal(qptr, q_list->prefix, length))
      {
        if (length == q_list->length)
          return q_list; /* same prefix: return the current class */

        /* found shorter prefix */
        if (!tmp)
        {
          /* add a node above q_list */
          tmp = mutt_mem_calloc(1, sizeof(struct QClass));
          tmp->prefix = mutt_mem_calloc(1, length + 1);
          strncpy(tmp->prefix, qptr, length);
          tmp->length = length;

          /* replace q_list by tmp in the top level list */
          if (q_list->next)
          {
            tmp->next = q_list->next;
            q_list->next->prev = tmp;
          }
          if (q_list->prev)
          {
            tmp->prev = q_list->prev;
            q_list->prev->next = tmp;
          }

          /* make q_list a child of tmp */
          tmp->down = q_list;
          q_list->up = tmp;

          /* q_list has no siblings for now */
          q_list->next = NULL;
          q_list->prev = NULL;

          /* update the root if necessary */
          if (q_list == *quote_list)
            *quote_list = tmp;

          index = q_list->index;

          /* tmp should be the return class too */
          qc = tmp;

          /* next class to test; if tmp is a shorter prefix for another
           * node, that node can only be in the top level list, so don't
           * go down after this point */
          q_list = tmp->next;
        }
        else
        {
          /* found another branch for which tmp is a shorter prefix */

          /* save the next sibling for later */
          save = q_list->next;

          /* unlink q_list from the top level list */
          if (q_list->next)
            q_list->next->prev = q_list->prev;
          if (q_list->prev)
            q_list->prev->next = q_list->next;

          /* at this point, we have a tmp->down; link q_list to it */
          ptr = tmp->down;
          /* sibling order is important here, q_list should be linked last */
          while (ptr->next)
            ptr = ptr->next;
          ptr->next = q_list;
          q_list->next = NULL;
          q_list->prev = ptr;
          q_list->up = tmp;

          index = q_list->index;

          /* next class to test; as above, we shouldn't go down */
          q_list = save;
        }

        /* we found a shorter prefix, so certain quotes have changed classes */
        *force_redraw = true;
        continue;
      }
      else
      {
        /* shorter, but not a substring of the current class: try next */
        q_list = q_list->next;
        continue;
      }
    }
    else
    {
      /* case 2: try subclassing the current top level node */

      /* tmp != NULL means we already found a shorter prefix at case 1 */
      if (!tmp && mutt_strn_equal(qptr, q_list->prefix, q_list->length))
      {
        /* ok, it's a subclass somewhere on this branch */

        ptr = q_list;
        offset = q_list->length;

        q_list = q_list->down;
        tail_lng = length - offset;
        tail_qptr = qptr + offset;

        while (q_list)
        {
          if (length <= q_list->length)
          {
            if (mutt_strn_equal(tail_qptr, (q_list->prefix) + offset, tail_lng))
            {
              /* same prefix: return the current class */
              if (length == q_list->length)
                return q_list;

              /* found shorter common prefix */
              if (!tmp)
              {
                /* add a node above q_list */
                tmp = mutt_mem_calloc(1, sizeof(struct QClass));
                tmp->prefix = mutt_mem_calloc(1, length + 1);
                strncpy(tmp->prefix, qptr, length);
                tmp->length = length;

                /* replace q_list by tmp */
                if (q_list->next)
                {
                  tmp->next = q_list->next;
                  q_list->next->prev = tmp;
                }
                if (q_list->prev)
                {
                  tmp->prev = q_list->prev;
                  q_list->prev->next = tmp;
                }

                /* make q_list a child of tmp */
                tmp->down = q_list;
                tmp->up = q_list->up;
                q_list->up = tmp;
                if (tmp->up->down == q_list)
                  tmp->up->down = tmp;

                /* q_list has no siblings */
                q_list->next = NULL;
                q_list->prev = NULL;

                index = q_list->index;

                /* tmp should be the return class too */
                qc = tmp;

                /* next class to test */
                q_list = tmp->next;
              }
              else
              {
                /* found another branch for which tmp is a shorter prefix */

                /* save the next sibling for later */
                save = q_list->next;

                /* unlink q_list from the top level list */
                if (q_list->next)
                  q_list->next->prev = q_list->prev;
                if (q_list->prev)
                  q_list->prev->next = q_list->next;

                /* at this point, we have a tmp->down; link q_list to it */
                ptr = tmp->down;
                while (ptr->next)
                  ptr = ptr->next;
                ptr->next = q_list;
                q_list->next = NULL;
                q_list->prev = ptr;
                q_list->up = tmp;

                index = q_list->index;

                /* next class to test */
                q_list = save;
              }

              /* we found a shorter prefix, so we need a redraw */
              *force_redraw = true;
              continue;
            }
            else
            {
              q_list = q_list->next;
              continue;
            }
          }
          else
          {
            /* longer than the current prefix: try subclassing it */
            if (!tmp && mutt_strn_equal(tail_qptr, (q_list->prefix) + offset,
                                        q_list->length - offset))
            {
              /* still a subclass: go down one level */
              ptr = q_list;
              offset = q_list->length;

              q_list = q_list->down;
              tail_lng = length - offset;
              tail_qptr = qptr + offset;

              continue;
            }
            else
            {
              /* nope, try the next prefix */
              q_list = q_list->next;
              continue;
            }
          }
        }

        /* still not found so far: add it as a sibling to the current node */
        if (!qc)
        {
          tmp = mutt_mem_calloc(1, sizeof(struct QClass));
          tmp->prefix = mutt_mem_calloc(1, length + 1);
          strncpy(tmp->prefix, qptr, length);
          tmp->length = length;

          if (ptr->down)
          {
            tmp->next = ptr->down;
            ptr->down->prev = tmp;
          }
          ptr->down = tmp;
          tmp->up = ptr;

          class_color_new(tmp, q_level);

          return tmp;
        }
        else
        {
          if (index != -1)
            shift_class_colors(*quote_list, tmp, index, q_level);

          return qc;
        }
      }
      else
      {
        /* nope, try the next prefix */
        q_list = q_list->next;
        continue;
      }
    }
  }

  if (!qc)
  {
    /* not found so far: add it as a top level class */
    qc = mutt_mem_calloc(1, sizeof(struct QClass));
    qc->prefix = mutt_mem_calloc(1, length + 1);
    strncpy(qc->prefix, qptr, length);
    qc->length = length;
    class_color_new(qc, q_level);

    if (*quote_list)
    {
      qc->next = *quote_list;
      (*quote_list)->prev = qc;
    }
    *quote_list = qc;
  }

  if (index != -1)
    shift_class_colors(*quote_list, tmp, index, q_level);

  return qc;
}

/**
 * check_marker - Check that the unique marker is present
 * @param q Marker string
 * @param p String to check
 * @retval num Offset of marker
 */
static int check_marker(const char *q, const char *p)
{
  for (; (p[0] == q[0]) && (q[0] != '\0') && (p[0] != '\0') && (q[0] != '\a') &&
         (p[0] != '\a');
       p++, q++)
  {
  }

  return (int) (*p - *q);
}

/**
 * check_attachment_marker - Check that the unique marker is present
 * @param p String to check
 * @retval num Offset of marker
 */
static int check_attachment_marker(const char *p)
{
  return check_marker(AttachmentMarker, p);
}

/**
 * check_protected_header_marker - Check that the unique marker is present
 * @param p String to check
 * @retval num Offset of marker
 */
static int check_protected_header_marker(const char *p)
{
  return check_marker(ProtectedHeaderMarker, p);
}

/**
 * mutt_is_quote_line - Is a line of message text a quote?
 * @param[in]  line   Line to test
 * @param[out] pmatch Regex sub-matches
 * @retval true Line is quoted
 *
 * Checks if line matches the `$quote_regex` and doesn't match `$smileys`.
 * This is used by the pager for calling classify_quote.
 */
int mutt_is_quote_line(char *line, regmatch_t *pmatch)
{
  bool is_quote = false;
  regmatch_t pmatch_internal[1], smatch[1];

  if (!pmatch)
    pmatch = pmatch_internal;

  if (mutt_regex_capture(C_QuoteRegex, line, 1, pmatch))
  {
    if (mutt_regex_capture(C_Smileys, line, 1, smatch))
    {
      if (smatch[0].rm_so > 0)
      {
        char c = line[smatch[0].rm_so];
        line[smatch[0].rm_so] = 0;

        if (mutt_regex_capture(C_QuoteRegex, line, 1, pmatch))
          is_quote = true;

        line[smatch[0].rm_so] = c;
      }
    }
    else
      is_quote = true;
  }

  return is_quote;
}

/**
 * resolve_types - Determine the style for a line of text
 * @param[in]  buf          Formatted text
 * @param[in]  raw          Raw text
 * @param[in]  line_info    Line info array
 * @param[in]  n            Line number (index into line_info)
 * @param[in]  last         Last line
 * @param[out] quote_list   List of quote colours
 * @param[out] q_level      Quote level
 * @param[out] force_redraw Set to true if a screen redraw is needed
 * @param[in]  q_classify   If true, style the text
 */
static void resolve_types(char *buf, char *raw, struct Line *line_info, int n,
                          int last, struct QClass **quote_list, int *q_level,
                          bool *force_redraw, bool q_classify)
{
  struct ColorLine *color_line = NULL;
  struct ColorLineList *head = NULL;
  regmatch_t pmatch[1];
  bool found;
  bool null_rx;
  int offset, i = 0;

  if ((n == 0) || IS_HEADER(line_info[n - 1].type) ||
      (check_protected_header_marker(raw) == 0))
  {
    if (buf[0] == '\n') /* end of header */
    {
      line_info[n].type = MT_COLOR_NORMAL;
      getyx(stdscr, braille_line, braille_col);
    }
    else
    {
      /* if this is a continuation of the previous line, use the previous
       * line's color as default. */
      if ((n > 0) && ((buf[0] == ' ') || (buf[0] == '\t')))
      {
        line_info[n].type = line_info[n - 1].type; /* wrapped line */
        if (!C_HeaderColorPartial)
        {
          (line_info[n].syntax)[0].color = (line_info[n - 1].syntax)[0].color;
          line_info[n].is_cont_hdr = 1;
        }
      }
      else
      {
        line_info[n].type = MT_COLOR_HDRDEFAULT;
      }

      /* When this option is unset, we color the entire header the
       * same color.  Otherwise, we handle the header patterns just
       * like body patterns (further below).  */
      if (!C_HeaderColorPartial)
      {
        STAILQ_FOREACH(color_line, &Colors->hdr_list, entries)
        {
          if (regexec(&color_line->regex, buf, 0, NULL, 0) == 0)
          {
            line_info[n].type = MT_COLOR_HEADER;
            line_info[n].syntax[0].color = color_line->pair;
            if (line_info[n].is_cont_hdr)
            {
              /* adjust the previous continuation lines to reflect the color of this continuation line */
              int j;
              for (j = n - 1; j >= 0 && line_info[j].is_cont_hdr; --j)
              {
                line_info[j].type = line_info[n].type;
                line_info[j].syntax[0].color = line_info[n].syntax[0].color;
              }
              /* now adjust the first line of this header field */
              if (j >= 0)
              {
                line_info[j].type = line_info[n].type;
                line_info[j].syntax[0].color = line_info[n].syntax[0].color;
              }
              *force_redraw = true; /* the previous lines have already been drawn on the screen */
            }
            break;
          }
        }
      }
    }
  }
  else if (mutt_str_startswith(raw, "\033[0m")) // Escape: a little hack...
    line_info[n].type = MT_COLOR_NORMAL;
  else if (check_attachment_marker((char *) raw) == 0)
    line_info[n].type = MT_COLOR_ATTACHMENT;
  else if (mutt_str_equal("-- \n", buf) || mutt_str_equal("-- \r\n", buf))
  {
    i = n + 1;

    line_info[n].type = MT_COLOR_SIGNATURE;
    while ((i < last) && (check_sig(buf, line_info, i - 1) == 0) &&
           ((line_info[i].type == MT_COLOR_NORMAL) || (line_info[i].type == MT_COLOR_QUOTED) ||
            (line_info[i].type == MT_COLOR_HEADER)))
    {
      /* oops... */
      if (line_info[i].chunks)
      {
        line_info[i].chunks = 0;
        mutt_mem_realloc(&(line_info[n].syntax), sizeof(struct TextSyntax));
      }
      line_info[i++].type = MT_COLOR_SIGNATURE;
    }
  }
  else if (check_sig(buf, line_info, n - 1) == 0)
    line_info[n].type = MT_COLOR_SIGNATURE;
  else if (mutt_is_quote_line(buf, pmatch))

  {
    if (q_classify && (line_info[n].quote == NULL))
    {
      line_info[n].quote = classify_quote(quote_list, buf + pmatch[0].rm_so,
                                          pmatch[0].rm_eo - pmatch[0].rm_so,
                                          force_redraw, q_level);
    }
    line_info[n].type = MT_COLOR_QUOTED;
  }
  else
    line_info[n].type = MT_COLOR_NORMAL;

  /* body patterns */
  if ((line_info[n].type == MT_COLOR_NORMAL) || (line_info[n].type == MT_COLOR_QUOTED) ||
      ((line_info[n].type == MT_COLOR_HDRDEFAULT) && C_HeaderColorPartial))
  {
    size_t nl;

    /* don't consider line endings part of the buffer
     * for regex matching */
    nl = mutt_str_len(buf);
    if ((nl > 0) && (buf[nl - 1] == '\n'))
      buf[nl - 1] = '\0';

    i = 0;
    offset = 0;
    line_info[n].chunks = 0;
    if (line_info[n].type == MT_COLOR_HDRDEFAULT)
      head = &Colors->hdr_list;
    else
      head = &Colors->body_list;
    STAILQ_FOREACH(color_line, head, entries)
    {
      color_line->stop_matching = false;
    }
    do
    {
      if (!buf[offset])
        break;

      found = false;
      null_rx = false;
      STAILQ_FOREACH(color_line, head, entries)
      {
        if (!color_line->stop_matching &&
            (regexec(&color_line->regex, buf + offset, 1, pmatch,
                     ((offset != 0) ? REG_NOTBOL : 0)) == 0))
        {
          if (pmatch[0].rm_eo != pmatch[0].rm_so)
          {
            if (!found)
            {
              /* Abort if we fill up chunks.
               * Yes, this really happened. */
              if (line_info[n].chunks == SHRT_MAX)
              {
                null_rx = false;
                break;
              }
              if (++(line_info[n].chunks) > 1)
              {
                mutt_mem_realloc(&(line_info[n].syntax),
                                 (line_info[n].chunks) * sizeof(struct TextSyntax));
              }
            }
            i = line_info[n].chunks - 1;
            pmatch[0].rm_so += offset;
            pmatch[0].rm_eo += offset;
            if (!found || (pmatch[0].rm_so < (line_info[n].syntax)[i].first) ||
                ((pmatch[0].rm_so == (line_info[n].syntax)[i].first) &&
                 (pmatch[0].rm_eo > (line_info[n].syntax)[i].last)))
            {
              (line_info[n].syntax)[i].color = color_line->pair;
              (line_info[n].syntax)[i].first = pmatch[0].rm_so;
              (line_info[n].syntax)[i].last = pmatch[0].rm_eo;
            }
            found = true;
            null_rx = false;
          }
          else
            null_rx = true; /* empty regex; don't add it, but keep looking */
        }
        else
        {
          /* Once a regexp fails to match, don't try matching it again.
           * On very long lines this can cause a performance issue if there
           * are other regexps that have many matches. */
          color_line->stop_matching = true;
        }
      }

      if (null_rx)
        offset++; /* avoid degenerate cases */
      else
        offset = (line_info[n].syntax)[i].last;
    } while (found || null_rx);
    if (nl > 0)
      buf[nl] = '\n';
  }

  /* attachment patterns */
  if (line_info[n].type == MT_COLOR_ATTACHMENT)
  {
    size_t nl;

    /* don't consider line endings part of the buffer for regex matching */
    nl = mutt_str_len(buf);
    if ((nl > 0) && (buf[nl - 1] == '\n'))
      buf[nl - 1] = '\0';

    i = 0;
    offset = 0;
    line_info[n].chunks = 0;
    do
    {
      if (!buf[offset])
        break;

      found = false;
      null_rx = false;
      STAILQ_FOREACH(color_line, &Colors->attach_list, entries)
      {
        if (regexec(&color_line->regex, buf + offset, 1, pmatch,
                    ((offset != 0) ? REG_NOTBOL : 0)) == 0)
        {
          if (pmatch[0].rm_eo != pmatch[0].rm_so)
          {
            if (!found)
            {
              if (++(line_info[n].chunks) > 1)
              {
                mutt_mem_realloc(&(line_info[n].syntax),
                                 (line_info[n].chunks) * sizeof(struct TextSyntax));
              }
            }
            i = line_info[n].chunks - 1;
            pmatch[0].rm_so += offset;
            pmatch[0].rm_eo += offset;
            if (!found || (pmatch[0].rm_so < (line_info[n].syntax)[i].first) ||
                ((pmatch[0].rm_so == (line_info[n].syntax)[i].first) &&
                 (pmatch[0].rm_eo > (line_info[n].syntax)[i].last)))
            {
              (line_info[n].syntax)[i].color = color_line->pair;
              (line_info[n].syntax)[i].first = pmatch[0].rm_so;
              (line_info[n].syntax)[i].last = pmatch[0].rm_eo;
            }
            found = 1;
            null_rx = 0;
          }
          else
            null_rx = 1; /* empty regex; don't add it, but keep looking */
        }
      }

      if (null_rx)
        offset++; /* avoid degenerate cases */
      else
        offset = (line_info[n].syntax)[i].last;
    } while (found || null_rx);
    if (nl > 0)
      buf[nl] = '\n';
  }
}

/**
 * is_ansi - Is this an ANSI escape sequence?
 * @param str String to test
 * @retval bool true, if it's an ANSI escape sequence
 */
static bool is_ansi(const char *str)
{
  while (*str && (isdigit(*str) || *str == ';'))
    str++;
  return (*str == 'm');
}

/**
 * grok_ansi - Parse an ANSI escape sequence
 * @param buf String to parse
 * @param pos Starting position in string
 * @param a   AnsiAttr for the result
 * @retval num Index of first character after the escape sequence
 */
static int grok_ansi(unsigned char *buf, int pos, struct AnsiAttr *a)
{
  int x = pos;

  while (isdigit(buf[x]) || (buf[x] == ';'))
    x++;

  /* Character Attributes */
  if (C_AllowAnsi && a && (buf[x] == 'm'))
  {
    if (pos == x)
    {
#ifdef HAVE_COLOR
      if (a->pair != -1)
        mutt_color_free(Colors, a->fg, a->bg);
#endif
      a->attr = ANSI_OFF;
      a->pair = -1;
    }
    while (pos < x)
    {
      if ((buf[pos] == '1') && ((pos + 1 == x) || (buf[pos + 1] == ';')))
      {
        a->attr |= ANSI_BOLD;
        pos += 2;
      }
      else if ((buf[pos] == '4') && ((pos + 1 == x) || (buf[pos + 1] == ';')))
      {
        a->attr |= ANSI_UNDERLINE;
        pos += 2;
      }
      else if ((buf[pos] == '5') && ((pos + 1 == x) || (buf[pos + 1] == ';')))
      {
        a->attr |= ANSI_BLINK;
        pos += 2;
      }
      else if ((buf[pos] == '7') && ((pos + 1 == x) || (buf[pos + 1] == ';')))
      {
        a->attr |= ANSI_REVERSE;
        pos += 2;
      }
      else if ((buf[pos] == '0') && ((pos + 1 == x) || (buf[pos + 1] == ';')))
      {
#ifdef HAVE_COLOR
        if (a->pair != -1)
          mutt_color_free(Colors, a->fg, a->bg);
#endif
        a->attr = ANSI_OFF;
        a->pair = -1;
        pos += 2;
      }
      else if ((buf[pos] == '3') && isdigit(buf[pos + 1]))
      {
#ifdef HAVE_COLOR
        if (a->pair != -1)
          mutt_color_free(Colors, a->fg, a->bg);
#endif
        a->pair = -1;
        a->attr |= ANSI_COLOR;
        a->fg = buf[pos + 1] - '0';
        pos += 3;
      }
      else if ((buf[pos] == '4') && isdigit(buf[pos + 1]))
      {
#ifdef HAVE_COLOR
        if (a->pair != -1)
          mutt_color_free(Colors, a->fg, a->bg);
#endif
        a->pair = -1;
        a->attr |= ANSI_COLOR;
        a->bg = buf[pos + 1] - '0';
        pos += 3;
      }
      else
      {
        while ((pos < x) && (buf[pos] != ';'))
          pos++;
        pos++;
      }
    }
  }
  pos = x;
  return pos;
}

/**
 * mutt_buffer_strip_formatting - Removes ANSI and backspace formatting
 * @param dest Buffer for the result
 * @param src  String to strip
 * @param strip_markers Remove
 *
 * Removes ANSI and backspace formatting, and optionally markers.
 * This is separated out so that it can be used both by the pager
 * and the autoview handler.
 *
 * This logic is pulled from the pager fill_buffer() function, for use
 * in stripping reply-quoted autoview output of ansi sequences.
 */
void mutt_buffer_strip_formatting(struct Buffer *dest, const char *src, bool strip_markers)
{
  const char *s = src;

  mutt_buffer_reset(dest);

  if (!s)
    return;

  while (s[0] != '\0')
  {
    if ((s[0] == '\010') && (s > src))
    {
      if (s[1] == '_') /* underline */
        s += 2;
      else if (s[1] && mutt_buffer_len(dest)) /* bold or overstrike */
      {
        dest->dptr--;
        mutt_buffer_addch(dest, s[1]);
        s += 2;
      }
      else /* ^H */
        mutt_buffer_addch(dest, *s++);
    }
    else if ((s[0] == '\033') && (s[1] == '[') && is_ansi(s + 2))
    {
      while (*s++ != 'm')
        ; /* skip ANSI sequence */
    }
    else if (strip_markers && (s[0] == '\033') && (s[1] == ']') &&
             ((check_attachment_marker(s) == 0) || (check_protected_header_marker(s) == 0)))
    {
      mutt_debug(LL_DEBUG2, "Seen attachment marker\n");
      while (*s++ != '\a')
        ; /* skip pseudo-ANSI sequence */
    }
    else
      mutt_buffer_addch(dest, *s++);
  }
}

/**
 * fill_buffer - Fill a buffer from a file
 * @param[in]     fp        File to read from
 * @param[in,out] last_pos  End of last read
 * @param[in]     offset    Position start reading from
 * @param[out]    buf       Buffer to fill
 * @param[out]    fmt       Copy of buffer, stripped of attributes
 * @param[out]    blen      Length of the buffer
 * @param[in,out] buf_ready true if the buffer already has data in it
 * @retval >=0 Bytes read
 * @retval -1  Error
 */
static int fill_buffer(FILE *fp, LOFF_T *last_pos, LOFF_T offset, unsigned char **buf,
                       unsigned char **fmt, size_t *blen, int *buf_ready)
{
  static int b_read;
  struct Buffer stripped;

  if (*buf_ready == 0)
  {
    if (offset != *last_pos)
      fseeko(fp, offset, SEEK_SET);

    *buf = (unsigned char *) mutt_file_read_line((char *) *buf, blen, fp, NULL, MUTT_EOL);
    if (!*buf)
    {
      fmt[0] = NULL;
      return -1;
    }

    *last_pos = ftello(fp);
    b_read = (int) (*last_pos - offset);
    *buf_ready = 1;

    mutt_buffer_init(&stripped);
    mutt_buffer_alloc(&stripped, *blen);
    mutt_buffer_strip_formatting(&stripped, (const char *) *buf, 1);
    /* This should be a noop, because *fmt should be NULL */
    FREE(fmt);
    *fmt = (unsigned char *) stripped.data;
  }

  return b_read;
}

/**
 * format_line - Display a line of text in the pager
 * @param[out] line_info Line info
 * @param[in]  n         Line number (index into line_info)
 * @param[in]  buf       Text to display
 * @param[in]  flags     Flags, see #PagerFlags
 * @param[out] pa        ANSI attributes used
 * @param[in]  cnt       Length of text buffer
 * @param[out] pspace    Index of last whitespace character
 * @param[out] pvch      Number of bytes read
 * @param[out] pcol      Number of columns used
 * @param[out] pspecial  Attribute flags, e.g. A_UNDERLINE
 * @param[in]  width     Width of screen (to wrap to)
 * @retval num Number of characters displayed
 */
static int format_line(struct Line **line_info, int n, unsigned char *buf,
                       PagerFlags flags, struct AnsiAttr *pa, int cnt,
                       int *pspace, int *pvch, int *pcol, int *pspecial, int width)
{
  int space = -1; /* index of the last space or TAB */
  int col = C_Markers ? (*line_info)[n].continuation : 0;
  size_t k;
  int ch, vch, last_special = -1, special = 0, t;
  wchar_t wc;
  mbstate_t mbstate;
  int wrap_cols = mutt_window_wrap_cols(width, (flags & MUTT_PAGER_NOWRAP) ? 0 : C_Wrap);

  if (check_attachment_marker((char *) buf) == 0)
    wrap_cols = width;

  /* FIXME: this should come from line_info */
  memset(&mbstate, 0, sizeof(mbstate));

  for (ch = 0, vch = 0; ch < cnt; ch += k, vch += k)
  {
    /* Handle ANSI sequences */
    while ((cnt - ch >= 2) && (buf[ch] == '\033') && (buf[ch + 1] == '[') && // Escape
           is_ansi((char *) buf + ch + 2))
    {
      ch = grok_ansi(buf, ch + 2, pa) + 1;
    }

    while ((cnt - ch >= 2) && (buf[ch] == '\033') && (buf[ch + 1] == ']') && // Escape
           ((check_attachment_marker((char *) buf + ch) == 0) ||
            (check_protected_header_marker((char *) buf + ch) == 0)))
    {
      while (buf[ch++] != '\a')
        if (ch >= cnt)
          break;
    }

    /* is anything left to do? */
    if (ch >= cnt)
      break;

    k = mbrtowc(&wc, (char *) buf + ch, cnt - ch, &mbstate);
    if ((k == (size_t)(-2)) || (k == (size_t)(-1)))
    {
      if (k == (size_t)(-1))
        memset(&mbstate, 0, sizeof(mbstate));
      mutt_debug(LL_DEBUG1, "mbrtowc returned %lu; errno = %d\n", k, errno);
      if (col + 4 > wrap_cols)
        break;
      col += 4;
      if (pa)
        mutt_window_printf("\\%03o", buf[ch]);
      k = 1;
      continue;
    }
    if (k == 0)
      k = 1;

    if (CharsetIsUtf8)
    {
      /* zero width space, zero width no-break space */
      if ((wc == 0x200B) || (wc == 0xFEFF))
      {
        mutt_debug(LL_DEBUG3, "skip zero-width character U+%04X\n", (unsigned short) wc);
        continue;
      }
      if (mutt_mb_is_display_corrupting_utf8(wc))
      {
        mutt_debug(LL_DEBUG3, "filtered U+%04X\n", (unsigned short) wc);
        continue;
      }
    }

    /* Handle backspace */
    special = 0;
    if (IsWPrint(wc))
    {
      wchar_t wc1;
      mbstate_t mbstate1 = mbstate;
      size_t k1 = mbrtowc(&wc1, (char *) buf + ch + k, cnt - ch - k, &mbstate1);
      while ((k1 != (size_t)(-2)) && (k1 != (size_t)(-1)) && (k1 > 0) && (wc1 == '\b'))
      {
        const size_t k2 =
            mbrtowc(&wc1, (char *) buf + ch + k + k1, cnt - ch - k - k1, &mbstate1);
        if ((k2 == (size_t)(-2)) || (k2 == (size_t)(-1)) || (k2 == 0) || (!IsWPrint(wc1)))
          break;

        if (wc == wc1)
        {
          special |= ((wc == '_') && (special & A_UNDERLINE)) ? A_UNDERLINE : A_BOLD;
        }
        else if ((wc == '_') || (wc1 == '_'))
        {
          special |= A_UNDERLINE;
          wc = (wc1 == '_') ? wc : wc1;
        }
        else
        {
          /* special = 0; / * overstrike: nothing to do! */
          wc = wc1;
        }

        ch += k + k1;
        k = k2;
        mbstate = mbstate1;
        k1 = mbrtowc(&wc1, (char *) buf + ch + k, cnt - ch - k, &mbstate1);
      }
    }

    if (pa && ((flags & (MUTT_SHOWCOLOR | MUTT_SEARCH | MUTT_PAGER_MARKER)) ||
               special || last_special || pa->attr))
    {
      resolve_color(*line_info, n, vch, flags, special, pa);
      last_special = special;
    }

    /* no-break space, narrow no-break space */
    if (IsWPrint(wc) || (CharsetIsUtf8 && ((wc == 0x00A0) || (wc == 0x202F))))
    {
      if (wc == ' ')
      {
        space = ch;
      }
      t = wcwidth(wc);
      if (col + t > wrap_cols)
        break;
      col += t;
      if (pa)
        mutt_addwch(wc);
    }
    else if (wc == '\n')
      break;
    else if (wc == '\t')
    {
      space = ch;
      t = (col & ~7) + 8;
      if (t > wrap_cols)
        break;
      if (pa)
        for (; col < t; col++)
          mutt_window_addch(' ');
      else
        col = t;
    }
    else if ((wc < 0x20) || (wc == 0x7f))
    {
      if (col + 2 > wrap_cols)
        break;
      col += 2;
      if (pa)
        mutt_window_printf("^%c", ('@' + wc) & 0x7f);
    }
    else if (wc < 0x100)
    {
      if (col + 4 > wrap_cols)
        break;
      col += 4;
      if (pa)
        mutt_window_printf("\\%03o", wc);
    }
    else
    {
      if (col + 1 > wrap_cols)
        break;
      col += k;
      if (pa)
        mutt_addwch(ReplacementChar);
    }
  }
  *pspace = space;
  *pcol = col;
  *pvch = vch;
  *pspecial = special;
  return ch;
}

/**
 * display_line - Print a line on screen
 * @param[in]  fp              File to read from
 * @param[out] last_pos        Offset into file
 * @param[out] line_info       Line attributes
 * @param[in]  n               Line number
 * @param[out] last            Last line
 * @param[out] max             Maximum number of lines
 * @param[in]  flags           Flags, see #PagerFlags
 * @param[out] quote_list      Email quoting style
 * @param[out] q_level         Level of quoting
 * @param[out] force_redraw    Force a repaint
 * @param[out] search_re       Regex to highlight
 * @param[in]  win_pager       Window to draw into
 * @retval -1 EOF was reached
 * @retval 0  normal exit, line was not displayed
 * @retval >0 normal exit, line was displayed
 */
int display_line(FILE *fp, LOFF_T *last_pos, struct Line **line_info,
                        int n, int *last, int *max, PagerFlags flags,
                        struct QClass **quote_list, int *q_level, bool *force_redraw,
                        regex_t *search_re, struct MuttWindow *win_pager)
{
  unsigned char *buf = NULL, *fmt = NULL;
  size_t buflen = 0;
  unsigned char *buf_ptr = NULL;
  int ch, vch, col, cnt, b_read;
  int buf_ready = 0;
  bool change_last = false;
  int special;
  int offset;
  int def_color;
  int m;
  int rc = -1;
  struct AnsiAttr a = { 0, 0, 0, -1 };
  regmatch_t pmatch[1];

  if (n == *last)
  {
    (*last)++;
    change_last = true;
  }

  if (*last == *max)
  {
    mutt_mem_realloc(line_info, sizeof(struct Line) * (*max += LINES));
    for (ch = *last; ch < *max; ch++)
    {
      memset(&((*line_info)[ch]), 0, sizeof(struct Line));
      (*line_info)[ch].type = -1;
      (*line_info)[ch].search_cnt = -1;
      (*line_info)[ch].syntax = mutt_mem_malloc(sizeof(struct TextSyntax));
      ((*line_info)[ch].syntax)[0].first = -1;
      ((*line_info)[ch].syntax)[0].last = -1;
    }
  }

  struct Line *const curr_line = &(*line_info)[n];

  if (flags & MUTT_PAGER_LOGS)
  {
    /* determine the line class */
    if (fill_buffer(fp, last_pos, curr_line->offset, &buf, &fmt, &buflen, &buf_ready) < 0)
    {
      if (change_last)
        (*last)--;
      goto out;
    }

    curr_line->type = MT_COLOR_MESSAGE_LOG;
    if (buf[11] == 'M')
      curr_line->syntax[0].color = MT_COLOR_MESSAGE;
    else if (buf[11] == 'W')
      curr_line->syntax[0].color = MT_COLOR_WARNING;
    else if (buf[11] == 'E')
      curr_line->syntax[0].color = MT_COLOR_ERROR;
    else
      curr_line->syntax[0].color = MT_COLOR_NORMAL;
  }

  /* only do color highlighting if we are viewing a message */
  if (flags & (MUTT_SHOWCOLOR | MUTT_TYPES))
  {
    if (curr_line->type == -1)
    {
      /* determine the line class */
      if (fill_buffer(fp, last_pos, curr_line->offset, &buf, &fmt, &buflen, &buf_ready) < 0)
      {
        if (change_last)
          (*last)--;
        goto out;
      }

      resolve_types((char *) fmt, (char *) buf, *line_info, n, *last,
                    quote_list, q_level, force_redraw, flags & MUTT_SHOWCOLOR);

      /* avoid race condition for continuation lines when scrolling up */
      for (m = n + 1; m < *last && (*line_info)[m].offset && (*line_info)[m].continuation; m++)
        (*line_info)[m].type = curr_line->type;
    }

    /* this also prevents searching through the hidden lines */
    if ((flags & MUTT_HIDE) && (curr_line->type == MT_COLOR_QUOTED) &&
        ((curr_line->quote == NULL) || (curr_line->quote->index >= C_ToggleQuotedShowLevels)))
    {
      flags = 0; /* MUTT_NOSHOW */
    }
  }

  /* At this point, (*line_info[n]).quote may still be undefined. We
   * don't want to compute it every time MUTT_TYPES is set, since this
   * would slow down the "bottom" function unacceptably. A compromise
   * solution is hence to call regexec() again, just to find out the
   * length of the quote prefix.  */
  if ((flags & MUTT_SHOWCOLOR) && !curr_line->continuation &&
      (curr_line->type == MT_COLOR_QUOTED) && !curr_line->quote)
  {
    if (fill_buffer(fp, last_pos, curr_line->offset, &buf, &fmt, &buflen, &buf_ready) < 0)
    {
      if (change_last)
        (*last)--;
      goto out;
    }

    if (mutt_regex_capture(C_QuoteRegex, (char *) fmt, 1, pmatch))
    {
      curr_line->quote =
          classify_quote(quote_list, (char *) fmt + pmatch[0].rm_so,
                         pmatch[0].rm_eo - pmatch[0].rm_so, force_redraw, q_level);
    }
    else
    {
      goto out;
    }
  }

  if ((flags & MUTT_SEARCH) && !curr_line->continuation && (curr_line->search_cnt == -1))
  {
    if (fill_buffer(fp, last_pos, curr_line->offset, &buf, &fmt, &buflen, &buf_ready) < 0)
    {
      if (change_last)
        (*last)--;
      goto out;
    }

    offset = 0;
    curr_line->search_cnt = 0;
    while (regexec(search_re, (char *) fmt + offset, 1, pmatch,
                   (offset ? REG_NOTBOL : 0)) == 0)
    {
      if (++(curr_line->search_cnt) > 1)
      {
        mutt_mem_realloc(&(curr_line->search),
                         (curr_line->search_cnt) * sizeof(struct TextSyntax));
      }
      else
        curr_line->search = mutt_mem_malloc(sizeof(struct TextSyntax));
      pmatch[0].rm_so += offset;
      pmatch[0].rm_eo += offset;
      (curr_line->search)[curr_line->search_cnt - 1].first = pmatch[0].rm_so;
      (curr_line->search)[curr_line->search_cnt - 1].last = pmatch[0].rm_eo;

      if (pmatch[0].rm_eo == pmatch[0].rm_so)
        offset++; /* avoid degenerate cases */
      else
        offset = pmatch[0].rm_eo;
      if (!fmt[offset])
        break;
    }
  }

  if (!(flags & MUTT_SHOW) && ((*line_info)[n + 1].offset > 0))
  {
    /* we've already scanned this line, so just exit */
    rc = 0;
    goto out;
  }
  if ((flags & MUTT_SHOWCOLOR) && *force_redraw && ((*line_info)[n + 1].offset > 0))
  {
    /* no need to try to display this line... */
    rc = 1;
    goto out; /* fake display */
  }

  b_read = fill_buffer(fp, last_pos, curr_line->offset, &buf, &fmt, &buflen, &buf_ready);
  if (b_read < 0)
  {
    if (change_last)
      (*last)--;
    goto out;
  }

  /* now chose a good place to break the line */
  cnt = format_line(line_info, n, buf, flags, NULL, b_read, &ch, &vch, &col,
                    &special, win_pager->state.cols);
  buf_ptr = buf + cnt;

  /* move the break point only if smart_wrap is set */
  if (C_SmartWrap)
  {
    if ((cnt < b_read) && (ch != -1) && !IS_HEADER(curr_line->type) && !IS_SPACE(buf[cnt]))
    {
      buf_ptr = buf + ch;
      /* skip trailing blanks */
      while (ch && ((buf[ch] == ' ') || (buf[ch] == '\t') || (buf[ch] == '\r')))
        ch--;
      /* A very long word with leading spaces causes infinite
       * wrapping when MUTT_PAGER_NSKIP is set.  A folded header
       * with a single long word shouldn't be smartwrapped
       * either.  So just disable smart_wrap if it would wrap at the
       * beginning of the line. */
      if (ch == 0)
        buf_ptr = buf + cnt;
      else
        cnt = ch + 1;
    }
    if (!(flags & MUTT_PAGER_NSKIP))
    {
      /* skip leading blanks on the next line too */
      while ((*buf_ptr == ' ') || (*buf_ptr == '\t'))
        buf_ptr++;
    }
  }

  if (*buf_ptr == '\r')
    buf_ptr++;
  if (*buf_ptr == '\n')
    buf_ptr++;

  if (((int) (buf_ptr - buf) < b_read) && !(*line_info)[n + 1].continuation)
    append_line(*line_info, n, (int) (buf_ptr - buf));
  (*line_info)[n + 1].offset = curr_line->offset + (long) (buf_ptr - buf);

  /* if we don't need to display the line we are done */
  if (!(flags & MUTT_SHOW))
  {
    rc = 0;
    goto out;
  }

  /* display the line */
  format_line(line_info, n, buf, flags, &a, cnt, &ch, &vch, &col, &special,
              win_pager->state.cols);

/* avoid a bug in ncurses... */
#ifndef USE_SLANG_CURSES
  if (col == 0)
  {
    mutt_curses_set_color(MT_COLOR_NORMAL);
    mutt_window_addch(' ');
  }
#endif

  /* end the last color pattern (needed by S-Lang) */
  if (special || ((col != win_pager->state.cols) && (flags & (MUTT_SHOWCOLOR | MUTT_SEARCH))))
    resolve_color(*line_info, n, vch, flags, 0, &a);

  /* Fill the blank space at the end of the line with the prevailing color.
   * ncurses does an implicit clrtoeol() when you do mutt_window_addch('\n') so we have
   * to make sure to reset the color *after* that */
  if (flags & MUTT_SHOWCOLOR)
  {
    m = (curr_line->continuation) ? (curr_line->syntax)[0].first : n;
    if ((*line_info)[m].type == MT_COLOR_HEADER)
      def_color = ((*line_info)[m].syntax)[0].color;
    else
      def_color = Colors->defs[(*line_info)[m].type];

    mutt_curses_set_attr(def_color);
  }

  if (col < win_pager->state.cols)
    mutt_window_clrtoeol(win_pager);

  /* reset the color back to normal.  This *must* come after the
   * clrtoeol, otherwise the color for this line will not be
   * filled to the right margin.  */
  if (flags & MUTT_SHOWCOLOR)
    mutt_curses_set_color(MT_COLOR_NORMAL);

  /* build a return code */
  if (!(flags & MUTT_SHOW))
    flags = 0;

  rc = flags;

out:
  FREE(&buf);
  FREE(&fmt);
  return rc;
}

