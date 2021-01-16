/**
 * @file
 * Config used by libpager
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
 * @page pager_config Config used by libpager
 *
 * Config used by libpager
 */

#include "config.h"
#include <stddef.h>
#include <config/lib.h>
#include <stdbool.h>
#include "lib.h"

// clang-format off
bool          C_AllowAnsi;          ///< Config: Allow ANSI colour codes in rich text messages
bool          C_HeaderColorPartial; ///< Config: Only colour the part of the header matching the regex
short         C_PagerContext;       ///< Config: Number of lines of overlap when changing pages in the pager
short         C_PagerIndexLines;    ///< Config: Number of index lines to display above the pager
bool          C_PagerStop;          ///< Config: Don't automatically open the next message when at the end of a message
short         C_SearchContext;      ///< Config: Context to display around search matches
short         C_SkipQuotedOffset;   ///< Config: Lines of context to show when skipping quoted text
bool          C_SmartWrap;          ///< Config: Wrap text at word boundaries
struct Regex *C_Smileys;            ///< Config: Regex to match smileys to prevent mistakes when quoting text
bool          C_Tilde;              ///< Config: Character to pad blank lines in the pager
// clang-format on

struct ConfigDef PagerVars[] = {
  // clang-format off
  { "allow_ansi", DT_BOOL, &C_AllowAnsi, false, 0, NULL,
    "Allow ANSI colour codes in rich text messages"
  },
  { "header_color_partial", DT_BOOL|R_PAGER_FLOW, &C_HeaderColorPartial, false, 0, NULL,
    "Only colour the part of the header matching the regex"
  },
  { "pager_context", DT_NUMBER|DT_NOT_NEGATIVE, &C_PagerContext, 0, 0, NULL,
    "Number of lines of overlap when changing pages in the pager"
  },
  { "pager_index_lines", DT_NUMBER|DT_NOT_NEGATIVE|R_PAGER|R_REFLOW, &C_PagerIndexLines, 0, 0, NULL,
    "Number of index lines to display above the pager"
  },
  { "pager_stop", DT_BOOL, &C_PagerStop, false, 0, NULL,
    "Don't automatically open the next message when at the end of a message"
  },
  { "search_context", DT_NUMBER|DT_NOT_NEGATIVE, &C_SearchContext, 0, 0, NULL,
    "Context to display around search matches"
  },
  { "skip_quoted_offset", DT_NUMBER|DT_NOT_NEGATIVE, &C_SkipQuotedOffset, 0, 0, NULL,
    "Lines of context to show when skipping quoted text"
  },
  { "smart_wrap", DT_BOOL|R_PAGER_FLOW, &C_SmartWrap, true, 0, NULL,
    "Wrap text at word boundaries"
  },
  { "smileys", DT_REGEX|R_PAGER, &C_Smileys, IP "(>From )|(:[-^]?[][)(><}{|/DP])", 0, NULL,
    "Regex to match smileys to prevent mistakes when quoting text"
  },
  { "tilde", DT_BOOL|R_PAGER, &C_Tilde, false, 0, NULL,
    "Character to pad blank lines in the pager"
  },
  { NULL, 0, NULL, 0, 0, NULL, NULL },
  // clang-format on
};

/**
 * config_init_pager - Register pager config variables - Implements ::module_init_config_t
 */
bool config_init_pager(struct ConfigSet *cs)
{
  return cs_register_variables(cs, PagerVars, 0);
}
