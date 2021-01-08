/**
 * @file
 * GUI display a file/email/help in a viewport with paging
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

#ifndef MUTT_PAGER_PRIVATE_H
#define MUTT_PAGER_PRIVATE_H

#include <stdbool.h>

struct Regex;

extern bool          C_AllowAnsi;
extern bool          C_HeaderColorPartial;
extern short         C_PagerContext;
extern short         C_PagerIndexLines;
extern bool          C_PagerStop;
extern short         C_SearchContext;
extern short         C_SkipQuotedOffset;
extern bool          C_SmartWrap;
extern struct Regex *C_Smileys;
extern bool          C_Tilde;

#endif /* MUTT_PAGER_PRIVATE_H */
