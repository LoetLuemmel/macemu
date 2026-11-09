/*
 *  clip_sdl.cpp - Clipboard handling via SDL (text only)
 *
 *  Basilisk II (C) 1997-2008 Christian Bauer
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 *  NOTES:
 *
 *  Used for SDL video builds on platforms without a native clipboard
 *  module (e.g. Linux/X11, where clip_unix.cpp needs the non-SDL X11
 *  video driver). Only 'TEXT' is exchanged; it is converted between
 *  MacRoman/CR and UTF-8/LF.
 *
 *  GetScrap()/PutScrap() are called from the emulator thread, which is
 *  the thread that created the SDL window and pumps its events
 *  (VideoInterrupt), as SDL's clipboard functions require.
 *
 *  ClipInit() runs before VideoInit(), so SDL is not touched there.
 */

#include "sysdeps.h"

#include "my_sdl.h"

#include <string>

#include "macos_util.h"
#include "clip.h"
#include "prefs.h"
#include "cpu_emulation.h"
#include "main.h"
#include "emul_op.h"

#define DEBUG 0
#include "debug.h"


// MacRoman 0x80..0xff -> Unicode
static const uint16 mac2uni[0x80] = {
	0x00c4, 0x00c5, 0x00c7, 0x00c9, 0x00d1, 0x00d6, 0x00dc, 0x00e1,
	0x00e0, 0x00e2, 0x00e4, 0x00e3, 0x00e5, 0x00e7, 0x00e9, 0x00e8,
	0x00ea, 0x00eb, 0x00ed, 0x00ec, 0x00ee, 0x00ef, 0x00f1, 0x00f3,
	0x00f2, 0x00f4, 0x00f6, 0x00f5, 0x00fa, 0x00f9, 0x00fb, 0x00fc,
	0x2020, 0x00b0, 0x00a2, 0x00a3, 0x00a7, 0x2022, 0x00b6, 0x00df,
	0x00ae, 0x00a9, 0x2122, 0x00b4, 0x00a8, 0x2260, 0x00c6, 0x00d8,
	0x221e, 0x00b1, 0x2264, 0x2265, 0x00a5, 0x00b5, 0x2202, 0x2211,
	0x220f, 0x03c0, 0x222b, 0x00aa, 0x00ba, 0x03a9, 0x00e6, 0x00f8,
	0x00bf, 0x00a1, 0x00ac, 0x221a, 0x0192, 0x2248, 0x2206, 0x00ab,
	0x00bb, 0x2026, 0x00a0, 0x00c0, 0x00c3, 0x00d5, 0x0152, 0x0153,
	0x2013, 0x2014, 0x201c, 0x201d, 0x2018, 0x2019, 0x00f7, 0x25ca,
	0x00ff, 0x0178, 0x2044, 0x20ac, 0x2039, 0x203a, 0xfb01, 0xfb02,
	0x2021, 0x00b7, 0x201a, 0x201e, 0x2030, 0x00c2, 0x00ca, 0x00c1,
	0x00cb, 0x00c8, 0x00cd, 0x00ce, 0x00cf, 0x00cc, 0x00d3, 0x00d4,
	0xf8ff, 0x00d2, 0x00da, 0x00db, 0x00d9, 0x0131, 0x02c6, 0x02dc,
	0x00af, 0x02d8, 0x02d9, 0x02da, 0x00b8, 0x02dd, 0x02db, 0x02c7
};

// Flag: Don't convert clipboard text (bytes >= 0x80 are treated as ISO-Latin1)
static bool no_clip_conversion;

// Flag for PutScrap(): the data was put by GetScrap(), don't bounce it back to the host side
static bool we_put_this_data = false;

// Last UTF-8 text exchanged with the host clipboard; used to skip
// copying the host clipboard back to the Mac when nothing changed
static std::string last_host_text;


/*
 *  Charset conversion
 */

static void append_utf8(std::string &out, uint32 c)
{
	if (c < 0x80)
		out += char(c);
	else if (c < 0x800) {
		out += char(0xc0 | (c >> 6));
		out += char(0x80 | (c & 0x3f));
	} else {
		out += char(0xe0 | (c >> 12));
		out += char(0x80 | ((c >> 6) & 0x3f));
		out += char(0x80 | (c & 0x3f));
	}
}

static std::string mac_to_utf8(const uint8 *p, int32 length)
{
	std::string out;
	out.reserve(length);
	for (int32 i = 0; i < length; i++) {
		uint8 c = p[i];
		if (c == 13)					// CR -> LF
			append_utf8(out, 10);
		else if (c < 0x80)
			append_utf8(out, c);
		else if (no_clip_conversion)
			append_utf8(out, c);
		else
			append_utf8(out, mac2uni[c - 0x80]);
	}
	return out;
}

static uint8 uni_to_mac(uint32 u)
{
	if (u < 0x80)
		return u == 10 ? 13 : u;		// LF -> CR
	if (no_clip_conversion)
		return u < 0x100 ? u : '?';
	for (int i = 0; i < 0x80; i++)
		if (mac2uni[i] == u)
			return 0x80 + i;
	if (u == 0x00a4)					// pre-Mac OS 8.5 currency sign
		return 0xdb;
	return '?';
}

static std::string utf8_to_mac(const char *s)
{
	std::string out;
	const uint8 *p = (const uint8 *)s;
	while (*p) {
		uint32 u;
		int extra;
		uint8 c = *p++;
		if (c < 0x80) { u = c; extra = 0; }
		else if ((c & 0xe0) == 0xc0) { u = c & 0x1f; extra = 1; }
		else if ((c & 0xf0) == 0xe0) { u = c & 0x0f; extra = 2; }
		else if ((c & 0xf8) == 0xf0) { u = c & 0x07; extra = 3; }
		else { out += '?'; continue; }	// stray continuation byte
		bool ok = true;
		for (int i = 0; i < extra; i++) {
			if ((*p & 0xc0) != 0x80) { ok = false; break; }
			u = (u << 6) | (*p++ & 0x3f);
		}
		if (!ok) { out += '?'; continue; }
		if (u == 13 && *p == 10)		// CRLF -> CR
			p++;
		out += char(uni_to_mac(u));
	}
	return out;
}


/*
 *  Initialization
 */

void ClipInit(void)
{
	no_clip_conversion = PrefsFindBool("noclipconversion");
}


/*
 *  Deinitialization
 */

void ClipExit(void)
{
}


/*
 *  Mac application zeroes clipboard
 */

void ZeroScrap()
{
}


/*
 *  Mac application wrote to clipboard
 */

void PutScrap(uint32 type, void *scrap, int32 length)
{
	D(bug("PutScrap type %08x, data %p, length %d\n", type, scrap, length));
	if (we_put_this_data) {
		we_put_this_data = false;
		return;
	}
	if (length <= 0 || type != FOURCC('T','E','X','T'))
		return;

	std::string text = mac_to_utf8((const uint8 *)scrap, length);
#if SDL_VERSION_ATLEAST(3, 0, 0)
	bool ok = SDL_SetClipboardText(text.c_str());
#else
	bool ok = SDL_SetClipboardText(text.c_str()) == 0;
#endif
	if (ok)
		last_host_text = text;
	else
		D(bug(" SDL_SetClipboardText failed: %s\n", SDL_GetError()));
}


/*
 *  Mac application reads clipboard
 */

void GetScrap(void **handle, uint32 type, int32 offset)
{
	D(bug("GetScrap handle %p, type %08x, offset %d\n", handle, type, offset));
	if (type != FOURCC('T','E','X','T'))
		return;
	if (!SDL_HasClipboardText())
		return;

	char *host = SDL_GetClipboardText();
	if (host == NULL)
		return;
	std::string text(host);
	SDL_free(host);

	// Unchanged since we last saw or set it: the Mac side already has it
	if (text.empty() || text == last_host_text)
		return;
	last_host_text = text;

	std::string mac = utf8_to_mac(text.c_str());
	if (mac.empty())
		return;

	// Allocate space for new scrap in MacOS side
	M68kRegisters r;
	r.d[0] = mac.size();
	Execute68kTrap(0xa71e, &r);			// NewPtrSysClear()
	uint32 scrap_area = r.a[0];
	if (!scrap_area)
		return;
	Host2Mac_memcpy(scrap_area, mac.data(), mac.size());

	// Add new data to clipboard
	static const uint8 proc[] = {
		0x59, 0x8f,					// subq.l	#4,sp
		0xa9, 0xfc,					// ZeroScrap()
		0x2f, 0x3c, 0, 0, 0, 0,		// move.l	#length,-(sp)
		0x2f, 0x3c, 0, 0, 0, 0,		// move.l	#type,-(sp)
		0x2f, 0x3c, 0, 0, 0, 0,		// move.l	#outbuf,-(sp)
		0xa9, 0xfe,					// PutScrap()
		0x58, 0x8f,					// addq.l	#4,sp
		M68K_RTS >> 8, M68K_RTS & 0xff
	};
	r.d[0] = sizeof(proc);
	Execute68kTrap(0xa71e, &r);			// NewPtrSysClear()
	uint32 proc_area = r.a[0];

	if (proc_area) {
		// The procedure must live in Mac address space (see clip_unix.cpp)
		Host2Mac_memcpy(proc_area, proc, sizeof(proc));
		WriteMacInt32(proc_area +  6, mac.size());
		WriteMacInt32(proc_area + 12, type);
		WriteMacInt32(proc_area + 18, scrap_area);
		we_put_this_data = true;
		Execute68k(proc_area, &r);
		we_put_this_data = false;

		r.a[0] = proc_area;
		Execute68kTrap(0xa01f, &r);		// DisposePtr
	}
	r.a[0] = scrap_area;
	Execute68kTrap(0xa01f, &r);			// DisposePtr
}
