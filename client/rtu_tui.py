#!/usr/bin/env python3
"""
Split-screen terminal UI for rtu_shell.

Layout:

    +--------------------------------------------------+
    | scrolling output pane (frames, replies, help)     |
    | ...                                               |
    +--------------------------------------------------+
    | status: target, ca, link state, V(S)/V(R), count  |
    | rtu> your input line, never overwritten           |
    +--------------------------------------------------+

The RTU's reader thread writes into the pane while the prompt stays pinned at
the bottom, so inbound frames can never garble what you are typing.

Scrolling the output pane
    A curses screen replaces the terminal's own scrollback, so scrolling is
    handled here instead:

    mouse wheel      scroll 3 lines (`mouse off` to restore text selection)
    PgUp / PgDn      scroll a screen, at any time
    Up / Down        scroll a line WHILE `-- MORE --` is showing; otherwise
                     they walk command history
    space            page down while `-- MORE --` is showing
    Shift-Up/Down    scroll a line
    Home / End       oldest output / back to live (on an empty input line)
    scroll up|down|top|end [n]      the same, as a command

Editing keys
    Enter            run the command
    Tab              complete a command name
    Up / Down        command history (when not scrolled back)
    Left / Right     move the cursor
    Ctrl-A / Ctrl-E  start / end of line
    Backspace / Del  delete
    Ctrl-W           delete previous word
    Ctrl-U / Ctrl-K  clear to start / end of line
    Ctrl-L           redraw
    Ctrl-C           interrupt a running command
    Ctrl-D           quit (on an empty line)
"""

from __future__ import annotations

import curses
import os
import sys
import threading
from collections import deque

HISTFILE = os.path.expanduser("~/.rtu_shell_history")
SCROLLBACK = 5000


class PaneWriter:
    """A file-like object that appends whatever is printed to the output pane."""

    def __init__(self, tui):
        self.tui = tui
        self.partial = ""
        self.lock = threading.Lock()

    def write(self, s):
        with self.lock:
            self.partial += s
            while "\n" in self.partial:
                line, self.partial = self.partial.split("\n", 1)
                self.tui.add_line(line)
        self.tui.refresh_output(source="output")
        return len(s)

    def flush(self):
        with self.lock:
            if self.partial:
                self.tui.add_line(self.partial)
                self.partial = ""
        self.tui.refresh_output(source="output")

    def isatty(self):
        return True


class TUI:
    def __init__(self, shell, log=None, folded_log=None):
        self.shell = shell
        self.log = log             # full log; the client feeds it every frame
        self.folded_log = folded_log   # optional second log, exactly as shown
        self.lines: deque[str] = deque(maxlen=SCROLLBACK)
        self.scroll = 0            # 0 = pinned to newest
        self.buf = ""
        self.cur = 0
        self.history: list[str] = []
        self.hidx = None
        self.draft = ""
        self.prompt = "rtu> "
        self.draw_lock = threading.RLock()
        self.stdscr = None
        self.quit = False
        self._pane_dirty = True    # pane content changed -> full repaint needed
        self._last_scroll = 0
        # While frozen, inbound lines are still recorded but the pane is not
        # repainted, so a text selection made with the mouse survives. The
        # terminal discards a selection as soon as the cells under it change.
        self.frozen = False
        self.pending = 0

    # -- output ------------------------------------------------------------ #

    def add_line(self, line):
        with self.draw_lock:
            self.lines.append(line.rstrip("\r"))
            self._pane_dirty = True
            # Pane text never carries ANSI, so this mirrors cleanly. Frozen or
            # scrolled back makes no difference - the logs always record.
            # The full log is muted while the client prints, because it already
            # received the unfolded line direct from the client.
            if self.log is not None and not self.log.is_muted:
                self.log.write_line(line)
            if self.folded_log is not None:
                self.folded_log.write_line(line)
            if self.frozen:
                self.pending += 1
                return
            if self.scroll:                       # keep the view anchored
                self.scroll = min(self.scroll + 1, max(0, len(self.wrapped()) - 1))

    def set_freeze(self, on, quiet=False):
        """Freeze/thaw the output pane. Frozen means inbound frames are recorded
        but not drawn, which is the only way a mouse selection can survive."""
        with self.draw_lock:
            was = self.frozen
            self.frozen = bool(on)
            if self.frozen:
                if not quiet and not was:
                    print("PAUSED - pane frozen so you can select and copy. "
                          "Frames still arrive. F2 or Ctrl-O resumes, and so "
                          "does running any command.")
                self.refresh_output(source="input")
            else:
                held, self.pending = self.pending, 0
                if not quiet and was:
                    print(f"resumed{f' - {held} line(s) arrived while paused' if held else ''}")
                self._pane_dirty = True
                self.refresh_output(source="input")

    def wrapped(self):
        """Word-wrapped view of the scrollback, as display rows."""
        w = max(self.width - 1, 20)
        rows = []
        for ln in self.lines:
            if not ln:
                rows.append("")
                continue
            while len(ln) > w:
                cut = ln.rfind(" ", 0, w)
                if cut < w // 2:
                    cut = w
                rows.append(ln[:cut])
                ln = "  " + ln[cut:].lstrip()
            rows.append(ln)
        return rows

    @property
    def width(self):
        return self.stdscr.getmaxyx()[1] if self.stdscr else 80

    @property
    def height(self):
        return self.stdscr.getmaxyx()[0] if self.stdscr else 24

    # -- drawing ----------------------------------------------------------- #

    def _put(self, y, x, text, attr=curses.A_NORMAL):
        """Write one row, tolerating the bottom-right-corner curses.error.

        addnstr on the last cell of the screen always errors; without catching
        it per row, one failure would abort the rest of the repaint and leave
        stale text on screen.
        """
        try:
            self.stdscr.addnstr(y, x, text, max(0, self.width - 1 - x), attr)
        except curses.error:
            pass

    def refresh_output(self, source="input"):
        """Repaint. Safe to call from the reader thread.

        source="output" marks a repaint caused by arriving data. While frozen,
        those leave the pane's cells untouched - only the status line is updated
        with the pending count - so a selection the user made stays intact.
        """
        if self.stdscr is None:
            return
        if self.frozen and source == "output":
            with self.draw_lock:
                try:
                    self.draw_status()
                    self.draw_input()
                    self.stdscr.noutrefresh()
                    curses.doupdate()
                except curses.error:
                    pass
            return
        with self.draw_lock:
            # Whenever the pane's content or scroll position changed, repaint the
            # whole screen instead of letting curses diff line interiors. Diffed
            # partial updates can merge two different bodies of text on one row
            # (e.g. paging through `help`). Pure input-line edits skip this, so
            # typing stays cheap.
            full = self._pane_dirty or self._last_scroll != self.scroll
            try:
                self.draw_output()
                self.draw_status()
                self.draw_input()
                if full:
                    self.stdscr.clearok(True)
                self.stdscr.noutrefresh()
                curses.doupdate()
            except curses.error:
                pass
            self._pane_dirty = False
            self._last_scroll = self.scroll

    def draw_output(self):
        rows = self.wrapped()
        h = self.height - 2
        if h < 1:
            return
        end = len(rows) - self.scroll
        view = rows[max(0, end - h):end]
        w = self.width - 1
        for i in range(h):
            text = view[i] if i < len(view) else ""
            # Pad to the full width rather than trusting clrtoeol, so a shorter
            # line can never leave characters of a longer one behind.
            self._put(i, 0, text.ljust(w)[:w], self._attr(text))

    def _attr(self, line):
        s = line.lstrip()
        if s.startswith("[->]"):
            return curses.color_pair(1)
        if s.startswith("[<-]"):
            return curses.color_pair(2)
        if s.startswith("[!]") or s.startswith("[~]"):
            return curses.color_pair(3) | curses.A_BOLD
        if s.startswith("[ok]"):
            return curses.color_pair(4) | curses.A_BOLD
        if s.startswith("rtu>") or s.startswith("---"):
            return curses.A_BOLD
        return curses.A_NORMAL

    def draw_status(self):
        c = self.shell.c
        if c is not None and c._running:
            link = f"up  V(S)={c.tx} V(R)={c.rx} acked={c.acked} rx={len(c.received)}"
        else:
            link = "DOWN - use `open`"
        left = (f" {self.shell.host}:{self.shell.port}  ca={self.shell.ca} "
                f"oa={self.shell.oa}  {link}")
        if self.frozen:
            held = f"{self.pending} new" if self.pending else "select freely"
            right = f"** PAUSED, {held} -- F2/ctrl-O resumes ** "
        elif self.scroll:
            right = (f"-- MORE -- up/down wheel PgUp/PgDn  End=live "
                     f"(+{self.scroll}) ")
        else:
            right = "help | PgUp scrolls | F2 pauses | ctrl-d quit "
        # The right-hand hint must survive; trim the left side to make room.
        room = self.width - 1 - len(right)
        if len(left) > room:
            left = left[:max(0, room - 1)] + ("~" if room > 0 else "")
        bar = left + " " * max(0, room - len(left)) + right
        w = self.width - 1
        self._put(self.height - 2, 0, bar.ljust(w)[:w],
                  curses.color_pair(5) | curses.A_REVERSE)

    def draw_input(self):
        y = self.height - 1
        w = self.width - 1
        avail = max(1, w - len(self.prompt))
        off = max(0, self.cur - avail + 1)
        self._put(y, 0, self.prompt, curses.A_BOLD)
        self._put(y, len(self.prompt), self.buf[off:].ljust(avail)[:avail])
        try:
            self.stdscr.move(y, min(len(self.prompt) + self.cur - off, w))
        except curses.error:
            pass

    # -- input ------------------------------------------------------------- #

    def complete(self):
        head = self.buf[:self.cur]
        word = head.split()[-1] if head and not head.endswith(" ") else ""
        if " " in head.strip() and word:
            return                                    # only complete command names
        opts = [n for n in self.shell.names() if n.startswith(word)]
        if not opts:
            return
        if len(opts) == 1:
            self.buf = opts[0] + " " + self.buf[self.cur:]
            self.cur = len(opts[0]) + 1
        else:
            pre = os.path.commonprefix(opts)
            if len(pre) > len(word):
                self.buf = pre + self.buf[self.cur:]
                self.cur = len(pre)
            print("  ".join(opts))

    def read_line(self, prompt="rtu> "):
        """Block until Enter. Returns the line, or None on Ctrl-D / EOF."""
        self.prompt = prompt
        self.buf, self.cur, self.hidx = "", 0, None
        self.refresh_output()
        while True:
            try:
                ch = self.stdscr.get_wch()
            except curses.error:
                continue
            except KeyboardInterrupt:
                self.buf, self.cur = "", 0
                print("^C")
                self.refresh_output()
                continue

            if isinstance(ch, str):
                o = ord(ch)
                if o == 27:                                   # ESC: decode it
                    self._handle_escape()
                    self.refresh_output()
                    continue
                if ch in ("\n", "\r"):
                    if self.frozen:
                        self.set_freeze(False)    # running a command resumes
                    line = self.buf
                    print(self.prompt + line)
                    if line.strip():
                        self.history.append(line)
                    self.buf, self.cur = "", 0
                    self.scroll = 0
                    self.refresh_output()
                    return line
                if o == 4:                                    # Ctrl-D
                    if not self.buf:
                        return None
                elif o == 9:                                  # Tab
                    self.complete()
                elif o in (8, 127):                           # Backspace
                    if self.cur:
                        self.buf = self.buf[:self.cur - 1] + self.buf[self.cur:]
                        self.cur -= 1
                elif o == 1:                                  # Ctrl-A
                    self.cur = 0
                elif o == 5:                                  # Ctrl-E
                    self.cur = len(self.buf)
                elif o == 11:                                 # Ctrl-K
                    self.buf = self.buf[:self.cur]
                elif o == 21:                                 # Ctrl-U
                    self.buf = self.buf[self.cur:]
                    self.cur = 0
                elif o == 23:                                 # Ctrl-W
                    head = self.buf[:self.cur].rstrip()
                    cut = head.rfind(" ") + 1
                    self.buf = self.buf[:cut] + self.buf[self.cur:]
                    self.cur = cut
                elif o == 15:                                 # Ctrl-O
                    self.set_freeze(not self.frozen)
                elif o == 12:                                 # Ctrl-L
                    self.stdscr.clearok(True)
                elif o == 3:                                  # Ctrl-C
                    self.buf, self.cur = "", 0
                elif ch == " " and not self.buf and self.scroll:
                    # space pages down while reviewing long output (`help` etc.)
                    self.scroll = max(0, self.scroll - max(1, self.height - 3))
                elif o >= 32:
                    self.buf = self.buf[:self.cur] + ch + self.buf[self.cur:]
                    self.cur += 1
            else:
                self._special(ch)
            self.refresh_output()

    WHEEL_LINES = 3

    # Escape sequences ncurses may not translate for us. Terminals send cursor
    # keys as either CSI (\e[A) or SS3 (\eOA) depending on application mode, and
    # a sequence we fail to decode would otherwise be inserted as literal text
    # ("[A" appearing in the input line instead of scrolling).
    ESC_KEYS = {
        "[A": curses.KEY_UP, "OA": curses.KEY_UP,
        "[B": curses.KEY_DOWN, "OB": curses.KEY_DOWN,
        "[C": curses.KEY_RIGHT, "OC": curses.KEY_RIGHT,
        "[D": curses.KEY_LEFT, "OD": curses.KEY_LEFT,
        "[H": curses.KEY_HOME, "OH": curses.KEY_HOME,
        "[1~": curses.KEY_HOME, "[7~": curses.KEY_HOME,
        "[F": curses.KEY_END, "OF": curses.KEY_END,
        "[4~": curses.KEY_END, "[8~": curses.KEY_END,
        "[5~": curses.KEY_PPAGE, "[6~": curses.KEY_NPAGE,
        "[3~": curses.KEY_DC,
        "OQ": curses.KEY_F2, "[12~": curses.KEY_F2, "[[B": curses.KEY_F2,
        "[1;2A": curses.KEY_SR, "[a": curses.KEY_SR,
        "[1;2B": curses.KEY_SF, "[b": curses.KEY_SF,
        # ctrl-arrows, treated as line-at-a-time scrolling
        "[1;5A": curses.KEY_SR, "[1;5B": curses.KEY_SF,
    }

    def _read_escape(self):
        """Collect the rest of an escape sequence after a bare ESC."""
        seq = ""
        self.stdscr.nodelay(True)
        try:
            for _ in range(20):
                try:
                    c = self.stdscr.get_wch()
                except curses.error:
                    break
                if not isinstance(c, str):
                    break
                seq += c
                if seq in ("[", "O", "[<", "[M") or seq[-1] in "0123456789;<":
                    if seq == "[M":                  # X10 mouse: 3 raw bytes
                        for _ in range(3):
                            try:
                                seq += self.stdscr.get_wch()
                            except (curses.error, TypeError):
                                break
                        break
                    continue
                break
        finally:
            self.stdscr.nodelay(False)
        return seq

    def _wheel_from_seq(self, seq):
        """Return +1 for wheel-up, -1 for wheel-down, 0 if not a wheel event."""
        btn = None
        if seq.startswith("[<"):                     # SGR 1006: \e[<64;x;yM
            try:
                btn = int(seq[2:].split(";")[0])
            except ValueError:
                return 0
        elif seq.startswith("[M") and len(seq) >= 5:  # X10: \e[M Cb Cx Cy
            btn = ord(seq[2]) - 32
        if btn is None:
            return 0
        if btn == 64:
            return 1
        if btn == 65:
            return -1
        return 0

    def _handle_escape(self):
        seq = self._read_escape()
        if not seq:
            return
        wheel = self._wheel_from_seq(seq)
        if wheel:
            rows = len(self.wrapped())
            if wheel > 0:
                self.scroll = min(self.scroll + self.WHEEL_LINES,
                                  max(0, rows - 1))
            else:
                self.scroll = max(0, self.scroll - self.WHEEL_LINES)
            return
        key = self.ESC_KEYS.get(seq)
        if key is not None:
            self._special(key)

    def _mouse(self, page):
        """Wheel up/down scrolls the output pane."""
        try:
            _id, _x, _y, _z, bstate = curses.getmouse()
        except curses.error:
            return
        rows = len(self.wrapped())
        up = getattr(curses, "BUTTON4_PRESSED", 0)
        down = getattr(curses, "BUTTON5_PRESSED", 0) or 0x00200000
        if bstate & up:
            self.scroll = min(self.scroll + self.WHEEL_LINES, max(0, rows - 1))
        elif bstate & down:
            self.scroll = max(0, self.scroll - self.WHEEL_LINES)

    def set_mouse(self, on):
        """Enable/disable wheel capture. Off restores the terminal's own
        text selection and copy, which mouse capture otherwise swallows."""
        try:
            curses.mousemask(curses.ALL_MOUSE_EVENTS if on else 0)
            self.mouse_on = bool(on)
            if on:
                print("mouse capture ON - wheel scrolls. Text selection is now "
                      "grabbed by the app; hold Shift to select anyway, or "
                      "`mouse off`.")
            else:
                print("mouse capture OFF - select and copy normally. "
                      "Scroll with PgUp/PgDn, arrows, or `scroll`.")
        except curses.error as exc:
            print(f"mouse unavailable: {exc}")

    def scroll_by(self, what, n=None):
        """Programmatic scrolling, used by the `scroll` command."""
        rows = len(self.wrapped())
        page = max(1, self.height - 3)
        step = n if n is not None else page
        if what == "up":
            self.scroll = min(self.scroll + step, max(0, rows - 1))
        elif what == "down":
            self.scroll = max(0, self.scroll - step)
        elif what == "top":
            self.scroll = max(0, rows - 1)
        elif what in ("end", "live", "bottom"):
            self.scroll = 0
        self.refresh_output()

    def _special(self, key):
        rows = len(self.wrapped())
        page = max(1, self.height - 3)
        if key == curses.KEY_LEFT:
            self.cur = max(0, self.cur - 1)
        elif key == curses.KEY_RIGHT:
            self.cur = min(len(self.buf), self.cur + 1)
        elif key == curses.KEY_HOME:
            if self.buf:
                self.cur = 0
            else:
                self.scroll = max(0, rows - 1)      # jump to oldest output
        elif key == curses.KEY_END:
            if self.buf:
                self.cur = len(self.buf)
            else:
                self.scroll = 0
        elif key in (curses.KEY_BACKSPACE,):
            if self.cur:
                self.buf = self.buf[:self.cur - 1] + self.buf[self.cur:]
                self.cur -= 1
        elif key == curses.KEY_DC:
            self.buf = self.buf[:self.cur] + self.buf[self.cur + 1:]
        elif key == curses.KEY_PPAGE:
            self.scroll = min(self.scroll + page, max(0, rows - 1))
        elif key == curses.KEY_NPAGE:
            self.scroll = max(0, self.scroll - page)
        elif key == curses.KEY_SR:                       # shift-up
            self.scroll = min(self.scroll + 1, max(0, rows - 1))
        elif key == curses.KEY_SF:                       # shift-down
            self.scroll = max(0, self.scroll - 1)
        elif key in (curses.KEY_F2, curses.KEY_F3):
            self.set_freeze(not self.frozen)
        elif key == curses.KEY_MOUSE:
            self._mouse(page)
        elif key == curses.KEY_UP and self.scroll:
            # While reviewing long output, the arrows scroll. Press End (or type
            # anything) to go back to live, where they walk command history.
            self.scroll = min(self.scroll + 1, max(0, rows - 1))
        elif key == curses.KEY_DOWN and self.scroll:
            self.scroll = max(0, self.scroll - 1)
        elif key == curses.KEY_UP:
            if self.history:
                if self.hidx is None:
                    self.hidx = len(self.history)
                    self.draft = self.buf
                self.hidx = max(0, self.hidx - 1)
                self.buf = self.history[self.hidx]
                self.cur = len(self.buf)
        elif key == curses.KEY_DOWN:
            if self.hidx is not None:
                self.hidx += 1
                if self.hidx >= len(self.history):
                    self.hidx = None
                    self.buf = self.draft
                else:
                    self.buf = self.history[self.hidx]
                self.cur = len(self.buf)
        elif key == curses.KEY_RESIZE:
            self.stdscr.clear()

    def run_and_page(self, line):
        """Run a command; if it printed more than one screenful, park the view
        at the START of that output instead of the tail, so long output (`help`,
        a big interrogation) can be read from the top rather than scrolling past."""
        before = len(self.wrapped())
        try:
            self.shell.run_line(line)
        finally:
            produced = len(self.wrapped()) - before
            pane = max(1, self.height - 2)
            if produced > pane:
                self.scroll = produced - pane
            self.refresh_output()

    # -- main loop --------------------------------------------------------- #

    def _load_history(self):
        try:
            with open(HISTFILE) as fh:
                self.history = [l.rstrip("\n") for l in fh][-500:]
        except OSError:
            pass

    def _save_history(self):
        try:
            with open(HISTFILE, "w") as fh:
                fh.write("\n".join(self.history[-500:]) + "\n")
        except OSError:
            pass

    def run(self, startup_cmds=(), auto_open=True):
        curses.wrapper(self._run, startup_cmds, auto_open)

    def _run(self, stdscr, startup_cmds, auto_open):
        self.stdscr = stdscr
        curses.cbreak()          # leaves ISIG on, so Ctrl-C still interrupts
        curses.noecho()
        stdscr.keypad(True)
        try:
            curses.start_color()
            curses.use_default_colors()
            for i, fg in enumerate((curses.COLOR_CYAN, curses.COLOR_GREEN,
                                    curses.COLOR_RED, curses.COLOR_GREEN,
                                    curses.COLOR_BLUE), start=1):
                curses.init_pair(i, fg, -1)
        except curses.error:
            pass

        # Mouse capture starts OFF on purpose: grabbing the wheel also grabs
        # click-drag, which stops the terminal's own text selection and makes
        # copying values out impossible. Keys scroll fine without it; enable the
        # wheel with `mouse on` when you want it.
        self.mouse_on = False
        try:
            curses.mouseinterval(0)
            curses.mousemask(0)
        except curses.error:
            pass

        writer = PaneWriter(self)
        real_stdout, real_stderr = sys.stdout, sys.stderr
        sys.stdout = sys.stderr = writer
        self.shell._ask = self.read_line
        self.shell._tui = self
        self._load_history()

        try:
            print("IEC 60870-5-104 shell - split screen")
            print("`help` for commands, `help control` for opening/closing outputs")
            print("PgUp/PgDn scrolls this pane; the prompt below stays put.")
            print("")
            if auto_open:
                self.shell.cmd_open([])
            for cmd in startup_cmds:
                print(f"{self.prompt}{cmd}")
                self.run_and_page(cmd)

            while not self.quit:
                up = "" if (self.shell.c and self.shell.c._running) else " [down]"
                line = self.read_line(f"rtu{up}> ")
                if line is None:
                    break
                if not line.strip():
                    continue
                try:
                    self.run_and_page(line)
                except SystemExit:
                    break
                except KeyboardInterrupt:
                    print("^C interrupted")
        finally:
            self._save_history()
            try:
                self.shell.cmd_close([])
            except Exception:
                pass
            sys.stdout, sys.stderr = real_stdout, real_stderr


def available() -> bool:
    """True when a split-screen UI can actually be run here."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return False
    if not os.environ.get("TERM") or os.environ["TERM"] == "dumb":
        return False
    try:
        import curses  # noqa: F401
    except ImportError:
        return False
    return True
