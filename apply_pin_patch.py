#!/usr/bin/env python3
"""
BareLauncher PIN patch (run from the repository root).

Adds:
  * PinLock.java  - 4-digit PIN pad (remote/D-pad friendly), hashed storage
  * a "Gizli uygulama PIN kilidi" row at the top of the Settings panel
  * a PIN check before "Manage hidden apps" opens (only once a PIN is set)
  * a small "Duzenleyen: Veysel Alemdar" credit at the bottom of Settings

Safe to run twice: it does nothing if the patch is already applied.
It stops with an error (instead of guessing) if the source code differs
from what it expects.
"""
import re
import sys

BASE = "LauncherV15/app/src/main/"
ACT  = BASE + "java/com/bare/launcher/LauncherActivity.java"
PIN  = BASE + "java/com/bare/launcher/PinLock.java"
STR  = BASE + "res/values/strings.xml"

PIN_LOCK_JAVA = r'''package com.bare.launcher;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Looper;
import android.os.SystemClock;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Locale;

/**
 * 4-digit PIN lock for the "Manage hidden apps" screen.
 *
 * The PIN pad is a dialog with on-screen number keys that are all focusable,
 * so a TV remote's D-pad moves between them and OK presses the key. Number
 * keys on a remote also work. The PIN is stored as a salted SHA-256 hash in
 * the launcher's SharedPreferences (never as plain text).
 */
final class PinLock {
    private PinLock() {}

    private static final String K_HASH = "pin_hash";
    private static final String K_SALT = "pin_salt";
    private static final int  LEN       = 4;
    private static final int  MAX_FAILS = 5;
    private static final long LOCK_MS   = 30000L;

    private static int  fails     = 0;
    private static long lockUntil = 0L;

    interface PinListener { void onPin(String pin, Pad pad); }

    // ── Public API ───────────────────────────────────────────────────────

    /** True when a PIN has been configured. */
    static boolean isSet(SharedPreferences p) {
        String h = p.getString(K_HASH, null);
        return h != null && !h.isEmpty();
    }

    /** Ask for the PIN (if one is set) and run {@code onOk} when it is right. */
    static void verify(final Activity a, final SharedPreferences p,
                       String title, final Runnable onOk) {
        if (!isSet(p)) { onOk.run(); return; }
        new Pad(a, title, "PIN'i girin").show((pin, pad) -> {
            if (SystemClock.elapsedRealtime() < lockUntil) {
                pad.fail("Kilitli, biraz bekleyin");
                return;
            }
            if (check(p, pin)) {
                fails = 0;
                pad.dismiss();
                onOk.run();
            } else {
                fails++;
                if (fails >= MAX_FAILS) {
                    fails = 0;
                    lockUntil = SystemClock.elapsedRealtime() + LOCK_MS;
                    pad.fail("\u00c7ok fazla deneme, 30 sn bekleyin");
                } else {
                    pad.fail("Yanl\u0131\u015f PIN");
                }
            }
        });
    }

    /**
     * The "PIN" settings row. No PIN yet: set one up straight away.
     * PIN already set: ask for it first, then offer change / turn off.
     */
    static void openSettings(final Activity a, final SharedPreferences p) {
        if (!isSet(p)) {
            createNew(a, p, "PIN belirle");
            return;
        }
        verify(a, p, "PIN kilidi", () -> showOptions(a, p));
    }

    // ── Flows ────────────────────────────────────────────────────────────

    private static void createNew(final Activity a, final SharedPreferences p,
                                  final String title) {
        new Pad(a, title, "Yeni PIN (" + LEN + " hane)").show((pin1, pad1) -> {
            pad1.dismiss();
            new Pad(a, title, "PIN'i tekrar girin").show((pin2, pad2) -> {
                if (pin1.equals(pin2)) {
                    save(p, pin1);
                    pad2.dismiss();
                    Toast.makeText(a, "PIN kaydedildi", Toast.LENGTH_SHORT).show();
                } else {
                    pad2.fail("PIN'ler uyu\u015fmuyor");
                }
            });
        });
    }

    private static void showOptions(final Activity a, final SharedPreferences p) {
        if (a.isFinishing()) return;
        final Dialog d = baseDialog(a);
        LinearLayout box = card(a);
        box.addView(label(a, "PIN kilidi", 15, 0xFFFFFFFF, 8));

        TextView change = button(a, "PIN'i de\u011fi\u015ftir", 220, 44, 15);
        TextView off    = button(a, "PIN'i kapat", 220, 44, 15);
        TextView cancel = button(a, "\u0130ptal", 220, 44, 15);
        change.setOnClickListener(v -> {
            d.dismiss();
            createNew(a, p, "PIN de\u011fi\u015ftir");
        });
        off.setOnClickListener(v -> {
            d.dismiss();
            clear(p);
            Toast.makeText(a, "PIN kapat\u0131ld\u0131", Toast.LENGTH_SHORT).show();
        });
        cancel.setOnClickListener(v -> d.dismiss());
        box.addView(change);
        box.addView(off);
        box.addView(cancel);

        present(d, box);
        change.requestFocus();
    }

    // ── Storage ──────────────────────────────────────────────────────────

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format(Locale.ROOT, "%02x", b & 0xff));
        return sb.toString();
    }

    private static String hash(String salt, String pin) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return hex(md.digest((salt + ":" + pin).getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return "";
        }
    }

    private static void save(SharedPreferences p, String pin) {
        byte[] s = new byte[16];
        new SecureRandom().nextBytes(s);
        String salt = hex(s);
        p.edit().putString(K_SALT, salt).putString(K_HASH, hash(salt, pin)).apply();
    }

    private static void clear(SharedPreferences p) {
        p.edit().remove(K_HASH).remove(K_SALT).apply();
    }

    private static boolean check(SharedPreferences p, String pin) {
        String salt   = p.getString(K_SALT, "");
        String stored = p.getString(K_HASH, "");
        if (stored == null || stored.isEmpty()) return false;
        return MessageDigest.isEqual(
                hash(salt, pin).getBytes(StandardCharsets.UTF_8),
                stored.getBytes(StandardCharsets.UTF_8));
    }

    // ── UI helpers ───────────────────────────────────────────────────────

    private static int dp(Context c, float v) {
        return Math.round(v * c.getResources().getDisplayMetrics().density);
    }

    private static Dialog baseDialog(Activity a) {
        Dialog d = new Dialog(a);
        d.requestWindowFeature(Window.FEATURE_NO_TITLE);
        d.setCancelable(true);
        d.setCanceledOnTouchOutside(false);
        return d;
    }

    private static void present(Dialog d, View content) {
        d.setContentView(content);
        Window w = d.getWindow();
        if (w != null) {
            w.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            w.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
            w.setDimAmount(0.65f);
            w.setLayout(ViewGroup.LayoutParams.WRAP_CONTENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT);
        }
        d.show();
    }

    private static LinearLayout card(Context c) {
        LinearLayout box = new LinearLayout(c);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(0xFF1A1A1F);
        bg.setStroke(Math.max(1, dp(c, 1) / 2), 0x33FFFFFF);
        bg.setCornerRadius(dp(c, 18));
        box.setBackground(bg);
        box.setPadding(dp(c, 16), dp(c, 14), dp(c, 16), dp(c, 14));
        return box;
    }

    private static TextView label(Context c, String text, int sp, int color, int bottomDp) {
        TextView t = new TextView(c);
        t.setText(text);
        t.setTextColor(color);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(c, bottomDp);
        t.setLayoutParams(lp);
        return t;
    }

    private static void paint(TextView t, GradientDrawable bg, boolean focused) {
        bg.setColor(focused ? 0xFFEFEFEF : 0x22FFFFFF);
        t.setTextColor(focused ? 0xFF111114 : 0xE6FFFFFF);
    }

    /** A focusable key / button. Lights up white when focused (remote D-pad). */
    private static TextView button(Context c, String text, int wDp, int hDp, int sp) {
        final TextView t = new TextView(c);
        t.setText(text);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setGravity(Gravity.CENTER);
        t.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        t.setFocusable(true);
        t.setClickable(true);
        final GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(c, 10));
        t.setBackground(bg);
        paint(t, bg, false);
        t.setOnFocusChangeListener((v, focused) -> paint(t, bg, focused));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(dp(c, wDp), dp(c, hDp));
        int m = dp(c, 3);
        lp.setMargins(m, m, m, m);
        t.setLayoutParams(lp);
        return t;
    }

    // ── The PIN pad dialog ───────────────────────────────────────────────

    static final class Pad {
        private final Dialog dlg;
        private final LinearLayout root;
        private final TextView dots;
        private final TextView msg;
        private final String subtitle;
        private final StringBuilder buf = new StringBuilder();
        private final android.os.Handler h = new android.os.Handler(Looper.getMainLooper());
        private TextView firstFocus;
        private PinListener listener;
        private boolean busy = false;

        Pad(Activity a, String title, String subtitleText) {
            subtitle = subtitleText;
            dlg = baseDialog(a);
            root = card(a);
            root.addView(label(a, title, 15, 0xFFFFFFFF, 2));
            msg = label(a, subtitleText, 12, 0xB3FFFFFF, 6);
            root.addView(msg);
            dots = label(a, "", 26, 0xFFFFFFFF, 8);
            root.addView(dots);

            String[][] keys = {
                    {"1", "2", "3"},
                    {"4", "5", "6"},
                    {"7", "8", "9"},
                    {"Sil", "0", "\u0130ptal"}
            };
            for (String[] rowKeys : keys) {
                LinearLayout row = new LinearLayout(a);
                row.setOrientation(LinearLayout.HORIZONTAL);
                for (final String k : rowKeys) {
                    TextView b = button(a, k, 72, 46, 17);
                    if (k.equals("5")) firstFocus = b;
                    b.setOnClickListener(v -> onKey(k));
                    row.addView(b);
                }
                root.addView(row);
            }
            refresh();

            dlg.setOnKeyListener((d, keyCode, ev) -> {
                if (ev.getAction() != KeyEvent.ACTION_DOWN) return false;
                if (keyCode >= KeyEvent.KEYCODE_0 && keyCode <= KeyEvent.KEYCODE_9) {
                    add(String.valueOf(keyCode - KeyEvent.KEYCODE_0));
                    return true;
                }
                if (keyCode >= KeyEvent.KEYCODE_NUMPAD_0 && keyCode <= KeyEvent.KEYCODE_NUMPAD_9) {
                    add(String.valueOf(keyCode - KeyEvent.KEYCODE_NUMPAD_0));
                    return true;
                }
                if (keyCode == KeyEvent.KEYCODE_DEL) {
                    backspace();
                    return true;
                }
                return false;   // D-pad, OK and BACK keep their normal behaviour
            });
        }

        void show(PinListener l) {
            listener = l;
            if (dlg.getContext() instanceof Activity
                    && ((Activity) dlg.getContext()).isFinishing()) return;
            present(dlg, root);
            if (firstFocus != null) firstFocus.requestFocus();
        }

        void dismiss() {
            h.removeCallbacksAndMessages(null);
            try { dlg.dismiss(); } catch (Exception ignored) { /* already gone */ }
        }

        /** Show an error, then clear the digits and accept input again. */
        void fail(String text) {
            msg.setText(text);
            msg.setTextColor(0xFFFF6B6B);
            busy = true;
            h.postDelayed(() -> {
                buf.setLength(0);
                refresh();
                msg.setText(subtitle);
                msg.setTextColor(0xB3FFFFFF);
                busy = false;
            }, 700);
        }

        private void onKey(String k) {
            if (k.equals("Sil")) backspace();
            else if (k.equals("\u0130ptal")) dlg.cancel();
            else add(k);
        }

        private void add(String digit) {
            if (busy || buf.length() >= LEN) return;
            buf.append(digit);
            refresh();
            if (buf.length() == LEN && listener != null) {
                busy = true;
                listener.onPin(buf.toString(), this);
            }
        }

        private void backspace() {
            if (busy || buf.length() == 0) return;
            buf.setLength(buf.length() - 1);
            refresh();
        }

        private void refresh() {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < LEN; i++) {
                if (i > 0) sb.append("  ");
                sb.append(i < buf.length() ? "\u25cf" : "\u25cb");
            }
            dots.setText(sb.toString());
        }
    }
}
'''


def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def write(p, s):
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(s)


def sub_once(text, pattern, repl, label, flags=0):
    new, n = re.subn(pattern, lambda m: repl(m) if callable(repl) else repl,
                     text, count=0, flags=flags)
    if n != 1:
        sys.exit("PATCH ERROR: '%s' matched %d times (expected 1)" % (label, n))
    return new


def main():
    src = read(ACT)
    if "PinLock.isSet" in src:
        print("Patch already applied - nothing to do.")
        return

    braces_before = src.count("{") - src.count("}")

    # 1) new row id
    src = sub_once(
        src, r"(private static final int SR_IDLE_HIDE\s*=\s*13;[^\n]*\n)",
        lambda m: m.group(1) + "    private static final int SR_PIN            = 14;\n",
        "SR_PIN constant")

    # 2) show the row (right after "Manage hidden apps")
    src = sub_once(
        src, r"SR_HIDE_APPS, SR_KEYMAP, SR_WALLPAPER_MENU, SR_CLOCK,",
        lambda m: "SR_HIDE_APPS, SR_PIN, SR_KEYMAP, SR_WALLPAPER_MENU, SR_CLOCK,",
        "SROWS_MAIN")

    # 3) row label
    src = sub_once(
        src,
        r"(            case SR_HIDE_APPS:\s+return R\.string\.settings_row_manage_hidden;\n)",
        lambda m: m.group(1)
        + "            case SR_PIN:                return R.string.settings_row_pin;\n",
        "row label")

    # 4) PIN check in front of the hidden-apps manager + the PIN row action
    old_case = (
        r"            case SR_HIDE_APPS:\n"
        r"\s*// Hand off to the keymap card's HIDE mode \(returns here on Back\)\.\n"
        r"\s*pendingSettingsCursor\s*=\s*SR_HIDE_APPS;\n"
        r"\s*keymapOpenedFromSettings\s*=\s*true;\n"
        r"\s*hideManagerSkipSlotsOnExit\s*=\s*true;\n"
        r"\s*hideSettingsPanel\(\);\n"
        r"\s*showKeymapOverlay\(\);\n"
        r"\s*enterHideManager\(\);\n"
        r"\s*break;\n")
    new_case = (
        "            case SR_HIDE_APPS:\n"
        "                // PIN gate: asks for the PIN only when one has been set.\n"
        "                if (PinLock.isSet(prefs)) {\n"
        "                    PinLock.verify(this, prefs, \"Gizli uygulamalar\",\n"
        "                            this::openHideManagerFromSettings);\n"
        "                } else {\n"
        "                    openHideManagerFromSettings();\n"
        "                }\n"
        "                break;\n"
        "            case SR_PIN:\n"
        "                PinLock.openSettings(this, prefs);\n"
        "                break;\n")
    src = sub_once(src, old_case, lambda m: new_case, "SR_HIDE_APPS action")

    # 5) helper method with the original hand-off steps
    helper = (
        "    /** Opens the hidden-apps manager from the settings panel\n"
        "     *  (called directly, or after the PIN was entered correctly). */\n"
        "    private void openHideManagerFromSettings() {\n"
        "        pendingSettingsCursor       = SR_HIDE_APPS;\n"
        "        keymapOpenedFromSettings    = true;\n"
        "        hideManagerSkipSlotsOnExit  = true;\n"
        "        hideSettingsPanel();\n"
        "        showKeymapOverlay();\n"
        "        enterHideManager();\n"
        "    }\n\n")
    src = sub_once(
        src, r"(    /\*\* Execute the action bound to a settings row id\. \*/\n)",
        lambda m: helper + m.group(1), "helper insertion point")

    # 6) small credit line at the bottom of the settings card
    i = src.find("private void buildSettingsPanel()")
    if i < 0:
        sys.exit("PATCH ERROR: buildSettingsPanel not found")
    anchor = "card.addView(col, new android.widget.LinearLayout.LayoutParams(WRAP, WRAP));\n"
    j = src.find(anchor, i)
    if j < 0 or j - i > 6000:
        sys.exit("PATCH ERROR: settings card anchor not found")
    j += len(anchor)
    credit = (
        "        // Small credit line at the bottom of the settings card.\n"
        "        TextView creditView = new TextView(this);\n"
        "        creditView.setText(\"D\\u00fczenleyen: Veysel Alemdar\");\n"
        "        creditView.setTextColor(0x66FFFFFF);\n"
        "        creditView.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 9);\n"
        "        creditView.setSingleLine(true);\n"
        "        creditView.setGravity(Gravity.CENTER_HORIZONTAL);\n"
        "        creditView.setPadding(dp(10), dp(6), dp(10), dp(2));\n"
        "        android.widget.LinearLayout.LayoutParams creditLp =\n"
        "                new android.widget.LinearLayout.LayoutParams(WRAP, WRAP);\n"
        "        creditLp.gravity = Gravity.CENTER_HORIZONTAL;\n"
        "        card.addView(creditView, creditLp);\n")
    src = src[:j] + credit + src[j:]

    braces_after = src.count("{") - src.count("}")
    if braces_before != braces_after:
        sys.exit("PATCH ERROR: brace balance changed (%d -> %d)"
                 % (braces_before, braces_after))

    # strings.xml
    xml = read(STR)
    xml = sub_once(
        xml, r"(    <string name=\"settings_row_about\">About</string>\n)",
        lambda m: m.group(1)
        + "    <string name=\"settings_row_pin\">Gizli uygulama PIN kilidi</string>\n",
        "strings.xml")

    write(ACT, src)
    write(STR, xml)
    write(PIN, PIN_LOCK_JAVA)
    print("PIN patch applied: LauncherActivity.java, strings.xml, PinLock.java")


main()
