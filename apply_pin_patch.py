#!/usr/bin/env python3
"""
BareLauncher patch (run from the repository root). Works on the ORIGINAL
source at build time; nothing is committed back.

  * PinLock.java : PIN pad, "Gizleme" (lock + hide) list, helpers
  * Settings     : Gizlilik (PIN, Gizleme, Ayarlar kilidi), Ozellestirme
                   (Tus kisayollari, Duvar kagidi, Saat) and Diger (Yedekle,
                   Sistem ayarlari, Hakkinda) pages
  * Locks        : app lock on every launch, optional settings lock
  * Long-press   : "Gizle" removed from the app context menu
  * Icons        : TV (leanback) activity is preferred, so TV banners show
  * Drawer       : more transparent all-apps background
  * Focus frame: on/off + colour (Ozellestirme), RingView supports both
  * Turkish UI, small credit line under the settings list

Stops with an error (never guesses) if the source differs from expectations;
does nothing if it was already applied.
"""
import re
import sys

BASE = "LauncherV15/app/src/main/"
ACT  = BASE + "java/com/bare/launcher/LauncherActivity.java"
PIN  = BASE + "java/com/bare/launcher/PinLock.java"
RING = BASE + "java/com/bare/launcher/RingView.java"
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
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * 4-digit PIN lock: Privacy page, locked apps, settings lock.
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
    static final String K_LOCK_SETTINGS = "lock_settings";
    private static final String K_LOCKED_APPS = "locked_apps";
    private static final int  LEN       = 4;
    private static final int  MAX_FAILS = 5;
    private static final long LOCK_MS   = 30000L;

    private static int  fails     = 0;
    private static long lockUntil = 0L;

    /** Highlight colour (the focus-ring colour picked in settings). */
    static int accent = 0xFF38BDF8;

    private static Typeface mediumFont;
    private static Typeface medium() {
        if (mediumFont == null) mediumFont = Typeface.create("sans-serif-medium", Typeface.NORMAL);
        return mediumFont;
    }

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
     * The "PIN" row inside the Privacy page (which is already PIN-gated).
     * No PIN yet: set one up straight away. PIN set: change / turn off.
     */
    static void openSettings(final Activity a, final SharedPreferences p,
                             final Runnable onChanged) {
        if (!isSet(p)) {
            createNew(a, p, "PIN belirle", onChanged);
            return;
        }
        showOptions(a, p, onChanged);
    }

    /** True when the settings panel itself must ask for the PIN. */
    static boolean settingsLocked(SharedPreferences p) {
        return p != null && isSet(p) && p.getBoolean(K_LOCK_SETTINGS, false);
    }

    private static Set<String> lockedSet(SharedPreferences p) {
        Set<String> s = p.getStringSet(K_LOCKED_APPS, null);
        return s == null ? new HashSet<String>() : new HashSet<String>(s);
    }

    /** True when {@code pkg} is a locked app and a PIN exists. */
    static boolean isAppLocked(SharedPreferences p, String pkg) {
        if (p == null || pkg == null || !isSet(p)) return false;
        return lockedSet(p).contains(pkg);
    }

    static int lockedCount(SharedPreferences p) {
        return p == null ? 0 : lockedSet(p).size();
    }

    /** Lets the launcher hide / unhide apps from the combined list. */
    interface PrivacyHost {
        boolean isHidden(String pkg);
        void setHidden(AppInfo app, boolean hide);
        void onClosed();
    }

    /**
     * "Gizleme" list: every installed app with two switches, "Kilit" (ask for
     * the PIN on every launch) and "Gizle" (hide from the home screen).
     * LEFT/RIGHT picks the switch, OK flips it.
     */
    static void showPrivacyList(final Activity a, final SharedPreferences p,
                                List<AppInfo> source, final PrivacyHost host) {
        if (a.isFinishing()) return;
        final ArrayList<AppInfo> apps = new ArrayList<AppInfo>();
        final Set<String> seen = new HashSet<String>();
        for (AppInfo ai : source) {
            if (ai.tvInputId != null || ai.packageName == null || ai.label == null) continue;
            if (seen.add(ai.packageName)) apps.add(ai);
        }
        Collections.sort(apps, (x, y) -> x.label.compareToIgnoreCase(y.label));

        final Set<String> locked = lockedSet(p);
        final Dialog d = baseDialog(a);
        LinearLayout box = card(a);
        box.addView(label(a, "Gizleme", 15, 0xFFFFFFFF, 2));
        box.addView(label(a, "Sol/Sa\u011f: se\u00e7  \u2022  OK: a\u00e7 / kapat", 12, 0xB3FFFFFF, 6));

        LinearLayout list = new LinearLayout(a);
        list.setOrientation(LinearLayout.VERTICAL);
        TextView first = null;
        if (apps.isEmpty()) {
            list.addView(label(a, "Uygulama bulunamad\u0131", 13, 0xB3FFFFFF, 6));
        }
        for (final AppInfo ai : apps) {
            final String pkg = ai.packageName;
            LinearLayout row = new LinearLayout(a);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);

            TextView name = label(a, ai.label, 13, 0xFFFFFFFF, 0);
            name.setGravity(Gravity.CENTER_VERTICAL | Gravity.START);
            name.setSingleLine(true);
            name.setEllipsize(android.text.TextUtils.TruncateAt.END);
            name.setPadding(dp(a, 6), 0, dp(a, 6), 0);
            name.setLayoutParams(new LinearLayout.LayoutParams(0, dp(a, 38), 1f));
            row.addView(name);

            final TextView lockBtn = button(a, "", 80, 34, 12);
            final TextView hideBtn = button(a, "", 80, 34, 12);
            setToggle(lockBtn, "Kilit", locked.contains(pkg));
            setToggle(hideBtn, "Gizle", host.isHidden(pkg));
            lockBtn.setOnClickListener(v -> {
                if (!isSet(p)) {
                    Toast.makeText(a, "\u00d6nce PIN kilidini ayarlay\u0131n", Toast.LENGTH_SHORT).show();
                    return;
                }
                boolean now = !locked.contains(pkg);
                if (now) locked.add(pkg); else locked.remove(pkg);
                p.edit().putStringSet(K_LOCKED_APPS, new HashSet<String>(locked)).apply();
                setToggle(lockBtn, "Kilit", now);
            });
            hideBtn.setOnClickListener(v -> {
                boolean now = !host.isHidden(pkg);
                host.setHidden(ai, now);
                setToggle(hideBtn, "Gizle", now);
            });
            row.addView(lockBtn);
            row.addView(hideBtn);
            list.addView(row);
            if (first == null) first = lockBtn;
        }
        ScrollView sv = new ScrollView(a);
        sv.addView(list);
        box.addView(sv, new LinearLayout.LayoutParams(dp(a, 340), dp(a, 230)));

        TextView close = button(a, "Kapat", 340, 40, 15);
        close.setOnClickListener(v -> d.dismiss());
        box.addView(close);

        d.setOnDismissListener(x -> host.onClosed());
        present(d, box, 380);
        if (first != null) first.requestFocus(); else close.requestFocus();
    }

    private static void setToggle(TextView t, String name, boolean on) {
        t.setSelected(on);
        t.setText((on ? "\u25cf " : "\u25cb ") + name);
        if (t.getBackground() instanceof GradientDrawable) {
            paint(t, (GradientDrawable) t.getBackground(), t.isFocused());
        }
    }

    // ── Flows ────────────────────────────────────────────────────────────

    private static void createNew(final Activity a, final SharedPreferences p,
                                  final String title, final Runnable onChanged) {
        new Pad(a, title, "Yeni PIN (" + LEN + " hane)").show((pin1, pad1) -> {
            pad1.dismiss();
            new Pad(a, title, "PIN'i tekrar girin").show((pin2, pad2) -> {
                if (pin1.equals(pin2)) {
                    save(p, pin1);
                    pad2.dismiss();
                    Toast.makeText(a, "PIN kaydedildi", Toast.LENGTH_SHORT).show();
                    if (onChanged != null) onChanged.run();
                } else {
                    pad2.fail("PIN'ler uyu\u015fmuyor");
                }
            });
        });
    }

    private static void showOptions(final Activity a, final SharedPreferences p,
                                    final Runnable onChanged) {
        if (a.isFinishing()) return;
        final Dialog d = baseDialog(a);
        LinearLayout box = card(a);
        box.addView(label(a, "PIN kilidi", 15, 0xFFFFFFFF, 8));

        TextView change = button(a, "PIN'i de\u011fi\u015ftir", 220, 44, 15);
        TextView off    = button(a, "PIN'i kapat", 220, 44, 15);
        TextView cancel = button(a, "\u0130ptal", 220, 44, 15);
        change.setOnClickListener(v -> {
            d.dismiss();
            createNew(a, p, "PIN de\u011fi\u015ftir", onChanged);
        });
        off.setOnClickListener(v -> {
            d.dismiss();
            clear(p);
            Toast.makeText(a, "PIN kapat\u0131ld\u0131", Toast.LENGTH_SHORT).show();
            if (onChanged != null) onChanged.run();
        });
        cancel.setOnClickListener(v -> d.dismiss());
        box.addView(change);
        box.addView(off);
        box.addView(cancel);

        present(d, box, 260);
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

    private static void present(Dialog d, View content, int widthDp) {
        d.setContentView(content);
        Window w = d.getWindow();
        if (w != null) {
            w.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            w.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
            w.setDimAmount(0.65f);
            w.setWindowAnimations(0);
            w.setLayout(dp(d.getContext(), widthDp),
                        ViewGroup.LayoutParams.WRAP_CONTENT);
        }
        content.setAlpha(0f);
        content.setScaleX(0.94f);
        content.setScaleY(0.94f);
        d.show();
        content.animate().alpha(1f).scaleX(1f).scaleY(1f).setDuration(110).start();
    }

    /** Quick "pressed" feedback for a key. */
    private static void pressFx(final View v) {
        v.animate().scaleX(0.9f).scaleY(0.9f).setDuration(40).withEndAction(() -> {
            float rest = v.isFocused() ? 1.06f : 1f;
            v.animate().scaleX(rest).scaleY(rest).setDuration(70).start();
        }).start();
    }

    /** Short left-right shake (wrong PIN). */
    private static void shake(final View v, final int amp) {
        v.animate().translationX(-amp).setDuration(45).withEndAction(() ->
        v.animate().translationX(amp).setDuration(70).withEndAction(() ->
        v.animate().translationX(-amp / 2f).setDuration(60).withEndAction(() ->
        v.animate().translationX(0f).setDuration(50).start()).start()).start()).start();
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
        boolean on = t.isSelected();
        bg.setColor(focused ? 0xFFEFEFEF : (on ? ((accent & 0x00FFFFFF) | 0x66000000) : 0x22FFFFFF));
        t.setTextColor(focused ? 0xFF111114 : (on ? 0xFFFFFFFF : 0xE6FFFFFF));
    }

    /** A focusable key / button. Lights up white when focused (remote D-pad). */
    private static TextView button(Context c, String text, int wDp, int hDp, int sp) {
        final TextView t = new TextView(c);
        t.setText(text);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setGravity(Gravity.CENTER);
        t.setTypeface(medium());
        t.setFocusable(true);
        t.setClickable(true);
        final GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(c, hDp) / 2f);
        t.setBackground(bg);
        paint(t, bg, false);
        t.setOnFocusChangeListener((v, focused) -> {
            paint(t, bg, focused);
            t.animate().scaleX(focused ? 1.06f : 1f).scaleY(focused ? 1.06f : 1f)
                    .setDuration(80).start();
        });
        LinearLayout.LayoutParams lp = (wDp > 0)
                ? new LinearLayout.LayoutParams(dp(c, wDp), dp(c, hDp))
                : new LinearLayout.LayoutParams(0, dp(c, hDp), 1f);
        int m = dp(c, 3);
        lp.setMargins(m, m, m, m);
        t.setLayoutParams(lp);
        return t;
    }

    // ── The PIN pad dialog ───────────────────────────────────────────────

    private static final int PAD_W = 264;   // dp, width of the key grid

    static final class Pad {
        private final Dialog dlg;
        private final LinearLayout root;
        private final Context ctx;
        private final LinearLayout dotRow;
        private final View[] dot = new View[LEN];
        private boolean errorTint = false;
        private final TextView msg;
        private final String subtitle;
        private final StringBuilder buf = new StringBuilder();
        private final android.os.Handler h = new android.os.Handler(Looper.getMainLooper());
        private TextView firstFocus;
        private PinListener listener;
        private boolean busy = false;

        Pad(Activity a, String title, String subtitleText) {
            ctx = a;
            subtitle = subtitleText;
            dlg = baseDialog(a);
            root = card(a);
            root.addView(label(a, title, 15, 0xFFFFFFFF, 2));
            msg = label(a, subtitleText, 12, 0xB3FFFFFF, 6);
            root.addView(msg);
            dotRow = new LinearLayout(a);
            dotRow.setOrientation(LinearLayout.HORIZONTAL);
            dotRow.setGravity(Gravity.CENTER);
            for (int i = 0; i < LEN; i++) {
                View dv = new View(a);
                LinearLayout.LayoutParams dlp = new LinearLayout.LayoutParams(dp(a, 14), dp(a, 14));
                dlp.setMargins(dp(a, 7), 0, dp(a, 7), 0);
                dv.setLayoutParams(dlp);
                dot[i] = dv;
                dotRow.addView(dv);
            }
            LinearLayout.LayoutParams rowLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            rowLp.bottomMargin = dp(a, 10);
            root.addView(dotRow, rowLp);

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
                    TextView b = button(a, k, 0, 46, 17);
                    if (k.equals("5")) firstFocus = b;
                    b.setOnClickListener(v -> { pressFx(v); onKey(k); });
                    row.addView(b);
                }
                root.addView(row, new LinearLayout.LayoutParams(
                        dp(a, PAD_W), ViewGroup.LayoutParams.WRAP_CONTENT));
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
            present(dlg, root, 300);
            if (firstFocus != null) firstFocus.requestFocus();
        }

        void dismiss() {
            h.removeCallbacksAndMessages(null);
            try { dlg.dismiss(); } catch (Exception ignored) { /* already gone */ }
        }

        /** Show an error (red dots + shake), then clear and accept input again. */
        void fail(String text) {
            msg.setText(text);
            msg.setTextColor(0xFFFF6B6B);
            busy = true;
            errorTint = true;
            refresh();
            shake(dotRow, dp(ctx, 9));
            h.postDelayed(() -> {
                errorTint = false;
                buf.setLength(0);
                refresh();
                msg.setText(subtitle);
                msg.setTextColor(0xB3FFFFFF);
                busy = false;
            }, 450);
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
            View nd = dot[buf.length() - 1];
            nd.setScaleX(1.4f);
            nd.setScaleY(1.4f);
            nd.animate().scaleX(1f).scaleY(1f).setDuration(110).start();
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
            int color = errorTint ? 0xFFFF6B6B : accent;
            for (int i = 0; i < LEN; i++) {
                boolean filled = i < buf.length();
                GradientDrawable g = new GradientDrawable();
                g.setShape(GradientDrawable.OVAL);
                g.setColor(filled ? color : 0x00000000);
                g.setStroke(dp(ctx, 2), filled ? color : 0x66FFFFFF);
                dot[i].setBackground(g);
            }
        }
    }
}
'''

STRINGS_TR = r'''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Bare Launcher</string>

    <!-- Erişilebilirlik açıklamaları -->
    <string name="cd_app_shelf">Uygulama rafı</string>
    <string name="cd_app_drawer">Uygulama çekmecesi</string>
    <string name="cd_clock">Geçerli saat</string>
    <string name="cd_network_settings">Ağ ayarları</string>
    <string name="cd_settings">Ayarlar</string>
    <string name="cd_selection_ring">Seçim halkası</string>
    <string name="cd_uninstall_app">Uygulamayı kaldır</string>
    <string name="cd_open_app_info">Uygulama bilgisini sistem ayarlarında aç</string>
    <string name="cd_move_app_position">Uygulama konumunu taşı</string>
    <string name="cd_hide_app">Uygulamayı raftan gizle</string>

    <!-- Uygulamaya uzun basınca çıkan menü -->
    <string name="menu_uninstall">\u2715  Kaldır</string>
    <string name="menu_app_info">\u24D8  Uygulama bilgisi</string>
    <string name="menu_move">\u21D4  Taşı</string>
    <string name="menu_hide">\u2298  Gizle</string>

    <!-- Tuş kısayolları -->
    <string name="keymap_not_assigned">Atanmadı</string>
    <string name="keymap_pick_app_for">%1$s için uygulama seç</string>
    <string name="keymap_hide_title">Göstermek için OK</string>
    <string name="keymap_hide_empty">Gizli uygulama yok</string>

    <!-- Ayarlar paneli -->
    <string name="settings_row_manage_hidden">Gizleme</string>
    <string name="settings_row_button_shortcuts">Tuş kısayolları</string>
    <string name="settings_row_set_wallpaper">Duvar kağıdı ayarla</string>
    <string name="settings_row_wallpaper_menu">Duvar kağıdı / Slayt gösterisi</string>
    <string name="settings_row_backup_menu">Yedekle ve geri yükle</string>
    <string name="settings_row_slideshow_folder">Slayt klasörü</string>
    <string name="settings_row_slideshow_duration">Slayt süresi</string>
    <string name="settings_row_slideshow_restart">Her açılışta değiştir</string>
    <string name="settings_row_idle_hide">Boştayken arayüzü gizle</string>
    <string name="settings_row_show_clock">Saati göster</string>
    <string name="settings_row_backup">Ayarları yedekle</string>
    <string name="settings_row_restore">Ayarları geri yükle</string>
    <string name="settings_row_system_settings">Sistem ayarları</string>
    <string name="settings_row_about">Hakkında</string>
    <string name="settings_row_privacy">Gizlilik</string>
    <string name="settings_row_customize">Özelleştirme</string>
    <string name="settings_row_other">Diğer</string>
    <string name="settings_row_pin">PIN kilidi</string>
    <string name="settings_row_settings_lock">Ayarlar kilidi</string>
    <string name="settings_row_focus_ring">Odak çerçevesi</string>
    <string name="settings_row_focus_color">Çerçeve rengi</string>

    <!-- Hakkında -->
    <string name="about_app_name">BareLauncher</string>
    <string name="about_kofi">Ko-fi üzerinden destek ol</string>
    <string name="about_downloader_code">Downloader kodu:  %1$s</string>
    <string name="about_check_github">GitHub\'daki son sürümü kontrol et</string>
    <string name="about_made_by">Mithun tarafından özenle yapıldı</string>
    <string name="about_qr_kofi_caption">Ko-fi sayfamı açmak için tara</string>
    <string name="about_qr_github_caption">GitHub sayfasında daha yeni bir sürüm bulursan, yukarıdaki Downloader kodunu kullanarak indirip kurabilirsin.</string>
    <string name="about_github_link_button">BareLauncher son sürüm</string>

    <!-- Kumanda tuşları -->
    <string name="key_red">Kırmızı</string>
    <string name="key_green">Yeşil</string>
    <string name="key_yellow">Sarı</string>
    <string name="key_blue">Mavi</string>
    <string name="key_menu">Menü</string>
    <string name="key_subtitle">Altyazı</string>

    <!-- Bildirimler -->
    <string name="toast_no_network_settings">Ağ ayarları açılamıyor</string>
    <string name="toast_no_settings">Ayarlar açılamıyor</string>
    <string name="toast_no_app_info">Uygulama bilgisi açılamıyor</string>
    <string name="toast_app_unavailable">Uygulama kullanılamıyor</string>
    <string name="toast_input_unavailable">Bu girişe geçilemiyor</string>
    <string name="toast_no_file_picker">Dosya seçici bulunamadı</string>
    <string name="toast_no_browser">Bağlantıyı açacak tarayıcı yok</string>
    <string name="toast_wallpaper_load_failed">Duvar kağıdı yüklenemedi</string>
    <string name="toast_wallpaper_no_permission">Bu görsel için izin alınamadı</string>
    <string name="toast_cannot_uninstall">%1$s kaldırılamıyor</string>

    <!-- Yedekleme -->
    <string name="toast_backup_saved">Ayarlar yedeklendi</string>
    <string name="toast_backup_failed">Yedek kaydedilemedi</string>
    <string name="toast_restore_done">Ayarlar geri yüklendi</string>
    <string name="toast_restore_failed">Yedek dosyası okunamadı</string>
    <string name="toast_restore_invalid">Geçerli bir BareLauncher yedeği değil</string>

    <!-- Slayt gösterisi -->
    <string name="toast_slideshow_folder_set">Slayt klasörü ayarlandı</string>
    <string name="toast_slideshow_pick_folder">Önce bir slayt klasörü seç</string>
    <string name="toast_slideshow_need_permission">Klasör seçmek için fotoğraf erişimi gerekli</string>
    <string name="toast_slideshow_no_folders">Görsel klasörü bulunamadı</string>
    <string name="folder_picker_title">Slayt klasörü seç</string>
</resources>
'''


def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def write(p, s):
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(s)


def sub_once(text, pattern, repl, label):
    new, n = re.subn(pattern, repl, text, count=0)
    if n != 1:
        sys.exit("PATCH ERROR: '%s' matched %d times (expected 1)" % (label, n))
    return new


def replace_n(text, old, new, label):
    if old not in text:
        sys.exit("PATCH ERROR: '%s' not found" % label)
    return text.replace(old, new)


def main():
    src = read(ACT)
    if "PinLock." in src:
        print("Patch already applied - nothing to do.")
        return
    braces_before = src.count("{") - src.count("}")

    # 1) ids ------------------------------------------------------------
    src = sub_once(
        src, r"(private static final int SR_IDLE_HIDE\s*=\s*13;[^\n]*\n)",
        lambda m: m.group(1) + r'''    private static final int SR_PIN            = 14;
    private static final int SR_PRIVACY_MENU   = 15;   // -> SPAGE_PRIVACY
    private static final int SR_SETTINGS_LOCK  = 17;
    private static final int SR_CUSTOM_MENU    = 18;   // -> SPAGE_CUSTOM
    private static final int SR_OTHER_MENU     = 19;   // -> SPAGE_OTHER
    private static final int SR_FOCUS_RING     = 20;
    private static final int SR_FOCUS_COLOR    = 21;
''', "row ids")
    src = sub_once(
        src, r"SPAGE_MAIN = 0, SPAGE_WALLPAPER = 1, SPAGE_BACKUP = 2;",
        lambda m: "SPAGE_MAIN = 0, SPAGE_WALLPAPER = 1, SPAGE_BACKUP = 2,\n"
                  "                              SPAGE_PRIVACY = 3, SPAGE_CUSTOM = 4, SPAGE_OTHER = 5;",
        "page ids")
    # the pending cursor used to default to row 0 (= "hidden apps", the old
    # first row); it now has to mean "first row of the main page"
    src = sub_once(
        src, r"(private int\s+pendingSettingsCursor\s*=\s*)0;",
        lambda m: m.group(1) + "SR_PRIVACY_MENU;", "pending cursor default")

    # 2) page contents ----------------------------------------------------
    src = sub_once(
        src, r"SR_HIDE_APPS, SR_KEYMAP, SR_WALLPAPER_MENU, SR_CLOCK,\s*SR_BACKUP_MENU, SR_SYSTEM, SR_ABOUT",
        lambda m: "SR_PRIVACY_MENU, SR_CUSTOM_MENU, SR_OTHER_MENU", "SROWS_MAIN")
    src = sub_once(
        src, r"(    private static final int\[\] SROWS_WALLPAPER = \{)",
        lambda m: r'''    private static final int[] SROWS_PRIVACY = {
            SR_PIN, SR_HIDE_APPS, SR_SETTINGS_LOCK };
    private static final int[] SROWS_CUSTOM = {
            SR_KEYMAP, SR_WALLPAPER_MENU, SR_CLOCK, SR_FOCUS_RING, SR_FOCUS_COLOR };
    private static final int[] SROWS_OTHER = {
            SR_BACKUP_MENU, SR_SYSTEM, SR_ABOUT };
''' + m.group(1), "new page arrays")
    src = sub_once(
        src, r"(            case SPAGE_WALLPAPER: return SROWS_WALLPAPER;\n)",
        lambda m: "            case SPAGE_PRIVACY:   return SROWS_PRIVACY;\n"
                  "            case SPAGE_CUSTOM:    return SROWS_CUSTOM;\n"
                  "            case SPAGE_OTHER:     return SROWS_OTHER;\n" + m.group(1),
        "page rows switch")

    # 3) labels -----------------------------------------------------------
    src = sub_once(
        src,
        r"(            case SR_HIDE_APPS:\s+return R\.string\.settings_row_manage_hidden;\n)",
        lambda m: m.group(1) + r'''            case SR_PRIVACY_MENU:       return R.string.settings_row_privacy;
            case SR_CUSTOM_MENU:        return R.string.settings_row_customize;
            case SR_OTHER_MENU:         return R.string.settings_row_other;
            case SR_PIN:                return R.string.settings_row_pin;
            case SR_SETTINGS_LOCK:      return R.string.settings_row_settings_lock;
            case SR_FOCUS_RING:         return R.string.settings_row_focus_ring;
            case SR_FOCUS_COLOR:        return R.string.settings_row_focus_color;
''', "row labels")

    # 4) state indicators for PIN / settings lock ------------------------------
    src = sub_once(
        src, r"(return rowId == SR_CLOCK\n)",
        lambda m: m.group(1) + "            || rowId == SR_PIN\n"
                               "            || rowId == SR_SETTINGS_LOCK\n"
                               "            || rowId == SR_FOCUS_RING\n"
                               "            || rowId == SR_FOCUS_COLOR\n",
        "indicator rows")
    src = sub_once(
        src, r'(            case SR_SLIDESHOW_FOLDER:   return "Not set";\n)',
        lambda m: m.group(1) + r'''            case SR_PIN:                return "Ayarl\u0131";
            case SR_SETTINGS_LOCK:      return "Kapal\u0131";
            case SR_FOCUS_RING:         return "Kapal\u0131";
            case SR_FOCUS_COLOR:        return "A\u00e7\u0131k ye\u015fil";
''', "indicator widest text")
    src = sub_once(
        src,
        r"(                \} else \{\n\s+ind\.setTextColor\(sel \? selTx : idleTx\);)",
        lambda m: r'''                } else if (rowId == SR_PIN) {
                    boolean pinOn = PinLock.isSet(prefs);
                    ind.setText(pinOn ? "Ayarl\u0131" : "Yok");
                    ind.setTextColor(pinOn ? (sel ? selTx : 0xFF7DD3FC) : (sel ? 0x66111114 : 0x66FFFFFF));
                } else if (rowId == SR_SETTINGS_LOCK) {
                    boolean setLockOn = prefs.getBoolean(PinLock.K_LOCK_SETTINGS, false);
                    ind.setText(setLockOn ? "A\u00e7\u0131k" : "Kapal\u0131");
                    ind.setTextColor(setLockOn ? (sel ? selTx : 0xFF7DD3FC) : (sel ? 0x66111114 : 0x66FFFFFF));
                } else if (rowId == SR_FOCUS_RING) {
                    boolean ringOn = prefs.getBoolean("ring_on", true);
                    ind.setText(ringOn ? "A\u00e7\u0131k" : "Kapal\u0131");
                    ind.setTextColor(ringOn ? (sel ? selTx : 0xFF7DD3FC) : (sel ? 0x66111114 : 0x66FFFFFF));
                } else if (rowId == SR_FOCUS_COLOR) {
                    int rcIdx = ringColorIndex();
                    ind.setText(RING_COLOR_NAMES[rcIdx]);
                    ind.setTextColor(sel ? selTx : RING_COLORS[rcIdx]);
''' + m.group(1), "indicator refresh")

    # 5) row actions -----------------------------------------------------------
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
    new_case = r'''            case SR_HIDE_APPS:
                // "Gizleme": every app with a Kilit (lock) and a Gizle (hide) switch.
                PinLock.showPrivacyList(this, prefs, new ArrayList<>(appList),
                        new PinLock.PrivacyHost() {
                            @Override public boolean isHidden(String pkg) {
                                return hiddenApps.contains(pkg);
                            }
                            @Override public void setHidden(AppInfo app, boolean hide) {
                                setAppHiddenFromPrivacy(app, hide);
                            }
                            @Override public void onClosed() {
                                finishPrivacyEdit();
                            }
                        });
                break;
            case SR_PRIVACY_MENU:
                // Asks for the PIN only when one has been set.
                PinLock.verify(this, prefs, "Gizlilik",
                        () -> enterSettingsPage(SPAGE_PRIVACY, SR_PRIVACY_MENU));
                break;
            case SR_CUSTOM_MENU:
                enterSettingsPage(SPAGE_CUSTOM, SR_CUSTOM_MENU);
                break;
            case SR_OTHER_MENU:
                enterSettingsPage(SPAGE_OTHER, SR_OTHER_MENU);
                break;
            case SR_PIN:
                PinLock.openSettings(this, prefs, this::refreshSettingsRows);
                break;
            case SR_SETTINGS_LOCK:
                if (!PinLock.isSet(prefs)) {
                    showToast("\u00d6nce PIN kilidini ayarlay\u0131n");
                } else {
                    prefs.edit().putBoolean(PinLock.K_LOCK_SETTINGS,
                            !prefs.getBoolean(PinLock.K_LOCK_SETTINGS, false)).apply();
                    refreshSettingsRows();
                }
                break;
            case SR_FOCUS_RING:
                prefs.edit().putBoolean("ring_on", !prefs.getBoolean("ring_on", true)).apply();
                applyRingStyle();
                refreshSettingsRows();
                break;
            case SR_FOCUS_COLOR:
                prefs.edit().putInt("ring_color", (ringColorIndex() + 1) % RING_COLORS.length).apply();
                applyRingStyle();
                refreshSettingsRows();
                break;
'''
    src = sub_once(src, old_case, lambda m: new_case, "SR_HIDE_APPS action")

    # 6) helpers: hide/unhide from the list, row lookup ---------------------------
    helper = r'''    private static final int[] RING_COLORS = {
            0xFFFFFFFF, 0xFF22D3EE, 0xFF86EFAC, 0xFFFDE047, 0xFFF472B6 };
    private static final String[] RING_COLOR_NAMES = {
            "Beyaz", "Cyan", "A\u00e7\u0131k ye\u015fil", "Sar\u0131", "Pembe" };

    private int ringColorIndex() {
        int i = prefs == null ? 0 : prefs.getInt("ring_color", 0);
        return (i < 0 || i >= RING_COLORS.length) ? 0 : i;
    }

    /** Applies the focus-frame on/off + colour settings (also tints the PIN pad). */
    private void applyRingStyle() {
        if (prefs == null) return;
        int c = RING_COLORS[ringColorIndex()];
        PinLock.accent = c;
        RingView rv = ringView;
        if (rv != null) rv.setStyle(prefs.getBoolean("ring_on", true), c);
    }

    private boolean privacyDirty = false;

    /** Hide / unhide one app from the "Gizleme" list (batched: the shelf is
     *  refreshed once when the list closes, see {@link #finishPrivacyEdit}). */
    private void setAppHiddenFromPrivacy(AppInfo app, boolean hide) {
        if (app == null) return;
        if (hide) {
            int idx = buildVisibleList().indexOf(app);
            int oldHc = effectiveHomeCount(countVisible(appList));
            boolean wasHome = idx >= 0 && idx < oldHc;
            if (!hiddenApps.add(app.packageName)) return;
            if (wasHome && homeCount > 1) { homeCount--; saveHomeCount(); }
            saveHiddenApps();
        } else {
            if (!hiddenApps.remove(app.packageName)) return;
            saveHiddenApps();
            repositionUnhiddenIntoDrawer(app);
        }
        privacyDirty = true;
    }

    /** Called when the "Gizleme" list closes: refresh the shelf if needed and
     *  give the settings panel its focus back. */
    private void finishPrivacyEdit() {
        if (privacyDirty) {
            privacyDirty = false;
            keymapHideBuiltSize = -1;
            keymapHideDirty     = true;
            RecyclingShelfView s = shelf;
            if (s != null) applyShelfApps(s);
        }
        final FrameLayout ov = settingsOverlay;
        if (ov != null) {
            ov.requestFocus();
            ov.post(() -> {
                ov.requestFocus();
                RingView rv = ringView;
                if (rv != null) rv.setVisibility(View.INVISIBLE);
            });
        }
    }

    private static int indexInRows(int[] rows, int id) {
        for (int i = 0; i < rows.length; i++) if (rows[i] == id) return i;
        return 0;
    }

'''
    src = sub_once(
        src, r"(    /\*\* Execute the action bound to a settings row id\. \*/\n)",
        lambda m: helper + m.group(1), "helper insertion point")

    # 7) back navigation: Wallpaper -> Ozellestirme, Backup -> Diger ----------------
    src = sub_once(
        src,
        r"    private void returnToSettingsMain\(\) \{\n"
        r"        settingsPage = SPAGE_MAIN;\n"
        r"        rebuildSettingsColumn\(\);\n"
        r"        settingsSelectedRow = mainRowIndex\(settingsReturnRowId\);\n"
        r"        refreshSettingsRows\(\);\n"
        r"    \}",
        lambda m: r'''    private void returnToSettingsMain() {
        int parent = SPAGE_MAIN, parentMenuRow = -1;
        if (settingsPage == SPAGE_WALLPAPER)   { parent = SPAGE_CUSTOM; parentMenuRow = SR_CUSTOM_MENU; }
        else if (settingsPage == SPAGE_BACKUP) { parent = SPAGE_OTHER;  parentMenuRow = SR_OTHER_MENU; }
        int landRow = settingsReturnRowId;
        settingsPage = parent;
        rebuildSettingsColumn();
        if (parent == SPAGE_MAIN) {
            settingsSelectedRow = mainRowIndex(landRow);
        } else {
            settingsSelectedRow = indexInRows(settingsPageRows(), landRow);
            settingsReturnRowId = parentMenuRow;
        }
        refreshSettingsRows();
    }''', "returnToSettingsMain")

    # 8) re-opening the panel after a hand-off (keymap, About, ...) lands on the
    #    page that holds the row we left from
    src = sub_once(
        src,
        r"        settingsPage = SPAGE_MAIN;\n"
        r"        rebuildSettingsColumn\(\);\n"
        r"        settingsSelectedRow = mainRowIndex\(pendingSettingsCursor\);\n"
        r"        pendingSettingsCursor = SR_HIDE_APPS;\n",
        lambda m: r'''        int pendRow = pendingSettingsCursor;
        int openPage = SPAGE_MAIN;
        int[] searchOrder = { SPAGE_MAIN, SPAGE_CUSTOM, SPAGE_OTHER,
                              SPAGE_PRIVACY, SPAGE_WALLPAPER, SPAGE_BACKUP };
        search:
        for (int pg : searchOrder) {
            settingsPage = pg;
            for (int r : settingsPageRows()) {
                if (r == pendRow) { openPage = pg; break search; }
            }
        }
        settingsPage = openPage;
        if      (openPage == SPAGE_CUSTOM)    settingsReturnRowId = SR_CUSTOM_MENU;
        else if (openPage == SPAGE_OTHER)     settingsReturnRowId = SR_OTHER_MENU;
        else if (openPage == SPAGE_PRIVACY)   settingsReturnRowId = SR_PRIVACY_MENU;
        else if (openPage == SPAGE_WALLPAPER) settingsReturnRowId = SR_WALLPAPER_MENU;
        else if (openPage == SPAGE_BACKUP)    settingsReturnRowId = SR_BACKUP_MENU;
        rebuildSettingsColumn();
        settingsSelectedRow = indexInRows(settingsPageRows(), pendRow);
        pendingSettingsCursor = SR_PRIVACY_MENU;
''', "showSettingsPanel page lookup")

    # 9) settings lock: gear click and gear long-press ----------------------------
    src = sub_once(
        src,
        r"(view\.playSoundEffect\(SoundEffectConstants\.CLICK\);\n)(\s+)showSettingsPanel\(\);",
        lambda m: (m.group(1)
                   + m.group(2) + "if (PinLock.settingsLocked(prefs)) {\n"
                   + m.group(2) + "    PinLock.verify(this, prefs, \"Ayarlar\", this::showSettingsPanel);\n"
                   + m.group(2) + "} else {\n"
                   + m.group(2) + "    showSettingsPanel();\n"
                   + m.group(2) + "}"),
        "gear click")
    src = sub_once(
        src,
        r"(view\.playSoundEffect\(SoundEffectConstants\.CLICK\);\n)(\s+)openSystemSettings\(\);\n(\s+return true;)",
        lambda m: (m.group(1)
                   + m.group(2) + "if (PinLock.settingsLocked(prefs)) {\n"
                   + m.group(2) + "    PinLock.verify(this, prefs, \"Ayarlar\", this::openSystemSettings);\n"
                   + m.group(2) + "} else {\n"
                   + m.group(2) + "    openSystemSettings();\n"
                   + m.group(2) + "}\n"
                   + m.group(3)),
        "gear long-press")

    # 10) app lock: every launch goes through one gate -----------------------------
    src = sub_once(
        src,
        r"    private void launchApp\(AppInfo app, View source\) \{\n"
        r"        final android\.os\.Bundle anim = launchAnimBundle\(source\);",
        lambda m: r'''    private void launchApp(AppInfo app, View source) {
        if (app.tvInputId == null && PinLock.isAppLocked(prefs, app.packageName)) {
            final AppInfo lockedApp = app;
            PinLock.verify(this, prefs, lockedApp.label,
                    () -> launchAppNow(lockedApp, null));
            return;
        }
        launchAppNow(app, source);
    }

    private void launchAppNow(AppInfo app, View source) {
        final android.os.Bundle anim = launchAnimBundle(source);''', "launchApp gate")

    # 11) long-press menu: no "Gizle" row ------------------------------------------
    src = sub_once(
        src, r"            RecyclingShelfView\.MENU_HIDE, RecyclingShelfView\.MENU_UNINSTALL,\n"
             r"            RecyclingShelfView\.MENU_APP_INFO, RecyclingShelfView\.MENU_MOVE \};",
        lambda m: "            RecyclingShelfView.MENU_UNINSTALL,\n"
                  "            RecyclingShelfView.MENU_APP_INFO, RecyclingShelfView.MENU_MOVE };",
        "menu rows full")
    src = sub_once(
        src, r"            RecyclingShelfView\.MENU_HIDE, RecyclingShelfView\.MENU_MOVE \};",
        lambda m: "            RecyclingShelfView.MENU_MOVE };", "menu rows input")
    src = sub_once(
        src, r"        menuCol\.addView\(menuHide, itemLp0\);\n",
        lambda m: "        // (\"Gizle\" row removed: hiding lives in Ayarlar > Gizlilik > Gizleme)\n",
        "menu hide row")

    # 12) all-apps drawer: more transparent ------------------------------------------
    src = sub_once(src, r"0x7326262B", lambda m: "0x5226262B", "drawer alpha (blur)")
    src = sub_once(src, r"0xE61E1E22", lambda m: "0xB81E1E22", "drawer alpha (no blur)")

    # 13) TV icons: prefer the TV (leanback) activity so its banner is used ---------------
    src = sub_once(
        src,
        r"        Intent first  = tv \? leanback : regular;\n"
        r"        Intent second = tv \? regular  : leanback;",
        lambda m: "        Intent first  = leanback;   // TV activity (with its banner) wins\n"
                  "        Intent second = regular;",
        "app discovery order")
    src = sub_once(
        src,
        r"(        \} catch \(PackageManager\.NameNotFoundException \| RuntimeException ignored\) \{ /\* none \*/ \}\n)"
        r"(        return null;\n)",
        lambda m: m.group(1) + r'''        // Last resort: the app's TV (leanback) activity may carry the banner
        // even when the activity we resolved for it is the phone one.
        try {
            Intent lb = new Intent(Intent.ACTION_MAIN)
                    .addCategory(Intent.CATEGORY_LEANBACK_LAUNCHER)
                    .setPackage(app.packageName);
            List<android.content.pm.ResolveInfo> lbList = pm.queryIntentActivities(lb, 0);
            if (lbList != null) {
                for (android.content.pm.ResolveInfo r : lbList) {
                    if (r.activityInfo == null) continue;
                    Drawable b = r.activityInfo.loadBanner(pm);
                    if (b != null) return b;
                }
            }
        } catch (RuntimeException ignored) { /* none */ }
''' + m.group(2), "banner fallback")

    src = sub_once(
        src, r"(        ringView\.setContentDescription\(getString\(R\.string\.cd_selection_ring\)\);\n)",
        lambda m: m.group(1) + "        applyRingStyle();\n", "apply ring style at start")

    # 13b) RingView: on/off + colour
    rv = read(RING)
    rv = replace_n(
        rv, "    @Override protected void onSizeChanged(",
        "    private boolean drawRing = true;\n\n"
        "    /** Focus frame on/off and colour (settings > Ozellestirme). */\n"
        "    void setStyle(boolean enabled, int color) {\n"
        "        drawRing = enabled;\n"
        "        ring.setColor(color);\n"
        "        invalidate();\n"
        "    }\n\n"
        "    @Override protected void onSizeChanged(", "RingView setStyle")
    rv = replace_n(rv, "if (halfW <= 0 || halfH <= 0) return;",
                   "if (!drawRing || halfW <= 0 || halfH <= 0) return;", "RingView draw")
    write(RING, rv)

    # 14) small credit line under the settings list -----------------------------------
    i = src.find("private void buildSettingsPanel()")
    if i < 0:
        sys.exit("PATCH ERROR: buildSettingsPanel not found")
    anchor = "card.addView(col, new android.widget.LinearLayout.LayoutParams(WRAP, WRAP));\n"
    j = src.find(anchor, i)
    if j < 0 or j - i > 6000:
        sys.exit("PATCH ERROR: settings card anchor not found")
    j += len(anchor)
    credit = r'''        // Small credit line at the bottom of the settings card.
        TextView creditView = new TextView(this);
        creditView.setText("D\u00fczenleyen: Veysel Alemdar");
        creditView.setTextColor(0x66FFFFFF);
        creditView.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 9);
        creditView.setSingleLine(true);
        creditView.setGravity(Gravity.CENTER_HORIZONTAL);
        creditView.setPadding(dp(10), dp(6), dp(10), dp(2));
        android.widget.LinearLayout.LayoutParams creditLp =
                new android.widget.LinearLayout.LayoutParams(WRAP, WRAP);
        creditLp.gravity = Gravity.CENTER_HORIZONTAL;
        card.addView(creditView, creditLp);
'''
    src = src[:j] + credit + src[j:]

    # 15) Turkish indicator texts that live in Java code ---------------------------------
    src = replace_n(src, '"Not set"', '"Ayars\\u0131z"', "Not set")
    src = replace_n(src, '? "Set" :', '? "Ayarl\\u0131" :', "Set")
    src = replace_n(src, '? "Full"', '? "Tam"', "Full")
    src = replace_n(src, 'return "Full";', 'return "Tam";', "Full widest")
    src = replace_n(src, '? "Time"', '? "Saat"', "Time")
    src = replace_n(src, '"Off"', '"Kapal\\u0131"', "Off")
    src = replace_n(src, '"On"', '"A\\u00e7\\u0131k"', "On")
    src = replace_n(src, 'min >"', 'dk >"', "min")
    src = replace_n(src, '+ "s >"', '+ " sn >"', "seconds")

    braces_after = src.count("{") - src.count("}")
    if braces_before != braces_after:
        sys.exit("PATCH ERROR: brace balance changed (%d -> %d)"
                 % (braces_before, braces_after))

    write(ACT, src)
    write(STR, STRINGS_TR)
    write(PIN, PIN_LOCK_JAVA)
    print("Patch applied: LauncherActivity.java, strings.xml (Turkish), PinLock.java")


main()
