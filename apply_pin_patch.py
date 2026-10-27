#!/usr/bin/env python3
"""
BareLauncher privacy / Turkish patch (run from the repository root).

Adds, on top of the ORIGINAL source (nothing is committed to the repo):
  * PinLock.java        - PIN pad (remote friendly), app lock list, helpers
  * "Gizlilik" page     - PIN lock, hidden apps, app lock, settings lock
  * app lock            - locked apps ask for the PIN every time they start
  * settings lock       - optional PIN before the launcher settings open
  * Turkish UI          - all texts in res/values/strings.xml + indicators
  * small credit line   - "Duzenleyen: Veysel Alemdar" under the settings list

It stops with an error (instead of guessing) if the source differs from what
it expects, and does nothing if it was already applied.
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

    /** Dialog listing every installed app; OK toggles its lock. */
    static void showAppLockPicker(final Activity a, final SharedPreferences p,
                                  List<AppInfo> source, final Runnable onChanged) {
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
        box.addView(label(a, "Uygulama kilidi", 15, 0xFFFFFFFF, 2));
        box.addView(label(a, "OK: kilitle / kilidi kald\u0131r", 12, 0xB3FFFFFF, 6));

        LinearLayout list = new LinearLayout(a);
        list.setOrientation(LinearLayout.VERTICAL);
        TextView first = null;
        if (apps.isEmpty()) {
            list.addView(label(a, "Uygulama bulunamad\u0131", 13, 0xB3FFFFFF, 6));
        }
        for (final AppInfo ai : apps) {
            final TextView row = rowButton(a, rowText(ai.label, locked.contains(ai.packageName)));
            row.setOnClickListener(v -> {
                boolean now;
                if (locked.contains(ai.packageName)) { locked.remove(ai.packageName); now = false; }
                else { locked.add(ai.packageName); now = true; }
                p.edit().putStringSet(K_LOCKED_APPS, new HashSet<String>(locked)).apply();
                row.setText(rowText(ai.label, now));
                if (onChanged != null) onChanged.run();
            });
            list.addView(row);
            if (first == null) first = row;
        }
        ScrollView sv = new ScrollView(a);
        sv.addView(list);
        box.addView(sv, new LinearLayout.LayoutParams(dp(a, 320), dp(a, 230)));

        TextView close = button(a, "Kapat", 320, 40, 15);
        close.setOnClickListener(v -> d.dismiss());
        box.addView(close);

        present(d, box, 360);
        if (first != null) first.requestFocus(); else close.requestFocus();
    }

    private static String rowText(String label, boolean locked) {
        return locked ? "\u25cf  " + label + "  \u2014  kilitli" : "\u25cb  " + label;
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
            w.setLayout(dp(d.getContext(), widthDp),
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
        LinearLayout.LayoutParams lp = (wDp > 0)
                ? new LinearLayout.LayoutParams(dp(c, wDp), dp(c, hDp))
                : new LinearLayout.LayoutParams(0, dp(c, hDp), 1f);
        int m = dp(c, 3);
        lp.setMargins(m, m, m, m);
        t.setLayoutParams(lp);
        return t;
    }

    /** A focusable list row (left aligned), used by the app-lock list. */
    private static TextView rowButton(Context c, String text) {
        TextView t = button(c, text, 320, 40, 14);
        t.setGravity(Gravity.CENTER_VERTICAL | Gravity.START);
        t.setPadding(dp(c, 12), 0, dp(c, 12), 0);
        return t;
    }

    // ── The PIN pad dialog ───────────────────────────────────────────────

    private static final int PAD_W = 264;   // dp, width of the key grid

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
                    TextView b = button(a, k, 0, 46, 17);
                    if (k.equals("5")) firstFocus = b;
                    b.setOnClickListener(v -> onKey(k));
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
    <string name="settings_row_manage_hidden">Gizli uygulamalar</string>
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
    <string name="settings_row_pin">PIN kilidi</string>
    <string name="settings_row_app_lock">Uygulama kilidi</string>
    <string name="settings_row_settings_lock">Ayarlar kilidi</string>

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


def replace_n(text, old, new, label, minimum=1):
    n = text.count(old)
    if n < minimum:
        sys.exit("PATCH ERROR: '%s' not found" % label)
    return text.replace(old, new)


def main():
    src = read(ACT)
    if "PinLock." in src:
        print("Patch already applied - nothing to do.")
        return
    braces_before = src.count("{") - src.count("}")

    # 1) row ids + page id --------------------------------------------------
    src = sub_once(
        src, r"(private static final int SR_IDLE_HIDE\s*=\s*13;[^\n]*\n)",
        lambda m: m.group(1)
        + "    private static final int SR_PIN            = 14;\n"
        + "    private static final int SR_PRIVACY_MENU   = 15;   // -> SPAGE_PRIVACY\n"
        + "    private static final int SR_APP_LOCK        = 16;\n"
        + "    private static final int SR_SETTINGS_LOCK   = 17;\n",
        "row ids")
    src = sub_once(
        src, r"SPAGE_MAIN = 0, SPAGE_WALLPAPER = 1, SPAGE_BACKUP = 2;",
        lambda m: "SPAGE_MAIN = 0, SPAGE_WALLPAPER = 1, SPAGE_BACKUP = 2, SPAGE_PRIVACY = 3;",
        "page ids")

    # 2) main list: one "Gizlilik" row instead of "Manage hidden apps" ------
    src = sub_once(
        src, r"SR_HIDE_APPS, SR_KEYMAP, SR_WALLPAPER_MENU, SR_CLOCK,",
        lambda m: "SR_PRIVACY_MENU, SR_KEYMAP, SR_WALLPAPER_MENU, SR_CLOCK,",
        "SROWS_MAIN")
    src = sub_once(
        src, r"(    private static final int\[\] SROWS_WALLPAPER = \{)",
        lambda m: ("    private static final int[] SROWS_PRIVACY = {\n"
                   "            SR_PIN, SR_HIDE_APPS, SR_APP_LOCK, SR_SETTINGS_LOCK };\n"
                   + m.group(1)),
        "SROWS_PRIVACY")
    src = sub_once(
        src, r"(            case SPAGE_WALLPAPER: return SROWS_WALLPAPER;\n)",
        lambda m: "            case SPAGE_PRIVACY:   return SROWS_PRIVACY;\n" + m.group(1),
        "page rows switch")

    # 3) labels -------------------------------------------------------------
    src = sub_once(
        src,
        r"(            case SR_HIDE_APPS:\s+return R\.string\.settings_row_manage_hidden;\n)",
        lambda m: m.group(1)
        + "            case SR_PRIVACY_MENU:       return R.string.settings_row_privacy;\n"
        + "            case SR_PIN:                return R.string.settings_row_pin;\n"
        + "            case SR_APP_LOCK:           return R.string.settings_row_app_lock;\n"
        + "            case SR_SETTINGS_LOCK:      return R.string.settings_row_settings_lock;\n",
        "row labels")

    # 4) right-side state indicators for the new rows -----------------------
    src = sub_once(
        src, r"(return rowId == SR_CLOCK\n)",
        lambda m: m.group(1)
        + "            || rowId == SR_PIN\n"
        + "            || rowId == SR_APP_LOCK\n"
        + "            || rowId == SR_SETTINGS_LOCK\n",
        "indicator rows")
    src = sub_once(
        src, r'(            case SR_SLIDESHOW_FOLDER:   return "Not set";\n)',
        lambda m: m.group(1)
        + '            case SR_PIN:                return "Ayarl\\u0131";\n'
        + '            case SR_APP_LOCK:           return "99 uyg.";\n'
        + '            case SR_SETTINGS_LOCK:      return "Kapal\\u0131";\n',
        "indicator widest text")
    src = sub_once(
        src,
        r"(                \} else \{\n\s+ind\.setTextColor\(sel \? selTx : idleTx\);)",
        lambda m: (
            "                } else if (rowId == SR_PIN) {\n"
            "                    boolean pinOn = PinLock.isSet(prefs);\n"
            "                    ind.setText(pinOn ? \"Ayarl\\u0131\" : \"Yok\");\n"
            "                    ind.setTextColor(pinOn ? (sel ? selTx : 0xFF7DD3FC) : (sel ? 0x66111114 : 0x66FFFFFF));\n"
            "                } else if (rowId == SR_APP_LOCK) {\n"
            "                    int lockedN = PinLock.lockedCount(prefs);\n"
            "                    ind.setText(lockedN > 0 ? (lockedN + \" uyg.\") : \"Yok\");\n"
            "                    ind.setTextColor(lockedN > 0 ? (sel ? selTx : 0xFF7DD3FC) : (sel ? 0x66111114 : 0x66FFFFFF));\n"
            "                } else if (rowId == SR_SETTINGS_LOCK) {\n"
            "                    boolean setLockOn = prefs.getBoolean(PinLock.K_LOCK_SETTINGS, false);\n"
            "                    ind.setText(setLockOn ? \"A\\u00e7\\u0131k\" : \"Kapal\\u0131\");\n"
            "                    ind.setTextColor(setLockOn ? (sel ? selTx : 0xFF7DD3FC) : (sel ? 0x66111114 : 0x66FFFFFF));\n"
            + m.group(1)),
        "indicator refresh")

    # 5) row actions --------------------------------------------------------
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
        "                // Already behind the PIN-protected Privacy page.\n"
        "                openHideManagerFromSettings();\n"
        "                break;\n"
        "            case SR_PRIVACY_MENU:\n"
        "                // Asks for the PIN only when one has been set.\n"
        "                PinLock.verify(this, prefs, \"Gizlilik\",\n"
        "                        () -> enterSettingsPage(SPAGE_PRIVACY, SR_PRIVACY_MENU));\n"
        "                break;\n"
        "            case SR_PIN:\n"
        "                PinLock.openSettings(this, prefs, this::refreshSettingsRows);\n"
        "                break;\n"
        "            case SR_APP_LOCK:\n"
        "                if (!PinLock.isSet(prefs)) showToast(\"\\u00d6nce PIN kilidini ayarlay\\u0131n\");\n"
        "                else PinLock.showAppLockPicker(this, prefs, new ArrayList<>(appList), this::refreshSettingsRows);\n"
        "                break;\n"
        "            case SR_SETTINGS_LOCK:\n"
        "                if (!PinLock.isSet(prefs)) {\n"
        "                    showToast(\"\\u00d6nce PIN kilidini ayarlay\\u0131n\");\n"
        "                } else {\n"
        "                    prefs.edit().putBoolean(PinLock.K_LOCK_SETTINGS,\n"
        "                            !prefs.getBoolean(PinLock.K_LOCK_SETTINGS, false)).apply();\n"
        "                    refreshSettingsRows();\n"
        "                }\n"
        "                break;\n")
    src = sub_once(src, old_case, lambda m: new_case, "SR_HIDE_APPS action")

    helper = (
        "    /** Opens the hidden-apps manager from the settings panel. */\n"
        "    private void openHideManagerFromSettings() {\n"
        "        pendingSettingsCursor       = SR_PRIVACY_MENU;\n"
        "        keymapOpenedFromSettings    = true;\n"
        "        hideManagerSkipSlotsOnExit  = true;\n"
        "        hideSettingsPanel();\n"
        "        showKeymapOverlay();\n"
        "        enterHideManager();\n"
        "    }\n\n")
    src = sub_once(
        src, r"(    /\*\* Execute the action bound to a settings row id\. \*/\n)",
        lambda m: helper + m.group(1), "helper insertion point")

    # 6) settings lock: gear button asks for the PIN first -------------------
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

    # 7) app lock: every launch goes through one gate ------------------------
    src = sub_once(
        src,
        r"    private void launchApp\(AppInfo app, View source\) \{\n"
        r"        final android\.os\.Bundle anim = launchAnimBundle\(source\);",
        lambda m: (
            "    private void launchApp(AppInfo app, View source) {\n"
            "        if (app.tvInputId == null && PinLock.isAppLocked(prefs, app.packageName)) {\n"
            "            final AppInfo lockedApp = app;\n"
            "            PinLock.verify(this, prefs, lockedApp.label,\n"
            "                    () -> launchAppNow(lockedApp, null));\n"
            "            return;\n"
            "        }\n"
            "        launchAppNow(app, source);\n"
            "    }\n\n"
            "    private void launchAppNow(AppInfo app, View source) {\n"
            "        final android.os.Bundle anim = launchAnimBundle(source);"),
        "launchApp gate")

    # 8) credit line under the settings list ---------------------------------
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

    # 9) Turkish indicator texts that live in Java code ----------------------
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
