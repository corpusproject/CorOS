"""
Generates authentic Windows 11 Fluent style assets for CorOS:
1. Windows 11 Bloom / Hero Wallpaper (1024x768 24-bit BMP)
2. Windows 11 Fluent Icons (40x40 32-bit BMP + 128x128 PNG)
   - File Explorer (Finder)
   - Windows Terminal (Terminal)
   - This PC / Task Manager (Monitor)
   - 3D Viewer (Cyber3D)
   - Windows Settings (Settings)
   - Recycle Bin (Trash)
"""

import os
import math
import struct
import numpy as np
from PIL import Image, ImageDraw, ImageFilter

WALLPAPERS_DIR = "assets/wallpapers"
ICONS_DIR = "assets/icons"
os.makedirs(WALLPAPERS_DIR, exist_ok=True)
os.makedirs(ICONS_DIR, exist_ok=True)

def write_bmp_24bpp(img_rgb, out_path):
    w, h = img_rgb.size
    row_bytes = w * 3
    padding = (4 - (row_bytes % 4)) % 4
    file_header_size = 14
    info_header_size = 40
    data_offset = file_header_size + info_header_size
    img_data_size = (row_bytes + padding) * h
    file_size = data_offset + img_data_size

    header = struct.pack('<2sIHHI', b'BM', file_size, 0, 0, data_offset)
    info = struct.pack('<IIIHHIIIIII', info_header_size, w, h, 1, 24, 0, img_data_size, 2835, 2835, 0, 0)

    data = bytearray()
    pixels = img_rgb.load()
    # Bottom-up
    for y in range(h - 1, -1, -1):
        for x in range(w):
            r, g, b = pixels[x, y][:3]
            data.extend([b, g, r])
        data.extend([0] * padding)

    with open(out_path, 'wb') as f:
        f.write(header)
        f.write(info)
        f.write(data)
    print(f"[OK] Saved 24bpp BMP: {out_path} ({file_size} bytes)")

def write_bmp_32bpp(img_rgba, out_path):
    w, h = img_rgba.size
    data = bytearray()
    pixels = img_rgba.load()
    for y in range(h - 1, -1, -1):
        for x in range(w):
            r, g, b, a = pixels[x, y]
            data.extend([b, g, r, a])

    file_header_size = 14
    info_header_size = 40
    data_offset = file_header_size + info_header_size
    file_size = data_offset + len(data)

    header = struct.pack('<2sIHHI', b'BM', file_size, 0, 0, data_offset)
    info = struct.pack('<IIIHHIIIIII', info_header_size, w, h, 1, 32, 0, len(data), 2835, 2835, 0, 0)

    with open(out_path, 'wb') as f:
        f.write(header)
        f.write(info)
        f.write(data)
    print(f"[OK] Saved 32bpp BMP: {out_path} ({file_size} bytes)")

# =========================================================================
# 1. WINDOWS 11 BLOOM / HERO WALLPAPER
# =========================================================================
def generate_windows11_wallpaper():
    w, h = 1024, 768
    print("==> Generating Windows 11 Fluent Bloom Wallpaper (1024x768)...")
    
    # Base background: Deep calming Windows Dark Mode royal blue
    base = Image.new("RGB", (w, h), (11, 17, 32))
    draw = ImageDraw.Draw(base)

    # 1. Multi-point smooth radial gradient glow
    # Center-glow at cx=512, cy=360
    cx, cy = 512, 360
    bg_arr = np.zeros((h, w, 3), dtype=np.float32)

    y_coords, x_coords = np.ogrid[:h, :w]
    
    # Distance from center glow
    d_center = np.sqrt(((x_coords - cx) / 1.4)**2 + (y_coords - cy)**2)
    # Distance from bottom-left soft ambient
    d_bl = np.sqrt((x_coords - 150)**2 + (y_coords - 650)**2)

    # Ambient deep tones
    # Center: (30, 68, 160)
    # Mid: (14, 28, 64)
    # Outer: (8, 12, 24)
    t = np.clip(d_center / 500.0, 0.0, 1.0)
    
    r_val = (1.0 - t) * 38.0 + t * 8.0
    g_val = (1.0 - t) * 82.0 + t * 13.0
    b_val = (1.0 - t) * 185.0 + t * 28.0

    # Add soft bottom ambient glow
    t_bl = np.clip(1.0 - (d_bl / 600.0), 0.0, 1.0)
    r_val += t_bl * 12.0
    g_val += t_bl * 24.0
    b_val += t_bl * 55.0

    bg_arr[:, :, 0] = np.clip(r_val, 0, 255)
    bg_arr[:, :, 1] = np.clip(g_val, 0, 255)
    bg_arr[:, :, 2] = np.clip(b_val, 0, 255)

    base = Image.fromarray(bg_arr.astype(np.uint8), "RGB")

    # 2. Render layered Bloom ribbon petals (Fluent Silk Flower)
    # We render petals on transparent layers with soft blur
    bloom_layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))

    # Petals definition: (angle_deg, length, width, color_rgb, alpha, curve_bend)
    petals = [
        # Deep back petals
        (-80, 260, 160, (26, 54, 138), 160, 40),
        (80, 270, 170, (30, 64, 150), 160, -45),
        (-140, 220, 140, (18, 38, 98), 140, 30),
        (140, 230, 145, (20, 42, 105), 140, -35),
        (0, 280, 180, (37, 99, 235), 180, 20),
        # Mid vibrant blue/cyan petals
        (-45, 230, 130, (59, 130, 246), 210, -25),
        (45, 240, 135, (37, 99, 235), 210, 30),
        (-20, 250, 120, (96, 165, 250), 220, 15),
        (20, 255, 125, (56, 189, 248), 220, -20),
        (-65, 190, 110, (147, 51, 234), 140, 35), # subtle violet accent
        (65, 195, 115, (99, 102, 241), 150, -35),
        # Foreground bright folded silk curls
        (-10, 180, 95, (147, 197, 253), 240, -15),
        (10, 185, 100, (186, 230, 253), 240, 18),
        (-35, 150, 80, (96, 165, 250), 230, 20),
        (35, 155, 85, (56, 189, 248), 230, -22),
        (0, 140, 75, (224, 242, 254), 250, 5),
    ]

    for ang, length, width, col, alpha, bend in petals:
        petal_img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
        pdraw = ImageDraw.Draw(petal_img)

        # Parametric smooth petal curve
        rad = math.radians(ang - 90)
        cos_a = math.cos(rad)
        sin_a = math.sin(rad)

        pts = []
        steps = 40
        for i in range(steps + 1):
            t = i / steps
            # Profile width
            w_t = math.sin(t * math.pi) * (width / 2.0)
            # Bend offset
            bend_off = math.sin(t * math.pi) * bend
            dist = t * length

            px = cx + (dist * cos_a) - ((w_t + bend_off) * sin_a)
            py = cy + (dist * sin_a) + ((w_t + bend_off) * cos_a)
            pts.append((px, py))

        for i in range(steps, -1, -1):
            t = i / steps
            w_t = math.sin(t * math.pi) * (width / 2.0)
            bend_off = math.sin(t * math.pi) * bend
            dist = t * length

            px = cx + (dist * cos_a) + ((w_t - bend_off) * sin_a)
            py = cy + (dist * sin_a) - ((w_t - bend_off) * cos_a)
            pts.append((px, py))

        if len(pts) >= 3:
            pdraw.polygon(pts, fill=(col[0], col[1], col[2], alpha))

        # Soft blur petal for silky smooth anti-aliased look
        petal_img = petal_img.filter(ImageFilter.GaussianBlur(radius=3.5))
        bloom_layer = Image.alpha_composite(bloom_layer, petal_img)

    # Composite bloom on base
    base = Image.alpha_composite(base.convert("RGBA"), bloom_layer).convert("RGB")

    # Add a soft warm light specular at the core of the bloom
    core_glow = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    cdraw = ImageDraw.Draw(core_glow)
    cdraw.ellipse((cx - 40, cy - 30, cx + 40, cy + 50), fill=(224, 242, 254, 90))
    core_glow = core_glow.filter(ImageFilter.GaussianBlur(radius=25))
    base = Image.alpha_composite(base.convert("RGBA"), core_glow).convert("RGB")

    # Save wallpaper
    out_bmp = os.path.join(WALLPAPERS_DIR, "wallpaper.bmp")
    out_png = os.path.join(WALLPAPERS_DIR, "wallpaper.png")
    base.save(out_png)
    write_bmp_24bpp(base, out_bmp)
    print(f"[SUCCESS] Windows 11 Bloom wallpaper created: {out_bmp}")


# =========================================================================
# 2. WINDOWS 11 FLUENT 3D ICONS GENERATOR
# =========================================================================
def create_supersampled_icon(draw_fn, target_size=40, scale=4):
    """Renders icon at 4x resolution (160x160) and downsamples with Lanczos for razor-sharp anti-aliased quality."""
    hi_size = target_size * scale
    img = Image.new("RGBA", (hi_size, hi_size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw_fn(draw, hi_size)
    
    # Smooth downsample
    res_40 = img.resize((target_size, target_size), Image.Resampling.LANCZOS)
    res_128 = img.resize((128, 128), Image.Resampling.LANCZOS)
    return res_40, res_128

# 1. Windows File Explorer (Folder)
def draw_windows_explorer(draw, S):
    # Padding
    m = S * 0.08
    w = S - 2 * m
    h = S - 2 * m
    
    # Back tab / folder top
    tab_x0 = m + w * 0.06
    tab_y0 = m + h * 0.16
    tab_w = w * 0.44
    tab_h = h * 0.22
    draw.rounded_rectangle([tab_x0, tab_y0, tab_x0 + tab_w, tab_y0 + tab_h], radius=S*0.04, fill=(2, 132, 199, 255)) # Fluent blue tab
    
    # Back body
    back_y0 = m + h * 0.26
    back_h = h * 0.62
    draw.rounded_rectangle([m + w * 0.06, back_y0, m + w * 0.94, back_y0 + back_h], radius=S*0.06, fill=(14, 165, 233, 255))
    
    # Middle documents preview (white sheets)
    doc_x0 = m + w * 0.16
    doc_y0 = m + h * 0.20
    draw.rounded_rectangle([doc_x0, doc_y0, doc_x0 + w * 0.68, doc_y0 + h * 0.40], radius=S*0.03, fill=(248, 250, 252, 240))
    # Doc inner lines
    draw.line([doc_x0 + w * 0.1, doc_y0 + h * 0.1, doc_x0 + w * 0.58, doc_y0 + h * 0.1], fill=(203, 213, 225, 255), width=int(S*0.02))
    draw.line([doc_x0 + w * 0.1, doc_y0 + h * 0.2, doc_x0 + w * 0.45, doc_y0 + h * 0.2], fill=(203, 213, 225, 255), width=int(S*0.02))

    # Front pocket: Radiant Fluent Amber/Yellow
    front_y0 = m + h * 0.38
    front_h = h * 0.54
    # Gradient simulation using layers
    draw.rounded_rectangle([m + w * 0.04, front_y0, m + w * 0.96, front_y0 + front_h], radius=S*0.07, fill=(245, 158, 11, 255))
    # Subtle glossy top highlight
    draw.rounded_rectangle([m + w * 0.06, front_y0 + h*0.02, m + w * 0.94, front_y0 + front_h * 0.48], radius=S*0.05, fill=(251, 191, 36, 255))
    draw.rounded_rectangle([m + w * 0.08, front_y0 + h*0.04, m + w * 0.92, front_y0 + front_h * 0.22], radius=S*0.03, fill=(253, 230, 138, 200))

# 2. Windows Terminal
def draw_windows_terminal(draw, S):
    m = S * 0.08
    # Modern dark acrylic tile (Windows Terminal dark theme)
    draw.rounded_rectangle([m, m, S - m, S - m], radius=S*0.16, fill=(12, 16, 24, 255))
    draw.rounded_rectangle([m, m, S - m, S - m], radius=S*0.16, outline=(51, 65, 85, 255), width=int(S*0.03))
    
    # Top Tab Bar (Windows Terminal style: active tab with blue accent)
    tab_x0 = m + S * 0.06
    tab_y0 = m + S * 0.06
    tab_w = S * 0.46
    tab_h = S * 0.16
    draw.rounded_rectangle([tab_x0, tab_y0, tab_x0 + tab_w, tab_y0 + tab_h], radius=S*0.04, fill=(30, 41, 59, 255))
    # Active tab blue line
    draw.line([tab_x0, tab_y0 + tab_h, tab_x0 + tab_w, tab_y0 + tab_h], fill=(56, 189, 248, 255), width=int(S*0.03))
    # Plus button for new tab
    plus_cx = tab_x0 + tab_w + S * 0.10
    plus_cy = tab_y0 + tab_h * 0.5
    draw.line([plus_cx - S*0.04, plus_cy, plus_cx + S*0.04, plus_cy], fill=(148, 163, 184, 255), width=int(S*0.025))
    draw.line([plus_cx, plus_cy - S*0.04, plus_cx, plus_cy + S*0.04], fill=(148, 163, 184, 255), width=int(S*0.025))

    # Inner Prompt: >_ in vibrant Fluent Cyan / PowerShell Blue
    px0 = m + S * 0.16
    py0 = m + S * 0.40
    p_size = S * 0.28
    draw.line([px0, py0, px0 + p_size * 0.70, py0 + p_size * 0.5], fill=(56, 189, 248, 255), width=int(S*0.06), joint="curve")
    draw.line([px0 + p_size * 0.70, py0 + p_size * 0.5, px0, py0 + p_size], fill=(56, 189, 248, 255), width=int(S*0.06), joint="curve")
    # _ underscore cursor
    cur_x = px0 + p_size * 1.05
    cur_y = py0 + p_size
    draw.line([cur_x, cur_y, cur_x + S * 0.26, cur_y], fill=(255, 255, 255, 255), width=int(S*0.06))

# 2.5 CorOS Start Button (Fluent 3D Faceted Star Logo)
def draw_windows_start(draw, S):
    cx, cy = S / 2, S / 2
    R = S * 0.44
    r = S * 0.20

    outer_pts = []
    inner_pts = []

    for i in range(5):
        a_out = -math.pi / 2 + i * (2 * math.pi / 5)
        outer_pts.append((cx + R * math.cos(a_out), cy + R * math.sin(a_out)))
        a_in = -math.pi / 2 + (i * 2 + 1) * (math.pi / 5)
        inner_pts.append((cx + r * math.cos(a_in), cy + r * math.sin(a_in)))

    # Draw 10 faceted triangles meeting at center (cx, cy)
    for i in range(5):
        p_tip = outer_pts[i]
        p_in_left = inner_pts[(i - 1) % 5]
        p_in_right = inner_pts[i]
        
        # Left facet (highlight - bright azure / sky blue)
        col_light = (56, 189, 248, 255) # Sky blue #38BDF8
        draw.polygon([(cx, cy), p_in_left, p_tip], fill=col_light)
        
        # Right facet (shadow - royal azure)
        col_dark = (2, 132, 199, 255)  # Royal azure #0284C7
        draw.polygon([(cx, cy), p_tip, p_in_right], fill=col_dark)

    # Subtle central highlight sparkle
    sr = S * 0.08
    draw.polygon([(cx, cy - sr), (cx + sr * 0.35, cy), (cx, cy + sr), (cx - sr * 0.35, cy)], fill=(255, 255, 255, 220))
    draw.polygon([(cx - sr, cy), (cx, cy + sr * 0.35), (cx + sr, cy), (cx, cy - sr * 0.35)], fill=(255, 255, 255, 220))

# 3. Windows This PC / Task Manager (Monitor)
def draw_windows_monitor(draw, S):
    m = S * 0.08
    # Slim-bezel monitor display
    mon_w = S - 2 * m
    mon_h = (S - 2 * m) * 0.68
    mon_x0 = m
    mon_y0 = m + S * 0.04
    
    # Bezel
    draw.rounded_rectangle([mon_x0, mon_y0, mon_x0 + mon_w, mon_y0 + mon_h], radius=S*0.10, fill=(30, 41, 59, 255), outline=(71, 85, 105, 255), width=int(S*0.02))
    # Active Screen: Windows Azure Gradient
    scr_m = S * 0.05
    draw.rounded_rectangle([mon_x0 + scr_m, mon_y0 + scr_m, mon_x0 + mon_w - scr_m, mon_y0 + mon_h - scr_m], radius=S*0.06, fill=(2, 132, 199, 255))
    # Screen inner telemetry graph (Task Manager heart rate)
    gx0 = mon_x0 + scr_m + S * 0.05
    gy_mid = mon_y0 + mon_h * 0.50
    graph_pts = [
        (gx0, gy_mid),
        (gx0 + S*0.12, gy_mid),
        (gx0 + S*0.20, gy_mid - S*0.16),
        (gx0 + S*0.28, gy_mid + S*0.14),
        (gx0 + S*0.38, gy_mid - S*0.08),
        (gx0 + S*0.48, gy_mid),
        (gx0 + S*0.58, gy_mid)
    ]
    for i in range(len(graph_pts) - 1):
        draw.line([graph_pts[i], graph_pts[i+1]], fill=(255, 255, 255, 255), width=int(S*0.04))

    # Metallic Aluminum Stand
    neck_w = S * 0.12
    neck_h = S * 0.12
    neck_x = (S - neck_w) / 2
    neck_y = mon_y0 + mon_h - S*0.01
    draw.rectangle([neck_x, neck_y, neck_x + neck_w, neck_y + neck_h], fill=(148, 163, 184, 255))
    
    # Stand Base
    base_w = S * 0.48
    base_h = S * 0.06
    base_x = (S - base_w) / 2
    base_y = neck_y + neck_h - S*0.01
    draw.rounded_rectangle([base_x, base_y, base_x + base_w, base_y + base_h], radius=S*0.03, fill=(203, 213, 225, 255))

# 4. Windows 3D Viewer (Isometric Fluent Cube)
def draw_windows_3d(draw, S):
    cx = S / 2.0
    cy = S / 2.0
    r = S * 0.38
    
    # Isometric vertices
    # Top center, top left, top right, bottom center, etc.
    p_center = (cx, cy)
    p_top = (cx, cy - r)
    p_top_right = (cx + r * math.cos(math.radians(30)), cy - r * math.sin(math.radians(30)))
    p_bot_right = (cx + r * math.cos(math.radians(30)), cy + r * math.sin(math.radians(30)) + r * 0.5)
    p_bot = (cx, cy + r)
    p_bot_left = (cx - r * math.cos(math.radians(30)), cy + r * math.sin(math.radians(30)) + r * 0.5)
    p_top_left = (cx - r * math.cos(math.radians(30)), cy - r * math.sin(math.radians(30)))

    # Face 1: Top (Azure Blue)
    draw.polygon([p_center, p_top_right, p_top, p_top_left], fill=(96, 165, 250, 255))
    # Highlight on top
    draw.line([p_top_left, p_top, p_top_right], fill=(224, 242, 254, 255), width=int(S*0.03))

    # Face 2: Right (Violet / Indigo)
    draw.polygon([p_center, p_top_right, p_bot_right, p_bot], fill=(147, 51, 234, 255))
    
    # Face 3: Left (Cyan / Teal)
    draw.polygon([p_center, p_top_left, p_bot_left, p_bot], fill=(6, 182, 212, 255))
    
    # Center 3D coordinate axes indicator
    draw.line([p_center, (cx, cy - r * 0.55)], fill=(255, 255, 255, 220), width=int(S*0.03))
    draw.line([p_center, (cx + r * 0.45 * math.cos(math.radians(30)), cy + r * 0.45 * math.sin(math.radians(30)))], fill=(255, 255, 255, 220), width=int(S*0.03))
    draw.line([p_center, (cx - r * 0.45 * math.cos(math.radians(30)), cy + r * 0.45 * math.sin(math.radians(30)))], fill=(255, 255, 255, 220), width=int(S*0.03))

# 5. Windows Settings (Fluent Blue Gear)
def draw_windows_settings(draw, S):
    cx = S / 2.0
    cy = S / 2.0
    r_outer = S * 0.42
    r_inner = S * 0.32
    r_hole = S * 0.16
    teeth = 8
    
    # Draw teeth
    for i in range(teeth):
        angle = (i * 360.0 / teeth)
        rad = math.radians(angle)
        tx = cx + (r_outer * 0.82) * math.cos(rad)
        ty = cy + (r_outer * 0.82) * math.sin(rad)
        # Tooth capsule
        tw = S * 0.14
        th = S * 0.22
        draw.rounded_rectangle([tx - tw/2, ty - th/2, tx + tw/2, ty + th/2], radius=S*0.04, fill=(2, 132, 199, 255))
        
    # Main outer wheel: Fluent Blue
    draw.ellipse([cx - r_inner, cy - r_inner, cx + r_inner, cy + r_inner], fill=(37, 99, 235, 255), outline=(96, 165, 250, 255), width=int(S*0.03))
    # Inner wheel layer
    draw.ellipse([cx - r_inner*0.82, cy - r_inner*0.82, cx + r_inner*0.82, cy + r_inner*0.82], fill=(29, 78, 216, 255))
    # Center hollow hole
    draw.ellipse([cx - r_hole, cy - r_hole, cx + r_hole, cy + r_hole], fill=(241, 245, 249, 255), outline=(147, 197, 253, 255), width=int(S*0.02))

# 6. Windows Recycle Bin (Translucent white/blue bin with 3 arrows)
def draw_windows_trash(draw, S):
    m = S * 0.12
    # Body: slightly tapered cylinder
    top_y = m + S * 0.16
    bot_y = S - m
    w_top = S * 0.64
    w_bot = S * 0.52
    
    x0_top = (S - w_top) / 2
    x1_top = x0_top + w_top
    x0_bot = (S - w_bot) / 2
    x1_bot = x0_bot + w_bot
    
    # Can body: Frosted glass / silver-blue
    draw.polygon([(x0_top, top_y), (x1_top, top_y), (x1_bot, bot_y), (x0_bot, bot_y)], fill=(226, 232, 240, 230))
    # Vertical rib lines (Aero/Fluent style)
    for t in [0.25, 0.50, 0.75]:
        lx_top = x0_top + w_top * t
        lx_bot = x0_bot + w_bot * t
        draw.line([(lx_top, top_y + S*0.04), (lx_bot, bot_y - S*0.04)], fill=(148, 163, 184, 180), width=int(S*0.02))

    # Top Rim
    rim_h = S * 0.10
    draw.ellipse([x0_top - S*0.02, top_y - rim_h/2, x1_top + S*0.02, top_y + rim_h/2], fill=(241, 245, 249, 255), outline=(148, 163, 184, 255), width=int(S*0.02))
    
    # Iconic 3-arrow recycling emblem on the front in Windows Blue
    cx = S / 2.0
    cy = (top_y + bot_y) / 2.0 + S * 0.04
    r_sym = S * 0.15
    for a in [0, 120, 240]:
        rad = math.radians(a - 30)
        ax = cx + r_sym * math.cos(rad)
        ay = cy + r_sym * math.sin(rad)
        draw.ellipse([ax - S*0.03, ay - S*0.03, ax + S*0.03, ay + S*0.03], fill=(2, 132, 199, 255))
    draw.arc([cx - r_sym, cy - r_sym, cx + r_sym, cy + r_sym], start=0, end=330, fill=(2, 132, 199, 255), width=int(S*0.04))


# 7. Windows Notepad (Fluent Blue & White Notebook with Pencil)
def draw_windows_notepad(draw, S):
    m = S * 0.10
    # Notepad sheet / notebook cover
    nx0 = m + S * 0.04
    ny0 = m
    nw = S * 0.72
    nh = S * 0.80
    # Back cyan accent cover
    draw.rounded_rectangle([nx0, ny0, nx0 + nw, ny0 + nh], radius=S*0.08, fill=(2, 132, 199, 255))
    # Crisp white notepad page
    px0 = nx0 + S * 0.06
    py0 = ny0 + S * 0.06
    pw = nw - S * 0.08
    ph = nh - S * 0.08
    draw.rounded_rectangle([px0, py0, px0 + pw, py0 + ph], radius=S*0.06, fill=(255, 255, 255, 255))
    # Ruled lines (Notepad text lines)
    for i in range(4):
        ly = py0 + S * 0.14 + i * (S * 0.12)
        draw.line([px0 + S * 0.08, ly, px0 + pw - S * 0.08, ly], fill=(203, 213, 225, 255), width=int(S*0.03))
    # Fluent blue pen at bottom-right
    pen_x = nx0 + nw - S * 0.18
    pen_y = ny0 + nh - S * 0.18
    draw.polygon([(pen_x, pen_y), (pen_x + S*0.22, pen_y - S*0.22), (pen_x + S*0.30, pen_y - S*0.14), (pen_x + S*0.08, pen_y + S*0.08)], fill=(37, 99, 235, 255))
    draw.polygon([(pen_x, pen_y), (pen_x - S*0.04, pen_y + S*0.04), (pen_x + S*0.08, pen_y + S*0.08)], fill=(251, 191, 36, 255))


# 8. Windows Calculator (Fluent Acrylic Tile with Grid & Equals Button)
def draw_windows_calc(draw, S):
    m = S * 0.08
    # Main calculator body: Dark slate acrylic tile
    draw.rounded_rectangle([m, m, S - m, S - m], radius=S*0.14, fill=(30, 41, 59, 255), outline=(71, 85, 105, 255), width=int(S*0.025))
    # Digital Display bar at top
    disp_x0 = m + S * 0.06
    disp_y0 = m + S * 0.06
    disp_w = S - 2*m - S*0.12
    disp_h = S * 0.22
    draw.rounded_rectangle([disp_x0, disp_y0, disp_x0 + disp_w, disp_y0 + disp_h], radius=S*0.06, fill=(15, 23, 42, 255))
    # Display digits hint "123"
    draw.line([disp_x0 + disp_w - S*0.12, disp_y0 + disp_h*0.5, disp_x0 + disp_w - S*0.04, disp_y0 + disp_h*0.5], fill=(56, 189, 248, 255), width=int(S*0.04))
    
    # 2x2 Grid of keypad buttons
    grid_y = disp_y0 + disp_h + S * 0.06
    gw = (disp_w - S * 0.06) / 2
    gh = (S - m - grid_y - S * 0.06) / 2
    
    # Button 1 (+): Top-left
    draw.rounded_rectangle([disp_x0, grid_y, disp_x0 + gw, grid_y + gh], radius=S*0.04, fill=(51, 65, 85, 255))
    draw.line([disp_x0 + gw*0.3, grid_y + gh*0.5, disp_x0 + gw*0.7, grid_y + gh*0.5], fill=(255, 255, 255, 255), width=int(S*0.03))
    draw.line([disp_x0 + gw*0.5, grid_y + gh*0.3, disp_x0 + gw*0.5, grid_y + gh*0.7], fill=(255, 255, 255, 255), width=int(S*0.03))
    
    # Button 2 (-): Top-right
    bx2 = disp_x0 + gw + S * 0.06
    draw.rounded_rectangle([bx2, grid_y, bx2 + gw, grid_y + gh], radius=S*0.04, fill=(51, 65, 85, 255))
    draw.line([bx2 + gw*0.3, grid_y + gh*0.5, bx2 + gw*0.7, grid_y + gh*0.5], fill=(255, 255, 255, 255), width=int(S*0.03))
    
    # Button 3 (X): Bottom-left
    by3 = grid_y + gh + S * 0.06
    draw.rounded_rectangle([disp_x0, by3, disp_x0 + gw, by3 + gh], radius=S*0.04, fill=(51, 65, 85, 255))
    draw.line([disp_x0 + gw*0.3, by3 + gh*0.3, disp_x0 + gw*0.7, by3 + gh*0.7], fill=(255, 255, 255, 255), width=int(S*0.03))
    draw.line([disp_x0 + gw*0.7, by3 + gh*0.3, disp_x0 + gw*0.3, by3 + gh*0.7], fill=(255, 255, 255, 255), width=int(S*0.03))
    
    # Button 4 (=): Bottom-right (Fluent Accent Blue)
    draw.rounded_rectangle([bx2, by3, bx2 + gw, by3 + gh], radius=S*0.04, fill=(2, 132, 199, 255))
    draw.line([bx2 + gw*0.3, by3 + gh*0.4, bx2 + gw*0.7, by3 + gh*0.4], fill=(255, 255, 255, 255), width=int(S*0.03))
    draw.line([bx2 + gw*0.3, by3 + gh*0.6, bx2 + gw*0.7, by3 + gh*0.6], fill=(255, 255, 255, 255), width=int(S*0.03))


# 9. Windows Paint (Fluent Colorful Palette & Brush)
def draw_windows_paint(draw, S):
    m = S * 0.08
    # Wooden/acrylic painter's palette
    cx = S * 0.48
    cy = S * 0.52
    r = S * 0.38
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(245, 245, 245, 255), outline=(203, 213, 225, 255), width=int(S*0.025))
    
    # Palette thumb hole
    hx = cx - S * 0.18
    hy = cy + S * 0.12
    hr = S * 0.08
    draw.ellipse([hx - hr, hy - hr, hx + hr, hy + hr], fill=(0, 0, 0, 0)) # transparent hole
    
    # Paint color blobs (Red, Orange, Yellow, Green, Cyan, Purple)
    blobs = [
        (cx - S * 0.18, cy - S * 0.18, (239, 68, 68, 255)),   # Red
        (cx - S * 0.04, cy - S * 0.26, (249, 115, 22, 255)),  # Orange
        (cx + S * 0.14, cy - S * 0.22, (234, 179, 8, 255)),   # Yellow
        (cx + S * 0.24, cy - S * 0.08, (34, 197, 94, 255)),   # Green
        (cx + S * 0.22, cy + S * 0.10, (6, 182, 212, 255)),   # Cyan
        (cx + S * 0.08, cy + S * 0.22, (168, 85, 247, 255)),  # Purple
    ]
    for bx, by, col in blobs:
        br = S * 0.075
        draw.ellipse([bx - br, by - br, bx + br, by + br], fill=col)

    # Paintbrush laying across top-right to bottom-left
    px0 = S * 0.20
    py0 = S * 0.75
    px1 = S * 0.85
    py1 = S * 0.15
    # Wooden handle
    draw.line([px0, py0, px1, py1], fill=(180, 83, 9, 255), width=int(S*0.06))
    # Silver ferrule
    fx = px0 + (px1 - px0) * 0.25
    fy = py0 + (py1 - py0) * 0.25
    draw.line([px0 + (px1 - px0) * 0.15, py0 + (py1 - py0) * 0.15, fx, fy], fill=(203, 213, 225, 255), width=int(S*0.07))
    # Brush tip with blue paint
    draw.polygon([(px0, py0), (px0 + S*0.06, py0 - S*0.02), (px0 - S*0.04, py0 + S*0.08)], fill=(37, 99, 235, 255))


def generate_all_windows_icons():
    print("==> Generating Ultra-Sharp Windows 11 Fluent Icons (48x48, 8x supersampled)...")
    icon_generators = [
        ("start", draw_windows_start),
        ("finder", draw_windows_explorer),
        ("terminal", draw_windows_terminal),
        ("monitor", draw_windows_monitor),
        ("cyber3d", draw_windows_3d),
        ("settings", draw_windows_settings),
        ("trash", draw_windows_trash),
        ("notepad", draw_windows_notepad),
        ("calc", draw_windows_calc),
        ("paint", draw_windows_paint),
    ]

    for name, gen_fn in icon_generators:
        # 48x48 at 8x supersampling (384x384 downsampled to 48x48 via Lanczos filter)
        im_48, im_128 = create_supersampled_icon(gen_fn, target_size=48, scale=8)
        
        bmp_48_path = os.path.join(ICONS_DIR, f"{name}_40.bmp") # keep filename for compatibility
        png_128_path = os.path.join(ICONS_DIR, f"{name}.png")
        
        im_128.save(png_128_path)
        write_bmp_32bpp(im_48, bmp_48_path)
        print(f"  [OK] {name} (48x48 ultra-sharp) -> {bmp_48_path} & {png_128_path}")

    # Generate boot star (112x112 for crystal clear Windows 11 boot splash screen)
    boot_im_112, _ = create_supersampled_icon(draw_windows_start, target_size=112, scale=4)
    boot_bmp_path = os.path.join(ICONS_DIR, "boot_star_96.bmp")
    write_bmp_32bpp(boot_im_112, boot_bmp_path)
    print(f"  [OK] boot_star (112x112 ultra-sharp) -> {boot_bmp_path}")

if __name__ == "__main__":
    generate_windows11_wallpaper()
    generate_all_windows_icons()
    print("All Windows 11 Fluent assets generated successfully!")
