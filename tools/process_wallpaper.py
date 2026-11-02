import os
import sys
import glob
import struct
from PIL import Image

wallpapers_dir = "assets/wallpapers"
target_bmp = os.path.join(wallpapers_dir, "wallpaper.bmp")
TARGET_W = 1024
TARGET_H = 768

def save_bmp_24bpp(img_rgb, out_path):
    w, h = img_rgb.size
    data = bytearray()
    pixels = img_rgb.load()
    
    # 24bpp bottom-up BMP with 4-byte row padding
    row_padding = (4 - (w * 3) % 4) % 4
    pad_bytes = bytes([0] * row_padding)
    
    for y in range(h - 1, -1, -1):
        for x in range(w):
            r, g, b = pixels[x, y]
            data.extend([b, g, r])
        if row_padding > 0:
            data.extend(pad_bytes)
            
    file_header_size = 14
    info_header_size = 40
    data_offset = file_header_size + info_header_size
    file_size = data_offset + len(data)
    
    header = struct.pack('<2sIHHI', b'BM', file_size, 0, 0, data_offset)
    info = struct.pack('<IIIHHIIIIII', info_header_size, w, h, 1, 24, 0, len(data), 2835, 2835, 0, 0)
    
    with open(out_path, 'wb') as f:
        f.write(header)
        f.write(info)
        f.write(data)
    print(f"  [OK] Saved 24-bit wallpaper BMP: {out_path} ({file_size} bytes)")

def process_image(src_path):
    print(f"==> Processing wallpaper: {src_path}")
    im = Image.open(src_path).convert("RGB")
    sw, sh = im.size
    
    # Aspect-fit crop to 1024x768
    target_aspect = TARGET_W / TARGET_H
    src_aspect = sw / sh
    
    if src_aspect > target_aspect:
        # Source is wider: crop horizontal sides
        new_w = int(sh * target_aspect)
        offset_x = (sw - new_w) // 2
        im = im.crop((offset_x, 0, offset_x + new_w, sh))
    else:
        # Source is taller: crop top/bottom
        new_h = int(sw / target_aspect)
        offset_y = (sh - new_h) // 2
        im = im.crop((0, offset_y, sw, offset_y + new_h))
        
    resized = im.resize((TARGET_W, TARGET_H), Image.Resampling.LANCZOS)
    save_bmp_24bpp(resized, target_bmp)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        src = sys.argv[1]
        if not os.path.isabs(src):
            src = os.path.join(wallpapers_dir, src) if os.path.exists(os.path.join(wallpapers_dir, src)) else src
        if os.path.exists(src):
            process_image(src)
        else:
            print(f"[!] Error: File '{src}' not found!")
    else:
        # Find first non-wallpaper.bmp image in assets/wallpapers
        images = [f for f in glob.glob(os.path.join(wallpapers_dir, "*.*")) if not f.endswith("wallpaper.bmp") and f.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp'))]
        if images:
            process_image(images[0])
        else:
            print("[i] No source image found, default wallpaper.bmp is ready.")
