import os
import glob
import struct
import numpy as np
from PIL import Image, ImageEnhance

icons_dir = "assets/icons"

def write_bmp_32bpp(img_rgba, out_path):
    w, h = img_rgba.size
    # Uncompressed 32bpp bottom-up BMP
    data = bytearray()
    pixels = img_rgba.load()
    
    # BMP is bottom-up
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
    print(f"  [OK] Saved 32-bit BMP: {out_path} ({file_size} bytes)")

def process_icon(png_path):
    base_name = os.path.splitext(os.path.basename(png_path))[0]
    print(f"==> Processing user icon: {base_name}.png")
    
    im = Image.open(png_path).convert("RGB")
    arr = np.array(im, dtype=np.float32)
    h, w = arr.shape[:2]
    
    # 1. Detect squircle bounding box (background is white > 245)
    is_bg = (arr[:, :, 0] > 245) & (arr[:, :, 1] > 245) & (arr[:, :, 2] > 245)
    ys, xs = np.where(~is_bg)
    x0, x1 = xs.min(), xs.max()
    y0, y1 = ys.min(), ys.max()
    
    cx = (x0 + x1) / 2.0
    cy = (y0 + y1) / 2.0
    dim = max(x1 - x0 + 1, y1 - y0 + 1)
    
    # Square crop coordinates
    half = dim / 2.0
    left = int(round(cx - half))
    top = int(round(cy - half))
    right = left + dim
    bottom = top + dim
    
    # Crop RGB
    cropped_rgb = arr[max(0, top):min(h, bottom), max(0, left):min(w, right), :]
    ch, cw = cropped_rgb.shape[:2]
    
    # Apple squircle superellipse mask (n = 4.4)
    Y, X = np.ogrid[:ch, :cw]
    norm_x = (X - (cw - 1) / 2.0) / ((cw - 1) / 2.0)
    norm_y = (Y - (ch - 1) / 2.0) / ((ch - 1) / 2.0)
    
    val = np.abs(norm_x)**4.4 + np.abs(norm_y)**4.4
    
    # Smooth anti-aliased edge between 0.94 and 0.98:
    # val <= 0.94 is 1.0 (inside squircle)
    # val >= 0.98 is 0.0 (outside squircle, pure transparent)
    alpha = np.clip((0.98 - val) / (0.98 - 0.94), 0.0, 1.0)
    
    # Premultiply RGB to eliminate ALL white fringing/bleeding during Lanczos downscale
    clean_rgb = cropped_rgb * alpha[:, :, np.newaxis]
    
    rgba = np.dstack([clean_rgb, alpha * 255.0]).astype(np.uint8)
    img_rgba = Image.fromarray(rgba, mode='RGBA')
    
    # Generate both 40x40 (Dock) and 128x128 (Window/App)
    for sz in [40, 128]:
        resized = img_rgba.resize((sz, sz), Image.Resampling.LANCZOS)
        
        # Unpremultiply RGB to get true color with smooth alpha
        r_arr = np.array(resized, dtype=np.float32)
        a_norm = r_arr[:, :, 3] / 255.0
        mask_a = a_norm > 0.02
        for c in range(3):
            col = r_arr[:, :, c]
            col[mask_a] = np.clip(col[mask_a] / a_norm[mask_a], 0, 255)
            col[~mask_a] = 0
            r_arr[:, :, c] = col
            
        final_img = Image.fromarray(r_arr.astype(np.uint8), mode='RGBA')
        
        # Slight sharpness enhancement for 40x40 icon clarity
        if sz == 40:
            final_img = ImageEnhance.Sharpness(final_img).enhance(1.4)
            
        suffix = "_40.bmp" if sz == 40 else ".bmp"
        out_path = os.path.join(icons_dir, f"{base_name}{suffix}")
        write_bmp_32bpp(final_img, out_path)

if __name__ == "__main__":
    icon_names = ["finder", "terminal", "monitor", "cyber3d", "settings", "trash"]
    for name in icon_names:
        png_path = os.path.join(icons_dir, f"{name}.png")
        if os.path.exists(png_path):
            process_icon(png_path)
        else:
            print(f"[!] Warning: {png_path} not found!")
    print("\n[SUCCESS] All user icons converted to 32bpp BMP with zero white borders!")
