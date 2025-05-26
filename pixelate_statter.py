import sys
import json
import base64
import numpy as np
import cv2
import argparse
from cryptography.fernet import Fernet

def select_region(img):
    max_w, max_h = 1000, 800
    h, w = img.shape[:2]
    scale = min(1.0, max_w/w, max_h/h)
    disp = cv2.resize(img, (int(w*scale), int(h*scale)), interpolation=cv2.INTER_AREA) \
           if scale < 1 else img.copy()
    cv2.namedWindow('Select ROI', cv2.WINDOW_NORMAL)
    cv2.resizeWindow('Select ROI', disp.shape[1], disp.shape[0])
    roi = cv2.selectROI('Select ROI', disp, fromCenter=False, showCrosshair=True)
    cv2.destroyWindow('Select ROI')
    if roi == (0,0,0,0):
        raise ValueError("No region selected")
    x,y,wd,hd = map(int, roi)
    return (int(x/scale), int(y/scale), int(wd/scale), int(hd/scale))

def pixelate(img, roi, bs):
    x,y,w,h = roi
    region = img[y:y+h, x:x+w]
    small = cv2.resize(region, (max(1,w//bs), max(1,h//bs)), interpolation=cv2.INTER_LINEAR)
    pix = cv2.resize(small, (w,h), interpolation=cv2.INTER_NEAREST)
    out = img.copy()
    out[y:y+h, x:x+w] = pix
    return out

def add_noise(img, roi, level):
    x,y,w,h = roi
    region = img[y:y+h, x:x+w].copy()
    prob = level / 100.0
    mask = np.random.rand(h, w) < prob
    salt = np.random.rand(h, w) < 0.5
    noisy = region.copy()
    for c in range(3):
        noisy[:,:,c][mask & salt]   = 255
        noisy[:,:,c][mask & ~salt]  = 0
    out = img.copy()
    out[y:y+h, x:x+w] = noisy
    return out

def embed_redundant(img: np.ndarray, payload: bytes, redundancy: int=4) -> np.ndarray:
    flat    = img.flatten()
    total   = flat.size
    seg_len = total // redundancy

    hdr  = len(payload).to_bytes(4, 'big') + payload
    bits = np.unpackbits(np.frombuffer(hdr, dtype=np.uint8))
    if bits.size > seg_len:
        raise ValueError("Payload too large for chosen redundancy")

    for i in range(redundancy):
        seg = flat[i*seg_len:(i+1)*seg_len]
        seg[:bits.size] = (seg[:bits.size] & 0xFE) | bits
        flat[i*seg_len:(i+1)*seg_len] = seg

    return flat.reshape(img.shape)

def extract_redundant(img: np.ndarray, redundancy: int=4) -> bytes:
    flat    = img.flatten()
    total   = flat.size
    seg_len = total // redundancy

    for i in range(redundancy):
        seg = flat[i*seg_len:(i+1)*seg_len]
        hdr_bits = seg[:32] & 1
        length   = int.from_bytes(np.packbits(hdr_bits).tobytes(), 'big')
        if length <= 0 or length*8 + 32 > seg_len:
            continue
        data_bits = seg[32:32+length*8] & 1
        return np.packbits(data_bits).tobytes()

    raise ValueError("No valid replica found in any segment")

def anonymize(args):
    img = cv2.imread(args.image)
    if img is None:
        raise FileNotFoundError(args.image)

    if args.x is not None and args.w > 0:
        roi = (args.x, args.y, args.w, args.h)
    else:
        roi = select_region(img)

    if args.mode_ext == 'noise':
        proc = add_noise(img, roi, args.noise_level)
    else:
        proc = pixelate(img, roi, args.pixel_size)

    region = img[roi[1]:roi[1]+roi[3], roi[0]:roi[0]+roi[2]]
    ok, buf = cv2.imencode('.jpg', region, [cv2.IMWRITE_JPEG_QUALITY, args.quality])
    if not ok:
        raise RuntimeError("JPEG encoding failed")
    img_bytes = buf.tobytes()

    key   = Fernet.generate_key()
    token = Fernet(key).encrypt(
        json.dumps({'coords':roi, 'data': base64.b64encode(img_bytes).decode()})
            .encode('utf-8')
    )
    payload = key + b'||' + token

    stego = embed_redundant(proc, payload, redundancy=4)
    cv2.imwrite(args.output, stego)
    print(f"Anonymized image → {args.output}")

def restore(args):
    img = cv2.imread(args.image)
    if img is None:
        raise FileNotFoundError(args.image)

    raw = extract_redundant(img, redundancy=4)
    key, token = raw.split(b'||', 1)
    payload = Fernet(key).decrypt(token)
    obj     = json.loads(payload)
    x,y,w,h = obj['coords']
    data    = base64.b64decode(obj['data'])
    region  = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_UNCHANGED)

    out = img.copy()
    out[y:y+h, x:x+w] = region
    cv2.imwrite(args.output, out)
    print(f"Restored image → {args.output}")

if __name__ == '__main__':
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument('--mode', choices=['anonymize','restore'])
    p.add_argument('--image'); p.add_argument('--output')
    p.add_argument('--pixel-size', type=int,   default=10)
    p.add_argument('--quality',    type=int,   default=30)
    p.add_argument('--mode_ext',    choices=['pixelate','noise'], default='pixelate')
    p.add_argument('--noise-level', type=float, default=50.0)
    p.add_argument('--x', type=int, default=None)
    p.add_argument('--y', type=int, default=None)
    p.add_argument('--w', type=int, default=None)
    p.add_argument('--h', type=int, default=None)
    args = p.parse_args()
    if args.mode == 'anonymize': anonymize(args)
    else:                      restore(args)
