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
           if scale<1 else img.copy()
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
    out = img.copy(); out[y:y+h, x:x+w] = pix
    return out

# ——— самовосстанавливающаяся стего с избыточностью ———

def embed_redundant(img: np.ndarray, payload: bytes, redundancy: int=4) -> np.ndarray:
    flat = img.flatten()
    total = flat.size
    seg_len = total // redundancy

    # соберём биты once (4‐byte length + payload)
    hdr = len(payload).to_bytes(4, 'big') + payload
    bits = np.unpackbits(np.frombuffer(hdr, dtype=np.uint8))

    if bits.size > seg_len:
        raise ValueError("Payload too large for chosen redundancy")

    for i in range(redundancy):
        start = i * seg_len
        segment = flat[start:start+seg_len]
        segment[:bits.size] = (segment[:bits.size] & 0xFE) | bits
        flat[start:start+seg_len] = segment

    return flat.reshape(img.shape)

def extract_redundant(img: np.ndarray, redundancy: int=4) -> bytes:
    flat = img.flatten()
    total = flat.size
    seg_len = total // redundancy

    for i in range(redundancy):
        segment = flat[i*seg_len:(i+1)*seg_len]
        hdr_bits = segment[:32] & 1
        length = int.from_bytes(np.packbits(hdr_bits).tobytes(), 'big')
        if length <= 0 or length*8 + 32 > seg_len:
            continue
        data_bits = segment[32:32 + length*8] & 1
        raw = np.packbits(data_bits).tobytes()
        return raw

    raise ValueError("No valid replica found in any segment")

# ———————————————————————————————————————————————

def anonymize(args):
    img = cv2.imread(args.image)
    if img is None:
        raise FileNotFoundError(args.image)

    # 1) Pixelate ROI
    roi = select_region(img)
    pix_img = pixelate(img, roi, args.pixel_size)

    # 2) JPEG‐encode ROI
    region = img[roi[1]:roi[1]+roi[3], roi[0]:roi[0]+roi[2]]
    ok, buf = cv2.imencode('.jpg', region, [cv2.IMWRITE_JPEG_QUALITY, args.quality])
    if not ok:
        raise RuntimeError("JPEG encoding failed")
    img_bytes = buf.tobytes()

    # 3) Генерация ключа и шифрование payload
    key = Fernet.generate_key()
    token = Fernet(key).encrypt(
        json.dumps({'coords': roi, 'data': base64.b64encode(img_bytes).decode()})
        .encode('utf-8')
    )

    # 4) Сбор payload = key || token
    payload = key + b'||' + token

    # 5) Embed с redundancy
    stego = embed_redundant(pix_img, payload, redundancy=4)

    cv2.imwrite(args.output, stego)
    print(f"Anonymized image → {args.output}")

def restore(args):
    img = cv2.imread(args.image)
    if img is None:
        raise FileNotFoundError(args.image)

    raw = extract_redundant(img, redundancy=4)
    try:
        key, token = raw.split(b'||', 1)
    except ValueError:
        raise ValueError("Malformed payload: cannot split key and token")

    payload = Fernet(key).decrypt(token)
    obj = json.loads(payload)
    x,y,w,h = obj['coords']
    data = base64.b64decode(obj['data'])

    region = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_UNCHANGED)
    out = img.copy()
    out[y:y+h, x:x+w] = region
    cv2.imwrite(args.output, out)
    print(f"Restored image → {args.output}")

if __name__=='__main__':
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument('--mode', choices=['anonymize','restore'])
    p.add_argument('--image'); p.add_argument('--output')
    p.add_argument('--pixel-size', type=int, default=10)
    p.add_argument('--quality',    type=int, default=30)
    args = p.parse_args()
    if args.mode=='anonymize': anonymize(args)
    if args.mode=='restore':   restore(args)
