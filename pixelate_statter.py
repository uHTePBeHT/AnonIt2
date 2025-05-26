import json
import base64
import numpy as np
import cv2
import argparse
from cryptography.fernet import Fernet

def pixelate(img, roi, bs):
    x,y,w,h = roi
    region = img[y:y+h, x:x+w]
    small = cv2.resize(region, (max(1,w//bs), max(1,h//bs)), interpolation=cv2.INTER_LINEAR)
    pix   = cv2.resize(small, (w,h), interpolation=cv2.INTER_NEAREST)
    out   = img.copy()
    out[y:y+h, x:x+w] = pix
    return out

def add_noise(img, roi, level):
    x,y,w,h = roi
    region = img[y:y+h, x:x+w].copy()
    prob   = level/100.0
    mask   = np.random.rand(h, w) < prob
    salt   = np.random.rand(h, w) < 0.5
    noisy  = region.copy()
    for c in range(3):
        noisy[:,:,c][mask & salt]  = 255
        noisy[:,:,c][mask & ~salt] = 0
    out = img.copy()
    out[y:y+h, x:x+w] = noisy
    return out

def embed_redundant(img: np.ndarray, payload: bytes, redundancy: int=4) -> np.ndarray:
    flat    = img.flatten()
    total   = flat.size
    seg_len = total // redundancy

    hdr  = len(payload).to_bytes(4,'big') + payload
    bits = np.unpackbits(np.frombuffer(hdr, dtype=np.uint8))
    if bits.size > seg_len:
        raise ValueError("Payload too large")

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
        seg      = flat[i*seg_len:(i+1)*seg_len]
        hdr_bits = seg[:32] & 1
        length   = int.from_bytes(np.packbits(hdr_bits).tobytes(),'big')
        if length <= 0 or length*8+32 > seg_len:
            continue
        data_bits = seg[32:32+length*8] & 1
        return np.packbits(data_bits).tobytes()

    raise ValueError("No valid replica")

def anonymize(args):
    img = cv2.imread(args.image)
    if img is None:
        raise FileNotFoundError

    # список областей
    rois = getattr(args, 'rois', None)
    if not rois:
        raise ValueError("Нет ROI для анонимизации")

    proc = img.copy()
    payload_list = []
    for (x,y,w,h) in rois:
        if args.mode_ext == 'noise':
            proc = add_noise(proc, (x,y,w,h), args.noise_level)
        else:
            proc = pixelate(proc, (x,y,w,h), args.pixel_size)

        region = img[y:y+h, x:x+w]
        ok, buf = cv2.imencode('.jpg', region, [cv2.IMWRITE_JPEG_QUALITY, args.quality])
        if not ok:
            raise RuntimeError("JPEG encode failed")
        payload_list.append({
            'coords': [x,y,w,h],
            'data': base64.b64encode(buf.tobytes()).decode()
        })

    full = json.dumps(payload_list).encode('utf-8')
    key  = Fernet.generate_key()
    token = Fernet(key).encrypt(full)

    payload = key + b'||' + token
    stego   = embed_redundant(proc, payload, redundancy=4)
    cv2.imwrite(args.output, stego)
    print(f"Anonymized → {args.output}")

def restore(args):
    img = cv2.imread(args.image)
    if img is None:
        raise FileNotFoundError

    raw = extract_redundant(img, redundancy=4)
    key, token = raw.split(b'||',1)
    full = Fernet(key).decrypt(token)
    regions = json.loads(full)

    out = img.copy()
    for r in regions:
        x,y,w,h = r['coords']
        data = base64.b64decode(r['data'])
        patch = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_UNCHANGED)
        out[y:y+h, x:x+w] = patch

    cv2.imwrite(args.output, out)
    print(f"Restored → {args.output}")

if __name__ == '__main__':
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument('--mode', choices=['anonymize','restore'])
    p.add_argument('--image'); p.add_argument('--output')
    p.add_argument('--pixel-size', type=int, default=10)
    p.add_argument('--quality',    type=int, default=30)
    p.add_argument('--mode_ext',    choices=['pixelate','noise'], default='pixelate')
    p.add_argument('--noise-level', type=float, default=50.0)
    p.add_argument('--rois', nargs='+', type=int, help="x y w h за каждую область")
    args = p.parse_args()
    if args.mode == 'anonymize':
        # rois передаются как: --rois x1 y1 w1 h1 x2 y2 w2 h2 ...
        coords = [tuple(args.rois[i:i+4]) for i in range(0,len(args.rois),4)]
        args.rois = coords
        anonymize(args)
    else:
        restore(args)
