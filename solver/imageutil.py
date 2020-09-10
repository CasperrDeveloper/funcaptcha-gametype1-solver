from io import BytesIO
from PIL import Image, ImageMath
from imagehash import phash, average_hash
import numpy as np

methods = dict(
    phash=phash,
    average_hash=average_hash
)

def hash_image(im, m, l):
    h = str(m(im, l))
    return h

def remove_background(im):
    im = im.convert("RGBA")
    red, green, blue, alpha = im.split()
    im.putalpha(ImageMath.eval("""convert(((((t - d(c, (r, g, b))) >> 31) + 1) ^ 1) * a, 'L')""",
        t=0, d=lambda a,b: (a[0] - b[0]) * (a[0] - b[0]) + (a[1] - b[1]) * (a[1] - b[1]) + (a[2] - b[2]) * (a[2] - b[2]),
        c=(255, 255, 255), r=red, g=green, b=blue, a=alpha))
    return im

def mask(im):
    im = np.array(im)
    red, green, blue, alpha = im.T
    s = (red != 255) & (blue != 255) & (green != 255)
    im[..., :-1][s.T] = (255, 0, 0)
    im = Image.fromarray(im)
    return im
    
def to_pil(imdata):
    if type(imdata) == str:
        return Image.open(imdata)
    elif type(imdata) == bytes:
        return Image.open(BytesIO(imdata))
    else:
        return Image.fromarray(imdata)