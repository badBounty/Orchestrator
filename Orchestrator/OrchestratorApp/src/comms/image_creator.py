import base64
from PIL import Image
from PIL import ImageDraw
from PIL import ImageFont
from io import BytesIO


font_size = 12
font = ImageFont.truetype("DejaVuSansMono.ttf", font_size) #Font sacada de la terminal del kali
black = (0,0,0)
small = (640,480)
normal = (800,600)
extraL = (1024,768)
image_format = "PNG"

def create_image_from_file(path_filename):
    print('---------------- CREATING IMAGE FROM OUTPUT--------------')
    global font_size,font,black,image_format
    num_lines = sum(1 for line in open(path_filename)) #Cantidad de lineas que tiene el archivo
    #Ancho y alto para la imagen, no hay problema si tiene mucho ancho ya que se cropea la imagen
    extraL = (1920,num_lines*font_size*2)
    img = Image.new('RGB', extraL, (255, 255, 255))
    d = ImageDraw.Draw(img)
    with open(path_filename,"r+") as file:
        text = file.read()
        d.text((6, 12), text, fill=black,font=font)
    buffered = BytesIO()
    img.save(buffered, format=image_format)
    img_str = base64.b64encode(buffered.getvalue())
    return img_str.decode('utf-8')
    print('---------------- DONE --------------')

def create_image_from_string(message):
    global font_size,font,black,extraL,image_format
    img = Image.new('RGB', small, (255, 255, 255))
    d = ImageDraw.Draw(img)
    d.text((6, 12), message, fill=black,font=font)
    buffered = BytesIO()
    img.save(buffered, format=image_format)
    img_str = base64.b64encode(buffered.getvalue())
    return img_str.decode('utf-8')
    print('---------------- DONE --------------')