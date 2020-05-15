from PIL import Image
from PIL import ImageDraw
from PIL import ImageFont

font_size = 12
font = ImageFont.truetype("DejaVuSansMono.ttf", font_size) #Font sacada de la terminal del kali
black = (0,0,0)
small = (640,480)
normal = (800,600)
extraL = (1024,768)

def create_image_from_file(path,path_filename,name):
    print('---------------- CREATING IMAGE FROM OUTPUT--------------')
    global font_size
    global font
    global black
    num_lines = sum(1 for line in open(path_filename)) #Cantidad de lineas que tiene el archivo
    #Ancho y alto para la imagen, no hay problema si tiene mucho ancho ya que se cropea la imagen
    extraL = (1920,num_lines*font_size*2)
    img = Image.new('RGB', extraL, (255, 255, 255))
    d = ImageDraw.Draw(img)
    with open(path_filename,"r+") as file:
        text = file.read()
        d.text((6, 12), text, fill=black,font=font)
    dest = path+"/"+name+".png"
    img.save(dest)
    file.close()
    print('---------------- DONE --------------')


def create_image_from_string(path,name,message):
    name = name.replace("http://","").replace("https://","").split("/")[0]
    global font_size
    global font
    global black
    global extraL
    img = Image.new('RGB', small, (255, 255, 255))
    d = ImageDraw.Draw(img)
    d.text((6, 12), message, fill=black,font=font)
    dest = path+"/"+name+"-HEADERS.png"
    img.save(dest)
