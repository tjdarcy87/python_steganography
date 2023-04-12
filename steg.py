from PIL import Image
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

isdebug = False

def modifyPixels(pix, data):
    """Given an image's getdata(), and a payload will loop through and provide an updated list of pixels to iterate through at the higher level"""
    datalist = []
    for i in data:
        # create list of 8 bit binary values for each character in the message
        datalist.append(format(ord(i), '08b'))
    imdata = iter(pix)

    # Loop through the pixels in the image
    for i in range(len(datalist)):
        # Get the next three color channel values from the iterator
        pix = [value for value in imdata.__next__()[:3] +
               imdata.__next__()[:3] +
               imdata.__next__()[:3]]

        # Loop through the bits of the binary message
        for j in range(0, 8):
            # Modify the color channel value if necessary to encode the bit
            if (datalist[i][j] == '0' and pix[j] % 2 != 0):
                pix[j] -= 1
            elif (datalist[i][j] == '1' and pix[j] % 2 == 0):
                if(pix[j] != 0):
                    pix[j] -= 1
                else:
                    pix[j] += 1
        # If this is the last pixel, modify the least significant bit of the blue channel
        # to indicate the end of the message
        if (i == len(datalist) - 1):
            if (pix[-1] % 2 == 0):
                if(pix[-1] != 0):
                    pix[-1] -= 1
                else:
                    pix[-1] += 1
        # Otherwise, modify the least significant bit of the blue channel to be even
        else:
            if (pix[-1] % 2 != 0):
                pix[-1] -= 1

        # Convert the modified pixel values back to a tuple (r,g,b) and yield them
        pix = tuple(pix)
        yield pix[0:3]
        yield pix[3:6]
        yield pix[6:9]

def encryptMessage(message, password):
    """Given a message and a password, will generate a list of integers as a secret and return an encrypted payload"""
    bytesHeader = password.encode('ascii') # encode the string to ascii
    bytesMessage = message.encode('ascii') # encode the string to ascii
    key = get_random_bytes(16) # get a new random key
    print("Keep this list of numbers secret as you can't retrieve")
    print(list(key)) # convert the key from bytes into a list of integers reflecting the bytes
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(bytesHeader)
    ciphertext, tag = cipher.encrypt_and_digest(bytesMessage)
    json_k = ['nonce', 'header', 'ciphertext', 'tag']
    json_v = [b64encode(x).decode('ascii') for x in (cipher.nonce, bytesHeader, ciphertext, tag)]
    result = json.dumps(dict(zip(json_k, json_v)))
    return result

def decryptMessage(json_input, keyList):
    """Given a json_input and a list of integers, will attempt to decrypt the message as well as return the original password"""
    key = bytes(keyList)
    b64 = json.loads(json_input)
    json_k = ['nonce', 'header', 'ciphertext', 'tag']
    jv = {k: b64decode(b64[k]) for k in json_k}
    cipher = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])
    cipher.update(jv['header'])
    plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
    return plaintext.decode('ascii'), jv['header'].decode('ascii')
    
def hidePayload(image_name, output_name, payload):
    """Given a image path as well as an encrypted payload, will create an _out suffixed file of the same type with the payload embedded"""
    image = Image.open(image_name, 'r')
    image_copy = image.copy()
    max_size_x = image_copy.size[0]
    (x, y) = (0, 0) # start at the first pixel

    for pixel in modifyPixels(image_copy.getdata(), payload): # modifyPixels returns a list of updated pixels that can be iterated through
        image_copy.putpixel((x, y), pixel) #
        if (x == max_size_x - 1):
            x = 0
            y += 1
        else:
            x += 1

    image_copy.save(output_name, str(output_name.split(".")[1].upper())) # dynamically get the file type from the output name

def retrievePayload(img):
    """Given an image, will return a payload if it can be found using the same formula"""
    image = Image.open(img, 'r')
    data = ''
    imgdata = iter(image.getdata())

    # Loop over the pixel data iterator indefinitely
    while (True):
        # Get the next three RGB pixel values from the iterator and concatenate them into a list
        pixels = [value for value in imgdata.__next__()[:3] +
                  imgdata.__next__()[:3] +
                  imgdata.__next__()[:3]]

        binstr = ''

        # Loop over the first 8 values in the "pixels" list
        for i in pixels[:8]:
            # If the value is even, append a '0' to the binary string; otherwise, append a '1'
            if (i % 2 == 0):
                binstr += '0'
            else:
                binstr += '1'

        # Convert the binary string to an integer and then to its corresponding ASCII character
        data += chr(int(binstr, 2))

        # Check the least significant bit of the last pixel value in the list
        # If it is odd (i.e., 1), then the last character has been decoded completely
        # and the decoded data can be returned
        if (pixels[-1] % 2 != 0):
            return data

def validateImagePath(image_path):
    """Ensure images are of type JPEG or PNG"""
    if not (image_path.endswith(".jpeg") or image_path.endswith(".png")):
        raise ValueError("Invalid file path, working for JPEG and PNG only")

def validateImageSizePayload(image_path, payload):
    """Ensure the image has enough pixels for the payload"""
    width, height = Image.open(image_path, 'r').size

    if ( len(payload) * 8 ) > ( width * height ):
        raise ValueError("Invalid image size for the encrypted payload")

def validatePayload(payload):
    """Ensure payload has the right format"""
    outDict = json.loads(payload)
    expectedFields = ['nonce', 'header', 'ciphertext', 'tag']

    if not all(name in outDict for name in expectedFields):
        raise ValueError("Payload doesn't meet the expected format")

def getOutputName(image_path):
    output_name = ''
    if ".jpeg" in image_path:
        output_name = image_path.replace(".jpeg", "_out.jpeg")
    elif ".png" in image_path:
        output_name = image_path.replace(".png", "_out.png")
    
    return output_name

def run():
    """The menu of the application"""
    while(True):
        userinput = int(input("Steganography Tool\n 1. Hide a message \n 2. Retrieve a message \n 3. Exit \n"))
        try:
            if (userinput == 1):
                image_path = input("Enter image path\n")
                validateImagePath(image_path)
                message = input("Enter the message\n")
                header = input("What was the pre-agreed password\n")
                encryptedPayload = encryptMessage(message, header)
                if isdebug:
                    print(encryptedPayload)
                validateImageSizePayload(image_path, encryptedPayload)
                hidePayload(image_path, getOutputName(image_path),encryptedPayload)
            elif (userinput == 2):
                image_path = input("Enter image path\n")
                validateImagePath(image_path)
                payload = retrievePayload(image_path)
                validatePayload(payload)
                print("Found payload: " + payload)
                keyString = input("Enter the keylist separated by commas\n")
                keyListString = keyString.split(",")
                keyList = [int(x) for x in keyListString]
                decryptedMessage, secret = decryptMessage(payload, keyList)
                print("The message was: " + decryptedMessage)
                print("The secret was: " + secret)
            elif (userinput == 3):
                quit()
            else:
                print("Invalid option")
        except Exception as e:
            print("Caught Exception:")
            print(e)

if __name__ == "__main__":
    run()