from pwn import *
from base64 import b64decode as dec
import re
from gmpy2 import iroot
from Crypto.Util.number import *
import codecs

class MorseCodeTranslator:

    # International morse code (sample)
    morse = {
        # Letters
        "a": ".-",
        "b": "-...",
        "c": "-.-.",
        "d": "-..",
        "e": ".",
        "f": "..-.",
        "g": "--.",
        "h": "....",
        "i": "..",
        "j": ".---",
        "k": "-.-",
        "l": ".-..",
        "m": "--",
        "n": "-.",
        "o": "---",
        "p": ".--.",
        "q": "--.-",
        "r": ".-.",
        "s": "...",
        "t": "-",
        "u": "..-",
        "v": "...-",
        "w": ".--",
        "x": "-..-",
        "y": "-.--",
        "z": "--..",
        # Numbers
        "0": "-----",
        "1": ".----",
        "2": "..---",
        "3": "...--",
        "4": "....-",
        "5": ".....",
        "6": "-....",
        "7": "--...",
        "8": "---..",
        "9": "----.",
        # Punctuation
        "&": ".-...",
        "'": ".----.",
        "@": ".--.-.",
        ")": "-.--.-",
        "(": "-.--.",
        ":": "---...",
        ",": "--..--",
        "=": "-...-",
        "!": "-.-.--",
        ".": ".-.-.-",
        "-": "-....-",
        "+": ".-.-.",
        '"': ".-..-.",
        "?": "..--..",
        "/": "-..-.",
    }

    def translate_morse(self, morse, strict=True):

        """
        Translates morse code to english.

        Accepts:
            morse (str): A string of morse code to translate
            strict (bool): If True, parse and return morse code containing 4 spaces

        Returns:
            str: A translated string of text
        """

        if morse == "":
            return "You must provide a string of text to translate"

        if "    " in morse:
            if strict:
                return "Unable to translate morse code. Found 4 spaces in morse code string"
            else:
                morse.replace("    ", "   ")

        translation = ""

        words = morse.split("   ")

        for morse_word in words:
            chars = morse_word.split(" ")
            for char in chars:
                for k, v in self.morse.items():
                    if char == v:
                        translation += k
            translation += " "

        return translation.rstrip()

    def translate_text(self, text):

        """
        Translates text to morse code.

        Accepts:
            text (str): A string of text to translate

        Returns:
            str: A translated string of morse code
        """

        if text == "":
            return "You must provide a morse code string to translate"

        translation = ""

        words = text.split(" ")

        for word in words:
            w = list()
            for char in word:
                if char.lower() in self.morse:
                    w.append(self.morse[char.lower()])

            translation += " ".join(w)
            translation += "   "

        return translation.rstrip()

host = "crypto.chal.csaw.io" 
port = 5001
r = remote(host,port)
print(r.recvuntil(b"\n"))
print(r.recvuntil(b"\n"))    
while True:
    tmp = r.recvuntil(b"\n")
    print(tmp)
    if b"flag" in tmp : 
        break
    enc = r.recvuntil(b"\n").decode().strip()
    enc = enc.split("/")
    translator = MorseCodeTranslator()
    morse = []
    for i in enc : 
        morse.append(translator.translate_morse(i))
    morse = [int(i) for i in morse]
    msg = "".join(chr(i) for  i in morse)
    d = re.compile(r"\d+")
    n,e,c = d.findall(dec(msg).decode())
    m = long_to_bytes(int(iroot(int(c),int(e))[0]))
    to_send = codecs.encode(m.decode(),"rot13")
    r.sendline(to_send)
    print(r.recvuntil(b"\n"))
    print(r.recvuntil(b"\n"))
    