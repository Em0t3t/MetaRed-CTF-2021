import string
from itertools import cycle
import binascii

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])
def decode_block_xor(ciphertext, clave):
    result = b""
    l = len(clave)
    result += byte_xor(clave, ciphertext[:l])
    for i in range(l, len(ciphertext), l):
        cipheri_1 = ciphertext[i - l:i]
        cipheri = ciphertext[i:i + l]
        aux = (byte_xor(cipheri_1, cipheri))
        result+=byte_xor(aux, clave)
    return(result)
def xorate_bytes(message, key, trunk=False):
    if len(key) > len(message):
        f = key
        key = message
        message = f
    result = (''.join(chr(c ^ k) for c, k in zip(message, cycle(key))))
    if trunk:
        result=result[:min(len(key),len(message))]
    return result
import string
def atbash(text):
    result = ""
    for c in text:
        if c in string.ascii_lowercase:
            N = ord('z') + ord('a')
            result += chr(N - ord(c))
        elif c in string.ascii_uppercase:
            N = ord('Z') + ord('A')
            result += chr(N - ord(c))
        else:
            result += c
    return result
# step 1
print(xorate_bytes(binascii.unhexlify("030811044425010363413c041c1b546b47220008171b0700230e52330b010f0d290e484106595c527f004250050d5d587e074257055a59567d5346585d5659587d5146025d0e642d240e1c04084f23043e121b5b440d575275534151530d5d522c5744535209585179564252076529002f131b04084f23082108060e5e4f0c537e514054555c0c587f564051515957597b044250515956517b597826050d1c08280d5223051b0712391406005e4f0c537e514054555c0c587f564051515957567b574357510a57517a034351510a565547381d14440e1c046d1717131d4f090e2205535b440e0d5228531155020d56572e534a50000e0c5374531151550957527a5741515d095c56746b782f0d190b0d6d524841060d5d597f0542020256590579554658075c59057c5746545d5f5d557c0242005d0c5c5879584304005f5c04795346545d5858507d0546005c0c58517c074559005659577c5945595d5b5f597c5443575c0a59527c524654005a5b057a074451000958047b584207005a5907780578"), b"Maradona"))
# step 2
print(decode_block_xor(binascii.unhexlify("bb382d0cf97d4449c37d164590341c0a9c29491ed02e424597610d4a8c601f78d9761878941815168e731345d55d7f60df6e690fd57f5d"), b"\xf5\x51").decode())
# step 3
print(atbash("uozt{fI3_4_y1t_n4hg3I_lU_C0I!}"))
