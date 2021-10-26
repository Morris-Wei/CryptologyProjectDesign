# 本文件定义了base64字符串与16进制的转换，16进制字符串与整数转换
# 以及16进制字符串与ascii字符串的转换
import base64


def hextobase64(hexstr:str):
    byteform = bytes.fromhex(hexstr)
    b64coded = base64.b64encode(byteform)
    b64str = str(b64coded, 'utf-8')
    return b64str

def base64tohex(base64str:str):
    byteform = bytes(base64str, 'utf-8')
    b64decoded = base64.b64decode(byteform)
    hexstr = b64decoded.hex()
    return hexstr

def hextonum(hexstr:str): # hex字符串到整数的转换
    fullHexStr = "0x" + hexstr
    return eval(fullHexStr)

def numtohex(num:int): # 整数到hex字符串的转换
    return hex(num)[2:]

def hextoasciiStr(hexstr:str): # return asciistr
    hexstr_len = len(hexstr)
    s = ""
    for i in range(0, hexstr_len, 2):
        tmpstr = hexstr[i:i+2]
        s += chr(hextonum(tmpstr))
    return s

def asciistrtohex(asciistr:str): # return a hexstr
    asciistr_len = len(asciistr)
    s = ""
    for i in range(0, asciistr_len):
        hexed = hex(ord(asciistr[i]))[2:]
        if ord(asciistr[i]) < 15: # 这里需要保留一位0
            hexed = '0' + hexed
        s += hexed
    return s


if __name__ == "__main__":
    s = hextoasciiStr('c3')
    s += chr(1)
    c = asciistrtohex(s)
    # print(he_str)
    print(c)