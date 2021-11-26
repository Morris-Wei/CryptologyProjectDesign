# import os
# import hashlib
# from Crypto.Cipher import DES as DES_Pro
# from Crypto import Random
# from Padding import pad, unpad
from CryptologyProj import *


from tkinter import *
from tkinter import ttk
global hashfunc, symmetic_func,sym_key_length,crypted_obj,sym_mode,seed, key,\
    ps, pr,ps1,pr1,stringEncResult, stringDecResult
# def CheckStatus2Param(isMD5, isSHA, isAES, isDES, is64bit, is128bit, is192bit,is256bit,isSEED, isInput, isString, isFile):
def CheckStatus2Param(*args):
    try:
        global hashfunc, symmetic_func, sym_key_length, crypted_obj, sym_mode,seed, key

        if (isMD5.get(), isSHA.get()) == (1, 0):
            hashfunc = "MD5"
        elif (isMD5.get(), isSHA.get()) == (0, 1):
            hashfunc = "SHA"
        else:
            raise Exception("参数错误重新检查")

        if (isAES.get(),isDES.get()) == (1, 0):
            symmetic_func = "AES"
        elif (isAES.get(),isDES.get()) == (0, 1):
            symmetic_func = "DES"
        else:
            raise Exception("参数错误重新检查")

        if (is64bit.get(), is128bit.get(), is192bit.get(),is256bit.get()) == (1,0,0,0):
            sym_key_length = 64
        elif (is64bit.get(), is128bit.get(), is192bit.get(),is256bit.get()) == (0,1,0,0):
            sym_key_length = 128
        elif (is64bit.get(), is128bit.get(), is192bit.get(),is256bit.get()) == (0,0,1,0):
            sym_key_length = 192
        elif (is64bit.get(), is128bit.get(), is192bit.get(),is256bit.get()) == (0,0,0,1):
            sym_key_length = 256
        else:
            raise Exception("参数错误重新检查")

        if (isString.get(), isFile.get()) == (1, 0):
            crypted_obj = 'string'
        elif (isString.get(), isFile.get()) == (0, 1):
            crypted_obj = 'file'
        else:
            raise Exception("参数错误重新检查")

        if (isSEED.get(), isInput.get()) == (1, 0):
            sym_mode = 1
            seed = seedOrSymkey.get()
            key = None
            print(seed)
        elif (isSEED.get(), isInput.get()) == (0, 1):
            sym_mode = 0
            seed = None
            key = seedOrSymkey.get()
            if len(key) == sym_key_length // 4:
                raise Exception("Key length error")
            print(key)
        else:
            raise Exception("参数错误重新检查")

    except Exception as e:
        resultText.insert('end', str(e) + '\n')
        pass
    else:
        print(hashfunc, symmetic_func, sym_key_length, crypted_obj, sym_mode)

def encrypt(*args):
    try:
        if crypted_obj == "file":
            global ps, pr
            ps = PGPSender(hashfunc, symmetic_func, sym_key_length, crypted_obj, seed, sym_mode)
            pr = PGPRecipient(hashfunc, symmetic_func, sym_key_length, crypted_obj, seed, sym_mode)
            ps.keyGenerateAndSave(senderPubKeyPath.get(), key)
            pr.keyGenerateAndSave(receiverPubKeyPath.get())
            ps.loadKey(receiverPubKeyPath.get())
            pr.loadKey(senderPubKeyPath.get())
            ps.bigFileEncryption(obj.get(), objout.get())

        elif crypted_obj == "string":
            global ps1, pr1, stringEncResult
            ps1 = PGPSender(hashfunc, symmetic_func, sym_key_length, crypted_obj, seed, sym_mode)
            pr1 = PGPRecipient(hashfunc, symmetic_func, sym_key_length, crypted_obj, seed, sym_mode)
            ps1.keyGenerate(key)
            pr1.keyGenerate()
            switchKey(ps1, pr1)
            stringEncResult = ps1.stringCrypt(obj.get())
            resultText.insert('end', stringEncResult+'\n')
    except Exception as e:
        resultText.insert('end', str(e) + '\n')

def decrypt(*args):
    try:
        global stringDecResult
        if crypted_obj == "file":
            configTransmit(ps, pr)
            pr.bigFileDecryption(objout.get(), objout2.get())
        elif crypted_obj == "string":
            configTransmit(ps1, pr1)
            stringDecResult = pr1.stringDecrypt(stringEncResult)
            resultText.insert('end', stringDecResult+'\n')
            print(stringDecResult)
    except Exception as e:
        resultText.insert('end', str(e) + '\n')

main = Tk()
main.title('PGP')
main.geometry('820x460+120+120')
main.columnconfigure(0, weight=1)
main.rowconfigure(0, weight=1)
mainframe = ttk.Frame(main)
mainframe.grid(column=0, row=0, sticky=(N, W, E, S))
Label(mainframe,text="哈希函数选择").place(x=40, y=20, anchor= 'nw')
Label(mainframe,text="对称加密选择").place(x=40, y=60, anchor= 'nw')
Label(mainframe,text="密钥长度").place(x=40, y=100, anchor= 'nw')
Label(mainframe,text="密钥生成方法").place(x=40, y=180, anchor= 'nw')
Label(mainframe,text="加密对象").place(x=40, y=260, anchor= 'nw')
Label(mainframe, text="公钥生成地址").place(x=40, y=340, anchor= 'nw')
Label(mainframe, text="公钥生成地址").place(x=400, y=340, anchor= 'nw')
Label(mainframe,text="文件地址").place(x=400, y=20, anchor= 'nw')

isMD5 = IntVar()
isSHA = IntVar()
isAES = IntVar()
isDES = IntVar()
is64bit = IntVar()
is128bit = IntVar()
is192bit = IntVar()
is256bit = IntVar()
isSEED = IntVar()
isInput = IntVar()
isString = IntVar()
isFile = IntVar()

Checkbutton(mainframe, text="MD5", variable=isMD5, onvalue = 1, offvalue = 0).place(x=140, y=20,anchor= 'nw')
Checkbutton(mainframe, text="SHA", variable=isSHA, onvalue = 1, offvalue = 0).place(x=200, y=20, anchor= 'nw')
Checkbutton(mainframe, text="AES", variable=isAES, onvalue = 1, offvalue = 0).place(x=140, y=60,anchor= 'nw')
Checkbutton(mainframe, text="DES", variable=isDES, onvalue = 1, offvalue = 0).place(x=200, y=60, anchor= 'nw')
Checkbutton(mainframe, text="64bit(仅DES)",variable=is64bit, onvalue = 1, offvalue = 0).place(x=140,y=100, anchor= 'nw')
Checkbutton(mainframe, text="128bit",variable=is128bit, onvalue = 1, offvalue = 0).place(x=240, y=100, anchor= 'nw')
Checkbutton(mainframe, text="192bit",variable=is192bit, onvalue = 1, offvalue = 0).place(x=140, y=140,anchor= 'nw')
Checkbutton(mainframe, text="256bit",variable=is256bit, onvalue = 1, offvalue = 0,).place(x=240, y=140,anchor= 'nw')
Checkbutton(mainframe, text="SEED", variable=isSEED, onvalue = 1, offvalue = 0,).place(x=140, y=180, anchor= 'nw')
Checkbutton(mainframe, text="输入",variable=isInput, onvalue = 1, offvalue = 0).place(x=240, y=180,anchor= 'nw')
seedOrSymkey = StringVar()
seedOrKey_entry = Entry(mainframe, width=30, textvariable=seedOrSymkey)
seedOrKey_entry.place(x=140, y=220, anchor= 'nw')
Checkbutton(mainframe,text="字符串",variable=isString).place(x=140, y=260, anchor= 'nw')
Checkbutton(mainframe,text="文件",variable=isFile).place(x=240, y=260, anchor= 'nw')
obj = StringVar()
encryptObj_entry = Entry(mainframe, width=30, textvariable=obj)
encryptObj_entry.place(x=140, y=300, anchor= 'nw')
senderPubKeyPath = StringVar()
pubKey1Path_entry = Entry(mainframe, width=30, textvariable=senderPubKeyPath) # 发送方的公钥存储地址
pubKey1Path_entry.place(x=140, y=340, anchor= 'nw')
# 接收端的控件
objout = StringVar()
filePath_entry = Entry(mainframe, width=30, textvariable=objout)
filePath_entry.place(x=480, y=20, anchor= 'nw')
objout2 = StringVar()
decryptfilePath_entry = Entry(mainframe, width=30, textvariable=objout2)
decryptfilePath_entry.place(x=480, y=40, anchor= 'nw')

resultText = Text(mainframe, height=20, width=30)
# resultText.insert('0.0',"NSAKJKD")
resultText.place(x=500, y=80)
receiverPubKeyPath = StringVar()
pubKey2Path_entry = Entry(mainframe, width=30, textvariable=receiverPubKeyPath)# 接收方的公钥存储地址
pubKey2Path_entry.place(x=500, y=340, anchor= 'nw')

Button(mainframe,text="确认参数",command=CheckStatus2Param).place(x=80, y=380, anchor= 'nw')
# Button(mainframe,text="公钥生成").place(x=140, y=380, anchor= 'nw')
Button(mainframe,text="加密",command=encrypt).place(x=200, y=380, anchor= 'nw')

# Button(mainframe,text="公钥生成").place(x=500, y=380, anchor= 'nw')
Button(mainframe,text="解密",command=decrypt).place(x=560, y=380, anchor= 'nw')

main.mainloop()
