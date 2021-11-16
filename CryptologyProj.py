import AES
import DES
import MD5
import SHA
import RSA
import AllConvert
import random
import base64
import os

## 以下为python原生或是发行包中的算法
from Crypto import PublicKey
from pyDes import des, CBC, PAD_PKCS5
import rsa
import hashlib
from Crypto.Cipher import DES as DES_Pro
from Crypto.Cipher import AES as AES_Pro
from Crypto import Random
from Padding import pad, unpad

class PGPConfig:
    def __init__(self, hashfunc, symmetic_func, sym_key_length, crypted_obj, seed,sym_mode = 1):
        self.hashfunc = hashfunc
        self.symmetic_func = symmetic_func
        self.crypto_obj = crypted_obj # 其值要么为string要么为file
        self.key_length = sym_key_length
        self.sym_mode = sym_mode # 0代表对称密钥由外部输入，而1代表由种子产生
        self.seed = seed

class PGPSender(PGPConfig):
    def __init__(self, hashfunc, symmetic_func, sym_key_length, crypted_obj, seed ,text, sym_mode = 1):
        super().__init__(hashfunc, symmetic_func, sym_key_length, crypted_obj, seed, sym_mode)
        if len(text) == 0:
            raise Exception("Empty text Error, Enter text")
        self.text = text
        self.pr_key_sender = None # 发送方私钥
        self.pub_key_sender = None # 发送方公钥
        self.pub_key_recipient = None # 接收方公钥
        self.sym_key = ""
        self.sig_field_length = 0 # 签名长度
        self.sym_key_field_length = 0 # 对称密钥域长度
        self.ispad = False

        self.ismessagepad = False # message有可能不是64，128 整数，这里需要指出是否需要pad
        self.issigpad = False # 签名部分同上
        self.issympad = False # 公钥加密的对称密钥同上


    def keyGenerate(self):
        RSAkey = RSA.get_RSAKey()
        Pub_key = RSAkey['puk'] # Pub = [n, e]
        Pr_key = RSAkey['prk'] # Pr = [n, d]
        self.pub_key_sender = Pub_key
        self.pr_key_sender = Pr_key
        random.seed(self.seed)
        Sym_key = random.randint(2**(self.key_length-1), 2**self.key_length)
        symkey = AllConvert.numtohex(Sym_key)
        print("symkey:", symkey)
        self.sym_key = symkey

    def keyGenerateAndSave(self, sender_pub_path:str): # 当然这里只保存公钥
        self.pub_key_sender, self.pr_key_sender = rsa.newkeys(1024)
        if "PEM" in sender_pub_path.upper():
            sender_pub_path = sender_pub_path[:-4]
        with open('{}.pem'.format(sender_pub_path), 'bw') as f:
            f.write(self.pub_key_sender.save_pkcs1())

    def loadKey(self, recipient_pub_path:str):
        with open(recipient_pub_path, "rb") as fp:
            self.pub_key_recipient = rsa.PublicKey.load_pkcs1(fp.read())
        return True
    

    def stringCrypt(self): # 加密前需要生成密钥，并交换公钥, block是128bit的16进制字符串
        if len(self.pr_key_sender) == 0  \
                or len(self.pub_key_sender) == 0  \
                or len(self.pub_key_recipient) == 0:
            raise Exception("No asymmetric key detected, generate it first")

        hashed = ""
        if self.hashfunc == 'MD5':
            hashed = MD5.MD5.hash(self.text)
        elif self.hashfunc == 'SHA':
            hashed = SHA.sha1(self.text)
        print('-' * 30)
        print("Hashing completed")
        print(self.hashfunc + "HashValue: ", hashed)

        hashed_num = AllConvert.hextonum(hashed)
        signed_num = RSA.encryption(hashed_num, self.pr_key_sender) # 这里是签名
        signed = AllConvert.numtohex(signed_num)
        print('-'*30)
        print("Signing completed")
        print("SignValue: ", signed)
        self.sig_field_length = len(signed)


        plaintextWithSig = AllConvert.asciistrtohex(self.text) + signed

        sym_crypted = "" # 对称加密后的数据
        if self.symmetic_func == 'AES':
            aes = AES.AES(master_key=self.sym_key, key_length=self.key_length // 8)
            stringChunkSize = 128 // 4
            for i in range(0, len(plaintextWithSig), stringChunkSize):
                chunked = plaintextWithSig[i:i+stringChunkSize] if i+stringChunkSize < len(plaintextWithSig) else plaintextWithSig[i:]
                if len(chunked) < stringChunkSize:
                    sym_crypted += aes.encrypt(chunked, padding=True)
                    self.ispad = True
                else:
                    sym_crypted += aes.encrypt(chunked, padding=False)
        if self.symmetic_func == 'DES':
            stringChunkSize = 64 // 4

            for i in range(0, len(plaintextWithSig), stringChunkSize):
                chunked = plaintextWithSig[i:i+stringChunkSize] if i+stringChunkSize < len(plaintextWithSig) else \
                    plaintextWithSig[i:]
                des = DES.des()
                if len(chunked) < stringChunkSize:
                    sym_crypted += des.encrypt(self.sym_key,chunked, padding=True)
                    self.ispad = True
                else:
                    sym_crypted += des.encrypt(self.sym_key,chunked, padding=False)
        print('-'*30)
        print(self.symmetic_func + "symmetric encrypt completed!")

        sym_key_num_form = AllConvert.hextonum(self.sym_key)

        pub_encrypted_sym_key = RSA.encryption(sym_key_num_form, self.pub_key_recipient)
        # 需要padding
        self.sym_key_field_length = len(AllConvert.numtohex(pub_encrypted_sym_key))
        result = sym_crypted + AllConvert.numtohex(pub_encrypted_sym_key)
        return result

    def fileEncrypt(self, inPath, outPath):
        with open(inPath, "rb") as fp:
            if fp:
                file_byte = fp.read()
            else:
                raise Exception("File not exists!")
        self.text = AllConvert.hextoasciiStr(file_byte.hex())
        file_byte = bytes.fromhex(self.stringCrypt())
        with open(outPath, "wb") as fp:
            fp.write(file_byte)

    def bigFileEncryption(self, inPath, outPath):
        if os.path.isfile(outPath):
            os.remove(outPath)
        mode = ""
        with open(inPath, "rb") as fp:
            if not fp:
                raise Exception("File not exists!")
            fileByte = fp.read(128)

            if self.hashfunc == "MD5":
                md5 = hashlib.md5()
                while fileByte:
                    md5.update(fileByte)
                    fileByte = fp.read(128)
                hash_result = md5.hexdigest()
                mode = hashfunc
            elif self.hashfunc == "SHA":
                sha = hashlib.sha1()
                while fileByte:
                    sha.update(fileByte)
                    fileByte = fp.read(128)
                hash_result = sha.hexdigest()
                mode = "SHA-1"
            print(self.hashfunc, "result: ", hash_result)

        if not(self.pub_key_recipient
               and self.pub_key_sender
               and self.pr_key_sender):
            raise Exception("No asymmetric key detected, generate it first")

        with open(inPath, "rb") as fp:
            signed = rsa.sign(fp, priv_key=self.pr_key_sender, hash_method=mode)
        self.sig_field_length = len(signed) # 128//8

        if self.symmetic_func == "AES":
            self.sym_key = Random.get_random_bytes(self.key_length // 8)
            aes = AES_Pro.new(self.sym_key, AES_Pro.MODE_ECB)
            with open(inPath, "rb") as fp:
                with open(outPath, "ab") as fp2:
                    fileChunk = fp.read(16)
                    while fileChunk:
                        if len(fileChunk) != 16:
                            fileChunk = pad(fileChunk, 16)
                            self.ismessagepad = True
                        encrypted_file_chunk = aes.encrypt(fileChunk)
                        fp2.write(encrypted_file_chunk)
                        fileChunk = fp.read(16)
            if self.sig_field_length % 16 != 0:
                signed = pad(signed, 16)
                self.issigpad = True
                self.sig_field_length = len(signed)
            encrypted_signature = aes.encrypt(signed)
            with open(outPath, "ab") as fp2: # 以追加模式进行写入
                fp2.write(encrypted_signature)

            encrypted_sym_key = rsa.encrypt(self.sym_key, self.pub_key_recipient)
            self.sym_key_field_length = len(encrypted_sym_key)
            with open(outPath, "ab") as fp3: # 以追加模式进行写入
                fp3.write(encrypted_sym_key)



        elif self.symmetic_func == "DES":
            self.sym_key = Random.get_random_bytes(8)
            des = DES_Pro.new(self.sym_key, DES_Pro.MODE_ECB)
            with open(inPath, "rb") as fp:
                with open(outPath, "ab") as fp2:
                    fileChunk = fp.read(8)
                    while fileChunk:
                        if len(fileChunk) != 8:
                            fileChunk = pad(fileChunk, 8)
                            self.ismessagepad = True
                        encrypted_file_chunk = des.encrypt(fileChunk)
                        fp2.write(encrypted_file_chunk)
                        fileChunk = fp.read(8)
            if self.sig_field_length % 8 != 0:
                signed = pad(signed, 8)
                self.issigpad = True
                self.sig_field_length = len(signed)
            encrypted_signature = des.encrypt(signed)
            with open(outPath, "ab") as fp2:  # 以追加模式进行写入
                fp2.write(encrypted_signature)

            encrypted_sym_key = rsa.encrypt(self.sym_key, self.pub_key_recipient)
            self.sym_key_field_length = len(encrypted_sym_key)
            with open(outPath, "ab") as fp3:  # 以追加模式进行写入
                fp3.write(encrypted_sym_key)


class PGPRecipient(PGPConfig):
    def __init__(self, hashfunc, symmetic_func, sym_key_length, crypted_obj, seed, text="", sym_mode=1):
        super().__init__(hashfunc, symmetic_func, sym_key_length, crypted_obj, seed, sym_mode)
        if len(text) == 0:
            raise Exception("Empty text Error, Enter text")
        self.text = text
        self.pr_key_receiver = None # 发送方私钥
        self.pub_key_receiver = None  # 发送方公钥
        self.pub_key_sender = None  # 接收方公钥
        self.sym_key = ""
        self.sig_field_length = 0 # 签名长度
        self.sym_key_field_length = 0 # 对称密钥域长度
        self.ispad = False

        self.ismessagepad = False # message有可能不是64，128 整数，这里需要指出是否需要pad
        self.issigpad = False # 签名部分同上
        self.issympad = False # 公钥加密的对称密钥同上


    def keyGenerate(self):
        RSAkey = RSA.get_RSAKey()
        Pub_key = RSAkey['puk']  # Pub = [n, e]
        Pr_key = RSAkey['prk']  # Pr = [n, d]
        self.pub_key_receiver = Pub_key
        self.pr_key_receiver = Pr_key

    def keyGenerateAndSave(self, recipent_pub_path:str): # 当然这里只保存公钥
        self.pub_key_receiver, self.pr_key_receiver = rsa.newkeys(1024)
        if "PEM" in recipent_pub_path.upper():
            recipent_pub_path = recipent_pub_path[:-4]
        with open('{}.pem'.format(recipent_pub_path), 'bw') as f:
            f.write(self.pub_key_receiver.save_pkcs1())

    def loadKey(self, recipient_pub_path:str):
        with open(recipient_pub_path, "rb") as fp:

            self.pub_key_sender = rsa.PublicKey.load_pkcs1(fp.read())
        return True

    def stringDecrypt(self, hex_text_crypted):
        self.text = hex_text_crypted
        if len(self.pr_key_receiver) == 0  \
                or len(self.pub_key_receiver) == 0  \
                or len(self.pub_key_sender) == 0:
            raise Exception("No asymmetric key detected, generate it first")

        sym_key_crypted = self.text[-self.sym_key_field_length:]
        crypted_text = self.text[0:-self.sym_key_field_length]

        sym_key = RSA.decryption(AllConvert.hextonum(sym_key_crypted), self.pr_key_receiver)
        self.sym_key = AllConvert.numtohex(sym_key)
        print("sym_key", self.sym_key)

        sym_decrypted = ""  # 对称解密后的数据
        if self.symmetic_func == 'AES':
            chunk_size =  128 // 4
            aes = AES.AES(master_key=self.sym_key, key_length=len(self.sym_key) // 2)
            for i in range(0, len(crypted_text), chunk_size):
                if i + chunk_size < len(crypted_text):
                    sym_decrypted += aes.decrypt(crypted_text[i:i+chunk_size])
                elif self.ispad:
                    sym_decrypted += aes.decrypt(crypted_text[i:], padding=True)
                elif not self.ispad:
                    sym_decrypted += aes.decrypt(crypted_text[i:])

        if self.symmetic_func == 'DES':
            chunk_size =  64 // 4
            des = DES.des()
            for i in range(0, len(crypted_text), chunk_size):
                if i + chunk_size < len(crypted_text):
                    sym_decrypted += des.decrypt(self.sym_key, crypted_text[i:i+chunk_size])
                elif self.ispad:
                    sym_decrypted += des.decrypt(self.sym_key, crypted_text[i:], padding=True)
                elif not self.ispad:
                    sym_decrypted += des.decrypt(self.sym_key, crypted_text[i:])

        sig_field_encrypted = sym_decrypted[-self.sig_field_length:]
        message_hex = sym_decrypted[0:-self.sig_field_length]
        message_asc = AllConvert.hextoasciiStr(message_hex)

        sig_field_encrypted_num_form = AllConvert.hextonum(sig_field_encrypted)
        sig_num_form = RSA.decryption(sig_field_encrypted_num_form, self.pub_key_sender)
        sig = AllConvert.numtohex(sig_num_form)
        hashed = ""
        if self.hashfunc == 'MD5':
            hashed = MD5.MD5.hash(message_asc)
        elif self.hashfunc == 'SHA':
            hashed = SHA.sha1(message_asc)

        if sig == hashed:
            print("integrity checked: no deletion")
        else:
            print("file changed!")
            return
        return message_asc

    def fileDecrypt(self, inPath, outPath):
        with open(inPath, "rb") as fp:
            if fp:
                file_byte = fp.read()
            else:
                raise Exception("File not exists!")
        self.text = file_byte.hex()
        tmp1 = self.stringDecrypt(self.text)
        tmp2 = AllConvert.asciistrtohex(tmp1)
        file_byte = bytes.fromhex(tmp2)
        with open(outPath, "wb") as fp:
            fp.write(file_byte)

    def bigFileDecryption(self, inPath:str, outPath:str):
        with open(inPath, "rb") as fp1:
            with open(outPath, "wb") as fp2:
                fp1.seek(-self.sym_key_field_length,2)
                encrypted_sym_key = fp1.read()
                self.sym_key = rsa.decrypt(encrypted_sym_key, self.pr_key_receiver)
                fp1.seek(-self.sym_key_field_length-self.sig_field_length,2)
                message_end_pos = fp1.tell()
                encrypted_signature = fp1.read(self.sig_field_length)

                if self.hashfunc == "MD5":
                    hashf = hashlib.md5()
                elif self.hashfunc == "SHA":
                    hashf = hashlib.sha1()

                if self.symmetic_func == "AES":
                    symf = AES_Pro.new(self.sym_key)
                    block_size = 16
                elif self.symmetic_func == "DES":
                    symf = DES_Pro.new(self.sym_key)
                    block_size = 8
                signature = symf.decrypt(encrypted_signature)

                fp1.seek(0)

                if self.issigpad:
                    if symmetic_func == "DES":
                        signature = unpad(signature, 8)
                    elif symmetic_func == "AES":
                        signature = unpad(signature, 16)
                while fp1.tell() < message_end_pos:
                    enc_file_block = fp1.read(block_size)
                    message_block = symf.decrypt(enc_file_block)
                    if fp1.tell() >= message_end_pos and self.ismessagepad:
                        message_block = unpad(message_block, block_size)
                    hashf.update(message_block)
                    fp2.write(message_block)

            with open(outPath, "rb") as fp3:
                try:
                    rsa.verify(fp3, signature, self.pub_key_sender)
                except Exception as e:
                    print(e)
                    print("Error when verify! File changed!")
                else:
                    print("verify succeed")
                    print("All finished")


def switchKey(sender:PGPSender, receiver:PGPRecipient):
    receiver.pub_key_sender = sender.pub_key_sender
    sender.pub_key_recipient = receiver.pub_key_receiver

def configTransmit(sender:PGPSender, receiver:PGPRecipient):
    receiver.sig_field_length = sender.sig_field_length
    receiver.sym_key_field_length = sender.sym_key_field_length
    receiver.ispad = sender.ispad
    receiver.issigpad = sender.issigpad
    receiver.ismessagepad = sender.ismessagepad
    receiver.issympad = sender.issympad

# def chunkFileEncryption(inFilePath:str, outFilePath:str, chunk_size = 6400,): # chunk_size smaller than filesize
#     fi = open(inFilePath, "rb")
#     fo = open(outFilePath, "wb")
#     fileChunk = fi.read(chunk_size)
#     while fileChunk:



if __name__ == '__main__':
    hashfunc, symmetic_func, sym_key_length, crypted_obj, seed, text, sym_mode = \
        ['MD5', 'DES', 64, 'string', 20, 'nmslwq', 1]
    ps = PGPSender(hashfunc, symmetic_func, sym_key_length, crypted_obj, seed, text, sym_mode)
    pr = PGPRecipient(hashfunc, symmetic_func, sym_key_length, crypted_obj, seed, text, sym_mode)
    ps.keyGenerate()
    pr.keyGenerate()
    ps.keyGenerateAndSave(r"E:/ps.pem")
    pr.keyGenerateAndSave(r"E:/pr.pem")
    ps.loadKey(r"E:/pr.pem")
    pr.loadKey(r"E:/ps.pem")
    switchKey(ps, pr)
    ps.bigFileEncryption(r"E:/计算机学习2/深度学习（花书）.pdf", r"E:/计算机学习2/dl.dat")
    configTransmit(ps, pr)
    pr.bigFileDecryption(r"E:/计算机学习2/dl.dat", r"E:/k.pdf")

    # ps.fileEncrypt(r'E:/qdh.jpg', r"E:/a.enc")
    # configTransmit(ps, pr)
    # pr.fileDecrypt(r"E:/a.enc", r'E:/a.jpg')

    # if res2:
    #     print(res2)
    # print("res: ")
    # for i in range(0, len(res), 20):
    #     print(res[i:i+20])

