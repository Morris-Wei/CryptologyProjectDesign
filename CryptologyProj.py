import AES
import DES
import MD5
import SHA
import RSA
import AllConvert
import random

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
        self.pr_key_sender = [] # 发送方私钥
        self.pub_key_sender = [] # 发送方公钥
        self.pub_key_recipient = [] # 接收方公钥
        self.sym_key = ""
        self.sig_field_length = 0 # 签名长度
        self.sym_key_field_length = 0 # 对称密钥域长度
        self.ispad = False
        
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
            stringChunkSize = 128 // 4
            for i in range(0, len(plaintextWithSig), stringChunkSize):
                chunked = plaintextWithSig[i:i+stringChunkSize] if i+stringChunkSize < len(plaintextWithSig) else \
                    plaintextWithSig[i:]
                aes = AES.AES(master_key = self.sym_key, key_length = self.key_length // 8)
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


class PGPRecipient(PGPConfig):
    def __init__(self, hashfunc, symmetic_func, sym_key_length, crypted_obj, seed, text="", sym_mode=1):
        super().__init__(hashfunc, symmetic_func, sym_key_length, crypted_obj, seed, sym_mode)
        if len(text) == 0:
            raise Exception("Empty text Error, Enter text")
        self.text = text
        self.pr_key_receiver = []  # 发送方私钥
        self.pub_key_receiver = []  # 发送方公钥
        self.pub_key_sender = []  # 接收方公钥
        self.sym_key = ""
        self.sig_field_length = 0 # 签名长度
        self.sym_key_field_length = 0 # 对称密钥域长度
        self.ispad = False

    def keyGenerate(self):
        RSAkey = RSA.get_RSAKey()
        Pub_key = RSAkey['puk']  # Pub = [n, e]
        Pr_key = RSAkey['prk']  # Pr = [n, d]
        self.pub_key_receiver = Pub_key
        self.pr_key_receiver = Pr_key

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

        if self.symmetic_func == 'DES':
            chunk_size =  64 // 4
            des = DES.des()
            for i in range(0, len(crypted_text), chunk_size):
                if i + chunk_size < len(crypted_text):
                    sym_decrypted += des.decrypt(self.sym_key, crypted_text[i:i+chunk_size])
                elif self.ispad:
                    sym_decrypted += des.decrypt(self.sym_key, crypted_text[i:], padding=True)

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


def switchKey(sender:PGPSender, receiver:PGPRecipient):
    receiver.pub_key_sender = sender.pub_key_sender
    sender.pub_key_recipient = receiver.pub_key_receiver

def configTransmit(sender:PGPSender, receiver:PGPRecipient):
    receiver.sig_field_length = sender.sig_field_length
    receiver.sym_key_field_length = sender.sym_key_field_length
    receiver.ispad = sender.ispad

if __name__ == '__main__':
    hashfunc, symmetic_func, sym_key_length, crypted_obj, seed, text, sym_mode = \
        ['MD5', 'AES', 128, 'string', 20, 'nmslwq', 1]
    ps = PGPSender(hashfunc, symmetic_func, sym_key_length, crypted_obj, seed, text, sym_mode)
    pr = PGPRecipient(hashfunc, symmetic_func, sym_key_length, crypted_obj, seed, text, sym_mode)
    ps.keyGenerate()
    pr.keyGenerate()
    switchKey(ps, pr)
    res = ps.stringCrypt()
    configTransmit(ps, pr)
    res2 = pr.stringDecrypt(res)
    if res2:
        print(res2)
    # for i in range(0, len(res), 20):
    #     print(res[i:i+20])