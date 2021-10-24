import unittest
from CryptologyProj import AES

class AES_TEST(unittest.TestCase):
    def setUp(self):
        master_key = 0x2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a62b7e151628aed2a6
        self.AES = AES(master_key, key_length=32)

    def test_encryption(self):
        plaintext = 0x3243f6a8885a308d313198a2e0370734
        encrypted = self.AES.encrypt(plaintext)

        self.assertEqual(encrypted, 0xdbaeefbd59bff9c3cd7bcf3e9725fce6)

    def test_decryption(self):
        ciphertext = 0xdbaeefbd59bff9c3cd7bcf3e9725fce6
        decrypted = self.AES.decrypt(ciphertext)

        self.assertEqual(decrypted, 0x3243f6a8885a308d313198a2e0370734)

if __name__ == '__main__':
    unittest.main()