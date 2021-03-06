from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import pickle


class CA:
    def __init__(self):
        self.CA_priv = RSA.generate(2048)
        self.CA_pub = self.CA_priv

    def CA_Key_Write(self):
        f = open('CAPriv.pem', 'wb')
        f.write(self.CA_priv.export_key('PEM', passphrase="!@#$"))
        f.close()
        self.CA_pub = self.CA_priv.publickey()
        f = open('CAPub.pem', 'wb')
        f.write(self.CA_pub.export_key('PEM'))
        f.close()
        print("CA generates keys\n", self.CA_pub, self.CA_priv)

    def genCertificate(self, myPubKey, CAPrivKey):
        h = SHA256.new(myPubKey.export_key('PEM'))
        S = pkcs1_15.new(CAPrivKey).sign(h)
        return list([myPubKey.export_key('PEM'), S])

    def veriCertificate(self, aCertificate, CACertificate=None):
        if CACertificate is None:
            with open('CACertCA.plk', 'rb') as f:
                CACertificate = pickle.load(f)

        h = SHA256.new(aCertificate[0])
        try:
            pkcs1_15.new(RSA.import_key(CACertificate[0])).verify(h, aCertificate[1])
            return True
        except (ValueError, TypeError):
            return False


class Bob:
    def __init__(self):
        self.Bob_priv = RSA.generate(2048)
        self.Bob_pub = self.Bob_priv

    def Bob_Key_Write(self):
        f = open('BobPriv.pem', 'wb')
        f.write(self.Bob_priv.export_key('PEM', passphrase="!@#$"))
        f.close()
        self.Bob_pub = self.Bob_priv.publickey()
        f = open('BobPub.pem', 'wb')
        f.write(self.Bob_pub.export_key('PEM'))
        f.close()
        print("Bob generates keys\n", self.Bob_pub, self.Bob_priv)

    def Bob_Send_Message(self):
        message = 'I bought 100 doge coins.'
        h = SHA256.new(message.encode('utf-8'))
        signature = pkcs1_15.new(self.Bob_priv).sign(h)
        with open('BobCertCA.plk', 'rb') as f:
            certificate = pickle.load(f)
        print("Bob sent (S:", signature, "\nM:", message, "\nCertificate:", certificate, "\n) to Alice\n")
        return signature, message, certificate


class Alice:
    def __init__(self, S, M, C):
        self.message = M
        self.signature = S
        self.certificateBob = C

    def readCertificate(self):
        with open('CACertCA.plk', 'rb') as f:
            data = pickle.load(f)
        return data

    def veriMessage(self):
        h = SHA256.new(self.message.encode('utf-8'))
        try:
            pkcs1_15.new(RSA.import_key(self.certificateBob[0])).verify(h, self.signature)
            print("Message verification success!")
        except (ValueError, TypeError):
            print("Message verification failed...")
            exit(1)


ca = CA()
ca.CA_Key_Write()  # a,b: CA??? RSA ?????????, ???????????? ????????? .pem ????????? ??????
with open('CACertCA.plk', 'wb') as f:  # c: CA ????????? ??????
    pickle.dump(ca.genCertificate(ca.CA_pub, ca.CA_priv), f)
print("CA generates CA's root certificate\n")

bob = Bob()
bob.Bob_Key_Write()  # d,e: Bob??? RSA ?????????, ???????????? ????????? .pem ????????? ??????
with open('BobCertCA.plk', 'wb') as f:  # f: CA??? ???????????? ????????? Bob??? ????????? ????????? ??????
    pickle.dump(ca.genCertificate(bob.Bob_pub, ca.CA_priv), f)
print("CA generates Bob's certificate\n")

S, M, certificateBob = bob.Bob_Send_Message()  # g: Bob??? ??????, ?????????, ????????? ???????????? Alice?????? ??????
alice = Alice(S, M, certificateBob)  # h: Alice??? Bob??? ???????????? ??????
certificateCA = alice.readCertificate()  # i: Alice??? CA??? root ???????????? ??????
if ca.veriCertificate(certificateCA):  # j: CA??? root ???????????? CA??? root ???????????? ??????
    print("CA root certificate and CA root certificate verification success!")
else:
    print("CA root certificate and CA root certificate verification failed...")
    exit(1)
if ca.veriCertificate(certificateBob, certificateCA):  # k: Bob??? ???????????? CA??? root ???????????? ??????
    print("CA root certificate and Bob root certificate verification success!")
else:
    print("CA root certificate and Bob root certificate verification failed...")
    exit(1)

alice.veriMessage()  # l: ???????????? Bob??? ???????????? ?????? ???????????? ??????
print("Good job. Well done!")  # m: ?????? ????????? ?????? ??? ??????
