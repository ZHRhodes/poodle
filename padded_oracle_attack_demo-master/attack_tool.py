#!/usr/bin/python2.7
import urllib2
import sys

TARGET = 'http://localhost:8081/enc='
def strxor(a,b):
    if len(a) > len(b):
        return "".join([chr(ord(x)^ord(y)) for (x,y) in zip(a[:len(b)],b)])
    else:
        return "".join([chr(ord(x)^ord(y)) for (x,y) in zip(b,a[:len(a)])])

class PaddingOracle(object):
    def query(self, q):
        target = TARGET + urllib2.quote(q)    # Create query URL
        req = urllib2.Request(target)         # Send HTTP request to server
        try:
            f = urllib2.urlopen(req)          # Wait for response
        except urllib2.HTTPError, e:          
            if e.code == 404:
                return True 
            return False 

    def decrypt_block(self, IV_block, CT_block):
        # IV_block <- C_n-1 
        # CT_block <- C_n 
        
        zero_block = ("ff"*16).decode("hex")
        padding = 1
        PT_block_list = []
        for pos in range(0,16):
            for gues in range(0,256):
                if len("".join(PT_block_list)) > 0:
                    evil_block = "".join(PT_block_list[::-1]) # string of PT bytes found
                    evil_padding = strxor(strxor(chr(padding)*len(evil_block),evil_block),IV_block[len(IV_block)-len(evil_block):])
                else:
                    evil_padding = ''
                print "%s - %s" % ("ff"*(16-len("".join(PT_block_list[::-1]).encode("hex"))) + "".join(PT_block_list[::-1]).encode("hex"),(zero_block[0:16-padding] + chr(gues) + evil_padding + CT_block).encode("hex"))

                if self.query((zero_block[0:16-padding] + chr(gues) + evil_padding + CT_block).encode("hex")) == True:
                    print "found PT-byte <- %s " % strxor(strxor(chr(padding), chr(gues)),IV_block[16-padding]).encode("hex")

                    PT_block_list.append(strxor(strxor(chr(padding), chr(gues)),IV_block[16-padding]))
                    padding += 1
                    break
        return PT_block_list
            
        
if __name__ == "__main__":
    CT = sys.argv[1].decode("hex")
    po = PaddingOracle()
    dec_list = []

    for (c,bound) in enumerate(range(16,len(CT),16)[::-1]):
        I_state = po.decrypt_block(CT[bound-16:bound],CT[bound:bound+16])
        print I_state[::-1]
        print "".join(I_state).encode("hex")
        dec_list.append(I_state[::-1])
        
    print ["".join(x) for x in dec_list]
