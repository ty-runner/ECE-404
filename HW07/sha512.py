from BitVector import *
import sys

# hash the ASCII in input.txt and write the resulting message digest to hashed.txt
# write to hashed.txt as hexstring format

def sha512(input_file, output_file):
    h0 = BitVector(hexstring='6a09e667f3bcc908')
    h1 = BitVector(hexstring='bb67ae8584caa73b')
    h2 = BitVector(hexstring='3c6ef372fe94f82b')
    h3 = BitVector(hexstring='a54ff53a5f1d36f1')
    h4 = BitVector(hexstring='510e527fade682d1')
    h5 = BitVector(hexstring='9b05688c2b3e6c1f')
    h6 = BitVector(hexstring='1f83d9abfb41bd6b')
    h7 = BitVector(hexstring='5be0cd19137e2179')

    K = [BitVector(hexstring=k) for k in ['428a2f98d728ae22', '7137449123ef65cd', 'b5c0fbcfec4d3b2f', 'e9b5dba58189dbbc', '3956c25bf348b538', '59f111f1b605d019', '923f82a4af194f9b', 'ab1c5ed5da6d8118', 'd807aa98a3030242', '12835b0145706fbe', '243185be4ee4b28c', '550c7dc3d5ffb4e2', '72be5d74f27b896f', '80deb1fe3b1696b1', '9bdc06a725c71235', 'c19bf174cf692694', 'e49b69c19ef14ad2', 'efbe4786384f25e3', '0fc19dc68b8cd5b5', '240ca1cc77ac9c65', '2de92c6f592b0275', '4a7484aa6ea6e483', '5cb0a9dcbd41fbd4', '76f988da831153b5', '983e5152ee66dfab', 'a831c66d2db43210', 'b00327c898fb213f', 'bf597fc7beef0ee4', 'c6e00bf33da88fc2', 'd5a79147930aa725', '06ca6351e003826f', '142929670a0e6e70', '27b70a8546d22ffc', '2e1b21385c26c926', '4d2c6dfc5ac42aed', '53380d139d95b3df', '650a73548baf63de', '766a0abb3c77b2a8', '81c2c92e47edaee6', '92722c851482353b', 'a2bfe8a14cf10364', 'a81a664bbc423001', 'c24b8b70d0f89791', 'c76c51a30654be30', 'd192e819d6ef5218', 'd69906245565a910', 'f40e35855771202a', '106aa07032bbd1b8', '19a4c116b8d2d0c8', '1e376c085141ab53', '2748774cdf8eeb99', '34b0bcb5e19b48a8', '391c0cb3c5c95a63', '4ed8aa4ae3418acb', '5b9cca4f7763e373', '682e6ff3d6b2b8a3', '748f82ee5defb2fc', '78a5636f43172f60', '84c87814a1f0ab72', '8cc702081a6439ec', '90befffa23631e28', 'a4506cebde82bde9', 'bef9a3f7b2c67915', 'c67178f2e372532b', 'ca273eceea26619c', 'd186b8c721c0c207', 'eada7dd6cde0eb1e', 'f57d4f7fee6ed178', '06f067aa72176fba', '0a637dc5a2c898a6', '113f9804bef90dae', '1b710b35131c471b', '28db77f523047d84', '32caab7b40c72493', '3c9ebe0a15c9bebc', '431d67c49c100d4c', '4cc5d4becb3e42b6', '597f299cfc657e2a', '5fcb6fab3ad6faec', '6c44198c4a475817']]
    print(len(K))
    #K_bv = [BitVector(hexstring = k) for k in K]

    #open input file
    input = input_file.read()
    bv = BitVector(textstring=input)
    bv1 = bv + BitVector(bitstring="1")
    how_many_zeros = (896 - bv1.length()) % 1024
    zero_pad = [0] * how_many_zeros
    bv2 = bv1 + BitVector(bitlist=zero_pad)
    bv3 = BitVector(intVal = bv.length(), size = 128)
    bv4 = bv2 + bv3

    # init the 80 words
    words = [None] * 80
    for n in range(0, bv4.length(), 1024):
        block = bv4[n:n+1024]
        words[0:16] = [block[i:i+64] for i in range(0, 1024, 64)]
        for i in range(16, 80):
            i_minus_2_word = words[i-2]
            i_minus_15_word = words[i-15]
            s0 = i_minus_15_word.deep_copy() >> 1 ^ i_minus_15_word.deep_copy() >> 8 ^ i_minus_15_word.deep_copy().shift_right(7)
            s1 = i_minus_2_word.deep_copy() >> 19 ^ i_minus_2_word.deep_copy() >> 61 ^ i_minus_2_word.deep_copy().shift_right(6)
            words[i] = BitVector(intVal=(int(words[i-16]) + int(s0) + int(words[i-7]) + int(s1)) & 0xFFFFFFFFFFFFFFFF, size=64)

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        for i in range(80):
            s1 = e.deep_copy() >> 14 ^ e.deep_copy() >> 18 ^ e.deep_copy() >> 41
            ch = (e & f) ^ (~e & g)
            temp1 = BitVector(intVal=(int(h) + int(s1) + int(ch) + int(K[i]) + int(words[i])) & 0xFFFFFFFFFFFFFFFF, size=64)
            s0 = a.deep_copy() >> 28 ^ a.deep_copy() >> 34 ^ a.deep_copy() >> 39
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = BitVector(intVal=(int(s0) + int(maj)) & 0xFFFFFFFFFFFFFFFF, size=64)

            h = g
            g = f
            f = e
            e = BitVector(intVal=(int(d) + int(temp1)) & 0xFFFFFFFFFFFFFFFF, size=64)
            d = c
            c = b
            b = a
            a = BitVector(intVal=(int(temp1) + int(temp2)) & 0xFFFFFFFFFFFFFFFF, size=64)
        
        h0 = BitVector(intVal=(int(h0) + int(a)) & 0xFFFFFFFFFFFFFFFF, size=64)
        h1 = BitVector(intVal=(int(h1) + int(b)) & 0xFFFFFFFFFFFFFFFF, size=64)
        h2 = BitVector(intVal=(int(h2) + int(c)) & 0xFFFFFFFFFFFFFFFF, size=64)
        h3 = BitVector(intVal=(int(h3) + int(d)) & 0xFFFFFFFFFFFFFFFF, size=64)
        h4 = BitVector(intVal=(int(h4) + int(e)) & 0xFFFFFFFFFFFFFFFF, size=64)
        h5 = BitVector(intVal=(int(h5) + int(f)) & 0xFFFFFFFFFFFFFFFF, size=64)
        h6 = BitVector(intVal=(int(h6) + int(g)) & 0xFFFFFFFFFFFFFFFF, size=64)
        h7 = BitVector(intVal=(int(h7) + int(h)) & 0xFFFFFFFFFFFFFFFF, size=64)

        message_digest = h0 + h1 + h2 + h3 + h4 + h5 + h6 + h7
        output_file.write(message_digest.getHexStringFromBitVector())
        print("Hashing complete")



#usability: python sha512.py input.txt hashed.txt
if __name__ == "__main__":
    sha512(open(sys.argv[1], 'r'), open(sys.argv[2], 'w'))
    #sha512(open('input.txt', 'r'), open('hashed.txt', 'w'))

# Current Hash: 300e02a3d38df475537ae78c8ee8bef900f6762775149b40e4ded7bc7b8b6ec05c01e7615d5853c4fc27d048d7ac4c9b721dd1e1de8f4070b5c8f2b668e7f677593d3e1faf23ab7b3c2e75a6f3195b6ca33e2ae80fc5c0a46e371e00e244176ee36eaa3b1a27ded30927ed30dcf8f320644abb947dc1d8c0871a2e15dc2cb1ba71f781a8e1fd8003dadbb9420d03023f9d68ef75bf70c84785625ce33d33be9e419561358a040c40215e847f5bf7342f4aa2f85c08238da4ef719fa9964c1ba92349f13ef6713a3af3992a700274884c40972ca7b387c0913f33a8c9f6840c950e49f81134c3dd6fede37ddc256223cad215374a7a25d766888c2e022fc29d9f86200d1d5de4867017f3e207bdfa76a13d12abf9bbca3763342dc8f842d6aa0c7c02fe929a55a474003b5ee493f43fe8091679725129ba70c7bbaf0c5ed85d4b84f353348a552229554fba7ba822005edcb6bca2fac8cf1735d53ae9e2915aa2e625f6d3cfa0106c8707ff0004d3ce95281b47b851b380ef91c86d2fb0e58b28
# Correct Hash: 84f353348a552229554fba7ba822005edcb6bca2fac8cf1735d53ae9e2915aa2e625f6d3cfa0106c8707ff0004d3ce95281b47b851b380ef91c86d2fb0e58b28