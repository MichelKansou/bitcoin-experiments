from ecc import FieldElement, Point, S256Point, G, N, PrivateKey
from Crypto.Hash import SHA256
from random import randint
from helper import encode_base58

a = FieldElement(3, 31)
b = FieldElement(24, 31)

print(a / b == FieldElement(4, 31))

p1 = Point(-1, -1, 5, 7)
# points not on the curve
#p2 = Point(-1, -2, 5, 7)
#p3 = Point(2, 4, 5, 7)
#p4 = Point(5, 7, 5, 7)
p5 = Point(18, 77, 5, 7)

point_a = Point(3, -7, 5, 7)
point_b = Point(18, 77, 5, 7)
print(point_a != point_b)
print(point_a != point_a)

# Exercise 2
p_1 = Point(-1, -1, 5, 7)
p_2 = Point(-1, 1, 5, 7)
inf = Point(None, None, 5, 7)
print(p_1 + inf)
print(inf + p_2)
print(p_1 + p_2)


# Exercise 4
a = 5
b = 7
x1, y1 = 2, 5
x2, y2 = -1, -1

point_a = Point(x1, y1, a, b)
point_b = Point(x2, y2, a, b)
print(point_a + point_b)

# Exercise 6
a = 5
b = 7
x1, y1 = -1, 1
point_a = Point(x1, y1, a, b)
point_b = Point(x1, y1, a, b)
print(point_a + point_b)
# (-1,1) + (-1,1)


# Scalar Multiplication Test
prime = 223
a = FieldElement(0, prime)
b = FieldElement(7, prime)
x = FieldElement(15, prime)
y = FieldElement(86, prime)
p = Point(x, y, a, b)
print(7*p)


# Check order of G 
print(N*G) #Point at infinity

# Verifying Signature
z = 0xbc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423
r = 0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6
s = 0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec
px = 0x04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574
py = 0x82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4
point = S256Point(px, py)
s_inv = pow(s, N-2, N)
u = z * s_inv % N
v = r * s_inv % N
R = u*G + v*point
print(R.x.num)
print(R.x.num == r) # check if the x coordinate is r



# Signing Message and Verify Signature
e = 12345
message = SHA256.new(b'Programming Bitcoin!').digest()
z = int.from_bytes(message, 'big')
p_key = PrivateKey(e)

signature = p_key.sign(z)
print(signature)

s_inv = pow(signature.s, N-2, N)
u = z * s_inv % N
v = signature.r * s_inv % N
R = u*G + v*p_key.point
print(R.x.num)
print(R.x.num == signature.r) # check if the x coordinate is r


# Convert Binary to Base58
address = bytes.fromhex('7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d')
print('BASE 58 ADDRESS')
print(encode_base58(address))


# get Public Key address from secret (private key)
secret = 0x12345deadbeef
public_key = PrivateKey(secret).point.address()
print('Public Key of 0x12345deadbeef')
print(public_key)

# get WIF Format from a secret (private key)
secret = 0x12345deadbeef
wif_of_secret = PrivateKey(secret).wif()
print('WIF Format of 0x12345deadbeef')
print(wif_of_secret)