from zokrates_pycrypto.babyjubjub import Point
import os


G = Point.generator();

rand = bytes(os.urandom(100))

H = G.from_hash(rand)

rand2 = bytes(os.urandom(100))

J = G.from_hash(rand2)

print("G VALUE")
print(G)

print("H VALUE: ")
print(H)

print("J VALUE: ")
print(J)

