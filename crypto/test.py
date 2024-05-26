a="30 82 02 0a 02 82 02 01 00 f0 02 8a c7 16 c3 85 88 23 af c1 c2 d5 ad 21 81 67 31 97 fe 02 45 9e 72 51 ea 72 63 a5 b4 74 e6 74 e4 fc 08 fa c6 d0 d0 cf 27 74 f4 73 5c b1 65 57 ae b6 9f 2f 07 4e 3c e3 3a 7c f0 fc 5e bb 1d 33 42 eb 53 ae d6 a4 00 9a e5 5b 7e 4f 87 4e 02 4d 1a 75 ee b1 85 09 41 68 5d 77 7d 0b 55 8e 06 9b 7d 85 13 10 3c d9 1f 1f 5a 91 9b ec 08 47 3e c2 1e 31 04 73 11 d8 83 38 88 35 6d 0b 07 1a 89 dd cf b7 81 6b 5c 6e b5 5f bf ae d0 3c b9 d3 a8 ec c7 0f 09 30 8b 0a d4 cc 2c f1 be 1e 36 97 59 b3 b5 97 ad dc 02 6a 24 37 89 e4 fe 6d 31 b3 0f c2 e1 35 8c 57 dd b3 f8 ce c8 c3 cc 23 90 e7 92 90 87 27 44 98 bb 41 72 c1 c7 15 ce 24 45 a1 4f 36 5e f6 99 73 04 32 7f aa 97 51 c8 00 85 51 bb e6 cd 59 52 be 40 7c cd 22 d7 53 d5 e5 ad 97 2d b6 40 6a 2a bd a5 7b 51 7f f6 f9 62 ee 8c 1c f5 36 5f 20 77 c2 22 98 18 96 04 6c 8a 2f 96 6e 18 c2 94 0e 1a 7d 8c ae bb 78 73 b0 7a a5 c9 b2 84 c7 1b 24 09 38 0f 6b d5 db e9 64 e2 72 a7 05 60 90 c3 72 5b 3e 4b 87 6e 51 76 cd 11 94 91 ec a7 2c b5 e4 a7 11 aa 8c 82 b6 43 8b 8c 97 e7 af f4 45 35 f7 1f fa e4 48 2d bc 10 04 5b b6 36 1c 7d c0 5b e3 f4 91 6e 6f 85 a1 ab d2 f6 0a 38 3a bf 86 da 0f 76 9a 81 5f 56 21 6e 5e 63 9f 67 69 89 d0 34 13 87 8b d3 c0 24 31 c1 ff db 0f 33 c2 ed 69 72 cc b3 76 c7 f3 50 c8 14 a3 31 5b 8b 7c 36 3a 10 96 3d e5 a3 ad f9 77 9c d1 32 a1 39 d3 cb 60 77 d3 55 c0 46 88 76 78 e8 5b f8 7e 44 91 a2 c2 08 4a de 45 e7 38 db 92 30 b7 34 90 b6 02 0f 26 4d c4 63 52 18 6b 07 59 4e 05 8d a4 ca 64 30 7f 0f 1a 62 4d 0f 02 6b 26 74 09 f0 49 59 d0 9c cb 97 9f a3 6e 02 f2 09 78 8d 14 4b 70 b8 d1 3d 02 03 01 00 01"

a = a.split()
print(len(a))

line = 0

for i in range(len(a)):
    if line >= 20:
        line=0
        print()
    line += 1
    print(f'0x{a[i]}, ', end='')
    