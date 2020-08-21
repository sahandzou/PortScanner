import struct

pcapHeader='d4 c3 b2 a1 02 00 04 00  00 00 00 00 00 00 00 00\
ff ff 00 00 01 00 00 00'
data="d4 c3 b2 a1 02 00 04 00  00 00 00 00 00 00 00 00\
ff ff 00 00 01 00 00 00  c2 ba cd 4f b6 35 0f 00\
36 00 00 00 36 00 00 00  00 12 cf e5 54 a0 00 1f\
3c 23 db d3 08 00 45 00  00 28 4a a6 40 00 40 06\
58 eb c0 a8 0a e2 c0 a8  0b 0c 4c fb 00 17 e7 ca\
f8 58 26 13 45 de 50 11  40 c7 3e a6 00 00 c3 ba\
cd 4f 60 04 00 00 3c 00  00 00 3c 00 00 00 00 1f\
3c 23 db d3 00 12 cf e5  54 a0 08 00 45 00 00 28\
8a f7 00 00 40 06 58 9a  c0 a8 0b 0c c0 a8 0a e2\
00 17 4c fb 26 13 45 de  e7 ca f8 59 50 10 01 df\
7d 8e 00 00 00 00 00 00  00 00 c3 ba cd 4f 70 2f\
00 00 3c 00 00 00 3c 00  00 00 00 1f 3c 23 db d3\
00 12 cf e5 54 a0 08 00  45 00 00 28 26 f9 00 00\
40 06 bc 98 c0 a8 0b 0c  c0 a8 0a e2 00 17 4c fb\
26 13 45 de e7 ca f8 59  50 11 01 df 7d 8d 00 00\
00 00 00 00 00 00 c3 ba  cd 4f db 2f 00 00 36 00\
00 00 36 00 00 00 00 12  cf e5 54 a0 00 1f 3c 23\
db d3 08 00 45 00 00 28  4a a7 40 00 40 06 58 ea\
c0 a8 0a e2 c0 a8 0b 0c  4c fb 00 17 e7 ca f8 59\
26 13 45 df 50 10 40 c7  3e a5 00 00"

data=data.replace(" ","")
data=bytearray.fromhex(data)
with open("test.pcap","wb") as f:
    f.write(data)
