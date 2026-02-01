import struct
with open("/Users/searchstars/Downloads/wine/helper_inline.bin","rb") as f:
    i=0
    while True:
        data=f.read(32)
        if len(data)<32: break
        x0,x1,x2,x3=struct.unpack("<QQQQ",data)
        print(i, hex(x0), hex(x1), hex(x2), hex(x3))
        i+=1
