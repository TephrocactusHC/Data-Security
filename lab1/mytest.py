from phe import paillier # 开源库
import random # 选择随机数
# 采取异或加密解密，只是为了简便起见。但是，需要注意的是，异或加密就是一种对称密钥算法。
def xor_encrypt_decrypt(data, key):
    # 将整型转换为字节数组
    data_bytes = data.to_bytes((data.bit_length() + 7) // 8, byteorder='big')
    key_bytes = key.to_bytes((key.bit_length() + 7) // 8, byteorder='big')
    # 将字节数组转换为可变的bytearray类型
    data_bytearray = bytearray(data_bytes)
    key_bytearray = bytearray(key_bytes)
    # 遍历字节数组，对每个字节进行异或操作
    for i in range(len(data_bytearray)):
        data_bytearray[i] ^= key_bytearray[i % len(key_bytearray)]
    # 将加密/解密后的字节数组转换为整型
    return int.from_bytes(data_bytearray, byteorder='big')
# key也是为了简化操作，设置为int型123456
key=123456
##################### 设置参数
# 服务器端保存的数值
message_list = [100,200,300,400,500,600,700,800,900,1000]
# 服务器要保存的加密后数值
server_list=[]
for i in message_list:
    encrypted_data = xor_encrypt_decrypt(i, key)
    server_list.append(encrypted_data)
    # print(encrypted_data)
# 加密后的数组
print("密钥k加密后的数组:", server_list)
length = len(server_list)
# 客户端生成公私钥
public_key, private_key = paillier.generate_paillier_keypair()
# 客户端随机选择一个要读的位置
pos = random.randint(0,length-1)
print("要读起的数值位置为：",pos)

##################### 客户端生成密文选择向量
select_list=[]
enc_list=[]
for i in range(length):
    select_list.append(  i == pos )
    enc_list.append( public_key.encrypt(select_list[i]) )

##################### 服务器端进行运算
c=0
for i in range(length):
    c = c + server_list[i] * enc_list[i]
print("产生密文：",c.ciphertext())

##################### 客户端进行解密
m=private_key.decrypt(c)
print("得到用密钥k加密后的数值:",m)
#然后再进行异或解密
decrypted_data = xor_encrypt_decrypt(m, key)
print("得到原始数值：",decrypted_data)
