import pymysql
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

local_table = {}
key = get_random_bytes(16)
base_iv = get_random_bytes(16)

def AES_ENC(plaintext, iv):
    # AES加密
    aes = AES.new(key, AES.MODE_CBC, iv=iv)
    padded_data = pad(plaintext, AES.block_size, style='pkcs7')
    ciphertext = aes.encrypt(padded_data)
    return ciphertext

def AES_DEC(ciphertext, iv):
    # AES解密
    aes = AES.new(key, AES.MODE_CBC, iv=iv)
    padded_data = aes.decrypt(ciphertext)
    plaintext = unpad(padded_data, AES.block_size, style='pkcs7')
    return plaintext

def Random_Encrypt(plaintext):
    # 随机生成iv来保证加密结果的随机性
    iv = get_random_bytes(16)
    ciphertext = AES_ENC(iv + AES_ENC(plaintext.encode('utf-8'), iv), base_iv)
    ciphertext = base64.b64encode(ciphertext)
    return ciphertext.decode('utf-8')

def Random_Decrypt(ciphertext):
    plaintext = AES_DEC(base64.b64decode(ciphertext.encode('utf-8')) ,base_iv)
    plaintext = AES_DEC(plaintext[16:],plaintext[:16])
    return plaintext.decode('utf-8')

def CalPos(plaintext):
    # 插入plaintext，返回对应的Pos
    presum = sum([v for k, v in local_table.items() if k < plaintext])
    print("本地表之中小于要插入明文的所有明文出现次数总和：",presum)
    if plaintext in local_table:
        local_table[plaintext] += 1
        the_pos=random.randint(presum, presum + local_table[plaintext] - 1)
        print("要插入的明文已经存在,选择范围:[",presum,",",presum + local_table[plaintext] - 1,"]",end=' ')
        print("随机选择的位置:",the_pos)
        return the_pos
    else:
        local_table[plaintext] = 1
        print('要插入的明文之前不存在，直接选择位置:',presum)
        return presum

def GetLeftPos(plaintext):
    return sum([v for k, v in local_table.items() if k < plaintext])

def GetRightPos(plaintext):
    return sum([v for k, v in local_table.items() if k <= plaintext])

def Insert(plaintext):
    ciphertext = Random_Encrypt(plaintext)
    # 连接数据库
    conn = pymysql.connect(host='localhost', user='user',
                           passwd='123456', database='test_db')
    cur = conn.cursor()
    the_result = CalPos(plaintext)
    print("插入的明文:",plaintext,'位置:',the_result)
    cur.execute(f"call pro_insert({the_result},'{ciphertext}')")
    conn.commit()
    print("------------此时编码树的结果-------------")
    #cur.execute(
    #    f"select ciphertext from example order by encoding")    
    #results = cur.fetchall()
    cur.execute(
        f"select encoding from example order by encoding")    
    results1 = cur.fetchall()
    for result in results1:
        print(result[0],end=" ")
    #for result in results:
    #for i in range(len(results)):
    #    print(Random_Decrypt(results[i][0]),":",results1[i][0],end=" ")
    #for result in results:
    #    print(Random_Decrypt(result[0]),end=" ")
    print("\n")
    conn.close()


def Search(left, right):
    # 搜索[left,right]中的信息
    left_pos = GetLeftPos(left)
    right_pos = GetRightPos(right)
    # 连接数据库
    conn = pymysql.connect(host='localhost', user='user',
                           passwd='123456', database='test_db')
    cur = conn.cursor()
    cur.execute(
        f"select ciphertext from example where encoding >= FHSearch({left_pos}) and encoding < FHSearch({right_pos})")
    rest = cur.fetchall()
    for x in rest:
        print(f"ciphtertext: {x[0]} plaintext: {Random_Decrypt(x[0])}")

if __name__ == '__main__':
    # 插入明文，同时设置了一部分重复的内容
    print("----------------------------------------")
    print("-----------下面展示实验过程-------------")
    print("----------------------------------------")
    # 加入了一大堆 apple 和 cherry,希望观察结果和树的变化
    for ciphertext in ['apple', 'pear', 'banana', 'orange', 'cherry', 'apple', 'cherry', 'orange', 'apple', 'apple', 'apple', 'apple', 'cherry', 'cherry', 'apple', 'cherry']:
        Insert(ciphertext)

    # 假设我们搜索b和p之间的数据
    print("----------------------------------------")
    print("-----假设我们搜索 b 和 p 之间的数据-----")
    print("----------------------------------------")
    Search('b', 'p')
    
    print("----------------------------------------")
    print("----------下面展示本地表内容------------")
    print("----------------------------------------")
    print("local_table:",local_table)
    total=sum([v for k, v in local_table.items()])
    print("本地表共:",total,"数据项")
    # 连接数据库
    conn = pymysql.connect(host='localhost', user='user',
                           passwd='123456', database='test_db')
    cur = conn.cursor()
    cur.execute("select count(distinct encoding) from example" )
    results = cur.fetchall() 
    for result in results:
        print("现在数据库之中共有:",result[0],"个数据项")
        if result[0]==total:
            print("数据数量一致，实验成功！")

