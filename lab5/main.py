# -*- coding: utf-8 -*-

"""
给定的代码实现了一个基本的加密和检索系统，使用陷门来处理文档。

generate_random_string函数生成给定长度的小写字母随机字符串。generate_hash函数为给定关键词生成SHA-256哈希值。generate_trapdoor函数通过获取关键词中每个字符的哈希值的第一个字符来为给定关键词生成陷门。encrypt_document函数通过将文档中每个字符添加上陷门值来加密给定文档。retrieve_documents函数从正向索引中检索包含给定关键词的文档。decrypt_document函数通过从文档中每个字符减去陷门值来解密给定文档。

主要功能是生成随机文件、为文件中每个关键字生成陷门、使用这些陷门加密文件、构建正向索引、检索包含指定关键字的文件、解密已检索到的文件，并打印原始文件和解密后的文件。

该代码使用hashlib，random和string库。
"""

import hashlib
import random
import string


# 一个用来生成随机定长字符串的函数
def generate_random_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

# 将已有的keyword生成对应的hash值
def generate_hash(keyword):
    hash_object = hashlib.sha256(keyword.encode())
    return hash_object.hexdigest()

# 为已有的keyword生成对应的陷门trapdoor
def generate_trapdoor(keyword):
    trapdoor = []
    for i in range(len(keyword)):
        trapdoor.append(generate_hash(keyword[i])[0])
    return trapdoor

# 加密文档，这个没什么可说的
def encrypt_document(document, trapdoors):
    encrypted_document = []
    for i in range(len(document)):
        encrypted_word = []
        for j in range(len(document[i])):
            encrypted_char = chr(ord(document[i][j]) + ord(trapdoors[i][j % len(trapdoors[i])]))
            encrypted_word.append(encrypted_char)
        encrypted_document.append(''.join(encrypted_word))
    return encrypted_document

# 通过已有的keyword查询正向索引，返回包含该keyword的文档
def retrieve_documents(keyword, index):
    documents = []
    for char in keyword:
        if char in index:
            documents.append(set(index[char]))
    if len(documents) == 0:
        return []
    else:
        return list(set.intersection(*documents))

# 解密文件
def decrypt_document(document, trapdoors):
    decrypted_document = []
    for i in range(len(document)):
        decrypted_word = []
        for j in range(len(document[i])):
            decrypted_char = chr(ord(document[i][j]) - ord(trapdoors[i][j % len(trapdoors[i])]))
            decrypted_word.append(decrypted_char)
        decrypted_document.append(''.join(decrypted_word))
    return decrypted_document

# 主函数，包含了测试样例和接口调用
if __name__ == "__main__":
    # 步骤一，生成随机文档，这里为了省事都是定长的
    document = []
    for i in range(10):
        document.append(generate_random_string(5))

    # 步骤二，为文档之中每个keyword生成对应的陷门tarapdoor
    trapdoors = []
    for i in range(len(document)):
        trapdoors.append(generate_trapdoor(document[i]))

    # 步骤三，使用陷门加密文档
    encrypted_document = encrypt_document(document, trapdoors)

    # 步骤四，构建正向索引
    index = {}
    for i in range(len(encrypted_document)):
        for j in range(len(encrypted_document[i])):
            keyword = encrypted_document[i][j]
            if keyword not in index:
                index[keyword] = []
            index[keyword].append(i)

    # 步骤五，检索包含指定keyword的文档
    query = encrypted_document[0][0]
    retrieved_documents = retrieve_documents(query, index)
    # 步骤六，解密已检索到的文档
    decrypted_documents = []
    for i in range(len(retrieved_documents)):
        decrypted_documents.append(decrypt_document([encrypted_document[retrieved_documents[i]]], [trapdoors[retrieved_documents[i]]])[0])

    # 步骤七，打印原始文档和解密后的文档
    print("原始文档:")
    print(document)
    print("我们要查询包含 %s 的文档" % decrypt_document(query, trapdoors[0][0])[0])
    print("查询到的解密后的文档:")
    print(decrypted_documents)


