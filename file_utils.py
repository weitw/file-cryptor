# -*- coding=utf-8 -*-
import os
import random


def restore_file(file_path, original_header):
    """
    恢复文件
    :param file_path:
    :param original_header:
    :return:
    """
    with open(file_path, 'r+b') as f:
        f.seek(0)
        f.write(original_header)


def remove_file(file_path):
    """
    删除文件
    :param file_path:
    :return:
    """
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"{file_path} 文件已删除")
        else:
            print(f"文件 {file_path} 不存在, 无需删除")
    except Exception as e:
        print(f"删除 {file_path} 时发生错误: {e}")


def corrupt_file(file_path):
    """
    损坏文件
    :param file_path:
    :return:
    """
    size = random.randint(20, 50)
    bs = bytes([random.randint(0, 255) for _ in range(size)])
    with open(file_path, 'r+b') as f:
        original_header = f.read(size)
        f.seek(0)
        f.write(bs)
    return original_header
