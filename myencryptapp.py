import json
import os
import uuid
import concurrent.futures

from aes_cipher import AESCipher
import file_utils


def generate_uuid():
    """
    生成uuid
    :return:
    """
    return str(uuid.uuid4())


def decrypt_file_task(uuid_name, file_info, key_data):
    try:
        old_file_path = file_info["old_file_path"]
        new_file_path = file_info["new_file_path"]
        original_header = bytes(file_info["original_header"])
        if not os.path.exists(new_file_path):
            print(f"文件{new_file_path}不存在，无需解密")
            return
        file_utils.restore_file(new_file_path, original_header)
        os.rename(new_file_path, old_file_path)
        del key_data[uuid_name]
        print(f"解密文件 {uuid_name} 成功")
    except Exception as e:
        print(f"解密文件 {uuid_name} 失败: {e}")


def check_is_re_encrypt(file_path, key_data):
    """
    判断是否重复操作。不允许重复加密
    :return: true表示已经加密过了
    """
    uuid_name = os.path.basename(file_path)
    if key_data and key_data.get(uuid_name):
        return True
    return False


def encrypt_file_task(file_path, key_data):
    if check_is_re_encrypt(file_path, key_data):
        print(f"文件{file_path}已经加密过，无需重复加密")
        return
    uuid_name = generate_uuid()
    new_file_path = os.path.join(os.path.dirname(file_path), uuid_name)
    os.rename(file_path, new_file_path)
    original_header = file_utils.corrupt_file(file_path)
    key_data[uuid_name] = {
        "old_file_path": file_path,
        "new_file_path": new_file_path,
        "original_header": list(original_header)
    }


def encrypt_dir_task(dir_path, key_data):
    if check_is_re_encrypt(dir_path, key_data):
        print(f"目录{dir_path}已经加密过，无需重复加密")
        return
    uuid_name = generate_uuid().upper()  # 目录名用大写
    new_file_path = os.path.join(os.path.dirname(dir_path), uuid_name)
    key_data[uuid_name] = {
        "old_dir_path": dir_path,
        "new_dir_path": new_file_path,
    }


def encrypt_dir_dfs(dir_path, key_data):
    """
    递归遍历目录，将所有子目录和当前目录名按顺序放入 key_data 中
    确保先处理子目录，再处理当前目录
    """
    # 确保目录存在
    if not os.path.isdir(dir_path):
        raise ValueError(f"{dir_path} 不是一个有效的目录")
    # 遍历当前目录的所有条目
    has_sub_dir = False
    for entry in os.listdir(dir_path):
        entry_path = os.path.join(dir_path, entry)
        # 如果是子目录，先递归处理子目录
        if os.path.isdir(entry_path):
            has_sub_dir = True
            encrypt_dir_dfs(entry_path, key_data)
    if not has_sub_dir:
        print(f"dir_path={dir_path}")
    # 处理当前目录（保证当前目录在所有子目录处理完成后才加入 key_data）
    dir_name = os.path.basename(dir_path)

    uuid_name = generate_uuid()  # 假设这是生成 UUID 的函数
    key_data[uuid_name] = {
        "dir_name": dir_name,
        "dir_path": dir_path
    }


def decrypt_dir_task(uuid_name, file_info, key_data):
    try:
        old_file_path = file_info["old_dir_path"]
        new_file_path = file_info["new_dir_path"]
        if not os.path.exists(new_file_path):
            print(f"目录{new_file_path}不存在，无需解密")
            return
        os.rename(new_file_path, old_file_path)
        del key_data[uuid_name]
        print(f"解密目录名 {uuid_name} 成功")
    except Exception as e:
        print(f"解密目录名 {uuid_name} 失败: {e}")


class FileEncryptor:
    def __init__(self, aes_key, dir_path, json_encrypt=True):
        self.aes_key = aes_key
        self.cipher = AESCipher(aes_key)  # AES 加解密器
        self.dir_path = dir_path
        self.root_dir = os.path.dirname(dir_path)
        self.sub_dir = os.path.basename(dir_path)
        self.key_file_path = os.path.join(f"{dir_path}.json")
        self.json_encrypt = json_encrypt

    # 读取 key 文件时进行解密，并验证密钥是否正确
    def read_key_file(self):
        if not os.path.exists(self.key_file_path):
            return {}
        try:
            with open(self.key_file_path, 'r') as key_file:
                encrypted_json = key_file.read()
                decrypted_json = self.cipher.decrypt(encrypted_json)
                key_data = json.loads(decrypted_json)
                return key_data
        except (json.JSONDecodeError, ValueError):
            raise ValueError("密钥错误或文件损坏")

    # 保存 key 文件时进行加密
    def save_key_file(self, key_data):
        if len(key_data) == 0:
            print(f"key文件已全部解密完成")
        print(f"保存key_data到文件里{key_data}")

        # 将 key_data 转换为 JSON 格式
        json_data = json.dumps(key_data, indent=4)

        # 对 JSON 数据进行 AES 加密
        json_encrypt = self.cipher.encrypt(json_data)

        # 将加密后的数据写入文件
        with open(self.key_file_path, 'w') as key_file:
            key_file.write(json_encrypt)

        print(f"Key file updated at: {self.key_file_path}")

    def encrypt_directory(self):
        key_data = self.read_key_file()
        file_utils.remove_file(f"{self.dir_path}.json")
        try:
            # 先递归的加密目录，目录加密完再加密文件
            for root, dirs, files in os.walk(self.dir_path):
                for dir_name in dirs:
                    dir_path = os.path.join(root, dir_name)
                    encrypt_dir_task(dir_path, key_data)
            # with concurrent.futures.ThreadPoolExecutor() as executor:
            #     futures = []
            #     for root, dirs, files in os.walk(self.dir_path):
            #         for file in files:
            #             file_path = os.path.join(root, file)
            #             futures.append(executor.submit(encrypt_file_task, file_path, key_data))
            #     for future in concurrent.futures.as_completed(futures):
            #         try:
            #             future.result()
            #         except Exception as e:
            #             print(f"文件加密过程中出现错误: {e}")
        except Exception as er:
            print(f"加密文件出现未知错误，文件恢复-start,e={er}")
            for uuid_name, file_info in list(key_data.items()):
                if file_info.get("old_file_path"):
                    file_utils.restore_file(file_info.get("old_file_path"), file_info.get("original_header"))
        self.save_key_file(key_data)
        for uuid_name, file_info in list(key_data.items()):
            # if os.path.exists(file_info["old_file_path"]):
            #     print(f"源文件{file_info['old_file_path']}重命名成{file_info['new_file_path']}")
            #     os.rename(file_info["old_file_path"], file_info["new_file_path"])
            if os.path.exists(file_info["old_dir_path"]):
                print(f"源目录{file_info['old_dir_path']}重命名成{file_info['new_dir_path']}")
                os.rename(file_info["old_dir_path"], file_info["new_dir_path"])
        print(f"加密完成，key 文件生成在 {self.dir_path}{self.sub_dir} 目录下")

    def decrypt_directory(self):
        try:
            key_data = self.read_key_file()
        except FileNotFoundError:
            print(f"没有读取到 Json 文件 {self.root_dir}{self.sub_dir}.json")
            return
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            for uuid_name, file_info in list(key_data.items()):
                if "old_file_path" in file_info:
                    futures.append(executor.submit(decrypt_file_task, uuid_name, file_info, key_data))
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"文件解密过程中出现错误: {e}")
        # 递归的解密目录
        for uuid_name, file_info in list(key_data.items()):
            if "old_dir_path" in file_info:
                decrypt_dir_task(uuid_name, file_info, key_data)
        self.save_key_file(key_data)
        print(f"解密完成，目录恢复至 {self.dir_path}")


if __name__ == '__main__':
    file_encrypt = FileEncryptor("wtw1029*#", "F:\\testtest")
    # file_encrypt.encrypt_directory()
    # file_encrypt.decrypt_directory()
    keys = {}
    encrypt_dir_dep_task("F:\\testtest", keys)
    # print(f"keys={keys}")
