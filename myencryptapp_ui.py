# -*- coding=utf-8 -*-
import tkinter as tk
from tkinter import filedialog, messagebox
from myencryptapp import FileEncryptor


def run_encryptor():
    def select_folder():
        folder_selected = filedialog.askdirectory()
        entry_folder.delete(0, tk.END)
        entry_folder.insert(0, folder_selected)

    def encrypt():
        folder = entry_folder.get()
        key = entry_key.get()
        if not folder or not key:
            messagebox.showerror("错误", "请选择文件夹并输入密钥！")
            return
        try:
            file_encrypt = FileEncryptor(key, folder)
            file_encrypt.encrypt_directory()
            messagebox.showinfo("成功", "加密成功！")
        except Exception as e:
            messagebox.showerror("错误", f"加密过程中出现错误: {e}")

    def decrypt():
        folder = entry_folder.get()
        key = entry_key.get()
        if not folder or not key:
            messagebox.showerror("错误", "请选择文件夹并输入密钥！")
            return
        try:
            file_encrypt = FileEncryptor(key, folder)
            file_encrypt.decrypt_directory()
            messagebox.showinfo("成功", "解密成功！")
        except Exception as e:
            messagebox.showerror("错误", f"解密过程中出现错误: {e}")

    # 创建主窗口
    root = tk.Tk()
    root.title("文件加密工具")

    # 文件夹选择
    label_folder = tk.Label(root, text="选择文件夹：")
    label_folder.grid(row=0, column=0, padx=10, pady=10)
    entry_folder = tk.Entry(root, width=50)
    entry_folder.grid(row=0, column=1, padx=10, pady=10)
    btn_folder = tk.Button(root, text="浏览", command=select_folder)
    btn_folder.grid(row=0, column=2, padx=10, pady=10)

    # 密钥输入
    label_key = tk.Label(root, text="输入密钥：")
    label_key.grid(row=1, column=0, padx=10, pady=10)
    entry_key = tk.Entry(root, width=50)
    entry_key.grid(row=1, column=1, padx=10, pady=10)

    # 加密和解密按钮
    btn_encrypt = tk.Button(root, text="加密", command=encrypt)
    btn_encrypt.grid(row=2, column=0, padx=10, pady=10)

    btn_decrypt = tk.Button(root, text="解密", command=decrypt)
    btn_decrypt.grid(row=2, column=1, padx=10, pady=10)

    root.mainloop()


if __name__ == '__main__':
    run_encryptor()
