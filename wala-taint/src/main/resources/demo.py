import subprocess
from flask import Flask, render_template, request
import os

# class oos:
#     def get(self, *args):
#         return args[6]
# def get(a,b,c,d,e):
#     return a
req_param = request.form['suggestion']
result=os.get(req_param,"B","C","D","E") # 不支持注解@staticmethod， get()能扫到
os.system(result) # subprocess.call(os.system(result))不行，没有os.system的函数摘要
