import subprocess
from flask import Flask, render_template, request
import requests

app = Flask(__name__)

def outer(outer_arg):
    outer_ret_val = outer_arg + 'hey'
    return outer_ret_val

def inner(inner_arg):
    inner_ret_val = inner_arg + 'hey'
    return inner_ret_val

@app.route('/menu', methods=['POST'])
def menu():
    req_param = request.form['suggestion']
    result = outer(inner("self isolating string"))
    subprocess.call(result, shell=True)

    result = outer(inner(str(req_param)))
    subprocess.call(result, shell=True) # subprocess.call(os.system(result))不行，没有os.system的函数摘要

    with open('menu.txt','r') as f:
        menu = f.read()

    return render_template('command_injection.html', menu=menu)
