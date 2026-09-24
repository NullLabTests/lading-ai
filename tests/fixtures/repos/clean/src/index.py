import os

def load(name):
    path = os.path.join("data", name)
    with open(path, "r") as fh:
        return fh.read()

def greet(who):
    return f"hello {who}"