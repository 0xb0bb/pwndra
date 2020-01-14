import json
import os

class Const:


    def __init__(self, arch, abi='default'):
        self.load('generic')
        self.load(arch)
        self.load(arch+'_'+abi)


    def load(self, name):

        filepath = os.path.dirname(os.path.realpath(__file__))
        filepath = '%s/../data/constants/%s_constants.json' % (filepath, name)
        filename = os.path.realpath(filepath)

        if os.path.isfile(filename):
            data = []
            with open(filename) as file:
                data = json.loads(file.read())
            for name in data:
                setattr(self, name, data[name])
