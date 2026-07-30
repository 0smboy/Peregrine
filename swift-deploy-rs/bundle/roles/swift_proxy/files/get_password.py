#!/usr/bin/env python
# encoding: utf-8

import hashlib
import sys

def Getpassword(user_password):
    res = hashlib.sha512(user_password).hexdigest()
    print res

Getpassword(sys.argv[1])
