import requests
import base64
import ormsgpack
import json
import re

baseURL = 'https://ciphersprint.pulley.com/'
taskURL = 'https://ciphersprint.pulley.com/task_'
email = ''

data = requests.get(baseURL+email)

instructions = data.json()
next = instructions['encrypted_path']
cipher = instructions['encryption_method']

def asciiRun(asciiArr):
    string = ''
    for a in asciiArr:
        string += chr(a)

    return string

def customHex(hash: str, code: str):
    newStr = ''
    for x in code:
        hashChar = hash.index(x)
        if (hashChar < 10):
            newStr += "%s"%hashChar
        elif hashChar == 10:
            newStr +=  'a'
        elif hashChar == 11:
            newStr += 'b'
        elif hashChar == 12:
            newStr += 'c'
        elif hashChar == 13:
            newStr += 'd'
        elif hashChar == 14:
            newStr += 'e'
        elif hashChar == 15:
            newStr += 'f'
        else:
            raise Exception("Out of Range")
    return newStr

while next and data.status_code == 200:
    print ("Level {0}".format(instructions['level']))

    if (cipher == 'nothing'):
        nextUrl = baseURL + next
    elif (cipher.find('messagepack') > 0):
        subIns = cipher.rfind(' ')
        cipherHash = cipher[subIns+1:]
        originalPositions = ormsgpack.unpackb(base64.b64decode(cipherHash))
        taskStr = ''
        for i in range(len(originalPositions)):
            nextChar = originalPositions.index(i)
            taskStr += next[nextChar]
            i += 1

        nextUrl = taskURL + taskStr
    elif (cipher.find('base64') > 0):
        nextUrl = taskURL + base64.urlsafe_b64decode(next).decode('utf-8')
    elif (cipher.find('ASCII') > 0):
        charArr = json.loads(next)
        nextUrl = taskURL + asciiRun(charArr)
    elif (cipher.find('non-hex') > 0):
        nextUrl = taskURL + re.sub("[^A-Fa-f0-9]", "", next)
    elif (cipher.find('right by') > 0):
        subIns = cipher.rfind(' ')
        rotateCount = int(subIns)
        rotateStr = next[rotateCount:] + next[0:rotateCount]
        nextUrl = taskURL + rotateStr
    elif (cipher.find('left by') > 0):
        subIns = cipher.rfind(' ')
        rotateCount = int(cipher[subIns:])
        rotateStr = next[-rotateCount:] + next[0:-rotateCount]
        nextUrl = taskURL + rotateStr
    elif (cipher.find('custom hex') > 0):
        subIns = cipher.rfind(' ')
        cipherHash = cipher[subIns+1:]
        cipherStr = customHex(cipherHash, next)
        nextUrl = taskURL + cipherStr

    else:
        break

    data = requests.get(nextUrl)
    if (data.status_code != 404):
        instructions = data.json()
        next = instructions['encrypted_path'].split('_')[1]
        cipher = instructions['encryption_method']
    else:
        print("WTFFFFF")
        print(data)
        next = None
