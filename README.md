En-Cryption
===========

A Password Encryption Software

It is important to note that in order to make this program completely secure, there is no provision for a recovery of the Master Password. If such a provision were made in the program, the unintended users would be able to hijack your data making use of this loophole, or "backdoor entry". Similarly, there is no method by which a person could reverse engineer the encrypted data in order to arrive at the original, without your Master Password.

Therefore, it is extremely important not to forget the Master Password. Making use of this program will help you in memorizing this Master Password, because it will free you from the task of remembering multiple passwords for multiple accounts, making your life easier:) However, if you should forget the Master Password, please make another Master Password and re-enter your info using the Create Window. This will re-create your accounts and the encryption will be done using your new master password, the new "key".

Does not require internet access- En-Cryption does not communicate with the internet and therefore requires no internet connection. The data you encrypt is stored on your device only and not on any "cloud". Therefore, your encrypted data is safe also from interception by the internet. In order to verify the programs on your computer that communicate or "talk" to the internet, simply open your Command Prompt. Type "cmd" in the start menu under "search program and files", right click "cmd" and press "run as administrator". When the black window opens up, type "cd \" and then type "netstat -b". This will bring up a list of programs that are currently communicating with the internet. When you run En-Cryption, you will notice that using "netstat -b" does not bring up En-Cryption as one of the programs "talking" with the internet.

A brief history- The idea for a simple and effective encryption scheme to protect and manage the numerous passwords we all struggle to manage came from my friend and computer security specialist, Khaja. https://www.linkedin.com/in/khaja 

I implemented the solution in Python as a fun way of learning the language as well as applied cryptography. The result is this easy to use and secure tool for managing passwords. 

More than a 1000 lines of code were required to make the final Windows app, but I have broken down the main encryption/decryption process in the encryption_snapshot_python.py file in a easy to understand manner in Python without the user-interface coding as well as a encryption_snapshot_python.js file in JavaScript. I have attached an Encryption Explained file as well where I walk through the process.

http://en-cryption.squarespace.com/

Questions and suggestions: 

encrypt.encryption@gmail.com

Enjoy!




