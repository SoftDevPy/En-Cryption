En-Cryption
===========

A Password Encryption Software

The Master Password Prompt- will guide you in setting up a unique, unforgettable password with a high 
entropy value. 

Entropy- is a measure of password strength. The main determinant of entropy is password length. So, 
although a password should ideally contain UPPERCASE,lowercase,  digits and special characters, you could also pick long phrases that are easy for you to remember, and these phrases should be at least 7 to 8 words in length, and should be unique to yourself, something not searchable on Google:). And if you know some foreign phrases, you could add them in as well for added security. This type of password construction is more resistant to attack than a password constructed with greater complexity, but shorter in length. 

Create Window- Use this window to create your accounts. There is no limit to the number of accounts you can create.
To create and store information, the following fields must be filled:

Account Name: this could be your email provider, bank, utility provider, cable etc.

Account ID: The ID you use to access the above account. For multiple accounts under the same email or bank for instance, use Account name and Account ID combinations for this field to help differentiate. Or use any method you please.

Randomize-it: Enter a random number, or number and letter combination. You will not need to remember this, so do not worry if you forget about it later. This is an extra layer of protection that acts as a 'seed' value to an in-built random number generator that gets passed along with your Master Password to a 512 bit hash algorithm generator. All this is part of the encryption process.

Account Password: The password associated with your account.

These fields are optional:

Secret Question and Secret Answer: Whatever you used that helps confirm your identity for the account you are encrypting.

Account Notes: Enter any notes you wish to make regarding this account.

The Demo and the Full Version of En-Cryption use different databases for your security. If you tested the Demo and stored accounts, you will have to re-enter those accounts on the full version.

View Window- Enter the Account Name you wish to view. This starts a decryption process of the encrypted data stored on your device. Your Master Password is the "key" that decrypts or decodes your encrypted data. The wrong master Password entered will result in an incorrect "key" and therefore, the data displayed will be incorrect. If you see something that looks incorrect, re-enter your Master Password. 

It is important to note that in order to make this program completely secure, there is no provision for a recovery of the Master Password. If such a provision were made in the program, the unintended users would be able to hijack your data making use of this loophole, or "backdoor entry". Similarly, there is no method by which a person could reverse engineer the encrypted data in order to arrive at the original, without your Master Password.

Therefore, it is extremely important not to forget the Master Password. Making use of this program will help you in memorizing this Master Password, because it will free you from the task of remembering multiple passwords for multiple accounts, making your life easier:) However, if you should forget the Master Password, please make another Master Password and re-enter your info using the Create Window. This will re-create your accounts and the encryption will be done using your new master password, the new "key".

Does not require internet access- En-Cryption does not communicate with the internet and therefore requires no internet connection. The data you encrypt is stored on your device only and not on any "cloud". Therefore, your encrypted data is safe also from interception by the internet. In order to verify the programs on your computer that communicate or "talk" to the internet, simply open your Command Prompt. Type "cmd" in the start menu under "search program and files", right click "cmd" and press "run as administrator". When the black window opens up, type "cd \" and then type "netstat -b". This will bring up a list of programs that are currently communicating with the internet. When you run En-Cryption, you will notice that using "netstat -b" does not bring up En-Cryption as one of the programs "talking" with the internet.

A brief history- The idea for a simple and effective encryption scheme to protect and manage the numerous passwords we all struggle to manage came from my friend and computer security specialist, Khaja. https://www.linkedin.com/in/khaja 
I implemented the solution in Python as a fun way of learning the language as well as applied cryptography. The result is this easy to use and secure tool for managing passwords. 

http://en-cryption.squarespace.com/

Questions and suggestions: 

encrypt.encryption@gmail.com

Enjoy!




