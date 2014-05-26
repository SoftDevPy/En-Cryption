from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from idlelib import ToolTip
from math import *

import os
import hashlib
import base64
import random
import sqlite3
import sys

conn = sqlite3.connect('sql.db')
cursor = conn.cursor()
gsalt = ''
cipher_text_ba_b64_str = ''
alpha_num = 'a2b5c1d10e15f17g13h9i6j1k0l19m27n23o26p33q30r40s50t90u65v75w99x100y2z4'

def create_table():# creates sqlite database
    try:
        cursor.execute("CREATE TABLE User_Accounts (ID INT, accName TEXT, accountID TEXT,"+\
                  "salt TEXT, password TEXT, secretQ TEXT,"+\
                  "SecretQans TEXT, Account_Notes TEXT )")
    except Exception:
        return 1
    
def makeSalt(salt): #when called takes the randomise-it field value and uses it as 'salt'
    # to seed the random generator. Creates hexdigest of the random number
    global gsalt
    random.seed(salt)
    shash = hashlib.sha512()
    randstart = random.random()
    shash.update(bytearray(str(randstart),'utf-8'))
    gsalt = shash.hexdigest()
    return gsalt

def key_for_acc_pass(m_pass):# use this as encryption/decryption key for acc pass
    m_pass_ba = bytearray(m_pass.encode())
    gsalt_ba = bytearray(gsalt.encode())
    hashed_m_pass_ba = hashlib.sha512()
    hashed_m_pass_ba.update(m_pass_ba)
    hashed_m_pass_ba.update(gsalt_ba)
    m_pass_ba_hash_str = hashed_m_pass_ba.hexdigest()
    return m_pass_ba_hash_str

def key_update_for_field(m_pass,fields):# use this as encryption/decryption key for
    # remaining fields
    m_pass_ba = bytearray(m_pass.encode())
    gsalt_ba = bytearray(gsalt.encode())
    fields_ba = bytearray(fields.encode())
    hashed_m_pass_ba = hashlib.sha512()
    hashed_m_pass_ba.update(m_pass_ba)
    hashed_m_pass_ba.update(gsalt_ba)   
    hashed_m_pass_ba.update(fields_ba)
    m_pass_ba_hash_str2 = hashed_m_pass_ba.hexdigest()
    return m_pass_ba_hash_str2

def encrypt_it(plain_text,key):
# in plain_text pass either password or field,
#in key pass key as desired from above keys
# cipher_text_ba_b64_str will be vaule stored in database
    m_pass_ba_hash_str_ba = bytearray (key.encode())
    plain_text_ba = bytearray(plain_text.encode())
    cipher_text_ba = bytearray()
    for item in range(len(plain_text)):
        ord_now = plain_text_ba[item] ^ m_pass_ba_hash_str_ba[item]
        cipher_text_ba.append(ord_now)
    cipher_text_ba_b64 = base64.encodebytes(cipher_text_ba)
    cipher_text_ba_b64_str = cipher_text_ba_b64.decode()
    return cipher_text_ba_b64_str

def decrypt_it(get_key,cipher_text_ba_b64_str):
# decrypts 1st position key against 2nd position encrypted str func
    cipher_text_ba_b64_str_decode = base64.b64decode(cipher_text_ba_b64_str)
    m_pass_byte_hash_str = get_key
    m_pass_byte_hash_str_byte = bytearray (m_pass_byte_hash_str.encode())
    get_it_back = []
    for item in range(len(cipher_text_ba_b64_str_decode)):
        re_ord = m_pass_byte_hash_str_byte[item] ^ cipher_text_ba_b64_str_decode [item]
        recovered = chr(re_ord)
        get_it_back.append(recovered)
    plain_text_back = ''.join(get_it_back)
    return plain_text_back

def get_ID(): # creates an ID number for each account in database
    global num
    ID_num = []    
    for row in cursor.execute("SELECT ID FROM User_Accounts "):
        ID_num.append(row)
    if ID_num:
        num = ID_num[-1][0]
    else:
        num = 0
    return num      

def goToDelete(*args): # goes to delete window and allows you to delete any selected account
    aName = StringVar()

    def D_destroy(*args):
        window2.destroy()
        
    def clear_Delete(*args):
        aName.set('')
        delete_entry.focus()

    def deleteAcc(*args):
        account = []
        accName = aName.get()
        create_table()
        for row in cursor.execute("SELECT accName FROM User_Accounts "):
            account.append(row)
        if (accName,) not in account:
            exists = 0
            if exists == 0:
                retry = messagebox.askretrycancel(message='This account does not exist',
	               icon='error', title='Error', parent = window2)
                if retry>0:
                    aName.get()
                    aName.set('')
                    delete_entry.focus()                    
                else:
                    aName.get()
                    aName.set('')
                    D_destroy()
        elif accName:
            question = messagebox.askyesno(message='Are you sure you want to delete this account?',
	               icon='question', title='Delete?', parent = window2)
            if question < 1:
                aName.get()
                aName.set('')
                delete_entry.focus()
            else:
                aName.get()
                aName.set('')
                delete_entry.focus()
                cursor.execute("delete from User_Accounts where accName = ? ", [(accName)])
                conn.commit()
                after_d = []
                
                for row in cursor.execute("SELECT accName FROM User_Accounts "):
                        after_d.append(row)
                if len(after_d)==1 and question == 1:
                    messagebox.showinfo(message='You have successfully deleted the '+accName+' account. \n\
You have '+ str(len(after_d))+ ' encrypted account on file now.',
	                    title='Account ', parent = window2)
                elif len(after_d)==0 or len(after_d)>1 and question == 1:
                    messagebox.showinfo(message='You have successfully deleted the '+accName+' account.\n\
You have '+ str(len(after_d))+ ' encrypted accounts on file now.',
	                    title='Accounts ', parent = window2)      
        
    window2 = Toplevel(root) 
    window2.title ('Delete')
    window2.geometry('500x450+500+10')
    window2.minsize(width = 440, height = 400)  
    window2.config(background="#0a1219")
    window2_frame = ttk.Frame(window2, style = "E.TFrame")   
    window2_frame.place(relx=0.03, rely=0.03)
    window2_frame.place(relheight=0.94, relwidth=0.94)
    window2_label = Label(window2_frame,image = delete_win,
                bd = -4,highlightthickness = -2)
    window2_label.pack()

    D1_f2 = ttk.Frame(window2_label,style = "B.TFrame")
    D1_f2.place(relx=0.095, rely=0.22)
    D1_f2.place(relheight=0.108, relwidth=.80)
    delete_band_label= Label(D1_f2,image =D_band2,
                bd = -4,highlightthickness = -2)
    delete_band_label.pack()

    D2_f2 = ttk.Frame(D1_f2,  style = "B.TFrame")
    D2_f2.place(relx=0.03, rely=0.2)
    D2_f2.place(relheight=0.65, relwidth=0.55)
    delete_name_label= Label(D2_f2,image =D_name,
                bd = -4,highlightthickness = -2)
    delete_name_label.pack()
    
    D1 = ttk.Frame(D1_f2,  style = "B.TFrame")
    D1.place(relx=0.58, rely=0.25)
    D1.place(relheight=0.45, relwidth=0.38)
    delete_entry = ttk.Entry(D1, width=27, textvariable= aName)
    delete_entry.pack()
    
    Del_Button_images = [Delete_D_B, Delete_C_B, Delete_Close_B]
    Del_Button_commands = [deleteAcc, clear_Delete, D_destroy]
    Del_Button_tootip = ['Delete the above account', 'Clear the above entry',
                         'Close this window']
    D_y = 0.54   
    for i in range(0,3):
        Del_Frame = ttk.Frame(window2_label,style = "B.TFrame")
        Del_Frame.place(relx=0.0, rely=D_y)
        Del_Frame.place(relheight=0.1, relwidth=1)
        del_label= Label(Del_Frame,image =D_band2,
                bd = -4,highlightthickness = -2)
        del_label.pack()
        D_frame2 = ttk.Frame(Del_Frame,style = "B.TFrame")
        D_frame2.place(relx=0.385, rely=0.15)
        D_frame2.place(relheight=0.65, relwidth=0.23)
        Del_Button = ttk.Button(D_frame2,  image = Del_Button_images[i],
                style = 'A.TButton', command = Del_Button_commands[i])
        ToolTip.ToolTip(Del_Button, Del_Button_tootip[i])
        Del_Button.pack()
        D_y += 0.11
   
    delete_entry.focus()

    menubar2 = Menu(window2)
    filemenu2 = Menu(menubar2, tearoff = 0)

    label_D = ["Clear entries", "Create Window", "View Window", "Help",
             "About", "Close", "Exit"]
    command_D = [clear_Delete, goToCreate, goToView, goToHelp, goToAbout,
               D_destroy, goToQuit]
    accelerator_D = ["DEL", "Alt+C", "Alt+V", "Ctrl+H", "Ctrl+A",
                     "Ctrl+F4", "Ctrl+Q"]   
    for i in range(0,7):
        filemenu2.add_command( label=label_D[i], 
                command=command_D[i], accelerator=accelerator_D[i])
    menubar2.add_cascade(label="File", menu = filemenu2)
    window2.config(menu = menubar2)

    bind_D= ["<Return>", "<Alt-c>", "<Delete>", "<Control-h>",
             "<Control-a>", "<Control-q>", "<Alt-v>", "<Control-F4>"]
    bind_Command_D = [deleteAcc, goToCreate, clear_Delete, goToHelp,
                    goToAbout, goToQuit, goToView, D_destroy]   
    for i in range(0,8):
        window2.bind(bind_D[i], bind_Command_D[i])
        
def goToView(*args):# goes to view window and allows you to view/decrypt any selected account  
    def G_destroy(*args):
            window3.destroy()
            
    mass_pass= StringVar()
    aName = StringVar()
    accID = StringVar()
    randomise = StringVar()
    accPass = StringVar()
    secQ = StringVar()
    secA = StringVar()
    notes = StringVar()
    delete_Acc = StringVar()
    view_Acc = StringVar()
    
    window3 = Toplevel(root)
    window3.title ('View')
    window3.geometry('550x700+750+80')  
    window3.minsize(width = 510, height = 650)
    window3.config(background="#0a1219")
    window3_frame = ttk.Frame(window3,style = "E.TFrame")   
    window3_frame.place(relx=0.03, rely=0.03)
    window3_frame.place(relheight=0.94, relwidth=0.94)
    window3_label = Label(window3_frame,image = view_win,
                bd = -4,highlightthickness = -2)
    window3_label.pack()

    v1 = ttk.Frame(window3_label,  style = "B.TFrame")
    v1.place(relx=0.54, rely=0.1595)
    v1.place(relheight=0.035, relwidth=0.31)
    view_entry = ttk.Entry(v1, width=27, textvariable= aName)
    view_entry.pack()
    view_entry.focus()

    v1_f2 = ttk.Frame(window3_label,style = "B.TFrame")
    v1_f2.place(relx=0.185, rely=0.159)
    v1_f2.place(relheight=0.035, relwidth=0.29)
    acc_to_view_label= Label(v1_f2,image =acc_to_view,
                bd = -4,highlightthickness = -2)
    acc_to_view_label.pack()

    t_View_variable = [accID, accPass, secQ, secA]
    View_images = [acc_ID, acc_P, S_Q, S_A]
    y_view = 0.3
    y_view_2 = 0.303    
    for i in range(0,4):
        view_Frame = ttk.Frame(window3_label,  style = "B.TFrame")
        view_Frame.place(relx=0.54, rely=y_view)
        view_Frame.place(relheight=0.06, relwidth=0.31)
        y_view+= 0.071
        
        view_Label_var = ttk.Entry(view_Frame,width=27,
                           textvariable = t_View_variable[i],
                                   )
        view_Label_var .pack()

        view_Frame2 = ttk.Frame(window3_label,style = "B.TFrame")
        view_Frame2.place(relx=0.17, rely=y_view_2)
        view_Frame2.place(relheight=0.035, relwidth=0.29)
        y_view_2 += 0.070
        label_V= Label(view_Frame2,image =View_images[i],
                bd = -4,highlightthickness = -2)
        label_V.pack()

    v6 = ttk.Frame(window3_label,  style = "B.TFrame")
    v6.place(relx=0.54, rely=0.585)
    v6.place(relheight=0.18, relwidth=0.30)
    view_N = ttk.Label(v6,style = "B.TLabel", width=127,
                           textvariable = notes,
                       wraplength=140, justify=LEFT)
    view_N.pack_propagate(0)
    view_N.pack()   

    v6_f2 = ttk.Frame(window3_label,style = "B.TFrame")
    v6_f2.place(relx=0.17, rely=0.587)
    v6_f2.place(relheight=0.035, relwidth=0.29)
    v6_f2.columnconfigure(0, weight=1)
    v6_f2.rowconfigure(0, weight=1)
    N_label= Label(v6_f2,image =Note,
                bd = -4,highlightthickness = -2)
    N_label.pack_propagate(0)
    N_label.pack()

    def clear_View(*args):
        aName.set('')
        accID.set('')
        accPass.set('')
        secQ.set('')
        secA.set('')
        notes.set('')
        view_entry.focus()
    
    def displayAccDetails(*args):           
        global alpha_num
        global mass_pass
        create_table()
        data = dict()
        account = []
        m_pass = mass_pass.get()
        accName = aName.get()
        for row in cursor.execute("SELECT accName FROM User_Accounts "):
            account.append(row)
        if (accName,) not in account:
            exists = 0
            if exists == 0:
                retry = messagebox.showinfo(message=
                'This account does not exist',
	        icon='error', title='Error', parent = window3)
                if retry:
                    clear_View()
                    mass_pass.get()
                    view_entry.focus()
        else:
            aName.set(accName)
            for row in cursor.execute (
                "SELECT * FROM User_Accounts WHERE accName = ? ",
                                       [(accName)]):
                data['salt'] = row[3]  
                gsalt = makeSalt(data['salt'])
                data['accountID'] = row[2]
                data['password'] = row[4]
                data['secretQ'] = row[5]
                data['SecretQans'] = row[6]
                data['Account_Notes'] = row[7]
                data['password']= decrypt_it(key_for_acc_pass(m_pass),data['password'])
                accPass.set(data['password'])
                data['accountID']= decrypt_it(key_update_for_field(m_pass,alpha_num[11:21]),
                                              data['accountID'])
                accID.set(data['accountID'])
                data['secretQ']= decrypt_it(key_update_for_field(m_pass,alpha_num[60:70]),
                                            data['secretQ'])
                secQ.set(data['secretQ'])
                data['SecretQans']= decrypt_it(key_update_for_field(m_pass,alpha_num[40:55]),
                                               data['SecretQans'])
                secA.set(data['SecretQans'])
                data['Account_Notes']= decrypt_it(key_update_for_field(m_pass,alpha_num[45:60]),
                                                  data['Account_Notes'])
                notes.set(data['Account_Notes'])

    v7 = ttk.Frame(window3_label,  style = "B.TFrame")
    v7.place(relx=0.00, rely=0.21)
    v7.place(relheight=0.062, relwidth=1)
    view_D = ttk.Label(v7,style = "B.TLabel", width=27, image =D_box)
    view_D.pack(expand = 'yes', fill = BOTH)
    v10 = ttk.Frame(view_D,  style = "B.TFrame", relief = 'raised')
    v10.place(relx=0.40, rely=0.10)
    v10.place(relheight=0.65, relwidth=.20)
    decrypt_BT = ttk.Button(v10,style ="A.TButton", image = decrypt_B,
                            command = displayAccDetails)
    decrypt_BT.pack(expand = 'yes', fill = BOTH)
    ToolTip.ToolTip(decrypt_BT, 'View account details for the above account')

    v8 = ttk.Frame(window3_label,  style = "B.TFrame")
    v8.place(relx=0.00, rely=0.76)
    v8.place(relheight=0.077, relwidth=1)
    view_C_C = ttk.Label(v8,style = "B.TLabel", width=27, image =C_C_Box)
    view_C_C.pack(expand = 'yes', fill = BOTH)

    B_View_Image = [clear_V, close_V]
    B_View_Image_commands = [clear_View, G_destroy]
    B_View_Image_tooltip = ['Clear the above entry', 'Close this window']
    view_X = 0.1333    
    for i in range(0,2):
       v = ttk.Frame(view_C_C,  style = "B.TFrame", relief = 'raised')
       v.place(relx=view_X, rely=0.20)
       v.place(relheight=0.55, relwidth=.20)
       view_X += 0.5333
       b = ttk.Button(v,style ="A.TButton", image = B_View_Image[i],
                      command = B_View_Image_commands[i])
       b.pack(expand = 'yes', fill = BOTH)
       ToolTip.ToolTip(b, B_View_Image_tooltip[i])
       
    view_entry.focus()
    
    menubar3 = Menu(window3)
    filemenu3 = Menu(menubar3, tearoff = 0)

    label_V = ["Clear entries", "Delete Window", "Create Window", "Help",
             "About", "Close", "Exit"]
    command_V = [clear_View, goToDelete, goToCreate, goToHelp, goToAbout,
               G_destroy, goToQuit]
    accelerator_V = ["DEL", "Alt+D", "Alt+C", "Ctrl+H", "Ctrl+A",
                     "Ctrl+F4", "Ctrl+Q"]   
    for i in range(0,7):
        filemenu3.add_command( label=label_V[i], 
                command=command_V[i], accelerator=accelerator_V[i])
    menubar3.add_cascade(label="File", menu = filemenu3)
    window3.config(menu = menubar3)

    bind_V= ["<Return>", "<Alt-d>", "<Delete>", "<Control-h>",
             "<Control-a>", "<Control-q>", "<Alt-c>", "<Control-F4>"]
    bind_Command = [displayAccDetails, goToDelete, clear_View, goToHelp,
                    goToAbout, goToQuit, goToCreate, G_destroy]   
    for i in range(0,8):
        window3.bind(bind_V[i], bind_Command[i])
   
def goToHelp(*args): # help window
    def H_destroy(*args):
            window4.destroy()
    window4 = Toplevel(root)
    window4.title ('Help')
    window4.geometry('650x700+700+100')
    window4.minsize(width = 550, height = 600)
    window4.config(background="#0a1219")
    window4_frame = ttk.Frame(window4,style = "E.TFrame")   
    window4_frame.place(relx=0.03, rely=0.03)
    window4_frame.place(relheight=0.94, relwidth=0.94)   
    window4_label = Label(window4_frame,image = help_win,
                bd = -4,highlightthickness = -2)
    window4_label.pack()

    window4.bind("<Control-a>", goToAbout)
    window4.bind("<Control-q>", goToQuit)
    window4.bind("<Control-F4>", H_destroy)

def goToAbout(*args): # about window
    def A_destroy(*args):
            window5.destroy()
    window5 = Toplevel(root)
    window5.title ('About')
    window5.geometry('650x700+800+100')
    window5.minsize(width = 550, height = 600)
    window5.config(background="#0a1219")
    style = ttk.Style()
    window5_frame = ttk.Frame(window5,
                       style = "E.TFrame")   
    window5_frame.place(relx=0.03, rely=0.03)
    window5_frame.place(relheight=0.94, relwidth=0.94)
    window5_label = Label(window5_frame,image = about_win,
                bd = -4,highlightthickness = -2)
    window5_label.pack()

    window5.bind("<Control-h>", goToHelp)
    window5.bind("<Control-q>", goToQuit)
    window5.bind("<Control-F4>", A_destroy)
    
def goToCreate(*args): # goes to the create window which allows you to encrypt and store data
    mass_pass= StringVar() 
    aName = StringVar()
    accID = StringVar()
    randomise = StringVar()
    accPass = StringVar()
    secQ = StringVar()
    secA = StringVar()
    notes = StringVar()
    delete_Acc = StringVar()
    view_Acc = StringVar()
    
    def clear(*args):      
        aName.set('')
        accID.set('')
        randomise.set('')
        accPass.set('')
        secQ.set('')
        secA.set('')
        text.delete(1.0, END)
        accName_entry.focus()
        
    def C_destroy(*args):       
        accName = aName.get()
        accountID = accID.get()
        salt = randomise.get()
        password = accPass.get()
        secretQ = secQ.get()
        SecretQans = secA.get()
        Account_Notes = text.get('1.0', 'end') 
           
        if accName or accountID or salt or password or secretQ or SecretQans or Account_Notes:
            e_message = messagebox.askyesno(message='Please use "Encrypt" to save the data entered.\n\
To Encrypt, please remember the following fields must be filled out:\n\
Account Name \n\
Account ID \n\
Randomise-it \n\
Account Password \n\
\n\
Save first?',title='Save Data?', parent = window1)
            if e_message < 1:
                window1.destroy()
        else:
            window1.destroy()
            
    def myfunc(*args):     
        accName = aName.get()
        accountID = accID.get()
        salt = randomise.get()
        password = accPass.get()
        secretQ = secQ.get()
        SecretQans = secA.get()
        
        F = [accName, accountID, password, secretQ, SecretQans]
        Names = ['Account Name', 'Account ID', 'Password',
                 'Secret Question', 'Secret Question Answer']
        Set = [aName, accID, accPass, secQ, secA]
        
        for i in range(0,5):
            if len(F[i])>25:
                e_message = messagebox.showerror(message='The length of your '+Names[i]+ \
' exceeds 25 characters.\nPlease try again',title='Error', parent = window1)
                Set[i].set('')
        if accName and accountID and salt and password:         
            window1_f = ttk.Frame(window1,style = "B.TFrame")
            window1_f.place(relx=0.00, rely=0.698)
            window1_f.place(relheight=0.05, relwidth=1)           
            encrypt_Button = ttk.Button(window1_f,  image = encrypt_B, style = 'A.TButton',
               command = enter_data,state=NORMAL)          
            encrypt_Button.pack()
            ToolTip.ToolTip(encrypt_Button, 'Press this button to encrypt and securely store all your data.\n\
To Encrypt, please remember the following fields must be filled out:\n\
Account Name \n\
Account ID \n\
Randomise-it \n\
Account Password')
        else:
            window1_f = ttk.Frame(window1,style = "B.TFrame")
            window1_f.place(relx=0.00, rely=0.698)
            window1_f.place(relheight=0.05, relwidth=1)         
            encrypt_Button = ttk.Button(window1_f,  image = encrypt_B, style = 'A.TButton',
               command = enter_data, state=DISABLED)           
            encrypt_Button.pack()
            ToolTip.ToolTip(encrypt_Button, 'Press this button to encrypt and securely store all your data.\n\
To Encrypt, please remember the following fields must be filled out:\n\
Account Name \n\
Account ID \n\
Randomise-it \n\
Account Password')
            
    def enter_data(*args):
        global mass_pass
        create_table()
        get_ID()
        global num
        global alpha_num
        global gsalt      
        m_pass = mass_pass.get()
        accName = aName.get()
        accountID = accID.get()
        salt = randomise.get()
        makeSalt(salt)
        password = accPass.get()
        secretQ = secQ.get()
        SecretQans = secA.get()
        Account_Notes = text.get('1.0', 'end')       
        if len(Account_Notes)-1 > 120:
                length = len(Account_Notes)- 120
                e_message = messagebox.askretrycancel(message='The length of your Account Notes \
exceeds 120 characters.' ,title='Error', parent = window1)
                if e_message < 1:          
                    text.delete(1.0, END)
                    text.focus()           
                else:
                    text.delete(1.0, END)
                    text.insert(END, Account_Notes[:len(Account_Notes)-length])
                    text.focus()                       
        else:           
            password = encrypt_it(password,key_for_acc_pass(m_pass))
            accountID = encrypt_it(accountID,key_update_for_field(m_pass,alpha_num[11:21])) 
            secretQ = encrypt_it(secretQ,key_update_for_field(m_pass,alpha_num[60:70]))  
            SecretQans = encrypt_it(SecretQans,key_update_for_field(m_pass,alpha_num[40:55]))
            Account_Notes = encrypt_it(Account_Notes,key_update_for_field(m_pass,alpha_num[45:60]))       
            ID = 1+num
            account_check = []
            for row in cursor.execute("SELECT accName FROM User_Accounts "):
                account_check.append(row)
            if (accName,) in account_check:
                exists = 1
                if exists == 1:
                    question = messagebox.askyesno(message='This account already exists. \n\
Do you want to replace it?',
	                   icon='question', title='Confirm', parent = window1, default = 'no')
                    if question < 1:
                        clear()
                        accName_entry.focus()
                    else:
                        cursor.execute("delete from User_Accounts where accName = ? ", [(accName)])
                        conn.commit()
                        cursor.execute("INSERT INTO User_Accounts (ID, accName, accountID, salt, password, secretQ,"+\
                      "SecretQans, Account_Notes) VALUES(?,?,?,?,?,?,?,?)",
                  (ID, accName, accountID, salt, password, secretQ, SecretQans, Account_Notes))
                        conn.commit()
                        num = num +1
                        e_message = messagebox.askokcancel(message='You have successfully encrypted the '
                                            +accName+' account.\n\
To view this data in encrypted format, press OK.\n\
Else, CANCEL to continue.', title='Account Encrypted', parent = window1)
                        if e_message < 1:
                            clear()
                            accName_entry.focus()
                        else:
                            e_message = messagebox.showinfo(message='You have successfully encrypted the '
                                            +accName+' account.\n\
\n\
Account ID encrypted as: \n\
'+ accountID+ '\n\
Password encrypted as: \n\
'+ password+'\n\
Secret Question encrypted as: \n\
'+ secretQ+'\n\
Secret Question Answer encrypted as: \n\
'+ SecretQans+'\n\
Account Notes encrypted as: \n\
'+ Account_Notes+'\n\
',  
                                                    
	                title='Data Encrypted as', parent = window1)
                            clear()
                            accName_entry.focus()

            else:
                cursor.execute("INSERT INTO User_Accounts (ID, accName, accountID, salt, password, secretQ,"+\
                      "SecretQans, Account_Notes) VALUES(?,?,?,?,?,?,?,?)",
                  (ID, accName, accountID, salt, password, secretQ, SecretQans, Account_Notes))
                conn.commit()
                num = num +1
                e_message = messagebox.askokcancel(message='You have successfully encrypted the '
                                            +accName+' account.\n\
To view this data in encrypted format, press OK.\n\
Else, CANCEL to continue.', title='Account Encrypted', parent = window1)
                if e_message < 1:
                    clear()
                    accName_entry.focus()
                else:
                    e_message = messagebox.showinfo(message='You have successfully encrypted the '
                                            +accName+' account.\n\
\n\
Account ID encrypted as: \n\
'+ accountID+ '\n\
Password encrypted as: \n\
'+ password+'\n\
Secret Question encrypted as: \n\
'+ secretQ+'\n\
Secret Question Answer encrypted as: \n\
'+ SecretQans+'\n\
Account Notes encrypted as: \n\
'+ Account_Notes+'\n\
',  
                                                    
	                title='Data Encrypted as', parent = window1)
                    clear()
                    accName_entry.focus()
                
    aName.trace("w", myfunc)
    accID.trace("w", myfunc)
    randomise.trace("w", myfunc)
    accPass.trace("w", myfunc)
    secQ.trace("w", myfunc)
    secA.trace("w", myfunc) 
    
    window1 = Toplevel(root)
    window1.title ('Create')
    window1.geometry('600x700+80+80')
    window1.minsize(width = 600, height = 700)
    window1.maxsize(width = 600, height = 700)
    window1.config(background="#0a1219")
    
    window1_frame = ttk.Frame(window1,style = "E.TFrame")
    window1_frame.place(relx=0.03, rely=0.06)
    window1_frame.place(relheight=0.92, relwidth=0.94)   
    window1_label = Label(window1_frame,image = create_win,
                bd = -4,highlightthickness = -2)
    window1_label.pack()

    f1_f2 = ttk.Frame(window1_label,style = "B.TFrame")
    f1_f2.place(relx=0.148, rely=0.10)
    f1_f2.place(relheight=0.07, relwidth=.71)
    acc_to_name_label= Label(f1_f2,image =A_name,
                bd = -4,highlightthickness = -2)
    acc_to_name_label.pack_propagate(0)
    acc_to_name_label.pack()
    ToolTip.ToolTip(acc_to_name_label,'Enter the name of the account. \
For multiple accounts \n\
(for example, under same email), use Account Name \n\
and Account ID combinations. \n\
Limit to 25 characters including spaces.')
    
    f1 = ttk.Frame(f1_f2,  style = "B.TFrame")
    f1.place(relx=0.54, rely=0.24)
    f1.place(relheight=0.5, relwidth=0.42)
    accName_entry = ttk.Entry(f1, width=27, textvariable= aName)
    accName_entry.focus()
    accName_entry.pack()
    
    images_Create = [ A_D, A_R, A_P, A_SQ, A_SA]
    t_variable = [ accID, randomise, accPass, secQ,
                  secA]
    Tools = ['Enter the account ID for this account \n\
Limit to 25 characters including spaces.',
'A random value to encrypt the account. This could be numbers or letters \n\
or a combination of both. You will not need to remember this later.',
'Enter the password associated with this account. \n\
Limit to 25 characters including spaces.',
'Enter the Secret Question associated with this account, else \n\
leave this field blank. Limit to 25 characters including spaces.',
'Enter the Secret Answer associated with this account, else \n\
leave this field blank. Limit to 25 characters including spaces.']
           
    y_frame = 0.175                       
    for i in range(0,5):
        label_Create= Label(window1_label,image =images_Create[i],
                bd = -4,highlightthickness = -2)
        label_Create.place(relx=0.148, rely= y_frame)
        label_Create.place(relheight=0.07, relwidth=.71)
        ToolTip.ToolTip(label_Create, Tools[i])
        entry = ttk.Entry(label_Create, width=27,
                          textvariable= t_variable[i])
        entry.place(relx=0.54, rely=0.24)
        entry.place(relheight=0.5, relwidth=0.42)
        y_frame += 0.075

    acc_to_N_label= Label(window1_label,image =A_N,
                bd = -4,highlightthickness = -2)
    acc_to_N_label.pack_propagate(0)
    acc_to_N_label.place(relx=0.148, rely=0.55)
    acc_to_N_label.place(relheight=0.07, relwidth=.71)

    f7 = ttk.Frame(window1_label,  style = "B.TFrame")
    f7.place(relx=0.15, rely=0.62)
    f7.place(relheight=.1, relwidth=0.71)
    scrollbar = Scrollbar(f7)
    scrollbar.pack(side=RIGHT, fill=Y) 
    text= Text(f7, undo = True, wrap = 'word',font = "Palatino 12 ",
               yscrollcommand=scrollbar.set)
    text.place(relx=0.01, rely=0.00)
    text.place(relheight=.95, relwidth=.96)
    scrollbar.config(command=text.yview)
    
    button_images_Create = [close_B ]
    button_Create_commands = [C_destroy]
    tool_Create = ['Close this window']
    rel_y = 0.822  
    for i in range(0,1):
        frame_Create_for_buttons = ttk.Frame(window1_label,style = "B.TFrame")
        frame_Create_for_buttons.place(relx=0.395, rely=rel_y)
        frame_Create_for_buttons.place(relheight=0.05, relwidth=0.20)
        
        button_Create = ttk.Button(frame_Create_for_buttons,
                        image = button_images_Create[i], style = 'A.TButton',
               command = button_Create_commands[i] )    
        button_Create.pack_propagate(0)
        button_Create.pack()
        ToolTip.ToolTip(button_Create, tool_Create[i])

    menubar1 = Menu(window1)
    filemenu1 = Menu(menubar1, tearoff = 0)

    label_C = ["Clear entries", "Delete Window", "View Window", "Help",
             "About", "Close", "Exit"]
    command_C = [clear, goToDelete, goToView, goToHelp, goToAbout,
               C_destroy, goToQuit]
    accelerator_C = ["DEL", "Alt+D", "Alt+V", "Ctrl+H", "Ctrl+A",
                     "Ctrl+F4", "Ctrl+Q"]   
    for i in range(0,7):
        filemenu1.add_command( label=label_C[i], 
                command=command_C[i], accelerator=accelerator_C[i])
    menubar1.add_cascade(label="File", menu = filemenu1)
    window1.config(menu = menubar1)
    
    bind_C= [ "<Alt-d>", "<Alt-v>",  "<Delete>", "<Control-h>",
             "<Control-a>", "<Control-F4>", "<Control-q>"]
    bind_Command_C = [ goToDelete, goToView, clear, goToHelp,
                    goToAbout, C_destroy, goToQuit]   
    for i in range(0,7):
        window1.bind(bind_C[i], bind_Command_C[i])


def funcky(*args): # this function checks for password strength with entropy
    v2 = ttk.Label(root,style = "C.TLabel", width=127,
                           text = 'Master Password should ideally\n\
contain UPPERCASE, lowercase,\n\
digits, and special characters.\n\
However, you could also pick\n\
long phrases (7 to 8 words or more)\n\
that are easy for you to remember.\n\
They are much stronger than complex\n\
short passwords.\n\
For even better security add in some\n\
foreign phrases that are not common.',
                       relief = 'raised',font = "Palatino 12 bold", foreground = '#99ccff',padding="4 4 4 4")
    v2.place(relx=0.00, rely=.34)
    v2.place(relheight=0.27, relwidth=0.24)


    lower_alpha = 'abcdefghijklmnopqrstuvwxyz'
    upper_alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    num = '0123456789'
    special_C = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')',
 '-', '_', '=', '+', '{', '[', '}', ']', '|', '/', '"', ':', ';', ',', '<', '.', '>', '?', "'", '~', '`']
    password = mass_pass.get()
    length = len(password)
    lower = 0
    l_U = 0
    number =0
    sp = 0  
    check= []
    total_possible_set = 94    
    if length ==0:
        entropy = 0
    for item in password:
        if item in lower_alpha:         
            lower += 1
        if item in upper_alpha  :         
            l_U += 1
        if item in num:
            number +=1
        if item in special_C:
            sp +=1  
    if lower:
        check.append('lowercase... ')
    if l_U:
        check.append('UPPERCASE... ')
    if number:
        check.append('digits... ')
    if sp:
        check.append('special characters... ')             
    check_list = ['special characters... ', 'digits... ','UPPERCASE... ', 'lowercase... ']
    calc = [32,10,26,26]  
    #y = .185
    x = 0
    p = []
    xax = ''
    for item in check_list:
        
        if total_possible_set >0:
                entropy = length *(log10(total_possible_set)/log10(2))
        if item not in check :
            #print(length, 'length')
            p.append(item)
            z = xax.join(p)        
            v2 = ttk.Label(root,style = "C.TLabel", width=127,
                           text = 'password has no '+ z,
                       relief = 'raised',font = "Palatino 12 bold", foreground = '#999999',padding="4 4 4 4")

            v2.place(relx=0.275, rely=.564)
            v2.place(relheight=0.04, relwidth=0.45)
            total_possible_set = total_possible_set -calc[x]
            #print(total_possible_set,'total_possible_set')
            if total_possible_set >0:
                entropy = length *(log10(total_possible_set)/log10(2))
            #print(entropy)
        if entropy >50 and entropy <=90:
            v2 = ttk.Label(root,style = "C.TLabel", width=127, 
                           text = 'password is reasonably strong', anchor = CENTER,
                       relief = 'raised',font = "Palatino 12 bold", foreground = '#999999', padding="4 4 4 4")
            v2.place(relx=0.275, rely=.564)
            v2.place(relheight=0.04, relwidth=0.45)
        if entropy>90:
            v2 = ttk.Label(root,style = "C.TLabel", width=127,
                           text = 'password is very strong', anchor = CENTER,
                    relief = 'raised',font = "Palatino 12 bold",foreground = '#99ccff',padding="4 4 4 4")
            v2.place(relx=0.275, rely=.564)
            v2.place(relheight=0.04, relwidth=0.45)
        if len(check) == len(check_list) :
            total_possible_set = total_possible_set -calc[x]
            if total_possible_set >0:
                entropy = length *(log10(total_possible_set)/log10(2))
            #print(entropy)
            if length <9:
                 v2 = ttk.Label(root,style = "C.TLabel", width=127,
                           text = 'password is too short',
                       relief = 'raised',font = "Palatino 12 bold ", anchor = CENTER,
                                foreground = '#cc3333',padding="4 4 4 4")
                 v2.place(relx=0.275, rely=.564)
                 v2.place(relheight=0.04, relwidth=0.45)
            elif entropy >25 and entropy <=50:
                    v2 = ttk.Label(root,style = "C.TLabel", width=127, 
                           text = 'password is not strong enough', anchor = CENTER,
                       relief = 'raised',font = "Palatino 12 bold", foreground = '#ffffff', padding="4 4 4 4")
                    v2.place(relx=0.275, rely=.564)
                    v2.place(relheight=0.04, relwidth=0.45)
            elif entropy >50 and entropy <=90:
                    v2 = ttk.Label(root,style = "C.TLabel", width=127, 
                           text = 'password is reasonably strong', anchor = CENTER,
                       relief = 'raised',font = "Palatino 12 bold", foreground = '#999999', padding="4 4 4 4")
                    v2.place(relx=0.275, rely=.564)
                    v2.place(relheight=0.04, relwidth=0.45)
            elif entropy>90:
                    v2 = ttk.Label(root,style = "C.TLabel", width=127,
                           text = 'password is very strong', anchor = CENTER,
                       relief = 'raised',font = "Palatino 12 bold",foreground = '#99ccff',padding="4 4 4 4")
                    v2.place(relx=0.275, rely=.564)
                    v2.place(relheight=0.04, relwidth=0.45)
        x += 1 

def enter(*args): # this creates the buttons that allow access to
    #other windows in the program
    def goToQuit(*args):
        root.destroy()
        
    m = mass_pass.get()    
    mass_pass.set(m)  
    images = [create_B, delete_B, view_B, help_B, about_B, quit_B]
    commands = [goToCreate, goToDelete, goToView, goToHelp,
                goToAbout, goToQuit]
    tool = ['Create, encrypt and store a new account \n\
Keyboard shortcut: "Alt+C", but must enter Master Password first',
            'Delete any selected account \n\
Keyboard shortcut: "Alt+D", but must enter Master Password first',
            'Use your Master Password to '+\
            'decrypt and view any selected account \n\
Keyboard shortcut: "Alt+V", but must enter Master Password first',
            'Help, Keyboard shortcut: "Ctrl+H"',
            'About, Keyboard shortcut: "Ctrl+A"',
            'Close the program, Keyboard shortcut: "Ctrl+Q"']
    y = 0.14                   
    for i in range(0,6):
        frame =ttk.Frame(root,style = "E.TFrame")
        frame.place(relx=0.80, rely= y)
        frame.place(relheight=0.06, relwidth=0.23)
        y+=0.1292
        button = ttk.Button(frame,style ="A.TButton",
                 image = images[i], command =commands[i])
        button.place(relx=0.00, rely=0.11)
        button.place(relheight=0.90, relwidth=0.54)
        ToolTip.ToolTip(button, tool[i])

        root.bind("<Alt-c>", goToCreate)
        root.bind("<Alt-d>", goToDelete)
        root.bind("<Alt-v>", goToView)
        
def goToQuit(*args): # destroys the main window and the program
        root.destroy()
       
root = Tk()
root.title("Welcome to EN-CRYPTION!!")
root.geometry('1100x750+150+25')
root.config(background="#0a1219")
root.minsize(width = 1100, height = 750)
root.maxsize(width = 1100, height = 750)
    
# all window images
main_win = PhotoImage(file='Blue Final2.gif')
help_win = PhotoImage(file='Help Window.gif')
about_win = PhotoImage(file='About Window.gif')
create_win = PhotoImage(file='Create Window3.gif')
delete_win = PhotoImage(file='Delete Window.gif')
view_win = PhotoImage(file='View Window1.gif')

# all button images
enter_B = PhotoImage(file='Enter button.gif')
create_B = PhotoImage(file='Create Button.gif')
delete_B = PhotoImage(file='Delete button.gif')
view_B = PhotoImage(file='View button.gif')
help_B = PhotoImage(file='Help button.gif')
about_B = PhotoImage(file='About button.gif')
quit_B = PhotoImage(file='Quit button.gif')
encrypt_B = PhotoImage(file='Encrypt button.gif')
decrypt_B = PhotoImage(file='Decrypt button.gif')
clear_B = PhotoImage(file='Clear button.gif')
close_B = PhotoImage(file='Close button.gif')
clear_V = PhotoImage(file='Clear View.gif')
close_V = PhotoImage(file='Close View.gif')
Delete_D_B = PhotoImage(file='Delete B.gif')
Delete_C_B = PhotoImage(file='Clear B.gif')
Delete_Close_B = PhotoImage(file='Close B.gif')

# all label images
enter_mp = PhotoImage(file='Enter mp.gif')
acc_to_view = PhotoImage(file='Enter account to view.gif')
acc_ID = PhotoImage(file='Account ID 2.gif')
acc_P = PhotoImage(file='Account Password.gif')
S_Q = PhotoImage(file='Secret Question.gif')
S_A = PhotoImage(file='Secret Answer.gif')
Note = PhotoImage(file='Account Notes.gif')
D_box = PhotoImage(file='Decrypt Box.gif')
C_C_Box = PhotoImage(file='Clear Close.gif')
A_name = PhotoImage(file='A Name.gif')
A_D = PhotoImage(file='A ID.gif')
A_R = PhotoImage(file='A Random.gif')
A_P = PhotoImage(file='AP.gif')
A_SQ = PhotoImage(file='A SQ.gif')
A_SA = PhotoImage(file='A SA.gif')
A_N = PhotoImage(file='A N.gif')
D_name = PhotoImage(file='D Name.gif')
D_band = PhotoImage(file='Delete band.gif')
D_band2 = PhotoImage(file='Delete band 2.gif')
E_frame = PhotoImage(file='Encrypt Frame.gif')

#ttk styles
style = ttk.Style()
style.configure("A.TFrame",background = "#333333")
style.configure("B.TFrame",background = '#99ccff')
style.configure("C.TFrame",background = '#000000')
style.configure("E.TFrame",background = '#0a1219')
style.configure("Z.TFrame",background = '#990000')
style.configure('A.TButton',padx=20, pady=20)
style.configure("D.TFrame",background = "#333333",padding="3 3 3 3")
style.configure("B.TLabel",background = '#99ccff',height = 20)
style.configure("A.TLabel",background = "#333333",height = 20)
style.configure("C.TLabel",background = "#000000",height = 20)
style.configure("D.TLabel",background = "#cc3333",height = 20)
style.configure("E.TLabel",background = "#990033",height = 20)

frame1 = ttk.Frame(root, style = "E.TFrame")
frame1.place(relx=0.055, rely=0.10)
frame1.place(relheight=0.79, relwidth=0.90)
main_label= Label(frame1,image = main_win, bd = -4,
         highlightthickness = -2)
main_label.pack()

mass_pass= StringVar()
massPass_entry = ttk.Entry(root, width=21, textvariable= mass_pass)
massPass_entry.place(relx=0.455, rely=0.523)
massPass_entry.place(relheight=0.03, relwidth=0.15)
massPass_entry.focus()

notesy= StringVar()
m = mass_pass.get()

mass_pass.trace("w", funcky)

m_p_Button = ttk.Button(root,  image = enter_B,
                        style = 'A.TButton', command = enter)
m_p_Button.place(relx=0.62, rely=0.514)
m_p_Button.place(relheight=0.045, relwidth=0.13)

menubar = Menu(root)
filemenu = Menu(menubar, tearoff = 0)
filemenu.add_command( label="Help", 
                command=goToHelp, accelerator="Ctrl+H")
filemenu.add_command( label="About",
                command=goToAbout, accelerator="Ctrl+A")
filemenu.add_command( label="Exit",
                command=goToQuit, accelerator="Ctrl+Q")

menubar.add_cascade(label="File", menu = filemenu)
root.config(menu = menubar)

root.bind('<Return>', enter)
root.bind("<Control-h>", goToHelp)
root.bind("<Control-a>", goToAbout)
root.bind("<Control-q>", goToQuit)

root.mainloop()

  

