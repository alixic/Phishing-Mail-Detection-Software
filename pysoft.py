import numpy as np
import collections
import pandas as pd
import string as string
import tkinter as tk
from tkinter import filedialog

from difflib import SequenceMatcher
import Levenshtein
import re

INPUT=""

# - output cu, cuvintele malitioase gasite pentru introducerea acestora in algoritmul de statistica.

# - STATISTICA VA AVEA CA REFERINTA BAZA DE DATE SI SE VA FACE O ASOCIERE PT FIECARE CUVANT (DIN DB) CU NR DE APARITII CARE A FOST IDENTIFICAT

# - SAU - PUTEM EXTRAGE NR DE CUVINTE DIN BAZA DE DATE SI CUVINTELE DIN BAZA DE DATE CARE NU AU FOST GASITE IN MAIL VOR AVEA AUTOMAT NR DE APARITII NUL 





mailadd_DB = [
    
    "support@microsoft.com", "noreply@apple.com", "support@google.com", "no-reply@amazon.com", 
    "support@facebook.com", "help@adobe.com", "support@intel.com", "noreply@ibm.com", 
    "support@nvidia.com", "support@dell.com", "support@hp.com", "support@lenovo.com", 
    "support@cisco.com", "support@oracle.com", "support@salesforce.com", 
    "support@sap.com", "feedback@slack.com", "support@zoom.us", "support@atlassian.com", 
    "support@linkedin.com", "support@twitter.com", "help@instagram.com", 
    "support@pinterest.com", "support@snapchat.com", "support@tiktok.com", 
    "support@reddit.com", "support@tumblr.com", "support@whatsapp.com", 
    "help@messenger.com", "support@ebay.com", "help@walmart.com", 
    "help@target.com", "support@costco.com", "help@bestbuy.com", 
    "support@alibaba.com", "help@etsy.com", "support@shopify.com", 
    "support@wayfair.com", "help@overstock.com", "support@paypal.com", 
    "support@square.com", "support@stripe.com", "support@visa.com", 
    "help@mastercard.com", "support@americanexpress.com", 
    "support@discover.com", "support@chase.com", "support@citibank.com", 
    "support@wellsfargo.com", "support@bankofamerica.com", "help@verizon.com", 
    "support@att.com", "support@t-mobile.com", "support@sprint.com", 
    "support@vodafone.com", "support@comcast.net", "support@spectrum.com", 
    "help@charter.com", "support@netflix.com", "support@hulu.com", 
    "help@disneyplus.com", "support@primevideo.com", "help@hbomax.com", 
    "support@spotify.com", "help@pandora.com", "support@youtube.com", 
    "support@edx.org", "support@coursera.org", "support@khanacademy.org", 
    "support@udemy.com", "support@mit.edu", "help@harvard.edu", 
    "help@stanford.edu", "info@ox.ac.uk", "info@cam.ac.uk", 
    "info@usa.gov", "support@nhs.uk", "help@irs.gov", "support@gov.uk", 
    "support@europa.eu", "support@dropbox.com", "help@box.com", 
    "support@wework.com", "support@mailchimp.com", "support@zoho.com", 
    "help@wix.com", "support@squarespace.com", "help@wordpress.com",
    
]






### - BAD WORDS DATABASE*

swords = [
    "urgent", "immediate", "Act now", "Action required", "Respond quickly", "Limited time offer", "Confirm now",
    "Verify your account", "Time-sensitive", "Final notice", "Last warning", "Lockout warning", "Refund", "Invoice",
    "Payment", "Overdue", "Transaction", "Credit card", "Wire transfer", "Bank account", "Pay now", "Billing",
    "Unpaid", "Settlement", "Balance due", "Verify", "Confirm", "Update account", "Login required", "Reset password",
    "Authentication failed", "Identity check", "Account validation", "Secure your account", "Re-activate", "Your bank",
    "PayPal", "Amazon", "Apple", "Microsoft", "Google", "Netflix", "IRS", "Social Security Administration", "eBay",
    "IT Department", "Helpdesk", "Suspended", "Disabled", "Compromised", "Blocked", "Breach detected", "Malicious activity",
    "Unauthorized access", "Security alert", "Warning", "Virus detected", "Firewall", "Congratulations", "Winner", "Prize",
    "Lottery", "Free", "Gift card", "Special offer", "Exclusive deal", "Earn money", "Cashback", "Bonus", "Open attachment",
    "Download here", "Click below", "Review document", "Secure download", "Important file", "Please see attached", "Click here",
    "Access here", "Visit this link", "Log in now", "View details", "Verify link", "Follow this URL", "Dear Customer",
    "Dear User", "Amaz0n", "Micr0soft", "confirm now", "bank", "bank account", 
    "alert", "breach", "claim", "confidential", "credentials", "crypto", "password", "payout", "phishing", 
    "sensitive", "threat", "verify", "warning", "access", "bitcoin", "card", "compromise", "credentials", 
    "fraud", "hack", "insurance", "legal", "limited", "login", "loss", "money", "offer", "password", 
    "private", "protected", "risk", "safety", "secret", "security", "steal", "win", "your account", "Dear Customer",
]



weights = [
    9, 9, 8, 8, 8, 7, 8, 8, 8, 8, 9, 9, 8, 7, 7, 7, 8, 8, 8, 8, 8,   # High to critical risk
    6, 6, 6, 6, 7, 8, 9, 8, 8, 8, 8, 7, 7, 9, 9, 7, 6, 6, 6, 6,       # Medium to high risk
    5, 5, 5, 6, 6, 6, 8, 8, 5, 5, 5, 6, 7, 7, 5, 5, 5, 5, 4, 4,       # Medium risk
    3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 3, 3, 3, 4, 4, 3, 3, 3,       # Low to medium risk
    2, 2, 2, 3, 3, 2, 2, 2, 3, 3, 2, 3, 3, 2, 2, 2, 3, 3, 3, 2,       # Minimal to low risk
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 8, 8, 8, 9, 9, 8, 8, 8, 8, 8,       # High to critical accounts/security
    7, 6, 7, 6, 7, 7, 6, 6, 6, 6, 6, 6, 5, 6, 5, 5, 5, 6, 6, 5        # Medium to high generic accounts
]




malicious_links = [
    "https://accountverification.paypal-update.com",
    "http://secureverify-auth-appleid.com",
    "http://login-verification-amazon-support.com",
    "https://secure-login-update-microsoftsupport.net",
    "http://google-drive-security-check.com",
    "http://account-update-paypalservices.com",
    "https://appleid-update-verification.co",
    "http://secure-paypal-authentication-update.com",
    "http://verify-apple-accounts-update.com",
    "https://account-recovery-google-security.com",
    "https://login-update-outlook-secure.com",
    "http://paypal-confirmation-recovery.net",
    "http://auth-verification-bank-login.com",
    "https://comcast-customer-verification-link.com",
    "https://apple-login-verification-check.com",
    "http://secure-verification-visa.com",
    "http://login-update-google-drive-alerts.com",
    "http://securepaypal-update.account-services.com",
    "http://account-verification-dropbox-update.com",
    "http://microsoft-support-verification-confirm.com",
    "https://alerts-facebook-loginconfirm.com",
    "http://bank-verify-login-secureupdate.com",
    "https://support-microsoftauth-login-verification.com",
    "https://tax-refund-irs-verification.com",
    "http://secure-verify-amazonaccount-update.com",
    "https://google-confirm-login-alerts.com",
    "http://account-verify-apple-auth.com",
    "http://comcast-verification-secure-alerts.com",
    "https://login-update-facebook-secure.com",
    "https://paypal-secure-loginupdate.net",
    "http://secure-verify-login-appleaccount.com",
    "https://outlook-verify-account-auth.com",
    "https://google-accountupdate-alert.com",
    "http://alert-secureupdate-google-authentication.com",
    "http://verification-support-link-secure-amazon.com",
    "http://appleid-support-account-authentication.com",
    "http://amazon-account-security-check.com",
    "https://dropbox-verification-alerts.com",
    "https://secure-verification-googleaccount.net",
    "http://verification-update-amazon-safety.com",
    "http://bank-secure-update-loginservice.com",
    "http://login-security-verification-amazon.com",
    "http://account-update-link-microsoftalerts.com",
    "https://google-alert-verification-security.com",
    "https://account-recovery-bank-loginsecure.com",
    "https://verify-facebook-secure-alert.com",
    "http://paypal-login-verification-support.net",
    "https://amazon-secure-auth-loginupdate.com",
    "http://outlook-login-verify-authentication.com",
    "http://tax-refund-secure-verification.com",
    "https://link-secure-facebook-update.com"
]



def is_similar(word1, word2, max_distance=16):
    
    distance = Levenshtein.distance(word1, word2)
    return distance <= max_distance



def MailAddExt1(incont):
    mail = incont
    pmail = str(mail)

    varchk = "From: "

    n=len(pmail)
    nv=len(varchk)

    bufstr=""
    mailadd=""

    index=0
    for i in range(n):
            for j in range(nv):
                if i+j>=n:
                    break
                bufstr=bufstr+pmail[i+j]   
            if(bufstr==varchk):
                index=i
                #print("1")
                n=index

                while pmail[n]!='<' and n<len(pmail)-1:
                    n+=1
                n+=1
                while pmail[n]!='>' and n<len(pmail)-1:
                    mailadd=mailadd+pmail[n]
                    n+=1
                
            bufstr=""
   
    #print(mailadd)
    dblen=len(mailadd_DB)

    for i in range(dblen):

        if(mailadd==mailadd_DB[i]):
            return 2
            #string-urile sunt exact la fel
        else:
            if(is_similar(mailadd_DB[i], mailadd)):
               #print("Found similar add - phishing address")
               #print(f"{mailadd_DB[i]} ", f"{mailadd}")
                return 1
            else:
                #nUll=""
                return 0




def MailAddExt2(incont2):
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emails = re.findall(email_pattern, incont2)

    i=0
    while i<len(mailadd_DB)-1:
        if(emails==mailadd_DB):
            break
        else:
            if(is_similar(emails,mailadd_DB[i])):
               return 1
        i+=1  
        #return emails
        #print("Email addresses found:", emails)
    return 0



def mLinkFinder(mcont): 
    inmail = ""
    inmail = str(mcont)
    strlen = len(inmail)
    strsearch = ["https"]  

    url=""  
    b=0
    for i in range(strlen-1):
        for j in range(len(strsearch[0])):  
            strval=strsearch[0]
            if i+j>=strlen or inmail[i+j]!=strval[j]:  
                b=0
                break
            b=1  
        while i<strlen and b==1:  
            url+=inmail[i]
            i+=1
            if i>=strlen:  
                break
            if inmail[i].isspace():  
                return url
    return 0
                


def RemovePunctuation(sentence):
    sentence = sentence.translate(str.maketrans('','',string.punctuation))
    return sentence


def ExtractWords(sentence):
    sentence = RemovePunctuation(sentence)
    sentence = str.lower(sentence)
    return sentence.split()


def CalculateBOW(wordList):
    l_dict = dict.fromkeys(wordList ,0)
    for word in wordList:
        l_dict[word] = wordList.count(word)
    return l_dict







def fINPUT():
    
    IN = INPUT.get()
    output_text.delete('1.0', tk.END)
    
    wordList = ExtractWords(IN)
    dictionary = CalculateBOW(wordList=wordList)
    #print(dictionary)

    """
    sout=str(dictionary)
    i=0
    auxstr=""
    while i<len(sout):
          #ord() - conversie din char in int si 39 reprez valoarea coresp caracterului '
          if(ord(sout[i])==39):
              i+=1
              while( (ord(sout[i])!=39) and (i<len(sout)) ):
                  auxstr=auxstr+sout[i]
                  i+=1
          else:
              i+=1
              
    for j in range(len(swords)):
              if(auxstr==swords[j]):
                  associated_output = auxstr
                  output_text.insert(tk.END, associated_output)
                  INPUT.set("")
              else:
                  associated_output = ""
                  output_text.insert(tk.END, associated_output)
                  INPUT.set("")
    """

    sdct=str(dictionary)

    data_dict = eval(sdct)
    keys_array = list(data_dict.keys())
    values_array = list(data_dict.values())

    
    maxWcnt=len(swords) # nr de cuvinte malitioase posibile
    
    associated_output = "{"
    bwcnt=0 #bad_words count
    
    for i in range(len(swords)):
        occ_val = data_dict.get(str(swords[i]), 0)
        if occ_val != 0:
            bwcnt+=1
            outpart = f"{swords[i]}:{occ_val},"
            associated_output += outpart
    
    #associated_output = dictionary

    associated_output = associated_output + f" {bwcnt}"
    associated_output = associated_output+'}'
    out1 = associated_output
    selm = ""
    xsum = 0

    RESULT=""
    
    if out1[0] == '{':
        i = 1
        while i < len(out1):
            if out1[i] != ':':
                selm += out1[i]
            else:
                try:
                    ind = swords.index(selm)  
                    occ_nr = 0
                    i += 1
                    while i < len(out1) and out1[i].isdigit():  
                        occ_nr = occ_nr * 10 + int(out1[i])  
                        i += 1
                    xsum += occ_nr * weights[ind]  
                    #print(xsum)
                    nr = int(out1[len(out1)-2])
                    state_val = (xsum / (len(swords)-nr))
                    #print(state_val)


                    phm_lvl=0 # nivel de mail phishing
                    if (state_val>0.4): #putem adauga si conditie ca continutul mail-ului sa fie mic.
                        phm_lvl+=2
                    
                    if (MailAddExt1(IN) or MailAddExt2(IN)):
                        phm_lvl+=4
                        
                    if (MailAddExt1(IN)>1):
                        phm_lvl=phm_lvl-4

                    if (mLinkFinder(IN)!=None):
                        #check for malicious link
                        #phm_lvl+=1
                        for i in range(len(malicious_links)):
                                       if(is_similar(mLinkFinder(IN),malicious_links[i]) or ("http" in mLinkFinder(IN))):
                                          phm_lvl+=1

                    if(phm_lvl==0 or phm_lvl<2):
                        associated_output="The mail content is marked as an regular mail."
                    if(phm_lvl>=2 and phm_lvl<4):
                        associated_output="The mail content is a possible phishing mail."
                    if(phm_lvl>=4):
                        associated_output="The mail content is considered a phishing mail."
                    
                except ValueError:
                    pass  
                selm = ""  
            i += 1

    
    #print(associated_output)
    output_text.insert(tk.END, associated_output)
    INPUT.set("")
    





def open_file():
    
    file_path = filedialog.askopenfilename(title="Select a File", filetypes=(("Text Files", "*.txt"), ("All Files", "*.*")))
    
    if file_path:
        
        content = open(f"{file_path}", 'r')
        content2 = content.read()
           
        print("")
        strcontent=str(content2)
        #print(strcontent)
        
    IN=strcontent
    output_text.delete('1.0', tk.END)
    
    wordList = ExtractWords(IN)
    dictionary = CalculateBOW(wordList=wordList)
    print(dictionary)

    sdct=str(dictionary)

    data_dict = eval(sdct)
    keys_array = list(data_dict.keys())
    values_array = list(data_dict.values())

    associated_output = ""
    for i in range(len(swords)):
        occ_val = data_dict.get(str(swords[i]), 0)
        if occ_val != 0:
            outpart = f"'{swords[i]}' - nr_aparitii: {occ_val} "
            associated_output += outpart
    
    #associated_output = dictionary
    OUTPUT=associated_output
    output_text.insert(tk.END, associated_output)
    INPUT.set("")






### GUI Setup

GUI = tk.Tk()
GUI.title("Proiect Python | Byte-Builders - PHISHING MAIL TOOL DETECTION")
geo = "1400x700"

length = len(geo)
fn = ""
sn = ""

i = 0
while geo[i] != 'x':
    fn = fn + geo[i]
    i += 1
i += 1

while i < length:
    sn = sn + geo[i]
    i += 1

GUI.geometry(geo)
GUI.configure(bg="#f0f8ff")
INPUT = tk.StringVar()

frame1 = tk.Frame(GUI, bg="#f0f8ff")
frame1.pack(pady=20)
label1 = tk.Label(frame1, text="Phishing Mail Detection Tool", fg="blue", bg="#f0f8ff", font=("Helvetica", 20, "bold"))
label1.pack()

label2 = tk.Label(GUI, text="By Team Byte-Builders", fg="green", bg="#f0f8ff", font=("Arial", 16, "italic"))
label2.place(relx=0.98, rely=0.98, anchor=tk.SE)

input_frame = tk.Frame(GUI, bg="#f0f8ff")
input_frame.pack(pady=50)

inlabel = tk.Label(input_frame, text='INPUT', font=('Helvetica', 16, 'bold'), bg="#f0f8ff")
inlabel.grid(row=0, column=0, padx=10)

inentry = tk.Entry(input_frame, textvariable=INPUT, font=('Helvetica', 16), width=30, bd=2, relief="solid")
inentry.grid(row=0, column=1, padx=10)

btn_input = tk.Button(input_frame, text='Enter', font=('Helvetica', 14, 'bold'), bg="#4682B4", fg="white", activebackground="#5A9", activeforeground="white", command=fINPUT)
btn_input.grid(row=0, column=2, padx=10)


btn_file = tk.Button(input_frame, text="Select File", font=('Helvetica', 14, 'bold'), bg="#4682B4", fg="white", activebackground="#5A9", activeforeground="white", command=open_file)
btn_file.grid(row=1, column=0, columnspan=3, pady=10)  


output_frame = tk.Frame(GUI, bg="#f0f8ff")
output_frame.pack(pady=20)

output_label = tk.Label(output_frame, text='OUTPUT', font=('Helvetica', 16, 'bold'), bg="#f0f8ff")
output_label.pack()

output_text = tk.Text(output_frame, height=5, width=80, font=('Helvetica', 14), bg="#ffffff", bd=2, relief="solid")
output_text.pack()

hint_label = tk.Label(GUI, text="Introduceți textul de verificat și apăsați Enter.", font=("Helvetica", 12), bg="#f0f8ff", fg="#555")
hint_label.pack()

GUI.mainloop()
