#!/usr/bin/env Python3      
import subprocess, socket, time
import psutil
from psutil._common import bytes2human
import os, sys, datetime, webbrowser
from tkinter import *
from tkinter import messagebox
import PySimpleGUI as sg
from health_check.providers import Resource
from health_check.providers import Provider
from subprocess import Popen, PIPE, STDOUT
import requests as req
import cmd
from tkinter.filedialog import askopenfilename
import tkinter.scrolledtext as tkst
import tkinter as tk
from tkinter import filedialog


new = 1
url2 = "www.ipchicken.com"
url3 = "www.speedtest.net"
url4 = "https://www.eset.com/afr/home/online-scanner/"
url5 = "https://earth.google.com/web/@0,0,-24018.82718741a,36750128.22569847d,35y,0h,0t,0r/data=CgAoAQ"
url6 = "https://www.ultratools.com/tools/ipWhoisLookup"
url7 = "https://mxtoolbox.com/"

def openEset():
    webbrowser.open(url4, new=new)
def openEarth():
    webbrowser.open(url5, new=new)
def openWhois():
    webbrowser.open(url6, new=new)
def openMX():
    webbrowser.open(url7, new=new)
def openSpeed():
    webbrowser.open(url3, new=new)
def openChicken():
    webbrowser.open(url2, new=new)
def ping():
    address = values['wipe1']
    pingnumber = values['wipe0']
    output = subprocess.run(["ping","-n",pingnumber,address], stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    window.FindElement('wipe2').Update(output)
    window.FindElement('wipe1').Update('')

# **** Menu Tools Functions ****
def cmdp():
    subprocess.Popen(["cmd.exe"])
def rdp():
    subprocess.Popen(["mstsc.exe"])
def fileexplorer():
    subprocess.Popen(["explorer.exe"])
def ctrlpanel():
    subprocess.Popen(["control.exe"])
def powershell():
    subprocess.Popen(["powershell.exe"])
def notepad():
    subprocess.Popen(["notepad"])
# **** Menu Admin Functions ****
def compmgmt():
    subprocess.call("control compmgmt.msc")
def bitlocker():
    subprocess.call("control /name Microsoft.BitLockerDriveEncryption")
def backup():
    subprocess.call("control /name Microsoft.BackupAndRestore")
def devicemgmt():
    subprocess.call("control /name Microsoft.DeviceManager")
def credmgmt():
    subprocess.call("control /name Microsoft.CredentialManager")
def datemgmt():
    subprocess.call("control /name Microsoft.DateAndTime")
def defpro():
    subprocess.call("control /name Microsoft.DefaultPrograms")
def devprint():
    subprocess.call("control /name Microsoft.DevicesAndPrinters")
def display():
    subprocess.call("control /name Microsoft.Display")
def indexopt():
    subprocess.call("control /name Microsoft.IndexingOptions")
def internetopt():
    subprocess.call("control /name Microsoft.InternetOptions")
def emailacct():
    subprocess.call("control mlcfg32.cpl")
def admintools():
    subprocess.call("control /name Microsoft.AdministrativeTools")
def netsharing():
    subprocess.call("control /name Microsoft.NetworkAndSharingCenter")
def poweropt():
    subprocess.call('control /name Microsoft.PowerOptions')
def profeat():
    subprocess.call('control /name Microsoft.ProgramsAndFeatures')
def seccenter():
    subprocess.call('control /name Microsoft.SecurityCenter')
def storagepool():
    subprocess.call('control /name Microsoft.StorageSpaces')
def acct():
    subprocess.call('control /name Microsoft.UserAccounts')
def useracct():
    subprocess.call('control.exe userpasswords2')
def winfire():
    subprocess.call('control /name Microsoft.WindowsFirewall')
def optfeat():
    subprocess.call('rundll32.exe shell32.dll,Control_RunDLL appwiz.cpl,,2')
def sysset():
    subprocess.call('control /name Microsoft.System')

# **** Menu Commands Functions ****
def netstat():
    output = subprocess.run(["netstat","-n"], stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    window.FindElement('wipe2').Update(output)
    window.FindElement('wipe1').Update('')

def gwc1():
    address = values['wipe3']
    output = subprocess.run(["tracert",address], stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    window.FindElement('wipe2').Update(output)
    window.FindElement('wipe3').Update('')
    
def gethostnip():
    hostname = socket.gethostname()    
    IPAddr = socket.gethostbyname(hostname)
    cpu = ("Your Computer Name is: " + hostname)
    addr = ("\nYour Computer IP Address is: " + IPAddr)
    results = cpu + addr
    window.FindElement('wipe2').Update(results)
def ipconfig():
    output = subprocess.run(["ipconfig","/all"], stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    window.FindElement('wipe2').Update(output)
def systeminfo():
    output = subprocess.run(["systeminfo"], stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    window.FindElement('wipe2').Update(output)
def process():
    output = subprocess.run(["tasklist"], stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    window.FindElement('wipe2').Update(output)
# **** Menu Performance Functions ****
def processes():

    window.FindElement('wipe2').Update('')
    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name', 'username'])
        except psutil.NoSuchProcess:
            pass
        else:
            window.FindElement('wipe2').Update(pinfo)
            
def diskusage():
    usage = psutil.disk_usage('/')
    d = "Disk Usage:\n\n"
    t = ("Total: {}".format(bytes2human(usage.total)))
    u = ("\nUsed: {}".format(bytes2human(usage.used)))
    f = ("\nFree: {}".format(bytes2human(usage.free)))
    p = ("\nPercent: %s%%" % round(usage.percent, 2))
    results = (d + t + u + f + p)
    window.FindElement('wipe2').Update(results)
        
def memory():
    usage = psutil.virtual_memory()
    m = "Memory Statistics:\n\n"
    t = ("Total: {}".format(bytes2human(usage.total)))
    u = ("\nUsed: {}".format(bytes2human(usage.used)))
    f = ("\nFree: {}".format(bytes2human(usage.free)))
    p = ("\nPercent: %s%%" % round(usage.percent, 2))
    results = (m + t + u + f + p)
    window.FindElement('wipe2').Update(results)
    
def cpuusage():
    cpu = psutil.cpu_percent(interval=1, percpu=True)
    window.FindElement('wipe2').Update(cpu)
def netconn():
    net = psutil.net_connections(kind='inet')
    window.FindElement('wipe2').Update(net)

def battery():
    def secs2hours(secs):
        mm, ss = divmod(secs, 60)
        hh, mm = divmod(mm, 60)
        return "%d:%02d:%02d" % (hh, mm, ss)
    if hasattr(psutil, "sensors_battery"):
        battery = psutil.sensors_battery()
    else:
        battery = None
    if battery:
        ch = ("Charge:     %s%%" % round(battery.percent, 2))
        L = ("\nLeft:       %s" % secs2hours(battery.secsleft))
        res = (ch + L)
        window.FindElement('wipe2').Update(res)
    
def boot():
    boot = psutil.boot_time()
    time = datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
    results1 = ("Boot Time: {} ".format(boot))
    results2 = ("\nTimestamp: {} ".format(time))
    results3 = (results1 + results2 )
    window.FindElement('wipe2').Update(results3)
# **** Help Functions ****

# **** Bottom Button Functions ****
def closeProgram():
    window.Close()
def clear():
    window.FindElement('wipe1').Update('')
    window.FindElement('wipe2').Update('')
def submit():
    contents = values['wipe2']
    f = filedialog.asksaveasfilename(   
        defaultextension=".txt",                 
        filetypes = (("text file", "*.txt"),    
             ("text", "*.txt")))
    with open(f, 'w') as outputFile:
        outputFile.write(contents)
    window.FindElement("wipe2").Update("")

def mail():
    win = tk.Tk()
    win.title("UBMT Dispatch")
    win.resizable(width=False, height=False)
    win.geometry("400x400")
    frame1 = Frame(win,width=390, height=390)
    frame1.configure(bg='black')
    frame1.place(x=5,y=5)

    def onclose():
        win.destroy()
    
    
def about():
    win = tk.Tk()
    win.resizable(width=False, height=True)
    win.geometry("200x200")
    win.mainloop()


# ------ Menu Definition ------ #      
menu_def = [['File', ['Open', 'Save', 'Exit', 'Properties']],
            
            ['Options', ['Services', ['Eset Scan','MxLookup','Whois IP',],
                        ['Tools',['Command Prompt','Control Panel','File Explorer',
                                   'PowerShell','Programs/Features','Storage Spaces',
                                   'System Settings',],
                        ['Performance',['Battery Usage','Boot Time','CPU Usage','Disk Usage',
                                        'Memory Usage','Network Connections',],],],],],            
            ['Commands',['Hostname/IP','IPConfig','Netstat','System Info',
                         'Tasklist'],],
            ['Admin', ['Administrative Tools',
                       ['Credential Manager','Internet Options',
                        'Optional Features','Network/Sharing',
                        'Security Center','User Accounts','Windows Firewall',],
                       ['Windows Tools',['Accounts','Default Programs','Devices/Printers',
                                         'Display Panel','Date/Time','Power Options',],],], ],
            ['World',['View Earth'],],
            
           ]      

# ------ Layout Definition ------ #      

layout = [      
    [sg.Menu(menu_def, tearoff=True)],          
    
    [sg.Frame(layout=[      
    [sg.Button('IP', size=(5,1),button_color=('black','#E0E0E0'),)],
    [sg.Button('Speed',size=(5,1),button_color=('black','#E0E0E0'),)],
    [sg.Button('Eset',size=(5,1),button_color=('black','#E0E0E0'),)],
    [sg.Button('Whois',size=(5,1),button_color=('black','#E0E0E0'),)],
    [sg.Button('MxLook',size=(5,1),button_color=('black','#E0E0E0'),)],
    [sg.Button('Earth',size=(5,1),button_color=('black','#E0E0E0'), ),],
    [sg.Button('Clear',size=(5,1),button_color=('black','#E0E0E0'))],
    [sg.Button('Save',size=(5,1),button_color=('black','#E0E0E0'))],
    [sg.Button('Exit',size=(5,1),button_color=('black','#E0E0E0'))],

    ], 
              title='', tooltip='',
              size=(10, 20), pad=None, border_width=None,
              background_color=None,relief="groove" ),      

    sg.Frame(layout=[      
    [sg.Text('Enter IP Address:', size=(13,1)),  sg.Input(size=(15,1),key='wipe1'),
     sg.Button('Ping',size=(5,1),button_color=('black','#E0E0E0')),
     sg.InputCombo(values=['4','8','12','16','20'],size=(3,1), key='wipe0'),],

    [sg.Multiline(size=(30, 15),key='wipe2')],
    [sg.Text('Enter Gateway:', size=(13,1)),sg.Input(size=(15,1),key='wipe3'),
     sg.Button('Trace',size=(5,1),button_color=('black','#E0E0E0'),)]
    ],
             title='', tooltip='',
             size=(40,20),pad=None,background_color=None)],
    

    ]  


window = sg.Window('Universal Bot Mesh Toolkit',
                   layout, default_element_size=(40, 1),
                   grab_anywhere=False,
                   background_color='Black',
                   resizable=False,size=(510,340),)      

while True:
    # Reads the Window
    event, values = window.Read()
    # Menu Services event Triggers
    if event == 'Eset Scan' or event == 'Eset':
        openEset()
    if event == 'Whois IP' or event == 'Whois':
        openWhois()
    if event == 'MxLookup' or event == 'MxLook':
        openMX()
    if event == 'View Earth' or event == 'Earth':
        openEarth()
    if event == 'Speed Test' or event == 'Speed':
        openSpeed()
    if event == 'Public IP' or event == 'IP':
        openChicken()
    # Menu Tools event Triggers
    if event == 'Remote Desktop':
       rdp() 
    if event == 'Control Panel':
        ctrlpanel()
    if event == 'File Explorer':
        fileexplorer()
    if event == 'Command Prompt':
        cmdp()
    if event == 'PowerShell':
        powershell()
    if event == 'Notepad':
        notepad()
    # Menu Commands event Triggers
    if event == 'Ping':
        ping()
    if event == 'Netstat':
        netstat()
    if event == 'Trace':
        gwc1()
    if event == 'Hostname/IP':
        gethostnip()
    if event == 'IPConfig':
        ipconfig()
    if event == 'System Info':
        systeminfo()
    if event == 'TaskList':
        process()
    #Menu Performance event Triggers
    if event == 'Disk Usage':
        diskusage()
    if event == 'CPU Usage':
        cpuusage()
    if event == 'Memory Usage':
        memory()
        
    if event == 'Network Connections':
        netconn()
    if event == 'Battery Usage':
        battery()
    if event == 'Boot Time':
        boot()

    #Menu Admin event Triggers
    if event == 'Administrative Tools':
        admintools()
    if event == 'Network/Sharing':
        netsharing()
    if event == 'Power Options':
        poweropt()
    if event == 'Computer Management':
        compmgmt()
    if event  == 'Credential Manager':
        credmgmt()
    if event == 'Date/Time':
        datemgmt()
    if event == 'Default Programs':
        defpro()
    if event == 'Devices/Printers':
        devprint()
    if event == 'Display Panel':
        display()
    if event == 'Indexing Options':
        indexopt()
    if event == 'Internet Options':
        internetopt()
    if event == 'Email Accounts':
        emailacct()
    if event == 'Programs/Features':
        profeat()
    if event == 'Security Center':
        seccenter()
    if event == 'Storage Spaces':
        storagepool()
    if event == 'Accounts':
        acct()
    if event == 'User Accounts':
        useracct()
    if event == 'Windows Firewall':
        winfire()
    if event == 'Optional Features':
        optfeat()
    if event == 'System Settings':
        sysset()
    
        
    # Bottom button event Triggers
    
    if event == 'Clear':
        clear()
    if event  == 'Save':
        submit()
    # Menu File event Triggers
    if event is None or event == 'Exit':
        closeProgram()
        break          
window.Close()

