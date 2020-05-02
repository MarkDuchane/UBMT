#!/usr/bin/env Python3      
import ctypes
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
from winreg import *
import requests as req
import cmd
import threading
from queue import Queue
from tkinter.filedialog import askopenfilename
import tkinter.scrolledtext as tkst
import tkinter as tk
from tkinter import filedialog



x = 1500
sys.setrecursionlimit(x) 


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

# Function Definitions

new = 1
url2 = "www.ipchicken.com"
url3 = "www.speedtest.net"
url4 = "https://www.eset.com/afr/home/online-scanner/"
url5 = "https://earth.google.com/web/@0,0,-24018.82718741a,36750128.22569847d,35y,0h,0t,0r/data=CgAoAQ"
url6 = "https://www.ultratools.com/tools/ipWhoisLookup"
url7 = "https://mxtoolbox.com/"
url8 = "https://ipleak.net/"
url9 = "www.deviceinfo.me"

def openChicken():
    webbrowser.open(url2, new=new)
def openSpeed():
    webbrowser.open(url3, new=new)
def openEset():
    webbrowser.open(url4, new=new)
def openEarth():
    webbrowser.open(url5, new=new)
def openWhois():
    webbrowser.open(url6, new=new)
def openMX():
    webbrowser.open(url7, new=new)
def openVPNLeak():
    webbrowser.open(url8, new=new)
def openFingerprint():
    webbrowser.open(url9, new=new)
    
def ping():
    address = values['wipe1']
    pingnumber = values['wipe0']
    msg2 = "One moment please. Your request is being processed\n"
    try:
        window.FindElement('wipe2').Update(msg2)
        output = subprocess.check_output(["ping","-n",pingnumber,address],
                                         stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)                 
def threadping():
    t = threading.Thread(target=ping)
    t.start()

def trace():
    address = values['wipe1']
    msg2 = ("One moment please. Your request is being processed\n" +
           "This may take a while. :)")
    try:        
        window.FindElement('wipe2').Update(msg2)
        output = subprocess.check_output(["tracert",address],
                                         stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
        window.FindElement('wipe1').Update('')
    except subprocess.CalledProcessError as e:        
        window.FindElement('wipe2').Update(e.output)    
def threadtrace():
    t = threading.Thread(target=trace)
    t.start()
    


# **** Menu Commands Functions ****

def taskkill():
    pid = values['task']

    try:        
        output = subprocess.check_output(["taskkill","/f","/pid",pid],
                                         stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
        window.FindElement('task').Update('')        
    except subprocess.CalledProcessError as e:
        window.FindElement('task').Update('')
        window.FindElement('wipe2').Update(e.output)


def netstat():
    try:        
        output = subprocess.check_output(["netstat","-ano"],
                                         stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
        window.FindElement('wipe1').Update('')
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)

def driverquery():   
    try:
        output = subprocess.check_output(["driverquery","/fo","table"],
                                         stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)        
    except subprocess.CalledProcessError as e:        
        window.FindElement('wipe2').Update(e.output)
    
def arp():
    try:        
        output = subprocess.check_output(["arp","-a"],
                                         stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
        window.FindElement('wipe1').Update('')
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)

def serialnumber():
    try:        
        output = subprocess.check_output(["wmic","bios","get","serialnumber"],
                                         stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)

def productkey():
    try:
        output = subprocess.check_output(["wmic","path","softwarelicensingservice","get",
                                          "OA3xOriginalProductKey"], stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)

def cmdkeylist():
    try:
        output = subprocess.check_output(["cmdkey","/list"], stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)

def searching():
    domain = values['wipe1']
    query = values['check']

    try:        
        output = subprocess.check_output(["nslookup",query,domain],
                                         stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
        window.FindElement('wipe1').Update('')
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)
        
def gethostnip():
    hostname = socket.gethostname()    
    IPAddr = socket.gethostbyname(hostname)
    cpu = ("Your Computer Name is: " + hostname)
    addr = ("\nYour Computer IP Address is: " + IPAddr)
    results = cpu + addr

    window.FindElement('wipe2').Update(results)

def gethostname():
    hostname = values['wipe1']
    address = socket.gethostbyname(hostname)
    results = ('The IP address of {} is {}'.format(hostname, address))
    window.FindElement('wipe2').Update(results)
    window.FindElement('wipe1').Update('')

def gethostaddr():
    address = values['wipe1']
    hostname = socket.gethostbyaddr(address)   
    results = ('The Hostname to IP Address of {} is {} '.format(address, hostname))
    window.FindElement('wipe2').Update(results)
    window.FindElement('wipe1').Update('')

def getdomain():
    fqdn = values['wipe1']
    domain = socket.getfqdn(fqdn)
    results = ('The Fully Qualified Domain Name of IP Address {} is {} '.format(fqdn,domain))
    window.FindElement('wipe2').Update(results)
    window.FindElement('wipe1').Update('')

def advertisewireless():
    try:        
        output = subprocess.check_output(["netsh","wlan","show","network"],
                                         stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
        window.FindElement('wipe1').Update('')
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)
        
def investigatewireless():

    try:        
        output = subprocess.check_output(["netsh","wlan","show","profiles"],
                                         stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
        window.FindElement('wipe1').Update('')
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)

def showwirelesspassword():
    ssid = values['ssid']
    try:
        
        output = subprocess.check_output(["netsh","wlan","show","profiles","name=",ssid,"key=clear"],
                                         stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
        window.FindElement('ssid').Update('')
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)

def tcpconn():
    try:        
        output = subprocess.check_output(["netsh","interface","ipv4","show","tcpconnections"],
                                         stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)
def udpconn():
    try:        
        output = subprocess.check_output(["netsh","interface","ipv4","show","udpconnections"],
                                         stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)

    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)
                        
def ipconfig():
    try:        
        output = subprocess.check_output(["ipconfig","/all"],
                                         stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)

def routeprint():
    try:
        output = subprocess.check_output(["route","print"], stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)


def showinterface():
    try:        
        output = subprocess.check_output(["netsh","interface","show","interface"],
                                         stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)

def macaddresses():
    try:
        output = subprocess.check_output(["getmac","/fo","table","/nh","/v"],
                                         stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)
        
def systeminfo():
    try:        
        output = subprocess.check_output(["systeminfo"],
                                         stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)

def logoff():
    try:
        output = subprocess.check_output(["shutdown","/l"], stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)

def restart():
    try:
        output = subprocess.check_output(["shutdown","/r"], stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)

def shutdown():
    try:
        output = subprocess.check_output(["shutdown","/s"], stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)

def remoteshutdown():
    try:
        output = subprocess.check_output(["shutdown","/i"], stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)
        
def process():
    try:
        output = subprocess.check_output(["tasklist","-svc"],
                                         stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=True)
        window.FindElement('wipe2').Update(output)
    except subprocess.CalledProcessError as e:
        window.FindElement('wipe2').Update(e.output)
    
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
            
 # An alternative way of formatting the output instead of using import bytes2human          
def diskusage():
    disk = psutil.disk_usage('/')
    total = disk.total
    ftotal= (total) / 1024**3
    used = disk.used
    fused = (used) / 1024**3
    free = disk.free
    ffree = (free) / 1024**3
    percent = disk.percent
    
    d = ("\tDisk Usage Statistics:")
    t = ("\nTotal: {0:.2f}GB ".format(ftotal))
    u = ("\nUsed: {0:.2f}GB ".format(fused))
    f = ("\nFree: {0:.2f}GB ".format(ffree))
    p = ("\nPercentage: {0:.2f}% ".format(percent))
    r = (d + t + u + f + p)
    window.FindElement('wipe2').Update(r)

        
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
    cpu = psutil.cpu_percent(interval=None)
    u = ("CPU Usage: {0:.2f}% ".format(cpu))
    window.FindElement('wipe2').Update(u)
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
        st = "Battery Stats: "
        ch = ("\n\nCharge:     %s%%" % round(battery.percent, 2))
        L = ("\nLeft:       %s" % secs2hours(battery.secsleft))
        res = (st + ch + L)
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

#New Features to be added in Version 1.3

def encryptmsg():
    msg = ("Im sorry this feature is only available" +
           " in UBMT version 1.3. ")
    sg.popup(msg)
def scannermsg():
    msg = ("Im sorry this feature is only available" +
           " in UBMT version 1.3. ")
    sg.popup(msg)




# ------ Menu Definition ------ #      


#Creates the Menu    
menu_def = [['File', ['Open', 'Save', 'Exit', 'Properties']],
            
            ['Options', ['Services', ['IP Chicken','Speed Test','Eset Scan','MxLookup',
                                      'Whois IP','Finger Print','VPN Leak'],
                        ['Tools',['Command Prompt','Control Panel','File Explorer',
                                   'PowerShell','Programs/Features','Storage Spaces',
                                   'System Settings',],
                        ['Performance',['Battery Usage','Boot Time','CPU Usage','Disk Usage',
                                        'Memory Usage','Network Connections',],],],],],            
            ['Commands',['Arp -a','Advertised Wireless Networks','Computer Hostname/IP','IP Configuration',
                         'Netstat -ano','Serial Number','Show Interface','MacAddresses','System Info',
                         'Investigate Wireless','TaskList','ProductKey','DriverQuery',
                         'CMDKey/List','Route Print','Restore','Logoff','Restart','Shutdown',
                         'RemoteShutdown','TCPConnections','UDPConnections'],],
            ['Admin', ['Administrative Tools',
                       ['Credential Manager','Internet Options',
                        'Optional Features','Network/Sharing',
                        'Security Center','User Accounts','Windows Firewall',],
                       ['Windows Tools',['Accounts','Default Programs','Devices/Printers',
                                         'Display Panel','Date/Time','Power Options',],],], ],
            ['World',['View Earth'],],
            
           ]      

# ------ Layout Definition ------ #      

# Administer Tab
# Tab1 Layout
tab1_layout = [
                 [sg.Frame(layout=[      
                        [sg.Button('IP', size=(7,1),button_color=('black','#E0E0E0'),
                                   tooltip='View your Public IP address')],
                        [sg.Button('Speed',size=(7,1),button_color=('black','#E0E0E0'),
                                   tooltip='Run a speed test')],
                        [sg.Button('Eset',size=(7,1),button_color=('black','#E0E0E0'),
                                   tooltip='Eset Online Scanner')],
                        [sg.Button('Whois',size=(7,1),button_color=('black','#E0E0E0'),
                                   tooltip='IP Address Lookup')],
                        [sg.Button('MxLook',size=(7,1),button_color=('black','#E0E0E0'),
                                   tooltip='MX Record Lookup')],
                        [sg.Button('VPNLeak',size=(7,1),button_color=('black','#E0E0E0'),
                                   tooltip='Test your VPN'+'\nNote: When using this site you' +
                                   '\nshould be connected to a VPN'),],
                        [sg.Button('Finger',size=(7,1),button_color=('black','#E0E0E0'),
                                   tooltip='Device security testing \nand privacy testing')],
                        [sg.Button('Earth',size=(7,1),button_color=('black','#E0E0E0'),
                                   tooltip='View maps using google earth')],
                        [sg.Button('Clear',size=(7,1),button_color=('black','#E0E0E0'),
                                   tooltip='Clear output information \non the screen')],
                        [sg.Button('Exit',size=(7,1),button_color=('black','#E0E0E0'),
                                   tooltip='Close\Exit the program')],
                        ], 
                              title='Q-Web Launch',
                           size=(10, 20), pad=None, border_width=None,
                              background_color=None,relief="groove" ),
                  
                     
                     sg.Frame(layout=[    
                        [sg.Text('Enter IP or Domain Name:', size=(20,1)),sg.Input(size=(30,1),key='wipe1'),
                         sg.InputCombo(values=['-q=MX','-q=A','-q=AAAA','-q=SOA'],size=(5,1),key='check'),
                         sg.Button('Search', size=(10,1),button_color=('green','black'))],
                         [sg.Button('Ping',size=(5,1),button_color=('black','#E0E0E0')),
                         sg.InputCombo(values=['4','8','12','16','20'],size=(3,1), key='wipe0'),
                         sg.Button('Trace',size=(5,1),button_color=('black','#E0E0E0')),
                         sg.Button('Get Host IP',size=(9,1),button_color=('black','#E0E0E0')),
                         sg.Button('Get IP Host',size=(9,1),button_color=('black','#E0E0E0')),],

                        [sg.Multiline(size=(70, 15),key='wipe2'),],
                        [sg.Text('Enter a PID:',size=(10,1)),sg.Input(size=(9,1),key='task'),
                         sg.Button('TaskKill',tooltip="You can get a list of PID's" +
                                   "\nby running Netstat located " +
                                   "\nin the menu command tab. ",
                         size=(8,1),button_color=('black','#E0E0E0'))],
                
                        [sg.Text('Enter SSID:',size=(10,1)),sg.Input(size=(20,1),key='ssid'),
                         sg.Button('Show Password',tooltip="You have to enter a Network" +
                                   "\nthis machine has connected to previously " +
                                   "\nRun Investigate Wireless located in the" +
                                   " \ncommand menu to list"+ "\nyour network history",
                                   size=(15,1),button_color=('black','#E0E0E0')),],
                        
                        ],
                     title='',
                     size=(10, 20), pad=None, border_width=None,
                     background_color=None,relief="groove" ),
            ],     
                
                ]
                
#______________________________________________________________________________________________________

# Encryption Tab
# Tab 2 Layout
tab2_layout = [
                 [sg.Frame(layout=[    
                        [sg.Text('Choose an Image:', size=(20,1)),
                         sg.Input(size=(30,1),key='wipe10'),
                         sg.Button('Image', size=(10,1),button_color=('white','darkblue')),
                         sg.Text(' ', size=(10,1)),
                         sg.Button('Encrypt', size=(10,1),button_color=('green','black'))],
                        
                        [sg.Radio('Choose File: ',"Radio1",default=True),
                         sg.Input(size=(30,1),key='wipe11'),],
                        [sg.Radio('Enter Text: ',"Radio1"),],
                        
                        [sg.Multiline(default_text='This feature is only available in version 1.3'  +
                                      '\t\t\t\t:)',
                                      size=(120, 15),key='wipe12'),],
                        [sg.Text('Choose output Image:', size=(20,1)),
                         sg.Input(size=(30,1),key='outputFile'),
                         sg.Button('File',size=(10,1),button_color=('white','darkblue'))]

                        ],
                     title='', tooltip='',
                     size=(10, 20), pad=None, border_width=None,
                     background_color=None,relief="groove" ),
            ],     
                
                ]
# Port Scanner Tab
# Tab 3 Layout
tab3_layout = [
                 [sg.Frame(layout=[    
                        [sg.Text('Target:',size=(6,1)),
                         sg.Input(size=(15,1),key='target1'),
                         sg.Text('Port Range:',size=(10,1)),
                         sg.Input(size=(10,1),key='port1'),
                         sg.Text(' ', size=(20,1)),
                         sg.Button('Scan', size=(10,1),button_color=('green','black'))],   
                         
                        [sg.Multiline(default_text='This feature is only available in version 1.3'  +
                                      '\t\t\t\t:)',
                                      size=(120, 20),key='scan1'),],
                        
                        ],
                     title='', tooltip='',
                     size=(10, 20), pad=None, border_width=None,
                     background_color=None,relief="groove" ),
            ],     
                
                ]

#_______________________________________________________________________________________________________________


# Creates the Layout
layout = [  [sg.Menu(menu_def, tearoff=True)],
            
            [sg.TabGroup([[sg.Tab('Administer', tab1_layout, key='tab1_layout'),
                           sg.Tab('Encrypt', tab2_layout, key='tab2_layout'),
                           sg.Tab('Scanner', tab3_layout)]], key='tab3_layout',
                         
                                   background_color='white', tab_location='topleft')],                 

          #[sg.RButton('Read')]
            ]

window = sg.Window('UBMT - Universal Bot Mesh Toolkit',resizable=False,
                   size=(800,430),background_color='Black',
                   default_element_size=(12,1)).Layout(layout)

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
    if event == 'IP Chicken' or event == 'IP':
        openChicken()
    if event == 'VPN Leak' or event == 'VPNLeak':
        openVPNLeak()
    if event == 'Finger Print' or event == 'Finger':
        openFingerprint()
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
        threadping()
    if event == 'TaskKill':
        taskkill()
    if event == 'DriverQuery':
        driverquery()
    if event == 'Get Host IP':
        gethostname()
    if event == 'Get IP Host':
        gethostaddr()
    if event == 'Netstat -ano':
        netstat()
    if event == 'Search':
        searching()
    if event == 'Arp -a':
        arp()
    if event == 'Serial Number':
        serialnumber()
    if event == 'ProductKey':
        productkey()
    if event == 'Advertised Wireless Networks':
        advertisewireless()
    if event == 'Investigate Wireless':
        investigatewireless()
    if event == 'Show Password':
        showwirelesspassword() 
    if event == 'Trace':
        threadtrace()
    if event == 'Computer Hostname/IP':
        gethostnip()
    if event == 'IP Configuration':
        ipconfig()
    if event == 'TCPConnections':
        tcpconn()
    if event == 'UDPConnections':
        udpconn()
    if event == 'Route Print':
        routeprint()
    if event == 'Show Interface':
        showinterface()
    if event == 'Restore':
        restorecpu()
    if event == 'Logoff':
        logoff()
    if event == 'Restart':
        restart()
    if event == 'Shutdown':
        shutdown()
    if event == 'RemoteShutdown':
        remoteshutdown()
    if event == 'MacAddresses':
        macaddresses()
    if event == 'System Info':
        systeminfo()
    if event == 'TaskList':
        process()
    if event == 'CMDKey/List':
        cmdkeylist()
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
    if event == 'Registry':
        registry()
        
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

#sg.Popup('Title',      
 #        'The results of the window.',      
  #       'The button clicked was "{}"'.format(event),      
   #      'The values are', values) 
