from tkinter import *
from PIL import Image
from tkinter import filedialog
import webbrowser
import subprocess
from subprocess import Popen, PIPE, STDOUT
import time
import datetime
import smtplib
import socket
import os
import psutil
from psutil._common import bytes2human
from tkinter import messagebox
from textwrap import TextWrapper
import tkinter.scrolledtext as tkst
from threading import Thread
from tkinter.filedialog import askopenfilename



# ****************************************
#       Universal Bot Mesh Toolkit
#
#                   By:
#
#              Mark A Duchane
#
#            Written in Python 3
#
#*****************************************



#---------------------------------------------------------------------------------       

class About(Toplevel):
    """"""
    
    def __init__(self, about):
        """Constructor"""
        self.original_frame = about
        Toplevel.__init__(self)
        self.resizable(width=FALSE, height=FALSE)
        self.geometry("380x150+200+200")
        self.configure(bg="White")  
        self.title("About UBMT")

        canvas3 = Canvas(self, width = 380, height = 150) 
        canvas3.configure(bg="White")
        canvas3.place(x=0,y=0) 
        self.img3 = PhotoImage(file="marks1.png")      
        canvas3.create_image(170,70, image=self.img3)
             
    def onClose(self):
        """"""
        self.destroy()
        self.original_frame.show()

#-------------------------------------------------------------------------

class WindowsFrame(Toplevel):
    """"""
    
    def __init__(self, original):
        """Constructor"""
        self.original_frame = original
        Toplevel.__init__(self)
        self.resizable(width=FALSE, height=FALSE)
        self.geometry("400x440+200+200")
        self.configure(bg="Black")
        self.title("Troubleshoot Windows ")

        # **** Site Menu Functions ****

        new = 1
        url2 = "https://www.ipchicken.com"
        url3 = "https://www.speedtest.net"
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
            date = time.asctime(time.localtime(time.time()))
            outputText.insert(END, "Todays Date: " + date + "\n")
            p = "\nPing Statistics:\n"
            address = ipAddress.get()
            pingnumber = tkvar.get()
            output = subprocess.run(["ping","-n",pingnumber,address], stdout=subprocess.PIPE,
                                    stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            outputText.insert(END,output)
            ipAddress.delete(0,END)

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
            subprocess.Popen(["notepad.exe"])
        # **** Menu Admin Functions ****

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
            outputText.insert(END,output)
        def gwc1():
            address = ipAddress.get()
            output = subprocess.run(["tracert",address], stdout=subprocess.PIPE,
                                    stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            outputText.insert(END,output)
            ipTrace.delete(0,END)
        def gethostnip():
            hostname = socket.gethostname()    
            IPAddr = socket.gethostbyname(hostname)
            cpu = ("Your Computer Name is: " + hostname)
            addr = ("\nYour Computer IP Address is: " + IPAddr)
            results = cpu + addr
            outputText.insert(END,results)
        def ipconfig():
            output = subprocess.run(["ipconfig","/all"], stdout=subprocess.PIPE,
                                    stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            outputText.insert(END,output)
        def systeminfo():
            output = subprocess.run(["systeminfo"], stdout=subprocess.PIPE,
                                    stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            outputText.insert(END,output)
        def process():
            output = subprocess.run(["tasklist"], stdout=subprocess.PIPE,
                                    stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            outputText.insert(END,output)
        # **** Menu Performance Functions ****
        def processes():
            for proc in psutil.process_iter():
                try:
                    pinfo = proc.as_dict(attrs=['pid', 'name', 'username'])
                except psutil.NoSuchProcess:
                    pass
                else:
                    outputText.insert(END,pinfo)            
        def diskusage():
            usage = psutil.disk_usage('/')
            d = "Disk Usage:\n\n"
            t = ("Total: {}".format(bytes2human(usage.total)))
            u = ("\nUsed: {}".format(bytes2human(usage.used)))
            f = ("\nFree: {}".format(bytes2human(usage.free)))
            p = ("\nPercent: %s%%" % round(usage.percent, 2))
            #p = ("\nPercent: {}".format(bytes2human(usage.percent)))
            results = (d + t + u + f + p)
            outputText.insert(END,results)
        def memory():
            usage = psutil.virtual_memory()
            m = "Memory Statistics:\n\n"
            t = ("Total: {}".format(bytes2human(usage.total)))
            u = ("\nUsed: {}".format(bytes2human(usage.used)))
            f = ("\nFree: {}".format(bytes2human(usage.free)))
            p = ("\nPercent: %s%%" % round(usage.percent, 2))
            #p = ("\nPercent: {}".format(bytes2human(usage.percent)))
            results = (m + t + u + f + p)
            outputText.insert(END,results)
        def cpuusage():
            cpu = psutil.cpu_percent(interval=1, percpu=True)
            outputText.insert(END,cpu)
        def netconn():
            net = psutil.net_connections(kind='inet')
            outputText.insert(END,net)
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
                outputText.insert(END,res)
        def boot():
            boot = psutil.boot_time()
            time = datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
            results1 = ("Boot Time: {} ".format(boot))
            results2 = ("\nTimestamp: {} ".format(time))
            results3 = (results1 + results2 )
            outputText.insert(END,results3)
        # **** Help Functions ****

        # **** Bottom Button Functions ****
        def closeProgram():
            window.Close()
        def clearfields():
            ipAddress.delete(0,END)
            outputText.delete(1.0,END)
        def submit():
            contents = outputText.get(1.0,"end-1c")
            f = filedialog.asksaveasfilename(   
                defaultextension=".txt",                 
                filetypes = (("text file", "*.txt"),    
                     ("text", "*.txt")))
            with open(f, 'w') as outputFile:
                outputFile.write(contents)
            outputText.delete(1.0,END)

        ###########################################3    
            
        def OpenFile():
            name = askopenfilename()
            print (name)
        
        def aboutus():
            subFrame = About(self)

        
        
        # **** Menu Commands Functions ****

        
        def ipconfig():
            i = "\nIP Configuration:\n"
            output = subprocess.run(["ipconfig","/all"], stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            results = (i ,output)
            outputText.insert(END,results)
            messagebox.showinfo("Information!","IP Configuration was successfully \n added to the GUI.")
            
        def process():
            p = "\nRunning Processes:\n"
            pro = subprocess.run(["tasklist.exe"], stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            #pro = subprocess.check_output("tasklist.exe").decode('utf-8')
            outputText.insert(END,pro)
            messagebox.showinfo("Information!","Running Processes were successfully \n added to the GUI.")
            
        def systeminfo():
            y = "\nSystem Information:\n"
            sysinfo = subprocess.run(["systeminfo"], stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            #sysinfo = subprocess.check_output("systeminfo").decode('utf-8')
            outputText.insert(END,sysinfo)
            messagebox.showinfo("Information!","System Information was successfully \n added to the GUI.")
            
        def startup():
            s = "\nStartup Processes:\n"
            start = subprocess.run(["wmic startup get caption,command"], stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            #start = subprocess.check_output("wmic startup get caption,command").decode('utf-8')
            outputText.insert(END,start)
            messagebox.showinfo("Information!","Startup Programs were successfully \n added to the GUI.")


        def submit():
            contents = outputText.get(1.0,"end-1c")
            f = tkFileDialog.asksaveasfilename(   
                defaultextension=".txt",                 
                filetypes = (("text file", "*.txt"),    
                     ("text", "*.txt")))
            with open(f, 'w') as outputFile:
                outputFile.write(contents)
            outputText.delete(1.0,END)
        def closeProgram():
            self.destroy()
            root.destroy()
         
            
        # Create the Menu bar

        menu = Menu(self)
        self.config(menu=menu)
        filemenu = Menu(menu)
        menu.add_cascade(label="File", menu=filemenu)
        filemenu.add_command(label="About",command=aboutus)
        #filemenu.add_command(label="Open...",)
        filemenu.add_command(label="Exit", command=root.destroy)

        sitesmenu = Menu(menu, tearoff=0)
        menu.add_cascade(label="Sites", menu=sitesmenu)
        sitesmenu.add_command(label="Eset",command=openEset)
        sitesmenu.add_command(label="Speed Test",command=openSpeed)
        sitesmenu.add_command(label="IpChicken",command=openChicken)
        sitesmenu.add_command(label="MxLookup",command=openMX)
        sitesmenu.add_command(label="Whois IP",command=openWhois)
        sitesmenu.add_command(label="Earth",command=openEarth)

        toolsmenu = Menu(menu, tearoff=0)
        menu.add_cascade(label="Tools", menu=toolsmenu)
        toolsmenu.add_command(label="Command Prompt", command=cmdp)
        toolsmenu.add_command(label="Control Panel", command=ctrlpanel)
        toolsmenu.add_command(label="File Explorer", command=fileexplorer)
        toolsmenu.add_command(label="Notepad",command=notepad)
        toolsmenu.add_command(label="Powershell", command=powershell)
        toolsmenu.add_command(label="Remote Desktop", command=rdp)

        performancemenu = Menu(menu, tearoff=0)
        menu.add_cascade(label="Performance", menu=performancemenu)
        performancemenu.add_command(label="Battery Usage",command=battery)
        performancemenu.add_command(label="Boot Time",command=boot)
        performancemenu.add_command(label="CPU Usage",command=cpuusage)
        performancemenu.add_command(label="Disk Usage",command=diskusage)
        performancemenu.add_command(label="Memory Usage",command=memory)
        performancemenu.add_command(label="Network Connections",command=netconn)

        
        commandsmenu = Menu(menu, tearoff=0)
        menu.add_cascade(label="Commands", menu=commandsmenu)
        #commandsmenu.add_command(label="Restart")
        commandsmenu.add_command(label="Hostname/IP", command=gethostnip)
        commandsmenu.add_command(label="IPConfig", command=ipconfig)
        commandsmenu.add_command(label="Netstat", command=netstat)
        commandsmenu.add_command(label="Systeminfo", command=systeminfo)
        commandsmenu.add_command(label="Tasklist", command=process)
        #commandsmenu.add_command(label="Startup",command=startup)

        windowsmenu = Menu(menu)
        menu.add_cascade(label="Windows Tools", menu=windowsmenu)
        windowsmenu.add_command(label="Accounts",command=acct)
        windowsmenu.add_command(label="Default Programs",command=defpro)
        windowsmenu.add_command(label="Devices/Printers",command=devprint)
        windowsmenu.add_command(label="Display Panel",command=display)
        windowsmenu.add_command(label="Time/Date",command=datemgmt)
        windowsmenu.add_command(label="Power Options",)

        adminmenu = Menu(menu)
        menu.add_cascade(label="Admin Tools", menu=adminmenu)
        adminmenu.add_command(label="Administrative Tools",command=admintools)
        adminmenu.add_command(label="Backup/Restore",command=backup)
        adminmenu.add_command(label="Bitlocker",command=bitlocker)
        #adminmenu.add_command(label="Certificate Manager",)
        adminmenu.add_command(label="Credential Manager",command=credmgmt)
        #adminmenu.add_command(label="Disk Cleanup",)
        adminmenu.add_command(label="Internet Options",command=internetopt)
        adminmenu.add_command(label="Indexing Options",command=indexopt)
        adminmenu.add_command(label="Optional Features",command=optfeat)
        adminmenu.add_command(label="Network/Sharing",command=netsharing)
        adminmenu.add_command(label="Security Center",command=seccenter)
        adminmenu.add_command(label="Storage Spaces ",command=storagepool)
        adminmenu.add_command(label="System Settings",command=sysset)
        adminmenu.add_command(label="User Accounts",command=useracct)
        adminmenu.add_command(label="Windows Firewall",command=winfire)
         
        frame1 = Frame(self, width = 390, height = 390)
        frame1.configure(bg='Black')
        frame1.place(x=10, y=10)

        frame2 = Frame(self, width = 380, height = 400)
        frame2.configure(bg="#F4F4F4")
        frame2.place(x=10, y=10)

        canvas3 = Canvas(self, width = 390, height = 110, bd=0, highlightthickness=0, relief='ridge')
        canvas3.configure(bg="Black")
        canvas3.place(x=10,y=0)
      
        self.img3 = PhotoImage(file="horus1.png")      
        canvas3.create_image(190,40, image=self.img3)

            
        #*********** Labels Windows OS ****************

        lblEpIP = Label(self, text="Enter IP/Domain :", bg='#F4F4F4')
        lblEpIP.place(x=10, y=120, height=20, width=120)



        # ************ Entry Fields Windows OS ************

        ipAddress = Entry(self)
        ipAddress.place(x=120, y=120, height=20, width=120)

        outputText = tkst.ScrolledText(self)
        outputText.place(x=20, y=160, height=220, width=360)
        
        # *************** BUTTONS WINDOWS OS **************

        btnTrace = Button(self, text="Trace",command=gwc1)
        btnTrace.place(x=250, y=120, height=20, width=50)

        btnPing = Button(self, text="Ping",command=ping)
        btnPing.place(x=300, y=120, height=20, width=50)
        

        tkvar = StringVar(self)
        choices = { '4','8','12','16','20'}
        tkvar.set('4')

        L2 = OptionMenu(self, tkvar, *choices)
        L2.place(x=350, y=120, height=20, width=40)

        btnSubmit = Button(self, text="Submit",command=submit)
        btnSubmit.place(x=20, y=385, height=20, width=50)
 
        btnMain = Button(self, text="Main", command=self.onClose)
        btnMain.place(x=70, y=385, height=20, width=50)

        btnExit = Button(self, text="Exit",command=closeProgram)
        btnExit.place(x=320, y=385, height=20, width=50)

        btnClear = Button(self, text="Clear",command=clearfields)
        btnClear.place(x=120, y=385, height=20, width=50)
 
    #----------------------------------------------------------------------
    def onClose(self):
        """"""
        self.destroy()
        self.original_frame.show()
    def openFrame3(self):
        """"""
        self.hide()
        subFrame = About(self)

#----------------------------------------------------------------------------------------

class MacFrame(Toplevel):
    """"""
    
    def __init__(self, original):
        """Constructor"""
        self.original_frame = original
        Toplevel.__init__(self)
        self.resizable(width=FALSE, height=FALSE)
        self.geometry("400x420+200+200")
        self.configure(bg="Black")
        self.title("Troubleshoot MAC ")

        def aboutus():
            subFrame = About(self)
            
        
        def ifconfig():
            ipaddr = subprocess.run(["ifconfig"], stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            outputText.insert(END,ipaddr)
            messagebox.showinfo("Information!","IP Configuration was successfully \n added to the GUI.")
            
        def process():
            pro = subprocess.run(["ps aux"], stdout=subprocess.PIPE,
                                    stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            outputText.insert(END,pro)
            messagebox.showinfo("Information!","Running Processes were successfully \n added to the GUI.")
            
        def systeminfo():
            sysinfo = subprocess.run(["system_profiler -detaillevel mini"], stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            outputText.insert(END,sysinfo)
            messagebox.showinfo("Information!","System Information was successfully \n added to the GUI.")
            
        def netstat():
            stat = subprocess.run(["netstat -i"], stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            outputText.insert(END, stat)
            messagebox.showinfo("Information!", "Netstat Statistics were successfuly \n added to the GUI.")
        
        # *** Preference Panes ***

        def usergroup():
            user = subprocess.run(["open /System/Library/PreferencePanes/Accounts.prefpane/"], stdout=subprocess.PIPE,
                                    stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            text = "You have successfully launched the User & Groups Preference Pane."
            outputText.insert(END, text)

        def network():
            net = subprocess.run(["open /System/Library/PreferencePanes/Network.prefpane/"],stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            text = "You have successfully launched the Network Preference Pane."
            outputText.insert(END, text)

        def appstore():
            appstore = subprocess.run(["open /System/Library/PreferencePanes/AppStore.prefpane/"],stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            text = "You have successfully launched the AppStore Preference Pane."
            outputText.insert(END, text)

        def datetime():
            datetime = subprocess.run(["open /System/Library/PreferencePanes/DateAndTime.prefpane/"],stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            text = "You have successfully launched the DateTime Preference Pane."
            outputText.insert(END, text)

        def appearance():
            appearance = subprocess.run(["open /System/Library/PreferencePanes/Appearance.prefpane/"],stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            text = "You have successfully launched the Appearance Preference Pane."
            outputText.insert(END, text)

        def displays():
            displays = subprocess.run(["open /System/Library/PreferencePanes/Displays.prefpane/"],stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            text = "You have successfully launched the Displays Preference Pane."
            outputText.insert(END, text)

        def energysaver():
            energysaver = subprocess.run(["open /System/Library/PreferencePanes/EnergySaver.prefpane/"],stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            text = "You have successfully launched the Energy Saver Preference Pane."
            outputText.insert(END, text)
        
        def security():
            security = subprocess.run(["open /System/Library/PreferencePanes/Security.prefpane/"],stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            text = "You have successfully launched the Security & Privacy Preference Pane."
            outputText.insert(END, text)

        def printers():
            printers = subprocess.run(["open /System/Library/PreferencePanes/PrintAndScan.prefpane/"],stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            text = "You have successfully launched the Printer & Scanner Preference Pane."
            outputText.insert(END, text)

        def timemachine():
            timemachine = subprocess.run(["open /System/Library/PreferencePanes/TimeMachine.prefpane/"],stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            text = "You have successfully launched the Time Machine Preference Pane."
            outputText.insert(END, text)

        def sharing():
            sharing = subprocess.run(["open /System/Library/PreferencePanes/SharingPref.prefpane/"],stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            text = "You have successfully launched the Sharing Preference Pane."
            outputText.insert(END, text)

        # *** Applications ***

        def safari():
            safari = subprocess.run(["open -a Safari"],stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            text = "You have successfully launched the Safari Application."
            outputText.insert(END, text)
        
        def maps():
            maps = subprocess.run(["open -a Maps"],stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            text = "You have successfully launched the Maps Application."
            outputText.insert(END, text)

        def contacts():
            contacts = subprocess.run(["open -a Contacts"],stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            text = "You have successfully launched the Contacts Application."
            outputText.insert(END, text)

        def mail():
            mail = subprocess.run(["open -a Mail"],stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            text = "You have successfully launched the Mail Application."
            outputText.insert(END, text)

        def launchpad():
            launchpad = subprocess.run(["open -a Launchpad"],stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            text = "You have successfully launched the Launchpad Application."
            outputText.insert(END, text)

        def notes():
            notes = subprocess.run(["open -a Notes"],stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            text = "You have successfully launched the Notes Application."
            outputText.insert(END, text)

        def messages():
            messages = subprocess.run(["open -a Messages"],stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            text = "You have successfully launched the Messages Application."
            outputText.insert(END, text)

        def calendar():
            calendar = subprocess.run(["open -a Calendar"],stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            text = "You have successfully launched the Calendar Application."
            outputText.insert(END, text)

        def calculator():
            calculator = subprocess.run(["open -a Calculator"],stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            text = "You have successfully launched the Calculator Application."
            outputText.insert(END, text)

        def openEset():
            webbrowser.open(url4, new=new)

        def openEarth():
            webbrowser.open(url5, new=new)

        def openWhois():
            webbrowser.open(url6, new=new)
            
        def openMX():
            webbrowser.open(url7, new=new)
            
        new = 1
        url2 = "www.ipchicken.com"
        url3 = "www.speedtest.net"
        url4 = "https://www.eset.com/int/home/cyber-security/download/"
        url5 = "https://earth.google.com/web/@0,0,-24018.82718741a,36750128.22569847d,35y,0h,0t,0r/data=CgAoAQ"
        url6 = "https://whoer.net/checkwhois"
        url7 = "https://mxtoolbox.com/"

        

        def openChicken():
            webbrowser.open(url2,new=new)

        def openSpeed():
            webbrowser.open(url3,new=new)

        def closeProgram():
            self.destroy()
            root.destroy()

                    
        def trace():
            address = ipAddress.get()
            trace = subprocess.run(["traceroute",address], stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            outputText.insert(END, trace)
            ipAddress.delete(0,END)
        
        def ping():
            date = time.asctime(time.localtime(time.time()))
            outputText.insert(END, "Todays Date: " + date + "\n")
            address = ipAddress.get()
            pingnumber = tkvar.get()
            Pp = subprocess.run(["ping -c",pingnumber,address], stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            outputText.insert(END,Pp)
            ipAddress.delete(0,END)
            
            messagebox.showinfo("Information!","Ping Statistics were successfully added \n to the GUI.")

        def clearfields():
            ipAddress.delete(0,END)
            outputText.delete(1.0,END)

            
            
        # Create the Menu bar

        menu = Menu(self)
        self.config(menu=menu)
        filemenu = Menu(menu)
        menu.add_cascade(label="File", menu=filemenu)
        filemenu.add_command(label="About", command=aboutus)
        filemenu.add_command(label="Exit", command=root.destroy)

        sitesmenu = Menu(menu, tearoff=0)
        menu.add_cascade(label="Sites", menu=sitesmenu)
        sitesmenu.add_command(label="Eset Scan", command=openEset)
        sitesmenu.add_command(label="Whois IP", command=openWhois)
        sitesmenu.add_command(label="MX Lookup",command=openMX)
        sitesmenu.add_command(label="Google Earth", command=openEarth)
        
        prefpanemenu = Menu(menu, tearoff=0)
        menu.add_cascade(label="Preference Panes", menu=prefpanemenu)
        prefpanemenu.add_command(label="Appearance",command=appearance)
        prefpanemenu.add_command(label="AppStore",command=appstore)
        prefpanemenu.add_command(label="Date/Time",command=datetime)
        prefpanemenu.add_command(label="Display",command=displays)
        prefpanemenu.add_command(label="Energy Saver",command=energysaver)
        prefpanemenu.add_command(label="Network",command=network)
        prefpanemenu.add_command(label="Printers",command=printers)
        prefpanemenu.add_command(label="Security",command=security)
        prefpanemenu.add_command(label="Sharing",command=sharing)
        prefpanemenu.add_command(label="Time Machine",command=timemachine)
        prefpanemenu.add_command(label="User Group",command=usergroup)
        
        appsmenu = Menu(menu, tearoff=0)
        menu.add_cascade(label="Applications", menu=appsmenu)
        appsmenu.add_command(label="Safari",command=safari)
        appsmenu.add_command(label="Maps", command=maps)
        appsmenu.add_command(label="Contacts", command=contacts)
        appsmenu.add_command(label="Mail", command=mail)
        appsmenu.add_command(label="Launchpad", command=launchpad)
        appsmenu.add_command(label="Notes", command=notes)
        appsmenu.add_command(label="Messages", command=messages)
        appsmenu.add_command(label="Calendar", command=calendar)
        appsmenu.add_command(label="Calculator", command=calculator)

        commandsmenu = Menu(menu, tearoff=0)
        menu.add_cascade(label="Commands", menu=commandsmenu)
        commandsmenu.add_command(label="Netstat",command=netstat)
        commandsmenu.add_command(label="IFConfig", command=ifconfig)
        commandsmenu.add_command(label="Systeminfo", command=systeminfo)
        commandsmenu.add_command(label="Tasklist", command=process)

         
        frame1 = Frame(self, width = 390, height = 390)
        frame1.configure(bg='Black')
        frame1.place(x=10, y=10)

        frame2 = Frame(self, width = 380, height = 400)
        frame2.configure(bg="#F4F4F4")
        frame2.place(x=10, y=10)

        canvas3 = Canvas(self, width = 390, height = 110, bd=0, highlightthickness=0, relief='ridge')
        canvas3.configure(bg="Black")
        canvas3.place(x=10,y=0)
      
        self.img3 = PhotoImage(file="horus1.png")      
        canvas3.create_image(190,40, image=self.img3)

            
        #*********** Labels MAC OS ****************

        lblEpIP = Label(self, text="Enter IP/Domain :", bg='#F4F4F4')
        lblEpIP.place(x=10, y=120, height=20, width=120)



        # ************ Entry Fields MAC OS ************

        ipAddress = Entry(self)
        ipAddress.place(x=120, y=120, height=20, width=120)

        outputText = tkst.ScrolledText(self)
        outputText.place(x=20, y=160, height=220, width=360)
        
        # *************** BUTTONS MAC OS **************

        btnTrace = Button(self, text="Trace",command=trace)
        btnTrace.place(x=250, y=120, height=20, width=50)

        btnPing = Button(self, text="Ping",command=ping)
        btnPing.place(x=300, y=120, height=20, width=50)
        

        tkvar = StringVar(self)
        choices = { '4','8','12','16','20'}
        tkvar.set('4')

        L2 = OptionMenu(self, tkvar, *choices)
        L2.place(x=350, y=120, height=20, width=40)

        btnSubmit = Button(self, text="Submit",command=submit)
        btnSubmit.place(x=20, y=385, height=20, width=50)
 
        btnMain = Button(self, text="Main", command=self.onClose)
        btnMain.place(x=70, y=385, height=20, width=50)

        btnExit = Button(self, text="Exit",command=closeProgram)
        btnExit.place(x=320, y=385, height=20, width=50)

        btnClear = Button(self, text="Clear",command=clearfields)
        btnClear.place(x=120, y=385, height=20, width=50)
 
    #----------------------------------------------------------------------
    def onClose(self):
        """"""
        self.destroy()
        self.original_frame.show()
    def openFrame3(self):
        """"""
        self.hide()
        subFrame = About(self)
#----------------------------------------------------------------------------------

class LinuxFrame(Toplevel):
    """"""
    
    def __init__(self, original):
        """Constructor"""
        self.original_frame = original
        Toplevel.__init__(self)
        self.resizable(width=FALSE, height=FALSE)
        self.geometry("400x420+200+200")
        self.configure(bg="Black")
        self.title("Troubleshoot Linux ")

        def aboutus():
            subFrame = About(self)

        def ifconfig():
            ipaddr = subprocess.run(["ifconfig"], stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            outputText.insert(END,ipaddr)
            messagebox.showinfo("Information!","IP Configuration was successfully \n added to the GUI.")
            
        def openEset():
            webbrowser.open(url4, new=new)

        def openEarth():
            webbrowser.open(url5, new=new)

        def openWhois():
            webbrowser.open(url6, new=new)
            
        def openMX():
            webbrowser.open(url7, new=new)
            
        new = 1
        url2 = "www.ipchicken.com"
        url3 = "www.speedtest.net"
        url4 = "https://www.eset.com/afr/home/online-scanner/"
        url5 = "https://earth.google.com/web/@0,0,-24018.82718741a,36750128.22569847d,35y,0h,0t,0r/data=CgAoAQ"
        url6 = "https://whoer.net/checkwhois"
        url7 = "https://mxtoolbox.com/"

        

        def openChicken():
            webbrowser.open(url2,new=new)

        def openSpeed():
            webbrowser.open(url3,new=new)

        def closeProgram():
            self.destroy()
            root.destroy()
            
        def trace():
            address = ipAddress.get()
            trace = subprocess.run(["traceroute",address], stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            outputText.insert(END, trace)
            ipAddress.delete(0,END)
        
        def ping():
            date = time.asctime(time.localtime(time.time()))
            outputText.insert(END, "Todays Date: " + date + "\n")
            address = ipAddress.get()
            pingnumber = tkvar.get()
            Pp = subprocess.run(["ping -c",pingnumber,address], stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            outputText.insert(END,Pp)
            ipAddress.delete(0,END)
            
            messagebox.showinfo("Information!","Ping Statistics were successfully added \n to the GUI.")

    
        def clearfields():
            ipAddress.delete(0,END)
            outputText.delete(1.0,END)

            
            
        # Create the Menu bar

        menu = Menu(self)
        self.config(menu=menu)
        filemenu = Menu(menu)
        menu.add_cascade(label="File", menu=filemenu)
        filemenu.add_command(label="About", command=aboutus)
        filemenu.add_command(label="Exit", command=root.destroy)

        toolmenu = Menu(menu, tearoff=0)
        menu.add_cascade(label="Services", menu=toolmenu)
        toolmenu.add_command(label="Eset Scan", command=openEset)
        toolmenu.add_command(label="Whois IP", command=openWhois)
        toolmenu.add_command(label="MX Lookup",command=openMX)
        toolmenu.add_command(label="Google Earth", command=openEarth)
        

        commandmenu = Menu(menu, tearoff=0)
        menu.add_cascade(label="Tools", menu=commandmenu)
        
        scriptsmenu = Menu(menu, tearoff=0)
        menu.add_cascade(label="Commands", menu=scriptsmenu)
        scriptsmenu.add_command(label="Netstat")
        scriptsmenu.add_command(label="IFConfig", command=ifconfig)
        scriptsmenu.add_command(label="Systeminfo")
        scriptsmenu.add_command(label="Tasklist")
         
        frame1 = Frame(self, width = 390, height = 390)
        frame1.configure(bg='Black')
        frame1.place(x=10, y=10)

        frame2 = Frame(self, width = 380, height = 400)
        frame2.configure(bg="#F4F4F4")
        frame2.place(x=10, y=10)

        canvas3 = Canvas(self, width = 390, height = 110, bd=0, highlightthickness=0, relief='ridge')
        canvas3.configure(bg="Black")
        canvas3.place(x=10,y=0)
      
        self.img3 = PhotoImage(file="horus1.png")      
        canvas3.create_image(190,40, image=self.img3)

            
        #*********** Labels Linux OS ****************

        lblEpIP = Label(self, text="Enter IP/Domain :", bg='#F4F4F4')
        lblEpIP.place(x=10, y=120, height=20, width=120)



        # ************ Entry Fields Linux OS ************

        ipAddress = Entry(self)
        ipAddress.place(x=120, y=120, height=20, width=120)

        outputText = tkst.ScrolledText(self)
        outputText.place(x=20, y=160, height=220, width=360)
        
        # *************** BUTTONS Linux OS **************

        btnTrace = Button(self, text="Trace",command=trace)
        btnTrace.place(x=250, y=120, height=20, width=50)

        btnPing = Button(self, text="Ping",command=ping)
        btnPing.place(x=300, y=120, height=20, width=50)
        

        tkvar = StringVar(self)
        choices = { '4','8','12','16','20'}
        tkvar.set('4')

        L2 = OptionMenu(self, tkvar, *choices)
        L2.place(x=350, y=120, height=20, width=40)

        btnSubmit = Button(self, text="Submit")
        btnSubmit.place(x=20, y=385, height=20, width=50)
 
        btnMain = Button(self, text="Main", command=self.onClose)
        btnMain.place(x=70, y=385, height=20, width=50)

        btnExit = Button(self, text="Exit",command=closeProgram)
        btnExit.place(x=320, y=385, height=20, width=50)

        btnClear = Button(self, text="Clear",command=clearfields)
        btnClear.place(x=120, y=385, height=20, width=50)
 
    #----------------------------------------------------------------------
    def onClose(self):
        """"""
        self.destroy()
        self.original_frame.show()
    def openFrame3(self):
        """"""
        self.hide()
        subFrame = About(self)



#----------------------------------------------------------------------------------------        
class App(object):

    def __init__(self, parent):

        self.root = parent
        self.root.title("Universal Bot Mesh Toolkit")
        self.root.geometry("400x400+200+200")
        self.root.resizable(width=FALSE, height=FALSE)

        self.frame1 = Frame(root, width = 380, height = 380)
        self.frame1.configure(bg="Black")
        self.frame1.place(x=10, y=10)

        self.frame2 = Frame(root, width = 380, height = 100)
        self.frame2.configure(bg="White")
        self.frame2.place(x=10, y=10)

        self.canvas1 = Canvas(root, width = 380, height = 200, bd=0, highlightthickness=0, relief='ridge')
        self.canvas1.configure(bg="White")
        self.canvas1.place(x=10, y=10)
        self.img1 = PhotoImage(file="meshnet1.PNG")
        self.canvas1.create_image(0,0, anchor=NW, image=self.img1)

        btnWindowsOS = Button(root, text="Windows", command=self.openFrame)
        btnWindowsOS.place(x=60, y=270, height=50, width=80)

        btnMacOS = Button(root, text="MAC", command=self.openFrame2)
        btnMacOS.place(x=160, y=270, height=50, width=80)

        btnLinuxOS = Button(root, text="Linux", command=self.openFrame3)
        btnLinuxOS.place(x=260, y=270, height=50, width=80)
            

    def hide(self):
        """"""
        self.root.withdraw()

    def openFrame(self):
        """"""
        self.hide()
        subFrame = WindowsFrame(self)

    def openFrame2(self):
        """"""
        self.hide()
        subFrame = MacFrame(self)

    def openFrame3(self):
        """"""
        self.hide()
        subFrame = LinuxFrame(self)

    def show(self):
        """"""
        self.root.update()
        self.root.deiconify()


if __name__ == "__main__":

    root = Tk()
    app = App(root)
    
