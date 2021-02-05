import os 
import subprocess 
from collections import Counter 
from collections import deque
import datetime
from pathlib import Path 
import colorama 


def getFilesfromDirectory (Dir) : 
    files_list = []
    try : 
        for root, dir_names, file_names in os.walk (Dir) : 
            for file in file_names: 
                files_list.append(os.path.join (root, file))
        return files_list
    except : 
        print ("Something went wrong while searching in directories")

#Part 1 : SSH brute force
def isSSHFilelog (file) :
    if Path(file).suffix == '.log' : 
        try : 
            with open(file,'rb') as file: 
                contents = file.read()
                if b'ssh' in contents:
                    return True
                else : 
                    return False 
        except : 
            print ("Something went wrong while searching in file: "+file)



def IpWithFailedsshconnection (file) :
#return dict with ip address as key and occurences as value 
    cmd = "sudo cat "+file+" | grep 'Failed password' | grep -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'"
    listIp= subprocess.run(cmd,text= True, shell = True, stdout=subprocess.PIPE).stdout.splitlines()
    dictIp= dict(Counter(listIp))
    return dictIp

def IpWithFailedsshconnectionlist (file) :
#return dict with ip address as key and occurences as value 
    cmd = "sudo cat "+file+" | grep 'Failed password' | grep -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'"
    listIp= subprocess.run(cmd,text= True, shell = True, stdout=subprocess.PIPE).stdout.splitlines()
    return listIp


def detectBasicSSH ()  : 
    seuil = 50
    files = []
    try : 
        Dir = input (colorama.Fore.CYAN+"please Enter the path to scan a directory:   ")
        listofdirectoryfiles = getFilesfromDirectory(Dir)
        
        print (colorama.Fore.RESET+"****************************************************")
        print("Printing files of "+Dir+": ")
        print (colorama.Fore.RESET+"****************************************************")

        for file in listofdirectoryfiles : 
            print (file)
        
        print ("\n\n\n****************************************************")
        print ("SSH log files detected are ")
        print ("****************************************************")
        for file in listofdirectoryfiles : 
            if isSSHFilelog (file):
                files.append(file)
                print(colorama.Fore.GREEN+file)

        for i in files : 
            print ("\n")
            print (colorama.Fore.RESET+"Analyzing file "+i)

            info=IpWithFailedsshconnection(i) 
            if info :
                for ip in list(info.keys()) : 
                    if info[ip] >  seuil :
                        print (colorama.Fore.RED+"Brute force attack detected on "+ip+" with "+str(info[ip])+" failed attempts")
                    else :
                        print (colorama.Fore.GREEN+"No brute force attack detected on"+ip)     
            else : 
                print (colorama.Fore.GREEN+"No information available in "+i)
        
        print (colorama.Fore.RESET+"\n")
    
    except :
        print ("Something went wrong while detecting SSH brute force")



#Part 2: tomcat brute force 

def istomcatCatalinaFile (file) :
        try : 
            filenameWithoutExt = Path(file).stem
            if 'catalina.' in filenameWithoutExt  :
                return True
            else :
                return False
        except : 
            print ("Something went wrong while searching in file: "+file)

def failedauthenticationTomcat (file) : 
    cmd = "sudo cat "+file+" | grep 'An attempt was made to authenticate' | wc -l"
    nb_attempts= subprocess.run(cmd,text= True, shell = True, stdout=subprocess.PIPE).stdout
    return nb_attempts

def deploiementTomcat (file) :
    cmd = "sudo cat "+file+" | grep 'Déploiement' | wc -l"
    nb_attempts= subprocess.run(cmd,text= True, shell = True, stdout=subprocess.PIPE).stdout
    return nb_attempts

def ifaccessFile (file) : 
    try : 
            filenameWithoutExt = Path(file).stem
            if 'localhost_access_log.' in filenameWithoutExt  :
                return True
            else :
                return False
    except : 
            print ("Something went wrong while searching in file: "+file)


def getIpaddress (file) : 
#return dict with ip address as key and occurences as value 
    cmd = "sudo cat "+file+" | grep -E '401' | awk '{print $1}'"
    listIp= subprocess.run(cmd,text= True, shell = True, stdout=subprocess.PIPE).stdout.splitlines()
    dictIp= dict(Counter(listIp))
    return dictIp


def basicTomcatbrutforcedetect () : 
    catalina_files = []
    access_files = []
    seuil = 10
    
    try : 

        Dir = input (colorama.Fore.CYAN+"please Enter the path to scan a directory:   ")
        listofdirectoryfiles = getFilesfromDirectory(Dir)

        print (colorama.Fore.RESET+"\n\n\n****************************************************")
        print (" Retriving Tomcat files : ")
        print ("****************************************************\n\n\n")
        
        for file in listofdirectoryfiles : 
            if istomcatCatalinaFile (file): 
                catalina_files.append(file)
            elif ifaccessFile (file):
                access_files.append (file)
    
        print ("printing tomcat files \n")
        for file in catalina_files : 
            print (file)
        for file in access_files :
            print (file)

        
        for file in catalina_files : 
            
            nb_auth_attempts = int(failedauthenticationTomcat (file))
            nb_deploi_attempts = int(deploiementTomcat(file))

            print (colorama.Fore.RESET+"\n\n")
            print (colorama.Fore.RESET+"Detecting failed authenticaton and deployment attempts  in "+colorama.Fore.CYAN+file)
            
            if nb_auth_attempts != 0 :
                print (colorama.Fore.RED+"Number of failed authentication detected on "+file+" are "+str(nb_auth_attempts))
            else : 
                print (colorama.Fore.GREEN+"No failed authentication found on "+file)

            if nb_deploi_attempts !=0 :
                print (colorama.Fore.RED+"Number of deployment attempts detected on "+file+" are "+str(nb_deploi_attempts))
            else : 
                print (colorama.Fore.GREEN+"No deployement detected on"+file)
        

        print ("\n\n")
        for file in access_files : 
                print(colorama.Fore.RESET+"Analyzing file "+file)
                
                ips = getIpaddress(file)
                if ips : 
                    for ip in list(ips.keys()) : 
                        if ips[ip] > seuil : 
                            print (colorama.Fore.RED+"Confirmed brute force attack on Tomcat from "+ip+" with "+str(ips[ip])+" attempts")
                        else : 
                            print (colorama.Fore.GREEN+"No brute force attack detected on tomcat in "+file)
                    print("\n")
                else : 
                    print("No information availaible in  "+file)
        print (colorama.Fore.RESET+"\n")
    
    except :
        print("Something went wrong while detecting Tomcat brute force attacks")



if __name__ == "__main__": 
    detectBasicSSH ()
    basicTomcatbrutforcedetect ()


























"""
def IpTimeIntervalle (file) : 
    ipTime_Formatted  = []
    cmd = "sudo cat "+file+ " |grep 'Failed password'  | awk '{print $1, $2, $3, $(NF-3)}'"
    listIp_Time= subprocess.run(cmd,text= True, shell = True, stdout=subprocess.PIPE).stdout.splitlines()
    for info in listIp_Time : 
        info= info.split(" ")
        ipTime_Formatted.append(info)    
    return ipTime_Formatted


def formatIpTimeList (ipTime_Formated) :
    ipTimeDict = {} 
    count=0
    for info in ipTime_Formated : 
        ip = info[3]
        if ip in list(ipTimeDict.keys()):
            ipTimeDict[ip][0] +=1
        if ip not in list(ipTimeDict.keys()) :
            ipTimeDict[ip]=[0]
            ipTimeDict[ip][0] = 1
        info.pop()
        ipTimeDict[ip].append(info)
    return ipTimeDict

def getlisttimeintervalle(ipTimeDict) : 
    Timedict = {}
    for l in list(ipTimeDict.keys()) :
        timeList = []
        ipTimeDict[l].pop(0)
        for sublist in ipTimeDict[l] :
            time = " ".join(sublist)
            timeList.append(time)
        ipTimeDict[l]= timeList
    return ipTimeDict

def timedelta (start,end) : 
    time_delta = end - start
    total_seconds = time_delta.delta_seconds()
    minutes = total-seconds/60
    return minutes

def dateTimeformat (ipTimedict2) : 
    time = {}
    time2 = {}
    for timeliste in list(ipTimedict2.keys()) : 
        date_timeList = []
        for t in ipTimedict2[timeliste]: 
            t=datetime.datetime.strptime(str(t),"%b %d %H:%M:%S")
            date_timeList.append(t)
        time[timeliste] = date_timeList
    return time 

def isTimeintervalleshort (time) :
    time2 = {}
    for t in list(time.keys()) :
        print (t)
        for l in time[t] :
            print (l)
            minutes = timedelta (l[0],l[-1])
            print (minutes)
        time2[t] = minutes
    return time2


"""

  




#######os.system("sudo cat  | grep 'Failed password' | grep -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'")



