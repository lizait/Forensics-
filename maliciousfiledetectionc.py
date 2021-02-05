import os
import subprocess
import colorama 


def tool (tool_name, dir) :
    if tool_name == "malware_tools" :
        cmd = "./phpmalwarefinder "+dir+"| sed -e '1,/You should take a look at the files listed below:/ d' | awk '{print $NF}'"
        listIp= subprocess.run(cmd,text= True, shell = True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.splitlines()
        if not listIp : 
            print (colorama.Fore.GREEN+"No malicious files found in "+dir+"\n")
        elif listIp : 
            print (colorama.Fore.CYAN+" Malicous files detected "+colorama.Fore.RESET+"\n")
            for file in listIp :
                path_name = os.path.split(file) 
                print (colorama.Fore.RESET+"File path "+colorama.Fore.RED+path_name[0]+colorama.Fore.RESET+" and file name "+colorama.Fore.RED+path_name[1]+colorama.Fore.RESET)
  





if __name__ == "__main__": 
    try : 
        tool_name = input('Please specify the tool to use: ')
        directory = input('Please specify the directory to scan: ')
        tool (tool_name,directory)
    except : 
        print ("Error occured ")