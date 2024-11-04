hostdp_path = r"C:\Users\Abishek\Downloads\TIP_module-master\Network_code\host_blocklist.txt"
def database():
   with open(hostdp_path,"r") as f:
        for domain in f:
            print(domain.strip()) 
database()