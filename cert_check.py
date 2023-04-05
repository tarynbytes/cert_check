import sys
import csv
import OpenSSL
import ssl
import warnings
import requests
from datetime import datetime, date, timedelta
from tqdm import tqdm

warnings.filterwarnings("ignore", category=DeprecationWarning)
#warnings.filterwarnings("ignore", category=InsecureRequestWarning) 


class SSLUtils:

    @staticmethod
    def pem_to_x509(cert_data: str):
        return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, str.encode(cert_data))
    
    def get_cert(self, dns_name: str, port: int):
        pem_server_certificate = ssl.get_server_certificate((dns_name, port))
        x509_server_certificate = self.pem_to_x509(pem_server_certificate)
        return x509_server_certificate
    
    def get_cert_sni(self, dns_name: str, port: int):
        connection = ssl.create_connection((dns_name, port))
        context = ssl.SSLContext()
        sock = context.wrap_socket(connection, server_hostname=dns_name)
        server_certificate = self.pem_to_x509(ssl.DER_cert_to_PEM_cert(sock.getpeercert(True)))
        sock.close()
        return server_certificate

class Cert:
    def __init__(self, cert, port, sni):
        self._cert = cert
        self._port = port
        self._sni = sni

        nb = cert.get_notBefore().decode()
        nb_str = f'{nb[0:4]}-{nb[4:6]}-{nb[6:8]}'
        self._not_before = datetime.strptime(nb_str, '%Y-%m-%d').date()

        na = cert.get_notAfter().decode()
        na_str = f'{na[0:4]}-{na[4:6]}-{na[6:8]}'
        self._not_after = datetime.strptime(na_str, '%Y-%m-%d').date()

        self._subject = cert.get_subject()
        self._issuer = cert.get_issuer()

        if self._issuer == self._subject:
            self._self_signed = "True"
        elif self._issuer != self._subject:
            self._self_signed = "False"
        else:
            self._self_signed = "UNK"

        self._expired = date.today() >= self.NotAfter
        if self._expired == True:
            self._next_thirty_days = ''
        else:
            self._next_thirty_days = date.today() + timedelta(days=30) >= self.NotAfter

    def __str__(self):
        ret = f"SNI: {self._sni}\nPort: {self._port}\nSelf-signed: {self._self_signed}\nEXPIRED: {self._expired}\nExpiring in next 30 days: {self._next_thirty_days}\n" + \
            f"Not Before: {self._not_before}\nNot After: {self._not_after}\nIssuer: {self._issuer}\nSubject: {self._subject}"
        return ret

    
    @property
    def SNI(self):
        return self._sni
    @property
    def Port(self):
        return self._port
    @property
    def NotBefore(self):
        return self._not_before
    @property
    def NotAfter(self):
        return self._not_after
    @property
    def Subject(self):
        return self._subject
    @property
    def Issuer(self):
        return self._issuer
    @property
    def SelfSigned(self):
        return self._self_signed
    @property
    def Expired(self):
        return self._expired
    @property
    def NextThirtyDays(self):
        return self._next_thirty_days

class API:
    def __init__(self, ip, port, payload, method, username, password):
        self._ip = ip
        self._port = port
        self._url = f"https://{str(self._ip)}:{str(self._port)}/api/3/"
        self._payload = payload
        self._method = method #GET|POST|etc.
        self._username = username
        self._password = password
        self._headers = {
            'Accept': 'application/json;charset=UTF-8'
        }    
        self.response = requests.request(self._method, self._url, headers=self._headers, data=self._payload, auth=(self._username, self._password), verify=False)
        print(self.response.text)



def read_file(file_name: str) -> list[str]:
    with open(file_name, 'r') as fp:
        return fp.readlines()[1:]

def parse_lines(lines: list[str]) -> list[list[str]]:
    return list(map(lambda line: (line.strip('\n').split(',')), lines))

def generate_certs(parsed_lines, port):
    certificates = dict()

    for line in tqdm(parsed_lines, desc="Querying domain list"):
        if line[0]:
            url = line[0]
        else:
            url = line[1]
        sslUtils = SSLUtils()

        try:
            x509 = sslUtils.get_cert(url, port)
            cert = Cert(x509, port, "False")
            certificates[tuple(line)] = cert
            print(f"{cert}\n")
        except Exception as e:
            if line[0]:
                print(f"Error with: {line[0]} [{line[1]}] : {e}\n")
            else:
                print(f"Error with: [{line[1]}] : {e}\n")
            certificates[tuple(line)] = e

        try:
            sni_x509 = sslUtils.get_cert_sni(url, port)
            sni_cert = Cert(sni_x509, port, "True")
            certificates[tuple(line)] = sni_cert
            print(f"{sni_cert}")
        except Exception as e:
            if line[0]:
                print(f"Error with: {line[0]} [{line[1]}] : {e}\n")
            else:
                print(f"Error with: [{line[1]}] : {e}\n")
            certificates[tuple(line)] = e
        print()

    return certificates


def main():
    argc, argv = len(sys.argv), sys.argv

    if 4 > argc:
        print(f"Usage: python3 {argv[0]} [csv_filepath] [port] [out_file]")
        sys.exit(-1)

    file_name = argv[1]
    port = int(argv[2])
    out_name = argv[3]

    lines = read_file(file_name)
    parsed_lines = parse_lines(lines)
    certificates = generate_certs(parsed_lines, port)


    with open(out_name, 'w+') as fp:
        fieldnames = ["Domain Name", "IP Address", "SNI", "Port", "Self-Signed", f"EXPIRED (as of {date.today()})", 
                      "Expiring in next 30 days", "Not Before", "Not After", "Issuer", "Subject"]
        w = csv.writer(fp, delimiter=',', dialect='excel', lineterminator='\n')
        w.writerow(fieldnames)
        for key, val in certificates.items():
            if isinstance(val, Exception):
                if key[0]:
                    w.writerow([key[0], key[1], val])
                continue
            w.writerow([key[0], key[1], val.SNI, str(val.Port), val.SelfSigned, val.Expired, val.NextThirtyDays,
                        val.NotBefore, val.NotAfter, str(val.Issuer), str(val.Subject)])


if __name__ == '__main__':
    main()


