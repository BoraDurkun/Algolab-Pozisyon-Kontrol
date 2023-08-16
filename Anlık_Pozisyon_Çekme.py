from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
import tkinter as tk
from tkinter import messagebox
import pandas as pd
from datetime import datetime
import json
import os
from datetime import datetime
import requests, hashlib, json, base64, inspect, time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import subprocess
# Bugünün tarihini al
bugunun_tarihi = datetime.today().strftime('%d-%m-%Y')
# URLS
hostname = "www.algolab.com.tr"
api_hostname = f"https://{hostname}"
api_url = api_hostname + "/api"
socket_url = f"wss://{hostname}/api/ws"
# ENDPOINTS
URL_LOGIN_USER = "/api/LoginUser"
URL_LOGIN_CONTROL = "/api/LoginUserControl"
URL_INSTANTPOSITION = "/api/InstantPosition"
URL_VIOPCUSTOMEROVERALL = "/api/ViopCustomerOverall"

### Bakiye bilgisi

last_request = 0.0
LOCK = False
class Backend():
    def __init__(self, api_key, username, password, auto_login=False, keep_alive=False, verbose=True):
        """
        api_key: API_KEY
        username: TC Kimlik No
        password: DENIZBANK_HESAP_ŞİFRENİZ
        verbose: True, False - İşlemlerin çıktısını yazdırır
        """
        if verbose:
            print("Sistem hazırlanıyor...")
        try:
            self.api_code = api_key.split("-")[1]
        except:
            self.api_code = api_key
        self.api_key = "API-" + self.api_code
        self.username = username
        self.password = password
        self.api_hostname = api_hostname
        self.api_url = api_url
        self.headers = {"APIKEY": self.api_key}
        self.verbose = verbose
        self.ohlc = []
        self.token = ""
        self.new_hour = False
        self.sms_code = ""
        self.hash = ""
        self.DataFrame1=pd.DataFrame(None)
    # LOGIN
    def start(self):             
        self.LoginUserControl()

    def LoginUser(self):
        try:
            if self.verbose:
                print("Login işlemi yapılıyor...")
                
            f = inspect.stack()[0][3]
            u = self.encrypt(self.username)
            p = self.encrypt(self.password)
            payload = {"username": u, "password": p}
            endpoint = URL_LOGIN_USER
            resp = self.post(endpoint=endpoint, payload=payload, login=True)
            login_user = self.error_check(resp, f)
            if not login_user:
                return False
            login_user = resp.json()
            succ = login_user["success"]
            msg = login_user["message"]
            content = login_user["content"]
            if succ:
                self.token = content["token"]
                if self.verbose:
                    print("Login başarılı.")
                return True
            else:
                if self.verbose:
                    print(f"Login Başarısız. self.mesaj: {msg}")
        except Exception as e:
            print(f"{f}() fonsiyonunda hata oluştu: {e}")

    def LoginUserControl(self):
        try:
            if self.verbose:
                print("Login kontrolü yapılıyor...")
            f = inspect.stack()[0][3]
            t = self.encrypt(self.token)
            s = self.encrypt(self.sms_code)
            payload = {'token': t, 'password': s}
            endpoint = URL_LOGIN_CONTROL
            resp = self.post(endpoint, payload=payload, login=True)
            login_control = self.error_check(resp, f)
            if not login_control:
                return False
            login_control = resp.json()
            succ = login_control["success"]
            msg = login_control["message"]
            content = login_control["content"]
            if succ:
                self.hash = content["hash"]
                if self.verbose:
                    print("Login kontrolü başarılı.")
                return True
            else:
                if self.verbose:
                    print(f"Login kontrolü başarısız.\nself.mesaj: {msg}")
        except Exception as e:
            print(f"{f}() fonsiyonunda hata oluştu: {e}")
            
    def GetViopCustomerOverall(self, sub_account=""):
        try:
            f = inspect.stack()[0][3]
            end_point = URL_VIOPCUSTOMEROVERALL
            payload = {'Subaccount': sub_account}
            resp = self.post(end_point, payload)
            bakiye = self.error_check(resp, f)
        except Exception as e:
            print(f"{f}() fonsiyonunda hata oluştu: {e}")
        if bakiye:
            try:
                succ = bakiye["success"]
                if succ:
                    content = bakiye["content"]
                    self.DataFrame1 = pd.DataFrame(content)
                    # Tüm boş dize alanlarını 0 ile doldurma
                    self.DataFrame1.replace('', '0', inplace=True)
                    # Belirli sütunları seçme
                    selected_columns = ['contract', 'units','totalcost', 'profit'] # sütunları düzenle
                    self.DataFrame1 = self.DataFrame1.loc[:, selected_columns]
                    self.DataFrame1 = self.DataFrame1.round(4)
                    # Yeni isimleri belirleyen bir sözlük oluşturun
                    new_columns = {
                        'contract': 'Menkul',
                        'units': 'Nominal\Adet',
                        'totalcost': 'Maliyet',
                        'profit': 'Pot. Kar',
                    }
                    # Sütun isimlerini yeniden adlandırın
                    self.DataFrame1.rename(columns=new_columns, inplace=True)
            except Exception as e:
                print(f"Hata oluştu: {e}") 
            
    def GetInstantPosition(self, sub_account=""):
        try:
            f = inspect.stack()[0][3]
            end_point = URL_INSTANTPOSITION
            payload = {'Subaccount': sub_account}
            resp = self.post(end_point, payload)
            bakiye = self.error_check(resp, f)
            if bakiye:
                succ = bakiye["success"]
                if succ:
                    content = bakiye["content"]

                    # İçeriği doğrudan bir DataFrame'e dönüştürme
                    DataFrame2 = pd.DataFrame(content)

                    # Tüm boş dize alanlarını 0 ile doldurma
                    DataFrame2.replace('', '0', inplace=True)
                    # Belirli sütunları seçme
                    selected_columns = ['code', 'totalstock','unitprice' ,'tlamaount','maliyet', 'profit','explanation'] # sütunları düzenle
                    DataFrame2 = DataFrame2.loc[:, selected_columns]
                    DataFrame2 = DataFrame2.round(4)
                    # Yeni isimleri belirleyen bir sözlük oluşturun
                    new_columns = {
                        'code': 'Menkul',
                        'totalstock': 'Nominal\Adet',
                        'unitprice': 'Fiyat',
                        'tlamaount': 'Tutar(₺)',
                        'maliyet': 'Maliyet',
                        'profit': 'Pot. Kar',
                        'explanation': 'Açıklama'
                    }
                    # Sütun isimlerini yeniden adlandırın
                    DataFrame2.rename(columns=new_columns, inplace=True)
                    # "F_" değeri ile başlayan bütün değerleri silme
                    
                    DataFrame2 = DataFrame2[~DataFrame2['Menkul'].str.startswith('F_')]
                        # Eksik olan sütunları DataFrame1'e ekleme
                    for col in DataFrame2.columns:
                        if col not in self.DataFrame1.columns:
                            self.DataFrame1[col] = 0  # veya NaN
                    self.DataFrame1 = self.DataFrame1[DataFrame2.columns]
                    df = pd.concat([self.DataFrame1, DataFrame2], ignore_index=True)
                    df = df.sort_values(by='Menkul')
                    # Excel dosyası olarak kaydetme
                    excel_adı = f'{bugunun_tarihi}_POZİSYONLAR'
                    df.to_excel(f'{excel_adı}.xlsx', index=False, float_format='%.4f')

                    # Excel dosyasını otomatik olarak açma
                    excel_yolu = os.path.abspath(excel_adı)
                    subprocess.Popen(["start", "excel", excel_yolu], shell=True)            
        except Exception as e:
            print(f"{f}() fonsiyonunda hata oluştu: {e}")
            
    def error_check(self, resp, f, silent=False):
        try:
            if resp.status_code == 200:
                data = resp.json()
                return data
            else:
                if not silent:
                    print(f"Error kodu: {resp.status_code}")
                    
                    print(resp.text)
                    
                return False
        except:
            if not silent:
                print(f"{f}() fonksiyonunda veri tipi hatası. Veri, json formatından farklı geldi:")
                
                print(resp.text)
                
            return False

    def encrypt(self, text):
        iv = b'\0' * 16
        key = base64.b64decode(self.api_code.encode('utf-8'))
        cipher = AES.new(key, AES.MODE_CBC, iv)
        bytes = text.encode()
        padded_bytes = pad(bytes, 16)
        r = cipher.encrypt(padded_bytes)
        return base64.b64encode(r).decode("utf-8")

    def make_checker(self, endpoint, payload):
        if len(payload) > 0:
            body = json.dumps(payload).replace(' ', '')
        else:
            body = ""
        data = self.api_key + self.api_hostname + endpoint + body
        checker = hashlib.sha256(data.encode('utf-8')).hexdigest()
        return checker

    def _request(self, method, url, endpoint, payload, headers):
        global last_request, LOCK
        while LOCK:
            time.sleep(0.1)
        LOCK = True
        try:
            response = ""
            if method == "POST":
                t = time.time()
                diff = t - last_request
                wait_for = last_request > 0.0 and diff < 1.0 # son işlemden geçen süre 1 saniyeden küçükse bekle
                if wait_for:
                    time.sleep(1 - diff + 0.1)
                response = requests.post(url + endpoint, json=payload, headers=headers)
                last_request = time.time()
        finally:
            LOCK = False
        return response

    def post(self, endpoint, payload, login=False):
        url = self.api_url
        if not login:
            checker = self.make_checker(endpoint, payload)
            headers = {"APIKEY": self.api_key,
                       "Checker": checker,
                       "Authorization": self.hash
                       }
        else:
            headers = {"APIKEY": self.api_key}
        resp = self._request("POST", url, endpoint, payload=payload, headers=headers)
        return resp
class Menu():
    def __init__(self):
        pass

    @staticmethod
    def anahtar_olustur():
        """Anahtar oluşturma işlemi"""
        anahtar = Fernet.generate_key()
        with open('anahtar.txt', 'wb') as file:
            file.write(anahtar)
        return anahtar

    @staticmethod
    def anahtar_yukle():
        """Anahtarı yükler veya oluşturur"""
        try:
            with open('anahtar.txt', 'rb') as file:
                return file.read()
        except FileNotFoundError:
            return Menu.anahtar_olustur()
        
    def sms_ekrani():
        """SMS ekranını oluşturur ve kullanıcı girişini bekler"""
        def on_dogrula_ve_calistir():
            Conn.sms_code = str(sms_entry.get())
            if Conn.LoginUserControl():
                root.withdraw() # Ana pencereyi gizle
                messagebox.showwarning("Başarılı", "SMS Doğrulaması Başarılı, İşlem Gerçekleştiriliyor.")
                Conn.GetViopCustomerOverall()  # İlgili fonksiyon çağrısı
                Conn.GetInstantPosition() # İlgili fonksiyon çağrısı
            else:
                bilgi_label.config(text="SMS kodu Hatalı!")
                bilgi_label.pack()
                

        for widget in root.winfo_children():
            widget.destroy()
            
        root.geometry("260x100")  # Pencere boyutunu ayarlar
        root.title("SMS Doğrulama")
        tk.Label(root, text="Lütfen SMS ile gönderilen kodu girin:").pack()
        sms_entry = tk.Entry(root)
        sms_entry.pack()
        button = tk.Button(root, text="Doğrula ve Çalıştır", command=on_dogrula_ve_calistir)
        button.pack()
        bilgi_label = tk.Label(root, text="SMS kodu bekleniyor.")
        bilgi_label.pack()

    def giris_yap():
        """Kullanıcı girişini gerçekleştirir"""
        try:
            global Conn
            Conn = Backend(api_key=api_key_entry.get(), username=kullanici_adi_entry.get(), password=sifre_entry.get(), auto_login=False, verbose=False)
            if Conn.LoginUser():
                kullanici_adi = kullanici_adi_entry.get().encode()
                sifre = sifreleme.encrypt(sifre_entry.get().encode())
                api_key = sifreleme.encrypt(api_key_entry.get().encode())
                with open('bilgiler.txt', 'wb') as file:
                    file.write(kullanici_adi + b'\n')
                    file.write(sifre + b'\n')
                    file.write(api_key)     
                Menu.sms_ekrani()
        except Exception as e:  # Genel bir hata türü yakalıyor, daha spesifik olabilir.
            Menu.bilgi_guncelle(f"Giriş yapılırken bir hata oluştu: {str(e)}")

    def bilgileri_yukle():
        """Kullanıcı bilgilerini yükler"""
        try:
            with open('bilgiler.txt', 'rb') as file:
                kullanici_adi = file.readline().strip().decode() # Şifrelenmemiş olarak okur
                sifre = sifreleme.decrypt(file.readline().strip()).decode()
                api_key = sifreleme.decrypt(file.readline().strip()).decode()

            kullanici_adi_entry.delete(0, tk.END)
            kullanici_adi_entry.insert(0, kullanici_adi)
            sifre_entry.delete(0, tk.END)
            sifre_entry.insert(0, sifre)
            api_key_entry.delete(0, tk.END)
            api_key_entry.insert(0, api_key)

            Menu.bilgi_guncelle("Bilgiler yüklendi!")
        except FileNotFoundError:
            Menu.bilgi_guncelle("Bilgiler dosyası bulunamadı.")
        except InvalidToken:
            Menu.bilgi_guncelle("Şifre deşifre edilemedi. Geçersiz anahtar veya şifre.")
        except Exception as e:
            Menu.bilgi_guncelle(f"Bilgiler yüklenirken bir hata oluştu. Hata tipi: {type(e)}")

    def bilgi_guncelle(mesaj):
        bilgi_label.config(text=mesaj, wraplength=300)  # Metni sarar
    
if __name__ == "__main__":
    
    anahtar = Menu.anahtar_yukle()
    sifreleme = Fernet(anahtar)
    root = tk.Tk()
    root.iconbitmap('algolab-icon.ico')  # 'simge.ico', projenizin dizininde bulunan simge dosyasının adıdır.
    root.title("Kullanıcı Giriş Ekranı")
    
    # Ekranın ortasına yerleştirme
    genislik = 340
    yukseklik = 180
    x = (root.winfo_screenwidth() // 2) - (genislik // 2)
    y = (root.winfo_screenheight() // 2) - (yukseklik // 2)
    root.geometry(f'{genislik}x{yukseklik}+{x}+{y}')

    tk.Label(root, text="TC Kimlik Numaranız veya MobilDeniz Kullanıcı Adınız:").pack()
    kullanici_adi_entry = tk.Entry(root,width=20)
    kullanici_adi_entry.pack()

    tk.Label(root, text="Mobil Deniz Giriş Şifreniz:").pack()
    sifre_entry = tk.Entry(root, show="*",width=20)
    sifre_entry.pack()

    tk.Label(root, text="Algolab API Keyiniz:").pack()
    api_key_entry = tk.Entry(root,width=20)
    api_key_entry.pack()
    tk.Button(root, text="Giriş Yap", command=Menu.giris_yap,width=20,height=1).pack()
    bilgi_label = tk.Label(root, text="", wraplength=300)  # Metni sarar
    bilgi_label.pack()

    # Bilgileri yükleme
    Menu.bilgileri_yukle()
    root.mainloop()