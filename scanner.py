import socket
import ipaddress
import concurrent.futures
import csv
import json
import os
import sys
import logging
from logging.handlers import RotatingFileHandler
import requests
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.table import Table
from rich.prompt import Prompt, IntPrompt, Confirm
import urllib3
from urllib3.exceptions import InsecureRequestWarning
import random

# Ignorowanie ostrzeżeń dotyczących niezweryfikowanych certyfikatów SSL
urllib3.disable_warnings(InsecureRequestWarning)

# Konfiguracja logowania z rotacją plików
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler('port_scanner.log', maxBytes=5*1024*1024, backupCount=2, encoding='utf-8')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

console = Console()

# Mapa krajów do ich zakresów IP (CIDR)
COUNTRY_IP_RANGES = {
    "Polska": [
        "5.8.0.0/13",
        "31.6.0.0/16",
        "37.32.0.0/12",
        "46.229.0.0/16",
        "62.128.0.0/11",
        "77.49.0.0/16",
        "79.136.0.0/12",
        "83.130.0.0/16",
        "85.80.0.0/13",
        "94.130.0.0/14",
        "185.7.0.0/16",
        "185.31.0.0/16",
        "185.36.0.0/16",
        "185.87.0.0/16",
        "185.93.0.0/16",
        "185.108.0.0/16",
        "185.112.0.0/16",
        "185.128.0.0/16",
        "185.144.0.0/16",
        "185.160.0.0/16",
        "185.224.0.0/12",
        "195.154.0.0/15",
        "212.22.0.0/16",
        "212.188.0.0/14",
        "212.248.0.0/14",
        "213.24.0.0/15",
        "213.58.0.0/15",
        "213.120.0.0/14"
    ],
    "Niemcy": [
        "5.11.0.0/16",
        "5.12.0.0/14",
        "5.16.0.0/12",
        # Dodaj więcej zakresów według potrzeb
    ],
    "USA": [
        "3.0.0.0/8",
        "4.0.0.0/8",
        "8.0.0.0/8",
        "12.0.0.0/6",
        "13.0.0.0/8",
        # Dodaj więcej zakresów według potrzeb
    ],
    "Wielka Brytania": [
        "2.16.0.0/12",
        "5.62.0.0/15",
        "5.104.0.0/13",
        # Dodaj więcej zakresów według potrzeb
    ],
    "Kanada": [
        "24.48.0.0/12",
        "24.192.0.0/12",
        "24.208.0.0/13",
        # Dodaj więcej zakresów według potrzeb
    ]
}

def load_config(config_file='config.json'):
    """
    Ładuje konfigurację z pliku JSON.
    """
    if not os.path.isfile(config_file):
        console.print(f"[yellow]Plik konfiguracyjny {config_file} nie został znaleziony. Uruchamiam tryb interaktywny.[/yellow]")
        return None
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
        console.print(f"[green]Konfiguracja załadowana z {config_file}.[/green]")
        logging.info(f"Konfiguracja załadowana z {config_file}.")
        return config
    except json.JSONDecodeError as e:
        console.print(f"[red]Błąd podczas ładowania pliku konfiguracyjnego: {e}[/red]")
        logging.error(f"Błąd podczas ładowania pliku konfiguracyjnego: {e}")
        return None

def save_config(config, config_file='config.json'):
    """
    Zapisuje konfigurację do pliku JSON.
    """
    try:
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
        console.print(f"[green]Konfiguracja zapisana do {config_file}.[/green]")
        logging.info(f"Konfiguracja zapisana do {config_file}.")
    except IOError as e:
        console.print(f"[red]Błąd podczas zapisywania konfiguracji: {e}[/red]")
        logging.error(f"Błąd podczas zapisywania konfiguracji: {e}")

def validate_ip(ip_str):
    """
    Waliduje format adresu IP.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return str(ip)
    except ValueError:
        return None

def generate_random_ips_from_country(country, count):
    """
    Generuje losową listę adresów IP na podstawie wybranego kraju bez generowania całej listy.
    """
    ip_ranges = COUNTRY_IP_RANGES.get(country, [])
    total_hosts = sum(ipaddress.ip_network(cidr, strict=False).num_addresses - 2 for cidr in ip_ranges if '/' in cidr)
    if count > total_hosts:
        console.print(f"[yellow]Żądana liczba IP ({count}) przekracza dostępne IP w kraju {country} ({total_hosts}). Skanuję wszystkie dostępne IP.[/yellow]")
        logging.warning(f"Żądana liczba IP ({count}) przekracza dostępne IP w kraju {country} ({total_hosts}). Skanuję wszystkie dostępne IP.")
        count = total_hosts

    sampled_ips = set()
    while len(sampled_ips) < count:
        cidr = random.choice(ip_ranges)
        network = ipaddress.ip_network(cidr, strict=False)
        # Losowanie hosta w sieci
        random_ip = str(network[random.randint(1, network.num_addresses - 2)])
        sampled_ips.add(random_ip)
    return list(sampled_ips)

def generate_ip_range(start_ip, end_ip):
    """
    Generuje listę adresów IP w zadanym zakresie.
    """
    try:
        start = int(ipaddress.IPv4Address(start_ip))
        end = int(ipaddress.IPv4Address(end_ip))
    except ipaddress.AddressValueError as e:
        logging.error(f"Błąd w adresach IP: {e}")
        console.print(f"[red]Błąd w adresach IP: {e}[/red]")
        sys.exit(1)

    if start > end:
        logging.error("Adres początkowy jest większy niż adres końcowy.")
        console.print("[red]Adres początkowy musi być mniejszy lub równy adresowi końcowemu.[/red]")
        sys.exit(1)

    return [str(ipaddress.IPv4Address(ip)) for ip in range(start, end + 1)]

def port_is_open(ip, port, timeout, protocol='TCP'):
    """
    Sprawdza, czy dany port jest otwarty na danym adresie IP.
    """
    try:
        if protocol.upper() == 'TCP':
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout / 1000)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    logging.debug(f"Port {port} na {ip} jest otwarty.")
                    return True
                else:
                    logging.debug(f"Port {port} na {ip} jest zamknięty.")
                    return False
        else:
            # Implementacja sprawdzania UDP, jeśli potrzebne
            logging.debug(f"Nieobsługiwany protokół {protocol}.")
            return False
    except socket.error as e:
        logging.error(f"Błąd przy sprawdzaniu portu {port} na {ip}: {e}")
        return False

def get_service_name(port, protocol='TCP'):
    """
    Pobiera nazwę usługi działającej na danym porcie.
    """
    try:
        # Specjalna obsługa dla znanych portów
        known_services = {
            8001: "Dreambox",
            8002: "Dreambox",
            8888: "NBox",
            8080: "Kodi",
            65001: "HDHomeRun"
        }
        return known_services.get(port, socket.getservbyport(port, protocol.lower()))
    except:
        return "Nieznany"

# ---------------------------
# Definicje Funkcji Detekcji
# ---------------------------

def detect_dreambox(ip, port, timeout):
    """
    Sprawdza, czy dany adres IP należy do dekodera Dreambox poprzez sprawdzenie otwartego portu i obecności specyficznego tekstu w odpowiedzi HTTP.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout / 1000)
            result = sock.connect_ex((ip, port))
            if result == 0:
                # Wysyłanie zapytania HTTP GET do portu
                request = f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
                sock.sendall(request.encode())
                response = sock.recv(4096).decode(errors='ignore')
                logging.debug(f"Odpowiedź od Dreambox {ip}:{port}:\n{response}")
                if "Dreambox" in response or "dreambox" in response:
                    logging.debug(f"Dreambox potwierdzony na {ip}:{port}.")
                    return True
    except socket.error as e:
        logging.error(f"Błąd przy sprawdzaniu Dreambox na {ip}:{port} - {e}")
    return False

def detect_nbox(ip, port, timeout):
    """
    Sprawdza, czy dany adres IP należy do dekodera NBox poprzez sprawdzenie otwartego portu i obecności specyficznego tekstu w odpowiedzi HTTP.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout / 1000)
            result = sock.connect_ex((ip, port))
            if result == 0:
                # Wysyłanie zapytania HTTP GET do portu
                request = f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
                sock.sendall(request.encode())
                response = sock.recv(4096).decode(errors='ignore')
                logging.debug(f"Odpowiedź od NBox {ip}:{port}:\n{response}")
                if "NBox" in response or "nbox" in response:
                    logging.debug(f"NBox potwierdzony na {ip}:{port}.")
                    return True
    except socket.error as e:
        logging.error(f"Błąd przy sprawdzaniu NBox na {ip}:{port} - {e}")
    return False

def detect_vuplus(ip, port, timeout):
    """
    Sprawdza, czy dany adres IP należy do dekodera Vu+ poprzez sprawdzenie otwartego portu i obecności specyficznego tekstu w odpowiedzi HTTP.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout / 1000)
            result = sock.connect_ex((ip, port))
            if result == 0:
                # Wysyłanie zapytania HTTP GET do portu
                request = f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
                sock.sendall(request.encode())
                response = sock.recv(4096).decode(errors='ignore')
                logging.debug(f"Odpowiedź od VuPlus {ip}:{port}:\n{response}")
                if "Vu+" in response or "vuplus" in response:
                    logging.debug(f"VuPlus potwierdzony na {ip}:{port}.")
                    return True
    except socket.error as e:
        logging.error(f"Błąd przy sprawdzaniu VuPlus na {ip}:{port} - {e}")
    return False

def detect_kodi(ip, port, timeout):
    """
    Sprawdza, czy dany adres IP należy do serwera Kodi poprzez sprawdzenie otwartego portu i obecności specyficznego tekstu w odpowiedzi HTTP.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout / 1000)
            result = sock.connect_ex((ip, port))
            if result == 0:
                # Wysyłanie zapytania HTTP GET do portu
                request = f"GET /jsonrpc HTTP/1.1\r\nHost: {ip}\r\n\r\n"
                sock.sendall(request.encode())
                response = sock.recv(4096).decode(errors='ignore')
                logging.debug(f"Odpowiedź od Kodi {ip}:{port}:\n{response}")
                if "kodi" in response.lower():
                    logging.debug(f"Kodi potwierdzony na {ip}:{port}.")
                    return True
    except socket.error as e:
        logging.error(f"Błąd przy sprawdzaniu Kodi na {ip}:{port} - {e}")
    return False

def detect_tvheadend(ip, port, timeout):
    """
    Sprawdza, czy dany adres IP należy do serwera TVHeadend poprzez sprawdzenie otwartego portu i obecności specyficznego tekstu w odpowiedzi HTTP.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout / 1000)
            result = sock.connect_ex((ip, port))
            if result == 0:
                # Wysyłanie zapytania HTTP GET do portu
                request = f"GET /api/status HTTP/1.1\r\nHost: {ip}\r\n\r\n"
                sock.sendall(request.encode())
                response = sock.recv(4096).decode(errors='ignore')
                logging.debug(f"Odpowiedź od TVHeadend {ip}:{port}:\n{response}")
                if "tvheadend" in response.lower():
                    logging.debug(f"TVHeadend potwierdzony na {ip}:{port}.")
                    return True
    except socket.error as e:
        logging.error(f"Błąd przy sprawdzaniu TVHeadend na {ip}:{port} - {e}")
    return False

def detect_hdhr(ip, port, timeout):
    """
    Sprawdza, czy dany adres IP należy do urządzenia HDHomeRun poprzez sprawdzenie otwartego portu i obecności specyficznego tekstu w odpowiedzi HTTP.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout / 1000)
            result = sock.connect_ex((ip, port))
            if result == 0:
                # Wysyłanie zapytania HTTP GET do portu
                request = f"GET /discover.json HTTP/1.1\r\nHost: {ip}\r\n\r\n"
                sock.sendall(request.encode())
                response = sock.recv(4096).decode(errors='ignore')
                logging.debug(f"Odpowiedź od HDHomeRun {ip}:{port}:\n{response}")
                if "hdhomerun" in response.lower():
                    logging.debug(f"HDHomeRun potwierdzony na {ip}:{port}.")
                    return True
    except socket.error as e:
        logging.error(f"Błąd przy sprawdzaniu HDHomeRun na {ip}:{port} - {e}")
    return False

# ---------------------------
# Definicje Funkcji Pobierania
# ---------------------------

def download_m3u_from_dreambox(ip, port, username=None, password=None, use_https=False, session=None):
    """
    Pobiera plik m3u z dekodera Dreambox na określonym porcie.
    Zwraca True jeśli pobranie się powiodło, False w przeciwnym razie.
    """
    protocol = "https" if use_https else "http"
    m3u_url = f"{protocol}://{ip}:{port}/playlist.m3u"  # Dostosuj ścieżkę według potrzeb
    logging.debug(f"Próbuję pobrać playlistę z Dreambox na URL: {m3u_url}")

    try:
        if username and password:
            response = session.get(m3u_url, auth=HTTPBasicAuth(username, password), timeout=10, verify=False)
            logging.debug(f"Wykorzystano uwierzytelnianie dla {ip}.")
        else:
            response = session.get(m3u_url, timeout=10, verify=False)
            logging.debug(f"Próbuję pobrać playlistę z {ip} bez uwierzytelniania.")

        if response.status_code == 200:
            playlist_dir = "Dreambox_Playlists"
            os.makedirs(playlist_dir, exist_ok=True)
            playlist_filename = os.path.join(playlist_dir, f"dreambox_{ip.replace('.', '_')}_{port}.m3u")
            with open(playlist_filename, "w", encoding='utf-8') as file:
                file.write(response.text)
            console.print(f"[green]Playlisty Dreambox pobrane i zapisane: {playlist_filename}[/green]")
            logging.info(f"Playlisty Dreambox pobrane i zapisane: {playlist_filename}")
            return True
        else:
            console.print(f"[yellow]Nie udało się pobrać playlisty z Dreambox na {ip}. Status code: {response.status_code}[/yellow]")
            logging.warning(f"Nie udało się pobrać playlisty z Dreambox na {ip}. Status code: {response.status_code}")
            return False
    except requests.RequestException as e:
        console.print(f"[red]Błąd podczas pobierania playlisty z Dreambox na {ip}: {e}[/red]")
        logging.error(f"Błąd podczas pobierania playlisty z Dreambox na {ip}: {e}")
        return False

def download_m3u_from_nbox(ip, port, username=None, password=None, use_https=False, session=None):
    """
    Pobiera plik m3u z dekodera NBox na określonym porcie.
    Zwraca True jeśli pobranie się powiodło, False w przeciwnym razie.
    """
    protocol = "https" if use_https else "http"
    m3u_url = f"{protocol}://{ip}:{port}/playlist.m3u"  # Dostosuj ścieżkę według potrzeb
    logging.debug(f"Próbuję pobrać playlistę z NBox na URL: {m3u_url}")

    try:
        if username and password:
            response = session.get(m3u_url, auth=HTTPBasicAuth(username, password), timeout=10, verify=False)
            logging.debug(f"Wykorzystano uwierzytelnianie dla {ip}.")
        else:
            response = session.get(m3u_url, timeout=10, verify=False)
            logging.debug(f"Próbuję pobrać playlistę z {ip} bez uwierzytelniania.")

        if response.status_code == 200:
            playlist_dir = "NBox_Playlists"
            os.makedirs(playlist_dir, exist_ok=True)
            playlist_filename = os.path.join(playlist_dir, f"nbox_{ip.replace('.', '_')}_{port}.m3u")
            with open(playlist_filename, "w", encoding='utf-8') as file:
                file.write(response.text)
            console.print(f"[green]Playlisty NBox pobrane i zapisane: {playlist_filename}[/green]")
            logging.info(f"Playlisty NBox pobrane i zapisane: {playlist_filename}")
            return True
        else:
            console.print(f"[yellow]Nie udało się pobrać playlisty z NBox na {ip}. Status code: {response.status_code}[/yellow]")
            logging.warning(f"Nie udało się pobrać playlisty z NBox na {ip}. Status code: {response.status_code}")
            return False
    except requests.RequestException as e:
        console.print(f"[red]Błąd podczas pobierania playlisty z NBox na {ip}: {e}[/red]")
        logging.error(f"Błąd podczas pobierania playlisty z NBox na {ip}: {e}")
        return False

def download_m3u_from_vuplus(ip, port, username=None, password=None, use_https=False, session=None):
    """
    Pobiera plik m3u z dekodera Vu+ na określonym porcie.
    Zwraca True jeśli pobranie się powiodło, False w przeciwnym razie.
    """
    protocol = "https" if use_https else "http"
    m3u_url = f"{protocol}://{ip}:{port}/playlist.m3u"  # Dostosuj ścieżkę według potrzeb
    logging.debug(f"Próbuję pobrać playlistę z VuPlus na URL: {m3u_url}")

    try:
        if username and password:
            response = session.get(m3u_url, auth=HTTPBasicAuth(username, password), timeout=10, verify=False)
            logging.debug(f"Wykorzystano uwierzytelnianie dla {ip}.")
        else:
            response = session.get(m3u_url, timeout=10, verify=False)
            logging.debug(f"Próbuję pobrać playlistę z {ip} bez uwierzytelniania.")

        if response.status_code == 200:
            playlist_dir = "VuPlus_Playlists"
            os.makedirs(playlist_dir, exist_ok=True)
            playlist_filename = os.path.join(playlist_dir, f"vuplus_{ip.replace('.', '_')}_{port}.m3u")
            with open(playlist_filename, "w", encoding='utf-8') as file:
                file.write(response.text)
            console.print(f"[green]Playlisty VuPlus pobrane i zapisane: {playlist_filename}[/green]")
            logging.info(f"Playlisty VuPlus pobrane i zapisane: {playlist_filename}")
            return True
        else:
            console.print(f"[yellow]Nie udało się pobrać playlisty z VuPlus na {ip}. Status code: {response.status_code}[/yellow]")
            logging.warning(f"Nie udało się pobrać playlisty z VuPlus na {ip}. Status code: {response.status_code}")
            return False
    except requests.RequestException as e:
        console.print(f"[red]Błąd podczas pobierania playlisty z VuPlus na {ip}: {e}[/red]")
        logging.error(f"Błąd podczas pobierania playlisty z VuPlus na {ip}: {e}")
        return False

def download_playlist_from_kodi(ip, port, timeout):
    """
    Pobiera playlistę z serwera Kodi poprzez API na określonym porcie.
    Zwraca True jeśli pobranie się powiodło, False w przeciwnym razie.
    """
    try:
        api_url = f"http://{ip}:{port}/jsonrpc"
        payload = {
            "jsonrpc": "2.0",
            "method": "Playlist.GetItems",
            "params": {
                "playlistid": 1  # Zazwyczaj 1 to lista odtwarzania
            },
            "id": 1
        }
        logging.debug(f"Próbuję pobrać playlistę z Kodi na URL: {api_url}")
        response = requests.post(api_url, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            playlist = data.get("result", {}).get("items", [])
            if not playlist:
                logging.warning(f"Brak playlisty do pobrania z Kodi na {ip}:{port}.")
                return False
            playlist_dir = "Kodi_Playlists"
            os.makedirs(playlist_dir, exist_ok=True)
            playlist_filename = os.path.join(playlist_dir, f"kodi_{ip.replace('.', '_')}_{port}.m3u")
            with open(playlist_filename, "w", encoding='utf-8') as file:
                for item in playlist:
                    # Zakładając, że każdy element playlisty ma URL strumienia
                    stream_url = item.get("file", "")
                    if stream_url:
                        file.write(f"{stream_url}\n")
            console.print(f"[green]Playlisty Kodi pobrane i zapisane: {playlist_filename}[/green]")
            logging.info(f"Playlisty Kodi pobrane i zapisane: {playlist_filename}")
            return True
        else:
            console.print(f"[yellow]Nie udało się pobrać playlisty z Kodi na {ip}. Status code: {response.status_code}[/yellow]")
            logging.warning(f"Nie udało się pobrać playlisty z Kodi na {ip}. Status code: {response.status_code}")
            return False
    except requests.RequestException as e:
        console.print(f"[red]Błąd podczas pobierania playlisty z Kodi na {ip}: {e}[/red]")
        logging.error(f"Błąd podczas pobierania playlisty z Kodi na {ip}: {e}")
        return False

def download_playlist_from_tvheadend(ip, port, username=None, password=None, use_https=False, session=None):
    """
    Pobiera playlistę z serwera TVHeadend na określonym porcie.
    Zwraca True jeśli pobranie się powiodło, False w przeciwnym razie.
    """
    protocol = "https" if use_https else "http"
    if username:
        m3u_url = f"{protocol}://{ip}:{port}/api/stream/channel/{username}/playlist.m3u"  # Dostosuj ścieżkę według potrzeb
    else:
        m3u_url = f"{protocol}://{ip}:{port}/api/stream/playlist.m3u"  # Dostosuj ścieżkę według potrzeb
    logging.debug(f"Próbuję pobrać playlistę z TVHeadend na URL: {m3u_url}")

    try:
        if username and password:
            response = session.get(m3u_url, auth=HTTPBasicAuth(username, password), timeout=10, verify=False)
            logging.debug(f"Wykorzystano uwierzytelnianie dla {ip}.")
        else:
            response = session.get(m3u_url, timeout=10, verify=False)
            logging.debug(f"Próbuję pobrać playlistę z {ip} bez uwierzytelniania.")

        if response.status_code == 200:
            playlist_dir = "TVHeadend_Playlists"
            os.makedirs(playlist_dir, exist_ok=True)
            playlist_filename = os.path.join(playlist_dir, f"tvheadend_{ip.replace('.', '_')}_{port}.m3u")
            with open(playlist_filename, "w", encoding='utf-8') as file:
                file.write(response.text)
            console.print(f"[green]Playlisty TVHeadend pobrane i zapisane: {playlist_filename}[/green]")
            logging.info(f"Playlisty TVHeadend pobrane i zapisane: {playlist_filename}")
            return True
        else:
            console.print(f"[yellow]Nie udało się pobrać playlisty z TVHeadend na {ip}. Status code: {response.status_code}[/yellow]")
            logging.warning(f"Nie udało się pobrać playlisty z TVHeadend na {ip}. Status code: {response.status_code}")
            return False
    except requests.RequestException as e:
        console.print(f"[red]Błąd podczas pobierania playlisty z TVHeadend na {ip}: {e}[/red]")
        logging.error(f"Błąd podczas pobierania playlisty z TVHeadend na {ip}: {e}")
        return False

def create_playlist(ip, port, template_content, output_dir='HITS'):
    """
    Tworzy playlistę na podstawie szablonu, zastępując placeholder IP i port.
    """
    try:
        if "xxx.xxx.xxx.xxx" not in template_content or "PORT_PLACEHOLDER" not in template_content:
            console.print(f"[red]Szablon playlisty musi zawierać placeholdery 'xxx.xxx.xxx.xxx' i 'PORT_PLACEHOLDER'.[/red]")
            logging.error("Szablon playlisty nie zawiera wymaganych placeholderów.")
            return False
        playlist_content = template_content.replace("xxx.xxx.xxx.xxx", ip).replace("PORT_PLACEHOLDER", str(port))
        os.makedirs(output_dir, exist_ok=True)
        playlist_filename = os.path.join(output_dir, f"playlist_{ip.replace('.', '_')}_{port}.m3u")
        with open(playlist_filename, 'w', encoding='utf-8') as f:
            f.write(playlist_content)
        console.print(f"[green]Playlista utworzona: {playlist_filename}[/green]")
        logging.info(f"Playlista utworzona dla {ip} na porcie {port}: {playlist_filename}")
        return True
    except Exception as e:
        console.print(f"[red]Błąd przy tworzeniu playlisty dla {ip} na porcie {port}: {e}[/red]")
        logging.error(f"Błąd przy tworzeniu playlisty dla {ip} na porcie {port}: {e}")
        return False

def load_playlist_template():
    """
    Ładuje szablon playlisty. Jeśli nie istnieje, tworzy domyślny szablon.
    """
    template_filename = "playlist_template.m3u"

    if not os.path.isfile(template_filename):
        default_template = (
            "#EXTM3U\n"
            "# Playlist wygenerowana automatycznie\n"
            "# Dodaj poniższe linie, aby odtworzyć usługi\n"
            "#EXTINF:-1,Service on xxx.xxx.xxx.xxx:PORT_PLACEHOLDER\n"
            "http://xxx.xxx.xxx.xxx:PORT_PLACEHOLDER/stream\n"
        )
        try:
            with open(template_filename, "w", encoding='utf-8') as file:
                file.write(default_template)
            logging.info(f"Utworzono domyślny szablon playlisty: {template_filename}")
            console.print(f"[yellow]Utworzono domyślny szablon playlisty: {template_filename}[/yellow]")
        except IOError as e:
            console.print(f"[red]Nie udało się utworzyć szablonu playlisty: {e}[/red]")
            logging.error(f"Nie udało się utworzyć szablonu playlisty: {e}")
            sys.exit(1)

    try:
        with open(template_filename, "r", encoding='utf-8') as file:
            return file.read()
    except IOError as e:
        console.print(f"[red]Nie udało się odczytać szablonu playlisty: {e}[/red]")
        logging.error(f"Nie udało się odczytać szablonu playlisty: {e}")
        sys.exit(1)

# ---------------------------
# Definicje Klas Urządzeń
# ---------------------------

class Device:
    def __init__(self, ip, ports, timeout, session, logger):
        self.ip = ip
        self.ports = ports  # Lista portów dedykowanych dla tego urządzenia
        self.timeout = timeout
        self.session = session
        self.logger = logger

    def scan(self):
        raise NotImplementedError

    def get_playlist(self, port):
        raise NotImplementedError

class Dreambox(Device):
    ports = [8001, 8002]

    def scan(self):
        open_ports = []
        device_type = "Nieznany"
        detected_ports = []
        for port in self.ports:
            if port_is_open(self.ip, port, self.timeout):
                service = get_service_name(port)
                open_ports.append((port, service))
                if service == "Dreambox" and detect_dreambox(self.ip, port, self.timeout):
                    device_type = "Dreambox"
                    detected_ports.append(port)
        return open_ports, device_type, detected_ports

    def get_playlist(self, port):
        return download_m3u_from_dreambox(
            self.ip,
            port=port,
            username=self.session.get("username"),
            password=self.session.get("password"),
            use_https=self.session.get("use_https", False),
            session=self.session.get("session")
        )

class NBox(Device):
    ports = [8888]

    def scan(self):
        open_ports = []
        device_type = "Nieznany"
        detected_ports = []
        for port in self.ports:
            if port_is_open(self.ip, port, self.timeout):
                service = get_service_name(port)
                open_ports.append((port, service))
                if service == "NBox" and detect_nbox(self.ip, port, self.timeout):
                    device_type = "NBox"
                    detected_ports.append(port)
        return open_ports, device_type, detected_ports

    def get_playlist(self, port):
        return download_m3u_from_nbox(
            self.ip,
            port=port,
            username=self.session.get("username"),
            password=self.session.get("password"),
            use_https=self.session.get("use_https", False),
            session=self.session.get("session")
        )

class VuPlus(Device):
    ports = [8001, 8002]

    def scan(self):
        open_ports = []
        device_type = "Nieznany"
        detected_ports = []
        for port in self.ports:
            if port_is_open(self.ip, port, self.timeout):
                service = get_service_name(port)
                open_ports.append((port, service))
                if service == "HDHomeRun" and detect_hdhr(self.ip, port, self.timeout):
                    device_type = "HDHomeRun"
                    detected_ports.append(port)
                elif service == "VuPlus" and detect_vuplus(self.ip, port, self.timeout):
                    device_type = "VuPlus"
                    detected_ports.append(port)
        return open_ports, device_type, detected_ports

    def get_playlist(self, port):
        return download_m3u_from_vuplus(
            self.ip,
            port=port,
            username=self.session.get("username"),
            password=self.session.get("password"),
            use_https=self.session.get("use_https", False),
            session=self.session.get("session")
        )

class KodiDevice(Device):
    ports = [8080]

    def scan(self):
        open_ports = []
        device_type = "Nieznany"
        detected_ports = []
        for port in self.ports:
            if port_is_open(self.ip, port, self.timeout):
                service = get_service_name(port)
                open_ports.append((port, service))
                if service == "Kodi" and detect_kodi(self.ip, port, self.timeout):
                    device_type = "Kodi"
                    detected_ports.append(port)
        return open_ports, device_type, detected_ports

    def get_playlist(self, port):
        return download_playlist_from_kodi(
            self.ip,
            port=port,
            timeout=self.timeout
        )

class TVHeadend(Device):
    ports = [65001]

    def scan(self):
        open_ports = []
        device_type = "Nieznany"
        detected_ports = []
        for port in self.ports:
            if port_is_open(self.ip, port, self.timeout):
                service = get_service_name(port)
                open_ports.append((port, service))
                if service == "HDHomeRun" and detect_hdhr(self.ip, port, self.timeout):
                    device_type = "HDHomeRun"
                    detected_ports.append(port)
                elif service == "TVHeadend" and detect_tvheadend(self.ip, port, self.timeout):
                    device_type = "TVHeadend"
                    detected_ports.append(port)
        return open_ports, device_type, detected_ports

    def get_playlist(self, port):
        return download_playlist_from_tvheadend(
            self.ip,
            port=port,
            username=self.session.get("username"),
            password=self.session.get("password"),
            use_https=self.session.get("use_https", False),
            session=self.session.get("session")
        )

# ---------------------------
# Funkcja Skanowania IP
# ---------------------------

def scan_ip(ip, device_classes, ports, timeout, session, generate_playlist, template_content):
    """
    Skanuje określone porty na danym adresie IP.
    Tworzy playlistę z szablonu i pobiera playlistę z wykrytego urządzenia.
    """
    results = []
    for DeviceClass in device_classes:
        device = DeviceClass(ip, ports, timeout, session, logger)
        open_ports, device_type, detected_ports = device.scan()
        if open_ports:
            for port, service in open_ports:
                # Jeśli port odpowiada znanemu urządzeniu
                if service != "Nieznany":
                    playlist_success = device.get_playlist(port)
                    results.append({
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "device": device_type if port in detected_ports else "Nieznany",
                        "playlist_downloaded": playlist_success
                    })
                else:
                    # Port otwarty, ale usługa nieznana
                    results.append({
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "device": "Nieznany",
                        "playlist_downloaded": False
                    })
                # Generowanie playlisty niezależnie od typu urządzenia, jeśli opcja jest włączona
                if generate_playlist:
                    create_playlist(ip, port, template_content)
    return results

# ---------------------------
# Funkcja Zapisania Wyników
# ---------------------------

def save_results(results, output_format):
    """
    Zapisuje wyniki skanowania w wybranym formacie.
    """
    if not results:
        console.print("[yellow]Brak wyników do zapisania.[/yellow]")
        return

    try:
        if output_format == 'text':
            with open("scan_results.txt", "w", encoding='utf-8') as f:
                for result in results:
                    ip = result['ip']
                    port = result['port']
                    service = result['service']
                    device = result.get('device', 'Nieznany')
                    playlist_status = "Pobrano" if result.get('playlist_downloaded', False) else "Nie pobrano"
                    f.write(f"IP: {ip}\nPort: {port} ({service})\nUrządzenie: {device}\nPlaylista pobrana: {playlist_status}\n\n")
        elif output_format == 'csv':
            with open("scan_results.csv", "w", newline="", encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["IP", "Port", "Usługa", "Urządzenie", "Playlista Pobrania"])
                for result in results:
                    ip = result['ip']
                    port = result['port']
                    service = result['service']
                    device = result.get('device', 'Nieznany')
                    playlist_status = "Pobrano" if result.get('playlist_downloaded', False) else "Nie pobrano"
                    writer.writerow([ip, port, service, device, playlist_status])
        elif output_format == 'json':
            with open("scan_results.json", "w", encoding='utf-8') as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
        else:
            console.print(f"[red]Nieobsługiwany format zapisu: {output_format}[/red]")
            logging.error(f"Nieobsługiwany format zapisu: {output_format}")
            return
        console.print(f"[green]Wyniki zapisane w formacie {output_format}.[/green]")
        logging.info(f"Wyniki zapisane w formacie {output_format}.")
    except IOError as e:
        console.print(f"[red]Błąd przy zapisywaniu wyników: {e}[/red]")
        logging.error(f"Błąd przy zapisywaniu wyników: {e}")

# ---------------------------
# Główna Funkcja Programu
# ---------------------------

def main():
    console.print("[bold cyan]Witaj w profesjonalnym terminalowym skanerze portów skoncentrowanym na Dreambox, NBox, Vu+, Kodi oraz TVHeadend![/bold cyan]")

    # Ustawienie domyślnych portów
    default_ports = [8001, 8002, 8888, 8080, 65001]

    # Opcja ładowania konfiguracji
    if os.path.isfile('config.json'):
        if Confirm.ask("Czy chcesz załadować ustawienia z pliku konfiguracyjnego?"):
            config = load_config('config.json')
        else:
            config = None
    else:
        config = None

    if not config:
        # Wybór sposobu generowania IP
        generation_method = Prompt.ask(
            "Wybierz sposób generowania adresów IP",
            choices=["Kraj", "Manualny zakres IP"],
            default="Kraj"
        )

        if generation_method == "Kraj":
            # Lista dostępnych krajów
            available_countries = list(COUNTRY_IP_RANGES.keys())
            country_choice = Prompt.ask(
                "Wybierz kraj do skanowania",
                choices=available_countries,
                default="Polska"
            )
            selected_country = country_choice
            # Obliczanie całkowitej liczby dostępnych IP
            ip_ranges = COUNTRY_IP_RANGES.get(selected_country, [])
            total_hosts = sum(ipaddress.ip_network(cidr, strict=False).num_addresses - 2 for cidr in ip_ranges if '/' in cidr)
            console.print(f"[blue]Dla kraju {selected_country} dostępnych jest {total_hosts} adresów IP.[/blue]")
            # Wprowadzanie liczby IP do skanowania
            while True:
                try:
                    ip_count = IntPrompt.ask(
                        f"Wprowadź liczbę adresów IP do skanowania (max {total_hosts})",
                        default=min(100, total_hosts)
                    )
                    if 1 <= ip_count <= total_hosts:
                        break
                    else:
                        raise ValueError
                except ValueError:
                    console.print(f"[red]Liczba IP musi być między 1 a {total_hosts}.[/red]")
            selected_ips = generate_random_ips_from_country(selected_country, ip_count)
            console.print(f"[green]Wybrano {len(selected_ips)} adresów IP do skanowania.[/green]")
            logging.debug(f"Wybrano {len(selected_ips)} adresów IP do skanowania: {selected_ips}")
            start_ip = None
            end_ip = None
        else:
            # Wprowadzanie zakresu IP
            while True:
                start_ip = Prompt.ask("Wprowadź początkowy adres IP do skanowania")
                validated_start_ip = validate_ip(start_ip)
                if validated_start_ip:
                    break
                else:
                    console.print("[red]Nieprawidłowy format adresu IP. Spróbuj ponownie.[/red]")

            while True:
                end_ip = Prompt.ask("Wprowadź końcowy adres IP do skanowania")
                validated_end_ip = validate_ip(end_ip)
                if validated_end_ip:
                    break
                else:
                    console.print("[red]Nieprawidłowy format adresu IP. Spróbuj ponownie.[/red]")

            # Generowanie listy IP
            ip_list_all = generate_ip_range(validated_start_ip, validated_end_ip)
            ip_count_total = len(ip_list_all)
            # Wprowadzanie liczby IP do skanowania
            while True:
                try:
                    ip_count = IntPrompt.ask(
                        f"Wprowadź liczbę adresów IP do skanowania (max {ip_count_total})",
                        default=min(100, ip_count_total)
                    )
                    if 1 <= ip_count <= ip_count_total:
                        break
                    else:
                        raise ValueError
                except ValueError:
                    console.print(f"[red]Liczba IP musi być między 1 a {ip_count_total}.[/red]")
            selected_ips = random.sample(ip_list_all, ip_count)
            console.print(f"[green]Wybrano {len(selected_ips)} adresów IP do skanowania.[/green]")
            logging.debug(f"Wybrano {len(selected_ips)} adresów IP do skanowania: {selected_ips}")
            selected_country = None

        # Wprowadzanie timeoutu
        while True:
            try:
                timeout = IntPrompt.ask("Wprowadź timeout w milisekundach (domyślnie 5000)", default=5000)
                if timeout < 1:
                    raise ValueError
                break
            except ValueError:
                console.print("[red]Timeout musi być dodatnią liczbą całkowitą.[/red]")

        # Wprowadzanie liczby wątków
        while True:
            try:
                threads = IntPrompt.ask("Wprowadź liczbę wątków (domyślnie 50)", default=50)
                if threads < 1:
                    raise ValueError
                break
            except ValueError:
                console.print("[red]Liczba wątków musi być dodatnią liczbą całkowitą.[/red]")

        # Wprowadzanie portów
        while True:
            ports_input = Prompt.ask(
                "Wprowadź porty do skanowania (oddzielone przecinkami, domyślnie: 8001,8002,8888,8080,65001)",
                default="8001,8002,8888,8080,65001"
            )
            try:
                ports = [int(port.strip()) for port in ports_input.split(',') if port.strip().isdigit()]
                if not ports:
                    raise ValueError
                break
            except ValueError:
                console.print("[red]Nieprawidłowy format portów. Spróbuj ponownie.[/red]")

        # Wybór formatu zapisu wyników
        if Confirm.ask("Czy chcesz zapisać wyniki skanowania?"):
            output_format = Prompt.ask("Wybierz format zapisu", choices=["text", "csv", "json"], default="text")
        else:
            output_format = None

        # Opcja generowania playlisty
        if Confirm.ask("Czy chcesz wygenerować playlisty na podstawie otwartych portów?"):
            generate_playlist_option = True
        else:
            generate_playlist_option = False

        # Opcja wykrywania urządzeń i pobierania playlist
        if Confirm.ask("Czy chcesz wykrywać dekodery Dreambox, NBox, Vu+, Kodi oraz TVHeadend i pobierać z nich playlisty?"):
            detect_dreambox_option = True
            detect_nbox_option = True
            detect_vuplus_option = True
            detect_kodi_option = True
            detect_tvheadend_option = True
            # Wprowadzenie danych uwierzytelniających, jeśli wymagane
            if Confirm.ask("Czy Dreambox, NBox, Vu+, Kodi lub TVHeadend wymagają uwierzytelniania?"):
                username = Prompt.ask("Wprowadź nazwę użytkownika")
                password = Prompt.ask("Wprowadź hasło", password=True)
            else:
                username = None
                password = None
            # Opcja użycia HTTPS
            if Confirm.ask("Czy Dreambox, NBox, Vu+, Kodi lub TVHeadend używają HTTPS do komunikacji?"):
                use_https = True
            else:
                use_https = False
        else:
            detect_dreambox_option = False
            detect_nbox_option = False
            detect_vuplus_option = False
            detect_kodi_option = False
            detect_tvheadend_option = False
            username = None
            password = None
            use_https = False

        # Opcja zapisu konfiguracji
        if Confirm.ask("Czy chcesz zapisać te ustawienia jako domyślne w pliku konfiguracyjnym?"):
            config = {
                "generation_method": generation_method,
                "selected_country": selected_country,
                "start_ip": validated_start_ip if generation_method == "Manualny zakres IP" else None,
                "end_ip": validated_end_ip if generation_method == "Manualny zakres IP" else None,
                "selected_ips": selected_ips,
                "timeout": timeout,
                "threads": threads,
                "ports": ports,
                "output_format": output_format,
                "generate_playlist": generate_playlist_option,
                "detect_dreambox": detect_dreambox_option,
                "detect_nbox": detect_nbox_option,
                "detect_vuplus": detect_vuplus_option,
                "detect_kodi": detect_kodi_option,
                "detect_tvheadend": detect_tvheadend_option,
                "use_https": use_https,
                "auth": {
                    "username": username,
                    "password": password
                }
            }
            save_config(config, 'config.json')
    else:
        # Wczytane ustawienia z pliku konfiguracyjnego
        generation_method = config.get("generation_method", "Kraj")
        selected_country = config.get("selected_country")
        start_ip = config.get("start_ip")
        end_ip = config.get("end_ip")
        selected_ips = config.get("selected_ips", [])
        timeout = config.get("timeout", 5000)
        threads = config.get("threads", 50)
        ports = config.get("ports", default_ports)
        output_format = config.get("output_format")
        generate_playlist_option = config.get("generate_playlist", False)
        detect_dreambox_option = config.get("detect_dreambox", False)
        detect_nbox_option = config.get("detect_nbox", False)
        detect_vuplus_option = config.get("detect_vuplus", False)
        detect_kodi_option = config.get("detect_kodi", False)
        detect_tvheadend_option = config.get("detect_tvheadend", False)
        use_https = config.get("use_https", False)
        auth = config.get("auth", {})
        username = auth.get("username")
        password = auth.get("password")

        # Sprawdzenie, czy wymagane pola są obecne
        if generation_method == "Kraj":
            if not selected_country:
                console.print("[red]Konfiguracja jest niekompletna. Uruchamiam tryb interaktywny.[/red]")
                config = None
                main()  # Rekurencyjne wywołanie main() dla interaktywnego wprowadzania danych
                return
            ip_ranges = COUNTRY_IP_RANGES.get(selected_country, [])
            total_hosts = sum(ipaddress.ip_network(cidr, strict=False).num_addresses - 2 for cidr in ip_ranges if '/' in cidr)
            if len(selected_ips) > total_hosts:
                console.print(f"[yellow]Wybrana liczba IP ({len(selected_ips)}) przekracza dostępne IP w kraju {selected_country} ({total_hosts}). Skanuję wszystkie dostępne IP.[/yellow]")
                logging.warning(f"Wybrana liczba IP ({len(selected_ips)}) przekracza dostępne IP w kraju {selected_country} ({total_hosts}). Skanuję wszystkie dostępne IP.")
                selected_ips = generate_random_ips_from_country(selected_country, total_hosts)
            else:
                # Sprawdzenie, czy wszystkie wybrane IP są w odpowiednich zakresach
                valid_selected_ips = []
                for ip in selected_ips:
                    for cidr in ip_ranges:
                        if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False):
                            valid_selected_ips.append(ip)
                            break
                selected_ips = valid_selected_ips
        else:
            if not start_ip or not end_ip:
                console.print("[red]Konfiguracja jest niekompletna. Uruchamiam tryb interaktywny.[/red]")
                config = None
                main()  # Rekurencyjne wywołanie main() dla interaktywnego wprowadzania danych
                return
            ip_list_all = generate_ip_range(start_ip, end_ip)
            ip_count_total = len(ip_list_all)
            if len(selected_ips) > ip_count_total:
                console.print(f"[yellow]Wybrana liczba IP ({len(selected_ips)}) przekracza dostępne IP w zakresie ({ip_count_total}). Skanuję wszystkie dostępne IP.[/yellow]")
                logging.warning(f"Wybrana liczba IP ({len(selected_ips)}) przekracza dostępne IP w zakresie ({ip_count_total}). Skanuję wszystkie dostępne IP.")
                selected_ips = ip_list_all
            else:
                # Sprawdzenie, czy wszystkie wybrane IP są w zakresie
                valid_selected_ips = [ip for ip in selected_ips if ip in ip_list_all]
                selected_ips = valid_selected_ips

    # Sprawdzenie, czy lista IP jest pusta
    if not selected_ips:
        console.print("[red]Brak adresów IP do skanowania. Zakończam działanie programu.[/red]")
        logging.error("Brak adresów IP do skanowania. Zakończam działanie programu.")
        sys.exit(1)

    # Wstępne wyświetlenie informacji o skanowaniu
    console.print(f"[blue]Rozpoczynanie skanowania {len(selected_ips)} adresów IP za pomocą {threads} wątków na portach {ports}...[/blue]")
    logging.info(f"Rozpoczynanie skanowania {len(selected_ips)} adresów IP za pomocą {threads} wątków na portach {ports}.")

    # Inicjalizacja sesji z retry
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    # Przekazywanie sesji do struktury
    session_info = {
        "username": username,
        "password": password,
        "use_https": use_https,
        "session": session
    }

    # Definicja listy klas urządzeń do skanowania
    device_classes = []
    if detect_dreambox_option:
        device_classes.append(Dreambox)
    if detect_nbox_option:
        device_classes.append(NBox)
    if detect_vuplus_option:
        device_classes.append(VuPlus)
    if detect_kodi_option:
        device_classes.append(KodiDevice)
    if detect_tvheadend_option:
        device_classes.append(TVHeadend)

    # Inicjalizacja paska postępu
    progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console,
        transient=True
    )
    task_progress = progress.add_task("Skanowanie...", total=len(selected_ips))
    results = []

    # Załadowanie szablonu playlisty
    template_content = load_playlist_template()

    with progress:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            # Przekazywanie dodatkowych argumentów do funkcji scan_ip
            future_to_ip = {
                executor.submit(
                    scan_ip,
                    ip,
                    device_classes,
                    ports,
                    timeout,
                    session_info,
                    generate_playlist_option,
                    template_content
                ): ip for ip in selected_ips
            }
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    device_results = future.result()
                    if device_results:
                        for result in device_results:
                            results.append(result)
                            # Wyświetlanie wyników w tabeli
                            table = Table(show_header=True, header_style="bold magenta")
                            table.add_column("IP", style="dim", width=15)
                            table.add_column("Port", style="dim", width=10)
                            table.add_column("Usługa", justify="left")
                            table.add_column("Urządzenie", style="bold blue")
                            table.add_column("Playlista Pobrania", style="bold green")

                            port_info = result["port"]
                            service = result["service"]
                            device = result["device"]
                            playlist_status = "[green]Pobrano[/green]" if result["playlist_downloaded"] else "[red]Nie pobrano[/red]"

                            table.add_row(ip, str(port_info), service, device, playlist_status)
                            console.print(table)
                    else:
                        # Brak otwartych portów dla tego IP
                        console.print(f"[yellow]Brak otwartych portów na IP: {ip}.[/yellow]")
                        logging.info(f"Brak otwartych portów na IP: {ip}.")
                except Exception as e:
                    console.print(f"[red]Błąd przy skanowaniu {ip}: {e}[/red]")
                    logging.error(f"Błąd przy skanowaniu {ip}: {e}")
                finally:
                    progress.advance(task_progress)

    # Zapis wyników
    if output_format:
        save_results(results, output_format)
    else:
        console.print("[yellow]Wyniki nie zostały zapisane. Aby zapisać wyniki, uruchom program ponownie i wybierz opcję zapisu.[/yellow]")
        logging.info("Wyniki nie zostały zapisane przez użytkownika.")

    # Podsumowanie skanowania
    summary_table = Table(title="Podsumowanie Skanowania")
    summary_table.add_column("Całkowita liczba adresów IP", style="bold blue")
    summary_table.add_column("Wykryte urządzenia", style="bold green")
    summary_table.add_column("Wyniki zapisane", style="bold magenta")

    summary_table.add_row(
        str(len(selected_ips)),
        str(len(results)),
        output_format if output_format else "Nie zapisano"
    )

    console.print(summary_table)
    console.print("[bold cyan]Skanowanie zakończone.[/bold cyan]")
    logging.info("Skanowanie zakończone.")

if __name__ == "__main__":
    try:
        load_playlist_template()  # Upewnij się, że szablon playlisty jest załadowany przed skanowaniem
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Skanowanie przerwane przez użytkownika.[/red]")
        logging.warning("Skanowanie przerwane przez użytkownika.")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Nieoczekiwany błąd: {e}[/red]")
        logging.error(f"Nieoczekiwany błąd: {e}")
        sys.exit(1)
