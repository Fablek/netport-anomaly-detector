# 📖 Przewodnik Użytkownika - Network Port Anomaly Detector

**Prosty przewodnik jak używać aplikacji**

---

## 🚀 Szybki Start (5 minut)

### Krok 1: Przygotowanie

```bash
# Przejdź do katalogu projektu
cd "/Users/sebastianpytka/Documents/Studia/5 semestr/Cyberbezpieczeństwo/Moduł 3/netport-anomaly-detector"

# Aktywuj środowisko wirtualne
source .venv/bin/activate

# Sprawdź czy wszystko zainstalowane
python -c "import scapy; import sklearn; import flask; print('✅ Wszystko OK!')"
```

### Krok 2: Uruchom aplikację

```bash
python main.py
```

**Co się stanie:**
- Aplikacja wystartuje
- Wygeneruje 1000 pakietów z symulatora
- Dashboard będzie dostępny na http://127.0.0.1:5000
- Po zakończeniu wygeneruje raporty

### Krok 3: Zobacz wyniki

```bash
# W przeglądarce otwórz:
http://127.0.0.1:5000

# Albo zobacz raporty:
open reports/report_*.html
```

---

## 📋 Podstawowe Komendy

### Tryby Uruchomienia

#### 1. Symulator (Domyślny - Najlepszy do testów)
```bash
python main.py
```
✅ Nie wymaga uprawnień admina
✅ Szybki i powtarzalny
✅ Zawiera celowe anomalie do wykrycia

#### 2. Analiza pliku PCAP
```bash
python main.py --mode pcap --pcap-file data/moj_plik.pcap
```
📁 Analizuje zapisany ruch sieciowy
📁 Dobre do forensyki

#### 3. Live Capture (Na Żywo)
```bash
sudo python main.py --mode live --interface en0
```
⚠️ Wymaga sudo (uprawnienia administratora)
⚠️ Przechwytuje prawdziwy ruch sieciowy

#### 4. Bez Dashboardu (Tylko Analiza)
```bash
python main.py --no-dashboard
```
💻 Tylko terminal, bez przeglądarki
💻 Szybsze, do automatyzacji

#### 5. Tylko Raporty
```bash
python main.py --report-only
```
📊 Generuje tylko raporty, bez dashboardu
📊 Dobre do batch processing

---

## ⚙️ Konfiguracja

### Edytuj `config/config.yaml`

#### Zmień ilość pakietów
```yaml
data_source:
  packet_count: 2000  # Domyślnie 1000
```

#### Zmień procent anomalii
```yaml
data_source:
  anomaly_rate: 0.05  # 5% zamiast 10%
```
💡 **Niższy anomaly_rate = lepsze trenowanie ML**

#### Zmień czułość detekcji

**Mniej false positives (mniej fałszywych alarmów):**
```yaml
detection:
  statistical:
    z_score_threshold: 4.0  # Zwiększ z 3.0

  ml:
    isolation_forest:
      contamination: 0.2  # Zwiększ z 0.1

  heuristic:
    port_scan:
      threshold: 20  # Zwiększ z 10
```

**Więcej wykrytych anomalii (bardziej czuły):**
```yaml
detection:
  statistical:
    z_score_threshold: 2.0  # Zmniejsz z 3.0

  ml:
    isolation_forest:
      contamination: 0.05  # Zmniejsz z 0.1

  heuristic:
    port_scan:
      threshold: 5  # Zmniejsz z 10
```

#### Wyłącz konkretny detektor
```yaml
detection:
  ml:
    enabled: false  # Wyłącz ML
  statistical:
    enabled: true   # Zostaw resztę
```

#### Zmień port dashboardu
```yaml
dashboard:
  host: "127.0.0.1"
  port: 8080  # Zamiast 5000
```

---

## 🌐 Używanie Dashboardu

### Uruchomienie
```bash
python main.py
# Otwórz przeglądarkę: http://127.0.0.1:5000
```

### Co widzisz na dashboardzie?

#### 1. Status Bar (Górny Pasek)
```
🟢 Running / 🔴 Stopped
Total Packets: 1000
Total Anomalies: 250
Detection Rate: 25%
```

#### 2. Wykresy

**Protocol Distribution (Rozkład Protokołów)**
- Koło pokazujące TCP, UDP, ICMP
- Większość powinna być TCP (normalny ruch)

**Top Destination Ports (Najpopularniejsze Porty)**
- Słupki pokazujące najczęściej używane porty
- 80, 443, 22 = normalne
- Dziwne porty (30000+) = podejrzane

**Top Source IPs**
- Które IP generują najwięcej ruchu
- Jeden dominujący = możliwy atak

**Anomaly Timeline**
- Kiedy wykryto anomalie
- Kolor = poziom zagrożenia:
  - 🔴 Critical
  - 🟠 High
  - 🟡 Medium
  - 🟢 Low

#### 3. Lista Anomalii (Na Dole)

Kliknij na anomalię aby zobaczyć szczegóły:
```
[CRITICAL] Port scanning detected from 192.168.1.100
Timestamp: 2024-12-04 18:50:13
Source IP: 192.168.1.100
Destination IP: 192.168.1.1
Confidence: 89%
Details: 45 unique ports in 5 seconds
```

---

## 📄 Raporty

### Gdzie są raporty?
```bash
ls -la reports/

# Zobaczysz:
# report_20241204_185014.json  (dla programów)
# report_20241204_185014.csv   (dla Excela)
# report_20241204_185014.html  (do czytania)
```

### Jak otworzyć raporty?

#### HTML (Najładniejszy)
```bash
open reports/report_*.html  # macOS
start reports/report_*.html  # Windows
xdg-open reports/report_*.html  # Linux
```

#### CSV (Excel)
```bash
# Otwórz w Excel lub Google Sheets
# Możesz filtrować, sortować, tworzyć pivot tables
```

#### JSON (Programowanie)
```python
import json

with open('reports/report_20241204_185014.json') as f:
    data = json.load(f)

print(f"Total anomalies: {data['statistics']['total_anomalies']}")
```

### Co jest w raporcie?

**Sekcja Statistics:**
- Łączna liczba pakietów
- Łączna liczba anomalii
- Detection rate (procent wykrycia)
- Podział anomalii według typu
- Podział według ważności

**Sekcja Anomalies:**
- Lista wszystkich wykrytych anomalii
- Timestamp, typ, opis
- Source/Destination IP i Port
- Poziom confidence

**Wykresy (tylko HTML):**
- Interaktywne wykresy Plotly
- Można klikać, zoomować
- Export do PNG

---

## 🔍 Rozumienie Wyników

### Detection Rate

```
Total Packets: 1000
Total Anomalies: 250
Detection Rate: 25%
```

**Co to znaczy?**
- Przeanalizowano 1000 pakietów
- Wykryto 250 "zdarzeń anomalii"
- 25% = 1 anomalia na 4 pakiety

**Dlaczego może być >100%?**
- Jeden pakiet może być flagowany przez kilka detektorów
- Przykład: pakiet jest zarówno "statistically unusual" jak i "ML anomaly"
- To normalne!

### Typy Anomalii

| Typ | Co to znaczy | Przykład |
|-----|--------------|----------|
| `statistical` | Statystycznie nietypowe | Port użyty 50x zamiast 5x |
| `ml_isolation` | ML Isolation Forest | Wzorzec nieznany modelowi |
| `ml_svm` | ML One-Class SVM | Poza granicą normalności |
| `port_scan` | Skanowanie portów | 1 IP → 50 portów w 5 sec |
| `ddos` | Atak DDoS | 200 połączeń/sekundę |
| `unusual_port` | Dziwny port | Połączenie na port 55123 |
| `rate_limit` | Przekroczenie limitu | 100 pakietów/sec (limit 50) |
| `burst` | Nagły skok ruchu | 3x więcej niż normalnie |

### Severity (Ważność)

| Poziom | Znaczenie | Akcja |
|--------|-----------|-------|
| `LOW` | Podejrzane, ale może być OK | Monitoruj |
| `MEDIUM` | Prawdopodobnie problem | Sprawdź szczegóły |
| `HIGH` | Poważne zagrożenie | Zbadaj natychmiast |
| `CRITICAL` | Atak w toku | Natychmiastowa reakcja |

### Confidence Score

```
Confidence: 0.89 = 89%
```

**Co to znaczy?**
- Jak pewny jest system że to anomalia
- 90%+ = bardzo pewny
- 50-70% = może być false positive
- <50% = prawdopodobnie false positive

---

## 🛠️ Typowe Scenariusze Użycia

### Scenariusz 1: Szybki Test
```bash
python main.py
# Poczekaj 5 sekund
# Sprawdź dashboard
# Koniec!
```

### Scenariusz 2: Analiza Własnego PCAP
```bash
# Masz plik capture.pcap
python main.py --mode pcap --pcap-file capture.pcap

# Zobacz wyniki w reports/
open reports/report_*.html
```

### Scenariusz 3: Prezentacja
```bash
# 1. Uruchom z dashboardem
python main.py

# 2. Otwórz dashboard w przeglądarce
# http://127.0.0.1:5000

# 3. Udostępnij ekran
# 4. Pokazuj jak wykrywane są anomalie w czasie rzeczywistym
# 5. Otwórz HTML report
```

### Scenariusz 4: Batch Processing (Wiele Plików)
```bash
# Stwórz skrypt
for file in data/*.pcap; do
    python main.py --mode pcap --pcap-file "$file" --no-dashboard
done

# Wszystkie raporty w reports/
```

### Scenariusz 5: Własne Dane Testowe
```python
# Edytuj config.yaml
data_source:
  packet_count: 5000
  anomaly_rate: 0.15  # 15% anomalii

# Uruchom
python main.py
```

---

## 🐛 Rozwiązywanie Problemów

### Problem: "ModuleNotFoundError: No module named 'scapy'"

**Rozwiązanie:**
```bash
# Sprawdź czy środowisko aktywne
which python
# Powinno pokazać .venv/bin/python

# Jeśli nie, aktywuj
source .venv/bin/activate

# Zainstaluj zależności
pip install -r requirements.txt
```

### Problem: "Permission denied" (Live Capture)

**Rozwiązanie:**
```bash
# Live capture wymaga sudo
sudo python main.py --mode live --interface en0

# LUB użyj symulatora (nie wymaga sudo)
python main.py --mode simulator
```

### Problem: Dashboard nie ładuje się (localhost:5000)

**Rozwiązanie 1: Port zajęty**
```bash
# Sprawdź co używa portu 5000
lsof -i :5000

# Zabij proces lub zmień port w config.yaml
dashboard:
  port: 8080
```

**Rozwiązanie 2: Firewall**
```bash
# Tymczasowo wyłącz firewall
# LUB dodaj wyjątek dla portu 5000
```

### Problem: Brak wykrytych anomalii

**Rozwiązanie:**
```yaml
# config.yaml - zmniejsz thresholdy
detection:
  statistical:
    z_score_threshold: 2.0  # z 3.0
  heuristic:
    port_scan:
      threshold: 5  # z 10
```

### Problem: Za dużo anomalii (300%+)

**Rozwiązanie 1: Zmniejsz anomaly_rate**
```yaml
data_source:
  anomaly_rate: 0.05  # z 0.1
```

**Rozwiązanie 2: Wyłącz ML**
```yaml
detection:
  ml:
    enabled: false
```

**Rozwiązanie 3: Zwiększ contamination**
```yaml
detection:
  ml:
    isolation_forest:
      contamination: 0.2  # z 0.1
```

### Problem: Aplikacja wolno działa

**Rozwiązanie:**
```yaml
# Zmniejsz liczbę pakietów
data_source:
  packet_count: 500  # z 1000

# Wyłącz niektóre detektory
detection:
  ml:
    enabled: false  # ML jest najwolniejszy
```

---

## 📚 Przykładowe Komendy

### Podstawowe
```bash
# Standardowe uruchomienie
python main.py

# Z własną konfiguracją
python main.py --config moja_config.yaml

# Bez dashboardu
python main.py --no-dashboard

# Tylko raporty
python main.py --report-only
```

### PCAP Analysis
```bash
# Podstawowa analiza
python main.py --mode pcap --pcap-file data/traffic.pcap

# Bez dashboardu
python main.py --mode pcap --pcap-file data/traffic.pcap --no-dashboard

# Własny katalog na raporty
python main.py --mode pcap --pcap-file data/traffic.pcap --output-dir wyniki/
```

### Live Capture
```bash
# Interfejs domyślny
sudo python main.py --mode live

# Konkretny interfejs
sudo python main.py --mode live --interface en0

# Lista interfejsów
ifconfig  # macOS/Linux
ipconfig  # Windows
```

### Symulator
```bash
# Domyślnie
python main.py

# Równoważne
python main.py --mode simulator
```

---

## 🎯 Wskazówki

### Dla Prezentacji
1. **Użyj symulatora** - niezawodny, powtarzalny
2. **Zmniejsz anomaly_rate do 0.05** - lepsze wyniki ML
3. **Przygotuj backup** - screenshots na wypadek problemów
4. **Zwiększ czcionkę** - terminal i przeglądarka
5. **Otwórz dashboard przed prezentacją**

### Dla Testowania
1. **Zacznij od małej liczby pakietów** (500)
2. **Testuj jeden detektor na raz** (wyłączaj pozostałe)
3. **Porównuj różne ustawienia** (zapisuj konfiguracje)
4. **Sprawdź raporty** - nie tylko dashboard

### Dla Rozwoju
1. **Czytaj logi** - `tail -f logs/anomaly_detector.log`
2. **Testuj na prawdziwych PCAP** - pobierz z internetu
3. **Eksperymentuj z parametrami** - dokumentuj co działa
4. **Dodawaj własne detektory** - patrz TODO.md

---

## 📖 Więcej Informacji

### Dokumentacja
- **README.md** - Ogólny przegląd (po angielsku)
- **PROJECT_GUIDE.md** - Szczegółowy przewodnik techniczny
- **CLAUDE.md** - Dokumentacja dla programistów
- **TODO.md** - Plan rozwoju projektu
- **PRESENTATION.md** - Przewodnik prezentacji

### Przydatne Linki
- Scapy: https://scapy.readthedocs.io/
- scikit-learn: https://scikit-learn.org/
- Flask: https://flask.palletsprojects.com/
- Plotly: https://plotly.com/python/

### Przykładowe PCAP
- Wireshark Samples: https://wiki.wireshark.org/SampleCaptures
- Malware Traffic: https://www.malware-traffic-analysis.net/
- CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html

---

## ✅ Checklist Przed Użyciem

- [ ] Środowisko aktywowane: `source .venv/bin/activate`
- [ ] Zależności zainstalowane: `pip install -r requirements.txt`
- [ ] Konfiguracja sprawdzona: `cat config/config.yaml`
- [ ] Port 5000 wolny (jeśli używasz dashboardu)
- [ ] Masz uprawnienia sudo (jeśli live capture)

---

## 🆘 Szybka Pomoc

**Coś nie działa?**
1. Sprawdź logi: `cat logs/anomaly_detector.log`
2. Przeczytaj sekcję "Rozwiązywanie Problemów" powyżej
3. Zobacz przykłady w `example_test.py`
4. Sprawdź czy środowisko aktywne

**Potrzebujesz więcej szczegółów?**
- Technical: CLAUDE.md
- Complete guide: PROJECT_GUIDE.md
- Development: TODO.md

---

**Powodzenia! 🚀**

Pytania? Sprawdź pozostałe pliki dokumentacji lub eksperymentuj!
