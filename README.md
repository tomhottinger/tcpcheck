# tcpcheck

`tcpcheck` ist ein schlankes Python-Tool zur Überprüfung der Erreichbarkeit entfernter TCP-Ports.
Es unterstützt einfache TCP-Connect-Tests, TLS-Handshakes sowie konfigurierbare Probe-Tests mit Nutzdaten und Antwortprüfung.

Das Tool ist für automatisierte Checks, Monitoring, Skripting und CI-Umgebungen ausgelegt.

---

## Funktionen

- TCP-Connect-Test
- TLS-Handshake-Test mit optionaler Zertifikatsprüfung
- Probe-Modus: Daten senden und Antwortinhalt prüfen
- Konfiguration über YAML oder JSON
- Parallele Tests mehrerer Targets
- Text- oder JSONL-Ausgabe
- Definierte Exitcodes für Automatisierung

---

## Voraussetzungen

### Laufzeit (nicht kompiliert)

- Python ≥ 3.9
- Optional: PyYAML (nur bei YAML-Konfiguration)

Installation der Abhängigkeiten:

```bash
pip install pyyaml
```

---

## Verwendung

### Hilfe anzeigen

```bash
python tcpcheck.py --help
```

### Einfacher TCP-Test

```bash
python tcpcheck.py --host example.com --port 443
```

### TLS-Test

```bash
python tcpcheck.py --host example.com --port 443 --tls
```

### Probe-Test

```bash
python tcpcheck.py \
  --host mail.example.com \
  --port 25 \
  --mode probe \
  --send-text "EHLO test\r\n" \
  --expect "250"
```

### Nutzung mit Konfigurationsdatei

```bash
python tcpcheck.py --config config.yaml
```

---

## Konfigurationsdatei (YAML)

```yaml
options:
  parallel: 10
  format: text

defaults:
  timeout_s: 3.0
  retries: 2

targets:
  - name: web-https
    host: example.com
    port: 443
    mode: tls

  - name: smtp-probe
    host: mail.example.com
    port: 25
    mode: probe
    probe:
      send_text: "EHLO test\r\n"
      expect: "250"
```

---

## Exitcodes

| Code | Bedeutung |
|-----:|----------|
| 0 | Alle Targets erfolgreich |
| 2 | Mindestens ein Target fehlgeschlagen |
| 130 | Abbruch durch Benutzer |

---

## Kompilieren zu einer ausführbaren Datei

Das Projekt kann mit PyInstaller zu einem nativen Binary gebaut werden.

### Voraussetzungen für das Build

```bash
pip install pyinstaller
```

---

## Build unter Linux

```bash
pyinstaller \
  --onefile \
  --clean \
  --name tcpcheck \
  tcpcheck.py
```

Ergebnis:

```
dist/tcpcheck
```

Ausführbar machen:

```bash
chmod +x dist/tcpcheck
```

Test:

```bash
./dist/tcpcheck --help
```

---

## Build unter Windows

```powershell
pyinstaller `
  --onefile `
  --clean `
  --name tcpcheck `
  tcpcheck.py
```

Ergebnis:

```
dist\tcpcheck.exe
```

Test:

```powershell
dist\tcpcheck.exe --help
```

---

## Hinweise zum Cross-Compilation

- Linux-Binaries müssen unter Linux gebaut werden
- Windows-Binaries müssen unter Windows gebaut werden
- Cross-Compilation wird von PyInstaller nicht offiziell unterstützt

---

## Lizenz

MIT License
