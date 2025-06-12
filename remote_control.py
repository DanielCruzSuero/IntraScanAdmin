# remote_control.py

from wakeonlan import send_magic_packet
import subprocess
import platform # Necesario para verificar el SO si quieres flexibilidad


# --- Función Wake-on-LAN (Ya implementada y probada) ---
def send_wol_packet(mac_address):
   
    try:
        send_magic_packet(mac_address)
        print(f"Paquete mágico WoL enviado a la MAC: {mac_address}. El equipo debería encenderse si WoL está configurado.")
        return True
    except Exception as e:
        print(f"Error al enviar el paquete WoL a {mac_address}: {e}")
        return False


def remote_shutdown(ip_address, username, password, restart=False):
   
    if platform.system().lower() != "windows":
        print("Esta función de apagado remoto es solo compatible con sistemas Windows.")
        return False

    action = "/r" if restart else "/s"

    # Construir el comando shutdown.exe
    command = [
        "shutdown",
        action,
        "/f", # Forzar cierre de aplicaciones
        "/t", "0", # Esperar 0 segundos antes de apagar/reiniciar
        "/m", f"\\\\{ip_address}", # Especificar la máquina remota
        "/u", username, # Nombre de usuario remoto
        "/p", password  # Contraseña del usuario remoto
    ]

    print(f"\nIntentando {'reiniciar' if restart else 'apagar'} el equipo {ip_address}...")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)

        if result.returncode == 0:
            print(f"Comando de {'reinicio' if restart else 'apagado'} enviado exitosamente a {ip_address}.")
            return True
        else:
            print(f"Error al enviar el comando de {'reinicio' if restart else 'apagado'} a {ip_address}.")
            print(f"Código de error: {result.returncode}")
            print(f"Salida Stdout: {result.stdout}")
            print(f"Salida Stderr: {result.stderr}")
            return False
    except FileNotFoundError:
        print("El comando 'shutdown' no se encontró en el sistema. Asegúrate de que estás en Windows.")
        return False
    except Exception as e:
        print(f"Ocurrió un error inesperado al intentar {'reiniciar' if restart else 'apagar'} {ip_address}: {e}")
        return False

if __name__ == "__main__":
    print("--- Probando Remote Control ---")

    print("\n--- Probando Apagado/Reinicio Remoto ---")
    
    
    target_ip = "192.168.1.100" 
    admin_username = "TuUsuarioAdmin"
    admin_password = "TuContraseñaAdmin" 

    
    should_restart = False 

    if target_ip == "192.168.1.100":
        print("\nADVERTENCIA: Por favor, configura 'target_ip', 'admin_username' y 'admin_password' para probar el apagado remoto.")
        print("Asegúrate de que el equipo de destino esté encendido y tengas permisos de administrador.")
    else:
        print(f"\nIntentando {'reiniciar' if should_restart else 'apagar'} {target_ip}...")
        remote_shutdown(target_ip, admin_username, admin_password, should_restart)