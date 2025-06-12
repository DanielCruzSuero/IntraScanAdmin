# remote_control.py

from wakeonlan import send_magic_packet
import subprocess
import platform
from logger_config import app_logger # Importa el logger

def send_wol_packet(mac_address):
    """
    Envía un paquete mágico Wake-on-LAN a la dirección MAC especificada.
    :param mac_address: La dirección MAC del equipo a encender (ej. "AA:BB:CC:DD:EE:FF").
    """
    try:
        send_magic_packet(mac_address)
        app_logger.info(f"Paquete mágico WoL enviado a la MAC: {mac_address}. El equipo debería encenderse si WoL está configurado.")
        return True
    except Exception as e:
        app_logger.error(f"Error al enviar el paquete WoL a {mac_address}: {e}")
        return False

def remote_shutdown(ip_address, username, password, restart=False):
    """
    Intenta apagar o reiniciar un equipo Windows remoto usando shutdown.exe.
    Requiere credenciales de administrador en el equipo de destino.
    :param ip_address: La dirección IP del equipo de destino.
    :param username: Nombre de usuario con privilegios de administrador en el equipo remoto.
    :param password: Contraseña del usuario.
    :param restart: Si es True, reinicia el equipo; si es False, lo apaga.
    :return: True si el comando se envió con éxito, False en caso contrario.
    """
    if platform.system().lower() != "windows":
        app_logger.warning("Esta función de apagado remoto es solo compatible con sistemas Windows.")
        return False

    action = "/r" if restart else "/s"

    command = [
        "shutdown",
        action,
        "/f",
        "/t", "0",
        "/m", f"\\\\{ip_address}",
        "/u", username,
        "/p", password
    ]

    app_logger.info(f"Intentando {'reiniciar' if restart else 'apagar'} el equipo {ip_address}...")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)

        if result.returncode == 0:
            app_logger.info(f"Comando de {'reinicio' if restart else 'apagado'} enviado exitosamente a {ip_address}.")
            return True
        else:
            app_logger.error(f"Error al enviar el comando de {'reinicio' if restart else 'apagado'} a {ip_address}.")
            app_logger.error(f"Código de error: {result.returncode}. Stdout: {result.stdout.strip()}. Stderr: {result.stderr.strip()}")
            return False
    except FileNotFoundError:
        app_logger.error("El comando 'shutdown' no se encontró en el sistema. Asegúrate de que estás en Windows.")
        return False
    except Exception as e:
        app_logger.exception(f"Ocurrió un error inesperado al intentar {'reiniciar' if restart else 'apagar'} {ip_address}.")
        return False

if __name__ == "__main__":
    app_logger.info("--- Probando Remote Control (Directo) ---")
    
    # --- Prueba de Wake-on-LAN (Opcional) ---
    # target_mac = "XX:XX:XX:XX:XX:XX" # <-- ¡CAMBIA ESTO POR UNA MAC REAL!
    # if target_mac != "XX:XX:XX:XX:XX:XX":
    #     app_logger.info(f"\nIntentando encender el equipo con MAC: {target_mac}")
    #     send_wol_packet(target_mac)
    # else:
    #     app_logger.info("\nSkipping WoL test: MAC address not set for direct test.")


    # --- Prueba de Apagado Remoto ---
    app_logger.info("\n--- Probando Apagado/Reinicio Remoto (Directo) ---")
    
    # ¡IMPORTANTE! Rellena estos datos con una IP, usuario y contraseña REALES
    # de un equipo Windows en tu red con el que puedas probar.
    # ¡Ten mucho cuidado al probar esto para no apagar el equipo equivocado!
    target_ip = "192.168.1.100" # <-- ¡CAMBIA ESTO!
    admin_username = "TuUsuarioAdmin" # <-- ¡CAMBIA ESTO!
    admin_password = "TuContraseñaAdmin" # <-- ¡CAMBIA ESTO!

    should_restart = False

    if target_ip == "192.168.1.100":
        app_logger.warning("ADVERTENCIA: Por favor, configura 'target_ip', 'admin_username' y 'admin_password' para probar el apagado remoto.")
        app_logger.info("Asegúrate de que el equipo de destino esté encendido y tengas permisos de administrador.")
    else:
        app_logger.info(f"Intentando {'reiniciar' if should_restart else 'apagar'} {target_ip}...")
        remote_shutdown(target_ip, admin_username, admin_password, should_restart)