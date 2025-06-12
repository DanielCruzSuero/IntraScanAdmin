# remote_control.py

from wakeonlan import send_magic_packet as wol_send_magic_packet
import platform
import subprocess
import os
from logger_config import app_logger

# Renombramos send_magic_packet de wakeonlan para evitar conflictos
# y para que nuestro módulo remoto_control.py sea el que exponga la función.

def send_magic_packet(mac_address, ip_address="255.255.255.255", port=9):
    """
    Envía un paquete mágico Wake-on-LAN a la dirección MAC especificada.
    Requiere que el módulo 'wakeonlan' esté instalado (`pip install wakeonlan`).
    """
    try:
        wol_send_magic_packet(mac_address, ip_address=ip_address, port=port)
        app_logger.info(f"Paquete mágico WoL enviado a MAC: {mac_address} en IP: {ip_address}")
        return True
    except Exception as e:
        app_logger.error(f"Error al enviar paquete mágico WoL a {mac_address}: {e}")
        return False

def remote_shutdown(target, username, password):
    """
    Intenta apagar un equipo remoto (Windows/Linux).
    Para Windows, usa 'shutdown'. Para Linux, puede necesitar 'ssh' o 'sudo shutdown'.
    Esto es un ejemplo básico. En entornos reales, se usarían herramientas más robustas como PsExec (Windows)
    o SSH con claves (Linux) o APIs de gestión.
    """
    app_logger.info(f"Intentando apagar el host remoto: {target}")
    try:
        if platform.system() == "Windows":
            # Para Windows, usar shutdown /s /f /t 0 /m \\<target>
            # Puede necesitar credenciales configuradas en el sistema de origen o PsExec
            # Para una conexión remota con credenciales, PsExec sería la forma más común.
            # Este es un comando muy básico que solo funciona si tienes permisos de admin.
            command = ['shutdown', '/s', '/f', '/t', '0', '/m', f'\\\\{target}']
            # Considerar PsExec para Windows:
            # cmd = f'psexec \\\\{target} -u {username} -p {password} shutdown /s /f /t 0'
            # subprocess.run(cmd, shell=True, check=True)
            
            # Para simplificar y probar, usaremos subprocess.run directamente,
            # pero ten en cuenta que las credenciales no se pasan aquí de forma nativa.
            # Si target es un nombre, se resuelve por DNS/NetBIOS. Si es IP, va directo.
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            app_logger.info(f"Comando de apagado en Windows a {target} ejecutado. Salida: {result.stdout}")
            return True
        else: # Asumimos Linux/Unix
            # Para Linux, se requiere SSH. Esto asume que SSH está configurado y las credenciales funcionan.
            # En un entorno real, probablemente usarías 'paramiko' (librería SSH en Python)
            # o tendrías claves SSH sin contraseña configuradas.
            command = ['sshpass', '-p', password, 'ssh', f'{username}@{target}', 'sudo shutdown -h now']
            # O simplemente 'ssh' si tienes claves/configuración sin pass.
            # command = ['ssh', f'{username}@{target}', 'sudo shutdown -h now']
            
            # Advertencia: sshpass no es seguro para contraseñas en scripts.
            # Es solo para demostración.
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            app_logger.info(f"Comando de apagado en Linux a {target} ejecutado. Salida: {result.stdout}")
            return True
    except subprocess.CalledProcessError as e:
        app_logger.error(f"Fallo al ejecutar el comando de apagado en {target}: {e.stderr}")
        return False
    except FileNotFoundError:
        app_logger.error("Comando 'shutdown', 'ssh' o 'sshpass' no encontrado. Asegúrate de que estén en tu PATH.")
        return False
    except Exception as e:
        app_logger.error(f"Error inesperado al apagar {target}: {e}")
        return False

def remote_reboot(target, username, password):
    """
    Intenta reiniciar un equipo remoto (Windows/Linux).
    Similar a remote_shutdown, requiere configuraciones de permisos.
    """
    app_logger.info(f"Intentando reiniciar el host remoto: {target}")
    try:
        if platform.system() == "Windows":
            command = ['shutdown', '/r', '/f', '/t', '0', '/m', f'\\\\{target}']
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            app_logger.info(f"Comando de reinicio en Windows a {target} ejecutado. Salida: {result.stdout}")
            return True
        else: # Asumimos Linux/Unix
            command = ['sshpass', '-p', password, 'ssh', f'{username}@{target}', 'sudo reboot']
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            app_logger.info(f"Comando de reinicio en Linux a {target} ejecutado. Salida: {result.stdout}")
            return True
    except subprocess.CalledProcessError as e:
        app_logger.error(f"Fallo al ejecutar el comando de reinicio en {target}: {e.stderr}")
        return False
    except FileNotFoundError:
        app_logger.error("Comando 'shutdown', 'ssh' o 'sshpass' no encontrado. Asegúrate de que estén en tu PATH.")
        return False
    except Exception as e:
        app_logger.error(f"Error inesperado al reiniciar {target}: {e}")
        return False