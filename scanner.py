# scanner.py

import subprocess
import platform
import ipaddress
import service_discovery
from logger_config import app_logger # Importa el logger

# Funcion de ping: enviamos un solo ping con un segundo de tiempo de espera
def ping_host (ip_address, count=1, timeout=0.3):
    """
    Envía un paquete de ping a la dirección IP especificada para verificar si el host está en línea.
    :param ip_address: La dirección IP a hacer ping.
    :param count: Número de paquetes de ping a enviar.
    :param timeout: Tiempo de espera para la respuesta de cada paquete (en segundos).
    :return: True si el ping es exitoso, False en caso contrario.
    """
    param_n = "-n" if platform.system().lower() == "windows" else "-c"
    param_w = "-w" if platform.system().lower() == "windows" else "-W"

    ping_command = ["ping", param_n, str(count), ip_address]

    if platform.system().lower() == "windows":
        ping_command.extend(["-w", str(int(timeout * 1000))])
    else:
        ping_command.extend([param_w, str(timeout)])

    try:
        salida = subprocess.run(ping_command, capture_output=True, text=True, check=False)
        
        if salida.returncode == 0:
            app_logger.debug(f"Ping exitoso a {ip_address}") # Nivel DEBUG para pings individuales
            return True
        else:
            app_logger.debug(f"Ping fallido a {ip_address} (Código: {salida.returncode})") # Nivel DEBUG
            return False
    except FileNotFoundError:
        app_logger.error("Error: El comando 'ping' no se encuentra en el sistema de archivos.")
        return False
    except Exception as e:
        app_logger.exception(f"Error inesperado al intentar hacer ping a {ip_address}.")
        return False

# Funcion de escaneo de subred
def scan_network(network_range):
    """
    Escanea una subred para encontrar hosts en línea y detectar servicios comunes.
    :param network_range: Rango de red en formato CIDR (ej. "192.168.1.0/24").
    :return: Una lista de diccionarios, cada uno con la IP, estado y servicios detectados del host.
    """
    discovered_services_data = [] 

    try:
        network = ipaddress.ip_network(network_range, strict=False)
        app_logger.info(f"Comienzo de escaneo de subred {network_range}")

        # Excluir la dirección de red y la de broadcast para el escaneo de hosts
        # Esto puede variar si quieres incluirlas o no en tu escaneo, pero es una buena práctica.
        hosts_to_scan = [str(ip_obj) for ip_obj in network.hosts()]

        for ip_str in hosts_to_scan: # Iterar sobre las IPs como strings
            host_info = {
                "ip_address": ip_str,
                "status": "offline", 
                "services": []       
            }

            if ping_host(ip_str):
                app_logger.info(f"Host {ip_str} en línea (Ping).")
                host_info["status"] = "online"
                
                app_logger.info(f"  Escaneando servicios en {ip_str}...")
                
                if service_discovery.scan_port(ip_str, 3389, timeout=0.1):
                    host_info["services"].append("RDP (3389)")
                    app_logger.info(f"    Puerto 3389 (RDP) ABIERTO en {ip_str}.")
                
                if service_discovery.scan_port(ip_str, 22, timeout=0.1):
                    host_info["services"].append("SSH (22)")
                    app_logger.info(f"    Puerto 22 (SSH) ABIERTO en {ip_str}.")
                    
                if service_discovery.scan_port(ip_str, 80, timeout=0.1):
                    host_info["services"].append("HTTP (80)")
                    app_logger.info(f"    Puerto 80 (HTTP) ABIERTO en {ip_str}.")
                if service_discovery.scan_port(ip_str, 443, timeout=0.1):
                    host_info["services"].append("HTTPS (443)")
                    app_logger.info(f"    Puerto 443 (HTTPS) ABIERTO en {ip_str}.")

            else:
                app_logger.info(f"Host {ip_str} fuera de línea (Ping).")

            discovered_services_data.append(host_info)
            
    except ValueError as e:
        app_logger.error(f"Error: '{network_range}' no es un formato de red CIDR válido. Detalles: {e}")
        return [] # Devuelve lista vacía en caso de error de rango
    except Exception as e:
        app_logger.exception(f"Error inesperado durante el escaneo de la subred {network_range}.")
        return [] # Devuelve lista vacía en caso de error inesperado

    app_logger.info(f"Escaneo de subred {network_range} completado. Se procesaron {len(discovered_services_data)} hosts.")
    return discovered_services_data 

if __name__ == "__main__":
    app_logger.info("--- Probando escaneo de red con servicios (Directo) ---")

    # ¡IMPORTANTE: AJUSTA ESTE RANGO A UN RANGO PEQUEÑO Y REAL DE TU RED LOCAL PARA PROBAR!
    network_to_scan = "192.168.1.0/29" # Ejemplo: 8 IPs, más rápido para pruebas

    if network_to_scan:
        app_logger.info(f"Iniciando escaneo de la subred: {network_to_scan}...")

        scanned_results = scan_network(network_to_scan)

        app_logger.info("--- Resumen del Escaneo de Red y Servicios (Directo) ---")
        if scanned_results:
            app_logger.info("Se encontraron los siguientes hosts:")
            for host_data in scanned_results:
                app_logger.info(f"- IP: {host_data['ip_address']} (Estado: {host_data['status']})")
                if host_data['services']:
                    app_logger.info(f"  Servicios Abiertos: {', '.join(host_data['services'])}")
                else:
                    app_logger.info("  Ningún servicio común abierto detectado.")
        else:
            app_logger.info("No se encontraron hosts en el rango especificado.")
    else:
        app_logger.warning("Por favor, define un rango de red válido para escanear en el script (variable 'network_to_scan').")