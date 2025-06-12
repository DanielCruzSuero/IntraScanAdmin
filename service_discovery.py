# service_discovery.py

import socket
from logger_config import app_logger # Importa el logger

def scan_port(ip_address, port, timeout=0.5):
    """
    Intenta conectar a un puerto específico en una dirección IP.
    :param ip_address: La dirección IP del host a escanear.
    :param port: El número de puerto a escanear.
    :param timeout: Tiempo máximo de espera para la conexión (en segundos).
    :return: True si el puerto está abierto, False si está cerrado o hay un error.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        result = sock.connect_ex((ip_address, port))
        
        if result == 0:
            # app_logger.debug(f"Puerto {port} abierto en {ip_address}.") # Mensaje de depuración
            return True
        else:
            # app_logger.debug(f"Puerto {port} cerrado en {ip_address} (Código: {result}).") # Mensaje de depuración
            return False
    except socket.error as e:
        # Estos errores suelen indicar puerto cerrado o filtrado, no es necesario loguearlos a nivel de INFO/ERROR
        # app_logger.debug(f"Error de socket al escanear {ip_address}:{port}: {e}")
        return False
    except Exception as e:
        app_logger.error(f"Error inesperado al escanear {ip_address}:{port}: {e}")
        return False
    finally:
        sock.close()


# --- Bloque de prueba para service_discovery.py ---
if __name__ == "__main__":
    app_logger.info("--- Probando Descubrimiento de Servicios ---")
    
    test_ip = "192.168.1.1" # <-- ¡CAMBIA ESTO A UNA IP REAL DE TU RED PARA PROBAR!

    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        3389: "RDP (Escritorio Remoto)",
        8080: "HTTP Alternativo"
    }

    app_logger.info(f"Escaneando puertos comunes en {test_ip}...")
    for port, service_name in common_ports.items():
        if scan_port(test_ip, port, timeout=0.1):
            app_logger.info(f"  Puerto {port} ({service_name}) ¡ABIERTO!")
        else:
            app_logger.info(f"  Puerto {port} ({service_name}) CERRADO.") # Usar INFO para ver el estado de todos los puertos probados
    app_logger.info("Prueba de descubrimiento de servicios completada.")