# service_discovery.py

import socket

def scan_port(ip_address, port, timeout=0.5):
    """
    Intenta conectar a un puerto específico en una dirección IP.
    :param ip_address: La dirección IP del host a escanear.
    :param port: El número de puerto a escanear.
    :param timeout: Tiempo máximo de espera para la conexión (en segundos).
    :return: True si el puerto está abierto, False si está cerrado o hay un error.
    """
    try:
        # Crea un nuevo socket TCP/IP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout) 

        # Conexion al puerto
        result = sock.connect_ex((ip_address, port)) 

        # para debug
        if result == 0: # Si connect_ex devuelve 0, la conexión fue exitosa (puerto abierto)           
            # sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            # response = sock.recv(1024)
            # print(f"  [DEBUG] Recibido: {response.decode().strip()[:50]}...")
            return True
        else:
            return False
    except socket.error as e:
        # print(f"Error de socket al escanear {ip_address}:{port} - {e}") # Para depuración
        return False
    except Exception as e:
        # print(f"Error inesperado al escanear {ip_address}:{port} - {e}") # Para depuración
        return False
    finally:
        sock.close() # Asegura que el socket se cierre siempre


# solo test local
if __name__ == "__main__":
    print("--- Probando Descubrimiento de Servicios ---")

   
    test_ip = "138.100.110.67" 

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

    print(f"\nEscaneando puertos comunes en {test_ip}...")
    for port, service_name in common_ports.items():
        print(f"  Probando puerto {port} ({service_name})... ", end="")
        if scan_port(test_ip, port, timeout=0.3): 
            print("¡ABIERTO!")
        else:
            print("CERRADO.")