# scanner.py

import subprocess
import platform
import ipaddress


# Funcion de ping enviamos un solo ping con 0.3 segundos de tiempo de espera
def ping_host (ip_address, count =1, timeout =0.3):
    # verificar plataforma de ejecucion
    param_n = "-n" if platform.system().lower() == "windows" else "-c"
    param_w = "-w" if platform.system().lower() == "windows" else "-W"

    # definir el comando ping a utilizar
    ping_command = ["ping", param_n, str(count), ip_address]

    if platform.system().lower() == "windows":
        # Convertir segundos a milisegundos
        ping_command.extend(["-w", str(timeout * 1000)])
    else:
        ping_command.extend([param_w, str(timeout)])

    # Ejecucion de ping
    try:
        salida = subprocess.run(ping_command, capture_output=True, text=True, check=False)
        if salida.returncode == 0:
            return True
        else:
            return False
    except FileNotFoundError:
        print ("No se encuentra comando ping en el sistema de archivos")
        return False
    except Exception as e:
        print (f"Fallo en la realizacion del comando ping a {ip_address}, error {e}")
        return False

# Funcion de escaneo de subred
def scan_network(network_range):
    online_hosts = []
    try:
        network = ipaddress.ip_network(network_range, strict=False)
        print (f"Comienzo de escaneo de subred {network_range}")

        for ip_obj in network.hosts(): # ip_obj es el objeto IPv4Address
            # Convertir a string objeto ip
            ip_str = str(ip_obj) # ¡Esta es la variable que debemos usar!

            if ping_host(ip_str): # Usar ip_str en la llamada a la función
                print (f"El host {ip_str} se ha encontrado")
                online_hosts.append(ip_str) # <--- ¡CORRECCIÓN AQUÍ! Asegurarse de añadir ip_str
            else:
                print (f"El host {ip_str} no se ha encontrado")

    except ValueError as e:
        print (f"Error: '{network_range}' no es un formato de red CIDR válido. Detalles: {e}")
    except Exception as e:
        print (f"Error inesperado durante el escaneo de la subred {network_range}: {e}")

    return online_hosts

if __name__ == "__main__":
    print ("--- Probando escaneo de red ---")

    # ¡IMPORTANTE: AJUSTA ESTE RANGO A UN RANGO PEQUEÑO Y REAL DE TU RED LOCAL PARA PROBAR!
    # El rango 138.100.110.0/24 es muy amplio (256 IPs) y puede tardar mucho.
    # Prueba con algo como "192.168.1.0/29" o "192.168.0.0/29" para pruebas más rápidas.
    network_to_scan = "138.100.110.0/24" # Mantén tu rango si es necesario para tu prueba

    if network_to_scan:
        print (f"\nIniciando escaneo de la subred: {network_to_scan}...")

        # Ejecuta el escaneo y guarda los hosts encontrados
        hosts_en_linea = scan_network(network_to_scan)

        print ("\n--- Resumen del Escaneo ---")
        if hosts_en_linea: # Si la lista 'hosts_en_linea' NO está vacía
            print ("Se encontraron los siguientes hosts en línea:")
            for host in hosts_en_linea:
                print (f"- {host}")
        else: # Si la lista 'hosts_en_linea' SÍ está vacía
            print ("No se encontraron hosts en línea en el rango especificado.")
    else: # Si 'network_to_scan' está vacío
        print ("Por favor, define un rango de red válido para escanear en el script (variable 'network_to_scan').")