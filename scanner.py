# scanner.py

import subprocess
import platform
import ipaddress
import service_discovery 

# Funcion de ping: enviamos un solo ping con un segundo de tiempo de espera
def ping_host (ip_address, count =1, timeout =0.3):
   
    # Verificar plataforma de ejecución 
    param_n = "-n" if platform.system().lower() == "windows" else "-c"
    param_w = "-w" if platform.system().lower() == "windows" else "-W"

    # Definir comando ping 
    ping_command = ["ping", param_n, str(count), ip_address]

    if platform.system().lower() == "windows":
      
        ping_command.extend(["-w", str(int(timeout * 1000))])
    else:
        # Para sistemas tipo Unix (Linux/macOS)
        ping_command.extend([param_w, str(timeout)])

    # Ejecución de ping
    try:
        
        salida = subprocess.run(ping_command, capture_output=True, text=True, check=False)
        
        # 
        if salida.returncode == 0:
            return True
        else:
            return False
    except FileNotFoundError:
        print("Error: El comando 'ping' no se encuentra en el sistema de archivos.")
        return False
    except Exception as e:
        print(f"Error inesperado al intentar hacer ping a {ip_address}: {e}")
        return False

# Funcion de escaneo de subred
def scan_network(network_range):
    discovered_services_data = [] 

    try:
        network = ipaddress.ip_network(network_range, strict=False)
        print(f"Comienzo de escaneo de subred {network_range}")

        for ip_obj in network.hosts():
            ip_str = str(ip_obj)

          
            host_info = {
                "ip_address": ip_str,
                "status": "offline", 
                "services": []       
            }

            if ping_host(ip_str):
                print(f"El host {ip_str} se ha encontrado (Ping)")
                host_info["status"] = "online"
                
                # --- Escaneo de servicios ---
                print(f"  Escaneando servicios en {ip_str}...")
                
                # Puerto RDP
                if service_discovery.scan_port(ip_str, 3389, timeout=0.1):
                    host_info["services"].append("RDP (3389)")
                    print(f"    Puerto 3389 (RDP) ¡ABIERTO!")
                
                # Puerto SSH
                if service_discovery.scan_port(ip_str, 22, timeout=0.1):
                    host_info["services"].append("SSH (22)")
                    print(f"    Puerto 22 (SSH) ¡ABIERTO!")
                    
                # Puerto HTTP
                if service_discovery.scan_port(ip_str, 80, timeout=0.1):
                    host_info["services"].append("HTTP (80)")
                    print(f"    Puerto 80 (HTTP) ¡ABIERTO!")
                # Puerto HTTPS
                if service_discovery.scan_port(ip_str, 443, timeout=0.1):
                    host_info["services"].append("HTTPS (443)")
                    print(f"    Puerto 443 (HTTPS) ¡ABIERTO!")

            else:
                print(f"El host {ip_str} no se ha encontrado (Ping)")

            discovered_services_data.append(host_info)
            
    except ValueError as e:
        print(f"Error: '{network_range}' no es un formato de red CIDR válido. Detalles: {e}")
    except Exception as e:
        print(f"Error inesperado durante el escaneo de la subred {network_range}: {e}")

    return discovered_services_data 

if __name__ == "__main__":
    print ("--- Probando escaneo de red con servicios ---")

    
    network_to_scan = "138.100.110.1/29"

    if network_to_scan:
        print (f"\nIniciando escaneo de la subred: {network_to_scan}...")

        scanned_results = scan_network(network_to_scan)

        print ("\n--- Resumen del Escaneo de Red y Servicios ---")
        if scanned_results:
            print ("Se encontraron los siguientes hosts:")
            for host_data in scanned_results: 
                print(f"- IP: {host_data['ip_address']} (Estado: {host_data['status']})")
                if host_data['services']:
                    print(f"  Servicios Abiertos: {', '.join(host_data['services'])}")
                else:
                    print("  Ningún servicio común abierto detectado.")
        else:
            print ("No se encontraron hosts en el rango especificado.")
    else:
        print ("Por favor, define un rango de red válido para escanear en el script (variable 'network_to_scan').")