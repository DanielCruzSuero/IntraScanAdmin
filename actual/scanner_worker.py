import sys
import os
import time
import json
import logging
from multiprocessing import Process, Queue, Event # Estas importaciones están bien
import queue
from scapy.all import Ether, ARP, srp, IP, ICMP, TCP, sr, sr1, conf
import ipaddress
# Asegúrate de que el logger esté configurado en este módulo también si lo usas
# (o al menos un logger básico para la prueba)
# logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# worker_logger = logging.getLogger('ScannerWorker')


# TU CÓDIGO DE SCANNER_WORKER.PY VA AQUÍ
# Por ejemplo, tus funciones scan_network, _ping_host, _scan_ports, etc.
# Asegúrate de que todas tus funciones y clases estén definidas ANTES del if __name__ == "__main__":
# Por ejemplo:

# Dummy functions for demonstration if you don't have them handy
def _ping_host(ip_address, stop_event, output_queue, log_queue):
    # Simula un ping
    time.sleep(0.1)
    if stop_event.is_set():
        log_queue.put(logging.LogRecord('ScannerWorker', logging.WARNING, __file__, 0, 'Ping stopped early.', [], None))
        return False
    # log_queue.put(logging.LogRecord('ScannerWorker', logging.DEBUG, __file__, 0, f'Pinging {ip_address}', [], None))
    # Para la prueba, simulamos que encuentra un host
    if ip_address == "138.100.110.1" or ip_address == "138.100.110.100": # IPs que sabes que existen
        return True
    return False

def _scan_ports(ip_address, stop_event, output_queue, log_queue):
    # Simula un escaneo de puertos
    time.sleep(0.2)
    if stop_event.is_set():
        log_queue.put(logging.LogRecord('ScannerWorker', logging.WARNING, __file__, 0, 'Port scan stopped early.', [], None))
        return "Scan Stopped"
    # log_queue.put(logging.LogRecord('ScannerWorker', logging.DEBUG, __file__, 0, f'Scanning ports for {ip_address}', [], None))
    
    # Para la prueba, simulamos puertos abiertos y OS
    if ip_address == "192.168.1.1":
        return "80,443", "Linux"
    elif ip_address == "192.168.1.100":
        return "22,8080", "Windows"
    return "N/A", "Unknown"

def scan_network(ip_range, output_queue, stop_event, log_queue):
    worker_logger = logging.getLogger('ScannerWorker')
    worker_logger.setLevel(logging.DEBUG)
    if not worker_logger.handlers:
        worker_logger.addHandler(QueueHandler(log_queue))
        worker_logger.addHandler(logging.StreamHandler(sys.stdout))
        
    worker_logger.info(f"Worker: Iniciando escaneo para {ip_range}")
    
    # --- ¡CAMBIO CRÍTICO AQUÍ! ---
    # GENERAR LAS IPs A PARTIR DEL RANGO REAL, NO USAR UNA LISTA FIJA
    all_ips = []
    try:
        # Usa la librería ipaddress para expandir el rango
        ip_network = ipaddress.ip_network(ip_range, strict=False)
        all_ips = [str(ip) for ip in ip_network.hosts()] # Obtiene todas las IPs usables en el rango
        worker_logger.debug(f"Worker: Rango IP '{ip_range}' expandido a {len(all_ips)} IPs.")
    except ValueError as e:
        worker_logger.error(f"Worker: Error al parsear el rango IP '{ip_range}': {e}", exc_info=True)
        output_queue.put({"status": "error", "data": {"message": f"Formato de rango IP inválido: {e}"}})
        output_queue.put({"status": "completed", "data": "Escaneo fallido."})
        return

    output_queue.put({"status": "total_ips", "data": {"count": len(all_ips)}})
    
    for ip in all_ips:
        if stop_event.is_set():
            # ...
            return
            
        is_up, mac_address = _ping_host(ip, stop_event, output_queue, log_queue) 
        
        if is_up:
            ports, os_detected = _scan_ports(ip, stop_event, output_queue, log_queue)
            
            host_info = {
                "ip": ip,
                "hostname": "N/A", 
                "mac": mac_address, 
                "state": "up",
                "ports": ports,
                "os": os_detected
            }
            print(f"--- WORKER RAW PRINT: Enviando host_found para {ip} ---") # DEBUG ENVÍO WORKER
            output_queue.put({"status": "host_found", "data": host_info})
            worker_logger.debug(f"Worker: Host encontrado y enviado: {ip} - {mac_address}")
        else:
            worker_logger.debug(f"Worker: Host no responde al ping: {ip}")
            
    worker_logger.info("Worker: Escaneo completado.")
    print("--- WORKER RAW PRINT: Enviando completed ---") # DEBUG COMPLETED
    output_queue.put({"status": "completed", "data": "Escaneo completado."})


# Clase para manejar logs del worker a través de una cola
class QueueHandler(logging.Handler):
    def __init__(self, queue):
        super().__init__()
        self.queue = queue

    def emit(self, record):
        # Envía el registro de log completo a la cola
        self.queue.put(record)

# --- PROTECCIÓN PARA MULTIPROCESSING EN WINDOWS ---
# Esto es lo que necesitas añadir/modificar
def _ping_host_scapy(ip_address, stop_event, log_queue):
    mac_addr = "N/A"
    try:
        # log_queue.put(logging.LogRecord('ScannerWorker', logging.DEBUG, __file__, 0, f'Scapy: Pinging {ip_address} (ARP)', [], None))
        # Asegúrate de que conf.verb es 0 si no quieres output en la consola de Scapy
        # srp devuelve (answered, unanswered)
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=1, verbose=False)
        
        if ans: # Si hay respuestas
            for s, r in ans:
                mac_addr = r.hwsrc # MAC Address
                return True, mac_addr # Retorna True y la MAC
        
    except Exception as e:
        log_queue.put(logging.LogRecord('ScannerWorker', logging.ERROR, __file__, 0, f'Scapy ARP Ping Error for {ip_address}: {e}', [], None))
        # Fallback a ICMP ping si ARP falla o no es de la misma LAN
        try:
            # log_queue.put(logging.LogRecord('ScannerWorker', logging.DEBUG, __file__, 0, f'Scapy: Pinging {ip_address} (ICMP)', [], None))
            # sr devuelve (answered, unanswered)
            resp, unans = sr(IP(dst=ip_address)/ICMP(), timeout=1, verbose=False)
            if resp: # Si hay respuestas
                return True, "N/A" # No podemos obtener MAC con ICMP si no es de la misma LAN
        except Exception as icmp_e:
             log_queue.put(logging.LogRecord('ScannerWorker', logging.ERROR, __file__, 0, f'Scapy ICMP Ping Error for {ip_address}: {icmp_e}', [], None))
    return False, "N/A"

def _scan_ports_scapy(ip_address, stop_event, log_queue):
    open_ports = []
    ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389, 8080]
    
    for port in ports_to_scan:
        if stop_event.is_set():
            log_queue.put(logging.LogRecord('ScannerWorker', logging.WARNING, __file__, 0, 'Port scan stopped early.', [], None))
            return "Scan Stopped", "N/A"
        try:
            # log_queue.put(logging.LogRecord('ScannerWorker', logging.DEBUG, __file__, 0, f'Scapy: Scanning port {port} on {ip_address}', [], None))
            # SYN Scan
            # Usar verbose=False en lugar de verbose=0 para mayor claridad
            response = sr1(IP(dst=ip_address)/TCP(dport=port, flags="S"), timeout=0.5, verbose=False)
            
            if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12: # SYN-ACK
                open_ports.append(str(port))
                # Enviar RST para cerrar la conexión. Un timeout muy bajo puede causar problemas.
                # Establece un timeout mínimo para asegurar que el paquete RST se envía.
                sr(IP(dst=ip_address)/TCP(dport=response.dport, flags="R"), timeout=0.1, verbose=False) 
        except Exception as e:
            log_queue.put(logging.LogRecord('ScannerWorker', logging.ERROR, __file__, 0, f'Scapy Port Scan Error on {ip_address}:{port}: {e}', [], None))

    return ",".join(open_ports) if open_ports else "N/A", "Unknown"

def scan_network(ip_range, output_queue, stop_event, log_queue):
    worker_logger = logging.getLogger('ScannerWorker')
    worker_logger.setLevel(logging.DEBUG)
    if not worker_logger.handlers:
        worker_logger.addHandler(QueueHandler(log_queue))
        worker_logger.addHandler(logging.StreamHandler(sys.stdout)) # Para ver logs en la consola del worker

    worker_logger.info(f"Worker: Iniciando escaneo para {ip_range}")

    # --- AQUÍ VA LA LÓGICA REAL DE ESCANEO DE SCAPY ---
    # GENERACIÓN DE IPs A ESCANEAR A PARTIR DEL ip_range
    try:
        # Aquí generas la lista de IPs a partir del rango usando Scapy o alguna otra librería
        # Ejemplo (Scapy):
        # No se recomienda sr/srp directamente sobre el rango completo sin un generador
        # Una forma común es iterar y luego ping

        # Para escanear un rango completo como 192.168.1.0/24:
        # Puedes usar una herramienta como `ipaddress` para generar las IPs
        import ipaddress
        ip_network = ipaddress.ip_network(ip_range, strict=False)
        all_ips = [str(ip) for ip in ip_network.hosts()] # Excluye network y broadcast addresses

        output_queue.put({"status": "total_ips", "data": {"count": len(all_ips)}})
        worker_logger.debug(f"Worker: Total de IPs a escanear: {len(all_ips)}")

        for ip in all_ips:
            if stop_event.is_set():
                worker_logger.warning("Worker: Señal de detención recibida. Terminando escaneo.")
                output_queue.put({"status": "error", "data": {"message": "Escaneo detenido por el usuario."}})
                return

            # Intenta pinguear el host y obtener su MAC
            is_up, mac_address = _ping_host_scapy(ip, stop_event, log_queue)

            if is_up:
                ports, os_detected = _scan_ports_scapy(ip, stop_event, log_queue)

                host_info = {
                    "ip": ip,
                    "hostname": "N/A", # Scapy no resuelve hostname por defecto fácilmente, puedes añadir un dns.resolver si lo necesitas
                    "mac": mac_address,
                    "state": "up",
                    "ports": ports,
                    "os": os_detected
                }
                output_queue.put({"status": "host_found", "data": host_info})
                worker_logger.debug(f"Worker: Host encontrado y enviado: {ip} - {mac_address}")
            else:
                worker_logger.debug(f"Worker: Host no responde al ping: {ip}")

    except Exception as e:
        worker_logger.error(f"Worker: Error crítico durante el escaneo: {e}", exc_info=True)
        output_queue.put({"status": "error", "data": {"message": f"Error interno en el escaneo: {e}"}})
    finally:
        worker_logger.info("Worker: Escaneo completado.")
        output_queue.put({"status": "completed", "data": "Escaneo completado."})