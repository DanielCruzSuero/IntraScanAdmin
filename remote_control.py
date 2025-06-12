import sys
import subprocess
import logging
import re
from pypsrp.powershell import PowerShell
from pypsrp.wsman import WSMan
from pypsrp.exceptions import WinRMError

# Configurar el logger
app_logger = logging.getLogger('IntraScanAdmin') # Asegúrate de que el nombre coincida con logger_config

def send_magic_packet(mac_address, ip_address="255.255.255.255", port=9):
    """
    Envía un paquete mágico Wake-on-LAN.
    mac_address: Dirección MAC del equipo objetivo (ej. "00:1A:2B:3C:4D:5E").
    ip_address: Dirección IP o nombre de host del destino (por defecto, broadcast).
    port: Puerto UDP a usar (por defecto, 9).
    """
    if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac_address):
        app_logger.error(f"WOL: Formato de MAC inválido: {mac_address}")
        raise ValueError("Formato de dirección MAC inválido. Use XX:XX:XX:XX:XX:XX.")

    # Limpiar la MAC (quitar guiones o dos puntos) y convertir a bytes
    mac_address = mac_address.replace(':', '').replace('-', '')
    data = b'FF' * 6 + bytes.fromhex(mac_address) * 16
    
    app_logger.info(f"WOL: Enviando paquete mágico a MAC: {mac_address}, IP: {ip_address}, Puerto: {port}")

    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(data, (ip_address, port))
        app_logger.info(f"WOL: Paquete mágico enviado exitosamente a {mac_address}.")
        return True
    except Exception as e:
        app_logger.error(f"WOL: Error al enviar paquete mágico a {mac_address}: {e}", exc_info=True)
        raise

def remote_shutdown(target, username, password):
    """
    Apaga un equipo Windows de forma remota usando PsExec o WinRM (a través de PowerShell).
    target: IP o nombre de host del equipo objetivo.
    username: Nombre de usuario con permisos de administrador en el equipo remoto.
    password: Contraseña del usuario.
    """
    app_logger.info(f"Apagado remoto: Intentando apagar {target} como {username}...")
    try:
        # Usamos WinRM (PowerShell) para mayor compatibilidad y seguridad que PsExec
        # Asegúrate de que WinRM esté configurado en el objetivo
        with WSMan(target, auth_method='negotiate', username=username, password=password) as wsman:
            with PowerShell(wsman) as ps:
                ps.add_cmd("Stop-Computer", {"Force": True}) # -Force para apagar sin confirmación
                ps.invoke()
                if ps.had_errors:
                    error_output = "\n".join(str(e) for e in ps.output_streams.error)
                    app_logger.error(f"Apagado remoto fallido en {target}: {error_output}")
                    raise Exception(f"Errores en PowerShell: {error_output}")
                app_logger.info(f"Apagado remoto iniciado con éxito en {target}.")
                return True
    except WinRMError as e:
        app_logger.error(f"Error de WinRM al apagar {target}: {e}", exc_info=True)
        # Puedes añadir lógica para mensajes de error específicos (ej. credenciales inválidas)
        if "Access is denied" in str(e):
             raise ConnectionError("Acceso denegado. Verifica usuario/contraseña o permisos.")
        elif "Cannot connect" in str(e):
            raise ConnectionError("No se puede conectar al host. Verifica IP, red y que WinRM esté habilitado y el firewall abierto.")
        else:
            raise ConnectionError(f"Error de conexión remota: {e}")
    except Exception as e:
        app_logger.error(f"Error inesperado al apagar {target}: {e}", exc_info=True)
        raise

def remote_reboot(target, username, password):
    """
    Reinicia un equipo Windows de forma remota usando PsExec o WinRM (a través de PowerShell).
    target: IP o nombre de host del equipo objetivo.
    username: Nombre de usuario con permisos de administrador en el equipo remoto.
    password: Contraseña del usuario.
    """
    app_logger.info(f"Reinicio remoto: Intentando reiniciar {target} como {username}...")
    try:
        with WSMan(target, auth_method='negotiate', username=username, password=password) as wsman:
            with PowerShell(wsman) as ps:
                ps.add_cmd("Restart-Computer", {"Force": True}) # -Force para reiniciar sin confirmación
                ps.invoke()
                if ps.had_errors:
                    error_output = "\n".join(str(e) for e in ps.output_streams.error)
                    app_logger.error(f"Reinicio remoto fallido en {target}: {error_output}")
                    raise Exception(f"Errores en PowerShell: {error_output}")
                app_logger.info(f"Reinicio remoto iniciado con éxito en {target}.")
                return True
    except WinRMError as e:
        app_logger.error(f"Error de WinRM al reiniciar {target}: {e}", exc_info=True)
        if "Access is denied" in str(e):
             raise ConnectionError("Acceso denegado. Verifica usuario/contraseña o permisos.")
        elif "Cannot connect" in str(e):
            raise ConnectionError("No se puede conectar al host. Verifica IP, red y que WinRM esté habilitado y el firewall abierto.")
        else:
            raise ConnectionError(f"Error de conexión remota: {e}")
    except Exception as e:
        app_logger.error(f"Error inesperado al reiniciar {target}: {e}", exc_info=True)
        raise

def get_remote_host_info(target, username, password):
    """
    Obtiene información de hardware y software de un equipo Windows de forma remota
    usando PowerShell Remoting (a través de pypsrp).

    target: IP o nombre de host del equipo objetivo.
    username: Nombre de usuario con permisos de administrador en el equipo remoto.
    password: Contraseña del usuario.

    Devuelve un diccionario con la información recopilada.
    """
    app_logger.info(f"Recopilación remota: Conectando a {target} como {username} para obtener información...")
    
    info_data = {
        "ip_address": target, # La IP objetivo es la que estamos consultando
        "hostname": "N/A",
        "mac_address": "N/A",
        "os": "N/A",
        "brand": "N/A",
        "model": "N/A",
        "processor": "N/A",
        "memory": "N/A",
        "disks": "N/A",
        "graphics": "N/A",
        "display": "N/A",
        # Estos últimos campos no se pueden obtener genéricamente de forma remota,
        # así que se mantendrán N/A o deberán ser rellenados manualmente/por otras fuentes
        "network_point": "N/A",
        "cable_length": "N/A",
        "office": "N/A",
        "user": "N/A", # El usuario logeado puede obtenerse, pero el "usuario del equipo" es más subjetivo.
        "department": "N/A",
        "planta": "N/A",
        "description": "Obtenido remotamente" # Puedes poner una descripción por defecto
    }

    try:
        with WSMan(target, auth_method='negotiate', username=username, password=password) as wsman:
            with PowerShell(wsman) as ps:
                # 1. Obtener información básica del sistema
                ps.add_cmd("Get-ComputerInfo")
                ps.add_statement() # Separar comandos para mejor manejo de errores
                
                # 2. Obtener información de la tarjeta de red (IP, MAC)
                # Seleccionar la primera tarjeta Ethernet/Wi-Fi que tenga una IP
                ps.add_cmd("Get-NetAdapter", {"Physical": True})
                ps.add_cmd("Get-NetIPAddress", {"AddressFamily": "IPv4"})
                ps.add_cmd("Select-Object", {"Property": ["IPAddress", "InterfaceAlias"]})
                ps.add_statement()

                # 3. Obtener información del procesador
                ps.add_cmd("Get-WmiObject -Class Win32_Processor")
                ps.add_statement()

                # 4. Obtener información de la memoria física
                ps.add_cmd("Get-WmiObject -Class Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum")
                ps.add_statement()

                # 5. Obtener información de los discos lógicos
                ps.add_cmd("Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, Size, FreeSpace | Format-List")
                ps.add_statement()

                # 6. Obtener información de la tarjeta gráfica
                ps.add_cmd("Get-WmiObject -Class Win32_VideoController | Select-Object Description, AdapterRAM | Format-List")
                ps.add_statement()

                # 7. Obtener información de los monitores
                ps.add_cmd("Get-WmiObject -Class Win32_DesktopMonitor | Select-Object Caption, ScreenWidth, ScreenHeight | Format-List")
                ps.add_statement()
                
                # 8. Obtener información de la BIOS (para Marca y Modelo del sistema)
                ps.add_cmd("Get-WmiObject -Class Win32_ComputerSystem | Select-Object Manufacturer, Model")
                
                ps.invoke()

                if ps.had_errors:
                    error_output = "\n".join(str(e) for e in ps.output_streams.error)
                    app_logger.error(f"Recopilación remota fallida en {target} con errores de PowerShell: {error_output}")
                    raise Exception(f"Errores en PowerShell durante la recopilación: {error_output}")

                results = ps.output_streams.stdout

                # Procesar resultados
                # Get-ComputerInfo
                computer_info = next((r for r in results if hasattr(r, 'OsName') and hasattr(r, 'CsProcessors')), None)
                if computer_info:
                    info_data["hostname"] = getattr(computer_info, 'CsName', info_data["hostname"])
                    info_data["os"] = getattr(computer_info, 'OsName', info_data["os"])
                    
                    # Manufacturer y Model del sistema completo
                    system_info = next((r for r in results if hasattr(r, 'Manufacturer') and hasattr(r, 'Model')), None)
                    if system_info:
                        info_data["brand"] = getattr(system_info, 'Manufacturer', info_data["brand"])
                        info_data["model"] = getattr(system_info, 'Model', info_data["model"])


                # Get-NetIPAddress (para MAC y Hostname de la interfaz principal)
                # Esto es más complejo, la IP que ya tenemos es la del target.
                # Para la MAC necesitamos Get-NetAdapter, luego mapear con la IP si es posible.
                net_adapters_raw = [r for r in results if hasattr(r, 'InterfaceAlias')]
                mac_addresses_found = []
                for adapter in net_adapters_raw:
                    # Get-NetAdapter Physical indica adaptadores físicos.
                    # Luego necesitamos su MAC. Necesitamos un comando WMI específico para MAC.
                    # O ejecutar otra consulta específica para MAC.
                    # Esto lo haremos con Get-WmiObject Win32_NetworkAdapterConfiguration en el mismo script para evitar múltiples conexiones.
                    
                    # Ya tenemos el comando para obtener info de NICs para IP.
                    # Ahora, para la MAC, podemos usar Win32_NetworkAdapter
                    # Unir con la info de IP es más complejo. Por ahora, tomaremos la primera MAC válida.
                    # Vamos a modificar el script de powershell para incluir la MAC de la IP principal.
                    pass # La MAC se obtendrá mejor con Win32_NetworkAdapterConfiguration


                # Get-WmiObject -Class Win32_Processor
                processor_info = next((r for r in results if hasattr(r, 'Name') and 'Processor' in str(r.Name)), None)
                if processor_info:
                    info_data["processor"] = getattr(processor_info, 'Name', info_data["processor"])


                # Get-WmiObject -Class Win32_PhysicalMemory (sumar capacidad)
                memory_sum_info = next((r for r in results if hasattr(r, 'Sum') and r.Units == 1), None) # Capacity está en Bytes
                if memory_sum_info:
                    total_bytes = getattr(memory_sum_info, 'Sum', 0)
                    total_gb = round(total_bytes / (1024**3))
                    info_data["memory"] = f"{total_gb}GB"


                # Get-WmiObject -Class Win32_LogicalDisk (Discos)
                disks_raw = [r for r in results if hasattr(r, 'DeviceID') and 'Size' in str(r) and 'FreeSpace' in str(r)]
                disk_details = []
                for disk in disks_raw:
                    dev_id = getattr(disk, 'DeviceID', 'N/A')
                    total_size_bytes = getattr(disk, 'Size', 0)
                    total_size_gb = round(int(total_size_bytes) / (1024**3)) if total_size_bytes else 0
                    disk_details.append(f"{dev_id} ({total_size_gb}GB)")
                info_data["disks"] = ", ".join(disk_details) if disk_details else info_data["disks"]


                # Get-WmiObject -Class Win32_VideoController (Gráfica)
                graphics_raw = [r for r in results if hasattr(r, 'Description') and 'VideoController' in str(r.Description)]
                graphics_details = []
                for gpu in graphics_raw:
                    desc = getattr(gpu, 'Description', 'N/A')
                    ram = getattr(gpu, 'AdapterRAM', 0)
                    ram_mb = round(ram / (1024**2)) if ram else 0
                    graphics_details.append(f"{desc} ({ram_mb}MB)")
                info_data["graphics"] = ", ".join(graphics_details) if graphics_details else info_data["graphics"]


                # Get-WmiObject -Class Win32_DesktopMonitor (Pantallas)
                displays_raw = [r for r in results if hasattr(r, 'Caption') and 'Monitor' in str(r.Caption)]
                display_details = []
                for monitor in displays_raw:
                    caption = getattr(monitor, 'Caption', 'N/A')
                    width = getattr(monitor, 'ScreenWidth', 'N/A')
                    height = getattr(monitor, 'ScreenHeight', 'N/A')
                    display_details.append(f"{caption} ({width}x{height})")
                info_data["display"] = ", ".join(display_details) if display_details else info_data["display"]
                
                # Adquirir MAC Address y verificar Hostname para la IP principal
                # Ejecutamos un comando adicional para obtener la MAC de la IP que estamos usando
                ps_mac_cmd = f"Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {{ $_.IPAddress -Contains '{target}' }} | Select-Object MACAddress, DNSHostName"
                ps.add_cmd(ps_mac_cmd) # Add this to the existing session
                ps.invoke() # Re-invoke to get latest results

                mac_hostname_results = ps.output_streams.stdout
                mac_entry = next((r for r in mac_hostname_results if hasattr(r, 'MACAddress')), None)
                if mac_entry:
                    info_data["mac_address"] = getattr(mac_entry, 'MACAddress', info_data["mac_address"])
                    # Solo actualizamos el hostname si el actual es N/A o vacío y tenemos uno más específico
                    if info_data["hostname"] == "N/A" or not info_data["hostname"]:
                        info_data["hostname"] = getattr(mac_entry, 'DNSHostName', info_data["hostname"])


        app_logger.info(f"Recopilación remota de {target} completada con éxito.")
        return info_data

    except WinRMError as e:
        app_logger.error(f"Error de WinRM al obtener información remota de {target}: {e}", exc_info=True)
        if "Access is denied" in str(e):
             raise ConnectionError("Acceso denegado. Verifica usuario/contraseña o permisos en el host remoto. Asegúrate que el usuario tenga permisos WinRM.")
        elif "Cannot connect" in str(e):
            raise ConnectionError("No se puede conectar al host remoto. Verifica IP, conectividad de red, que WinRM esté habilitado y el firewall abierto (puerto 5985/5986).")
        else:
            raise ConnectionError(f"Error de conexión WinRM: {e}")
    except Exception as e:
        app_logger.error(f"Error inesperado al obtener información remota de {target}: {e}", exc_info=True)
        raise