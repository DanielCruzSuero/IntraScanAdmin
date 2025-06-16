import sys
import subprocess
import logging
import re
import json

# --- Configuración del Logger ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__) # Este logger es para este módulo (remote_control.py)
app_logger = logging.getLogger('IntraScanAdmin') # Si tu aplicación principal usa este nombre, úsalo aquí también.

# --- Función send_magic_packet (Wake-on-LAN) ---
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

# --- Función execute_remote_powershell_command ---
def execute_remote_powershell_command(hostname, username, password, command):
    """
    Ejecuta un comando de PowerShell en un host remoto utilizando Invoke-Command.
    """
    app_logger.info(f"Ejecución remota: Solicitando comando en {hostname} como {username}...")
    powershell_script_template = r"""
    $SecurePassword = ConvertTo-SecureString -String '{password_str}' -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential ('{username_str}', $SecurePassword)

    try {{
        Invoke-Command -ComputerName '{hostname_str}' -Credential $Credential -ScriptBlock {{
            try {{
                {command_str}
            }} catch {{
                Write-Error $_.Exception.Message -ErrorAction Stop
                Exit 1
            }}
        }} -ErrorAction Stop | Out-String # <--- ELIMINADO: -Encoding UTF8
    }} catch [System.Exception] {{
        Write-Error $_.Exception.Message -ErrorAction Stop
        Exit 1
    }}
    """
    
    # Escapar comillas simples para que no rompan el script de PowerShell
    powershell_script = powershell_script_template.format(
        password_str=password.replace("'", "''"), 
        username_str=username.replace("'", "''"),
        hostname_str=hostname.replace("'", "''"),
        command_str=command.replace("'", "''")
    )

    try:
        # Ejecutar el proceso sin decodificación de texto inicial
        process = subprocess.run(
            ["pwsh.exe", "-Command", powershell_script],
            capture_output=True,
            check=True, # Lanza CalledProcessError si el código de salida no es 0
            timeout=60
        )

        # Decodificar stdout y stderr manualmente con manejo de errores 'replace'
        stdout_output = process.stdout.decode('utf-8', errors='replace').strip()
        stderr_output = process.stderr.decode('utf-8', errors='replace').strip()

        shell_output_objects = "" # Mantener por compatibilidad

        app_logger.info(f"Ejecución remota en {hostname} exitosa. Stdout: {stdout_output}")
        if stderr_output:
            app_logger.warning(f"Ejecución remota en {hostname} con stderr: {stderr_output}")

        return {
            "stdout": stdout_output,
            "stderr": stderr_output,
            "shell_output": shell_output_objects
        }

    except subprocess.CalledProcessError as e:
        # Decodificar las salidas del error con manejo de errores 'replace'
        stdout_content = e.stdout.decode('utf-8', errors='replace').strip() if e.stdout else "No stdout available."
        stderr_content = e.stderr.decode('utf-8', errors='replace').strip() if e.stderr else "No stderr available."

        error_message = f"Error en PowerShell remoto (código {e.returncode})."
        error_message += f"\nSalida de error: {stderr_content}"
        error_message += f"\nSalida estándar: {stdout_content}"
        
        logger.error(f"GUI: {error_message}", exc_info=True)
        # Analizar el mensaje de error para dar pistas más específicas al usuario
        if "Access is denied" in stderr_content or "Access is denied" in stdout_content:
            raise ConnectionError("Acceso denegado. Verifica usuario/contraseña o permisos de administrador en el host remoto.")
        elif "Cannot connect" in stderr_content or "Cannot connect" in stdout_content:
            raise ConnectionError("No se puede conectar al host remoto. Verifica IP, red y que WinRM esté habilitado y el firewall abierto (puertos 5985/5986).")
        elif "Kerberos authentication" in stderr_content or "Kerberos authentication" in stdout_content:
            raise ConnectionError("Problema de autenticación Kerberos. Intenta usar un nombre de usuario en formato 'dominio\\usuario' o 'usuario@dominio' si estás en un dominio, o verifica la configuración de TrustedHosts.")
        else:
            raise RuntimeError(f"Error en el comando remoto: {error_message}")
        
    except subprocess.TimeoutExpired:
        logger.error(f"GUI: El comando remoto en {hostname} excedió el tiempo límite.")
        raise RuntimeError("El comando remoto excedió el tiempo límite.")
        
    except Exception as e:
        logger.error(f"GUI: Error inesperado al ejecutar comando remoto en {hostname}: {e}", exc_info=True)
        raise RuntimeError(f"Error inesperado al ejecutar comando remoto: {e}")

# --- Función remote_shutdown ---
def remote_shutdown(target, username, password):
    """
    Apaga un equipo Windows de forma remota usando PowerShell Invoke-Command.
    """
    app_logger.info(f"Apagado remoto: Intentando apagar {target} como {username}...")
    powershell_script_template = r"""
    $SecurePassword = ConvertTo-SecureString -String '{password_str}' -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential ('{username_str}', $SecurePassword)

    try {{
        Invoke-Command -ComputerName '{hostname_str}' -Credential $Credential -ScriptBlock {{
            try {{
                Stop-Computer -Force
            }} catch {{
                Write-Error $_.Exception.Message -ErrorAction Stop
                Exit 1
            }}
        }} -ErrorAction Stop | Out-String # <--- ELIMINADO: -Encoding UTF8
    }} catch [System.Exception] {{
        Write-Error $_.Exception.Message -ErrorAction Stop
        Exit 1
    }}
    """
    powershell_script = powershell_script_template.format(
        password_str=password.replace("'", "''"),
        username_str=username.replace("'", "''"),
        hostname_str=target.replace("'", "''")
    )
    
    try:
        process = subprocess.run(
            ["pwsh.exe", "-Command", powershell_script],
            capture_output=True,
            check=True,
            timeout=60
        )
        
        stdout_output = process.stdout.decode('utf-8', errors='replace').strip()
        stderr_output = process.stderr.decode('utf-8', errors='replace').strip()

        app_logger.info(f"Apagado remoto iniciado con éxito en {target}. Salida: {stdout_output}")
        if stderr_output:
            app_logger.warning(f"Apagado remoto con advertencias en {target}: {stderr_output}")
        return True

    except subprocess.CalledProcessError as e:
        stdout_content = e.stdout.decode('utf-8', errors='replace').strip() if e.stdout else "No stdout available."
        stderr_content = e.stderr.decode('utf-8', errors='replace').strip() if e.stderr else "No stderr available."

        error_message = f"Error en PowerShell remoto (código {e.returncode})."
        error_message += f"\nSalida de error: {stderr_content}"
        error_message += f"\nSalida estándar: {stdout_content}"
        app_logger.error(f"Apagado remoto fallido en {target}: {error_message}", exc_info=True)
        raise ConnectionError(f"Error de conexión remota o ejecución de comando: {error_message}")
    except subprocess.TimeoutExpired:
        app_logger.error(f"Apagado remoto en {target} excedió el tiempo límite.")
        raise ConnectionError("El comando remoto excedió el tiempo límite.")
    except Exception as e:
        app_logger.error(f"Error inesperado al apagar {target}: {e}", exc_info=True)
        raise

# --- Función remote_reboot ---
def remote_reboot(target, username, password):
    """
    Reinicia un equipo Windows de forma remota usando PowerShell Invoke-Command.
    """
    app_logger.info(f"Reinicio remoto: Intentando reiniciar {target} como {username}...")
    powershell_script_template = r"""
    $SecurePassword = ConvertTo-SecureString -String '{password_str}' -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential ('{username_str}', $SecurePassword)

    try {{
        Invoke-Command -ComputerName '{hostname_str}' -Credential $Credential -ScriptBlock {{
            try {{
                Restart-Computer -Force
            }} catch {{
                Write-Error $_.Exception.Message -ErrorAction Stop
                Exit 1
            }}
        }} -ErrorAction Stop | Out-String # <--- ELIMINADO: -Encoding UTF8
    }} catch [System.Exception] {{
        Write-Error $_.Exception.Message -ErrorAction Stop
        Exit 1
    }}
    """
    powershell_script = powershell_script_template.format(
        password_str=password.replace("'", "''"),
        username_str=username.replace("'", "''"),
        hostname_str=target.replace("'", "''")
    )

    try:
        process = subprocess.run(
            ["pwsh.exe", "-Command", powershell_script],
            capture_output=True,
            check=True,
            timeout=60
        )
        
        stdout_output = process.stdout.decode('utf-8', errors='replace').strip()
        stderr_output = process.stderr.decode('utf-8', errors='replace').strip()

        app_logger.info(f"Reinicio remoto iniciado con éxito en {target}. Salida: {stdout_output}")
        if stderr_output:
            app_logger.warning(f"Reinicio remoto con advertencias en {target}: {stderr_output}")
        return True

    except subprocess.CalledProcessError as e:
        stdout_content = e.stdout.decode('utf-8', errors='replace').strip() if e.stdout else "No stdout available."
        stderr_content = e.stderr.decode('utf-8', errors='replace').strip() if e.stderr else "No stderr available."

        error_message = f"Error en PowerShell remoto (código {e.returncode})."
        error_message += f"\nSalida de error: {stderr_content}"
        error_message += f"\nSalida estándar: {stdout_content}"
        app_logger.error(f"Reinicio remoto fallido en {target}: {error_message}", exc_info=True)
        raise ConnectionError(f"Error de conexión remota o ejecución de comando: {error_message}")
    except subprocess.TimeoutExpired:
        app_logger.error(f"Reinicio remoto en {target} excedió el tiempo límite.")
        raise ConnectionError("El comando remoto excedió el tiempo límite.")
    except Exception as e:
        app_logger.error(f"Error inesperado al reiniciar {target}: {e}", exc_info=True)
        raise

# --- Función get_remote_host_info ---
def get_remote_host_info(target, username, password):
    """
    Obtiene información de hardware y software de un equipo Windows de forma remota
    utilizando PowerShell Invoke-Command y ConvertTo-Json.

    target: IP o nombre de host del equipo objetivo.
    username: Nombre de usuario con permisos de administrador en el equipo remoto.
    password: Contraseña del usuario.

    Devuelve un diccionario con la información recopilada.
    """
    app_logger.info(f"Recopilación remota: Conectando a {target} como {username} para obtener información...")
    
    info_data = {
        "ip_address": target,
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
        "network_point": "N/A",
        "cable_length": "N/A",
        "office": "N/A",
        "user": "N/A",
        "department": "N/A",
        "planta": "N/A",
        "description": "Obtenido remotamente"
    }

    powershell_script_template = r"""
    $SecurePassword = ConvertTo-SecureString -String '{password_str}' -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential ('{username_str}', $SecurePassword)

    try {{
        Invoke-Command -ComputerName '{hostname_str}' -Credential $Credential -ScriptBlock {{
            try {{
                $computerInfo = Get-ComputerInfo | Select-Object CsName, OsName, OsHardwareAbstractionLayer, Manufacturer, Model
                $processor = Get-WmiObject -Class Win32_Processor | Select-Object Name
                $memory = (Get-WmiObject -Class Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum
                # Modificación importante aquí para Discos y asegurarse de que sea una lista
                $disks = (Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, Size, FreeSpace) | ForEach-Object {{$_}}; if (-not $disks) {{ $disks = @() }}
                # Modificación importante aquí para Gráficos y asegurarse de que sea una lista
                $graphics = (Get-WmiObject -Class Win32_VideoController | Select-Object Description, AdapterRAM) | ForEach-Object {{$_}}; if (-not $graphics) {{ $graphics = @() }}
                # Modificación importante aquí para Displays y asegurarse de que sea una lista
                $displays = (Get-WmiObject -Class Win32_DesktopMonitor | Select-Object Caption, ScreenWidth, ScreenHeight) | ForEach-Object {{$_}}; if (-not $displays) {{ $displays = @() }}
                $networkAdapter = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {{ $_.IPAddress -Contains '{hostname_str}' }} | Select-Object MACAddress, DNSHostName, IPAddress

                $result = @{{
                    ComputerInfo = $computerInfo
                    Processor = $processor
                    Memory = $memory
                    Disks = $disks
                    Graphics = $graphics
                    Displays = $displays
                    NetworkAdapter = $networkAdapter
                }}
                $result | ConvertTo-Json -Depth 5 -Compress
            }} catch {{
                Write-Error $_.Exception.Message -ErrorAction Stop
                Exit 1
            }}
        }} -ErrorAction Stop | Out-String # <--- ELIMINADO: -Encoding UTF8
    }} catch [System.Exception] {{
        Write-Error $_.Exception.Message -ErrorAction Stop
        Exit 1
    }}
    """
    powershell_script = powershell_script_template.format(
        password_str=password.replace("'", "''"),
        username_str=username.replace("'", "''"),
        hostname_str=target.replace("'", "''")
    )

    try:
        process = subprocess.run(
            ["pwsh.exe", "-Command", powershell_script],
            capture_output=True,
            check=True,
            timeout=120
        )

        json_output = process.stdout.decode('utf-8', errors='replace').strip()
        stderr_output = process.stderr.decode('utf-8', errors='replace').strip()

        # Añadimos un log para ver la salida RAW (la hemos usado para depurar y la mantendremos)
        app_logger.info(f"Salida CRUDA de PowerShell para {target}: '{json_output}'") 

        if stderr_output:
            app_logger.warning(f"Recopilación remota en {target} con stderr: {stderr_output}")

        remote_data = json.loads(json_output)

        # Rellenar info_data desde el JSON (el parsing es el mismo que antes)
        if 'ComputerInfo' in remote_data and remote_data['ComputerInfo']:
            info = remote_data['ComputerInfo']
            info_data["hostname"] = info.get('CsName', info_data["hostname"])
            info_data["os"] = info.get('OsName', info_data["os"])
            info_data["brand"] = info.get('Manufacturer', info_data["brand"])
            info_data["model"] = info.get('Model', info_data["model"])

        # Procesador: Ya lo manejabas bien, pero aseguramos el 'is not None'
        if 'Processor' in remote_data and remote_data['Processor'] is not None:
            proc_info = remote_data['Processor']
            if isinstance(proc_info, list) and proc_info:
                info_data["processor"] = proc_info[0].get('Name', info_data["processor"])
            elif isinstance(proc_info, dict):
                info_data["processor"] = proc_info.get('Name', info_data["processor"])
        
        if 'Memory' in remote_data and remote_data['Memory'] is not None:
            total_bytes = int(remote_data['Memory'])
            total_gb = round(total_bytes / (1024**3))
            info_data["memory"] = f"{total_gb}GB"

        # Discos: Aplicar la misma lógica que para Graphics y Displays
        if 'Disks' in remote_data and remote_data['Disks'] is not None:
            disk_details = []
            disk_list = remote_data['Disks']
            if not isinstance(disk_list, list):
                disk_list = [disk_list] # Aseguramos que siempre sea una lista
            
            for disk in disk_list:
                dev_id = disk.get('DeviceID', 'N/A')
                total_size_bytes = int(disk.get('Size', 0))
                total_size_gb = round(int(total_size_bytes) / (1024**3)) if total_size_bytes else 0
                disk_details.append(f"{dev_id} ({total_size_gb}GB)")
            info_data["disks"] = ", ".join(disk_details)

        # Gráficos: Corrección implementada
        if 'Graphics' in remote_data and remote_data['Graphics'] is not None:
            graphics_details = []
            gpu_list = remote_data['Graphics']
            if not isinstance(gpu_list, list):
                gpu_list = [gpu_list] # Si es un solo diccionario, conviértelo en una lista de un elemento
            
            for gpu in gpu_list:
                desc = gpu.get('Description', 'N/A')
                ram = gpu.get('AdapterRAM', 0)
                ram_mb = round(ram / (1024**2)) if ram else 0
                graphics_details.append(f"{desc} ({ram_mb}MB)")
            info_data["graphics"] = ", ".join(graphics_details)

        # Displays: Corrección implementada
        if 'Displays' in remote_data and remote_data['Displays'] is not None:
            display_details = []
            display_list = remote_data['Displays']
            if not isinstance(display_list, list):
                display_list = [display_list] # Si es un solo diccionario, conviértelo en una lista de un elemento
            
            for monitor in display_list:
                caption = monitor.get('Caption', 'N/A')
                width = monitor.get('ScreenWidth', 'N/A')
                height = monitor.get('ScreenHeight', 'N/A')
                display_details.append(f"{caption} ({width}x{height})")
            info_data["display"] = ", ".join(display_details)

        # NetworkAdapter: Tu código ya maneja bien lista/dict
        if 'NetworkAdapter' in remote_data and remote_data['NetworkAdapter']:
            net_adapter = remote_data['NetworkAdapter']
            if isinstance(net_adapter, list) and net_adapter:
                found_adapter = next((a for a in net_adapter if target in a.get('IPAddress', [])), None)
                if not found_adapter and target in [a.get('DNSHostName') for a in net_adapter if a.get('DNSHostName')]:
                    found_adapter = next((a for a in net_adapter if target == a.get('DNSHostName')), None)

                if found_adapter:
                    info_data["mac_address"] = found_adapter.get('MACAddress', info_data["mac_address"])
                    if info_data["hostname"] == "N/A" or not info_data["hostname"]:
                        info_data["hostname"] = found_adapter.get('DNSHostName', info_data["hostname"])
            elif isinstance(net_adapter, dict):
                info_data["mac_address"] = net_adapter.get('MACAddress', info_data["mac_address"])
                if info_data["hostname"] == "N/A" or not info_data["hostname"]:
                    info_data["hostname"] = net_adapter.get('DNSHostName', info_data["hostname"])

        app_logger.info(f"Recopilación remota de {target} completada con éxito.")
        return info_data

    except subprocess.CalledProcessError as e:
        stdout_content = e.stdout.decode('utf-8', errors='replace').strip() if e.stdout else "No stdout available."
        stderr_content = e.stderr.decode('utf-8', errors='replace').strip() if e.stderr else "No stderr available."

        error_message = f"Error en PowerShell remoto (código {e.returncode})."
        error_message += f"\nSalida de error: {stderr_content}"
        error_message += f"\nSalida estándar: {stdout_content}"

        app_logger.error(f"Error al obtener info remota de {target}: {error_message}", exc_info=True)
        if "Access is denied" in stdout_content or "Access is denied" in stderr_content:
            raise ConnectionError("Acceso denegado. Verifica usuario/contraseña o permisos en el host remoto.")
        elif "Cannot connect" in stdout_content or "Cannot connect" in stderr_content:
            raise ConnectionError("No se puede conectar al host remoto. Verifica IP, red y que WinRM esté habilitado y el firewall abierto (puertos 5985/5986).")
        elif "Kerberos authentication" in stdout_content or "Kerberos authentication" in stderr_content:
            raise ConnectionError("Problema de autenticación Kerberos. Intenta usar un nombre de usuario en formato 'dominio\\usuario' o 'usuario@dominio' si estás en un dominio, o verifica la configuración de TrustedHosts.")
        else:
            raise ConnectionError(f"Error de conexión o ejecución al obtener información: {error_message}")
    except subprocess.TimeoutExpired:
        app_logger.error(f"La recopilación de información en {target} excedió el tiempo límite.")
        raise ConnectionError("La recopilación de información excedió el tiempo límite.")
    except json.JSONDecodeError as e:
        app_logger.error(f"Error al parsear la salida JSON de PowerShell en {target}: {e}. Salida recibida (posibles caracteres reemplazados): {json_output}", exc_info=True)
        raise RuntimeError(f"Error al procesar la información del host remoto: La salida no es un JSON válido o está corrupta: {e}. Salida: {json_output[:200]}...")
    except Exception as e:
        app_logger.error(f"Error inesperado al obtener información remota de {target}: {e}", exc_info=True)
        raise