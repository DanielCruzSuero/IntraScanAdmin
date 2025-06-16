# main.py

import actual.scanner as scanner
import actual.remote_control as remote_control
import actual.inventory_manager as inventory_manager
import sys
import ipaddress
from actual.logger_config import app_logger # Importa el logger

def display_menu():
    """Muestra el menú principal de opciones al usuario."""
    print("\n--- IntraScan & Admin - Menú Principal ---")
    print("1. Escanear red")
    print("2. Encender equipo (Wake-on-LAN)")
    print("3. Apagar/Reiniciar equipo remoto")
    print("4. Gestionar Inventario de Hosts")
    print("5. Salir")
    print("------------------------------------------")

def display_hosts(hosts):
    """Muestra la lista de hosts con un índice."""
    if not hosts:
        print("No hay hosts en el inventario.")
        return False
    print("\n--- Hosts en Inventario ---")
    for i, host in enumerate(hosts):
        print(f"{i+1}. Nombre: {host.get('name', 'N/A')} | IP: {host.get('ip_address', 'N/A')} | MAC: {host.get('mac_address', 'N/A')}")
    print("---------------------------")
    return True

def add_host(hosts):
    """Permite al usuario añadir un nuevo host al inventario."""
    print("\n--- Añadir Nuevo Host ---")
    name = input("Nombre del host (ej. PC-Salon): ").strip()
    ip_address = input("Dirección IP (ej. 192.168.1.100): ").strip()
    mac_address = input("Dirección MAC (ej. AA:BB:CC:DD:EE:FF, opcional para WoL): ").strip()
    username = input("Usuario administrador para acceso remoto (opcional): ").strip()
    password = input("Contraseña del usuario administrador (opcional): ").strip()

    try:
        if ip_address: # Solo validar si no está vacío
            ipaddress.ip_address(ip_address)
    except ValueError:
        app_logger.error(f"Error: La dirección IP introducida '{ip_address}' no es válida.")
        print("Error: La dirección IP introducida no es válida.") # Para el usuario
        return

    if not name:
        app_logger.warning("Nombre del host es obligatorio para añadir un host.")
        print("Nombre del host es obligatorio.") # Para el usuario
        return

    new_host = {
        "name": name,
        "ip_address": ip_address,
        "mac_address": mac_address,
        "username": username,
        "password": password
    }
    hosts.append(new_host)
    if inventory_manager.save_hosts(hosts): # save_hosts ahora devuelve True/False
        app_logger.info(f"Host '{name}' añadido al inventario y guardado.")
        print(f"Host '{name}' añadido al inventario.") # Para el usuario
    else:
        app_logger.error(f"Fallo al guardar el host '{name}' en el inventario.")
        print(f"Fallo al guardar el host '{name}' en el inventario.") # Para el usuario


def delete_host(hosts):
    """Permite al usuario eliminar un host del inventario."""
    if not display_hosts(hosts):
        app_logger.info("Intento de eliminar host: no hay hosts en el inventario.")
        return

    try:
        choice = int(input("Introduce el número del host a eliminar: "))
        if 1 <= choice <= len(hosts):
            removed_host = hosts.pop(choice - 1)
            if inventory_manager.save_hosts(hosts):
                app_logger.info(f"Host '{removed_host.get('name', 'N/A')}' eliminado del inventario y guardado.")
                print(f"Host '{removed_host.get('name', 'N/A')}' eliminado del inventario.")
            else:
                app_logger.error(f"Fallo al guardar el inventario después de eliminar el host '{removed_host.get('name', 'N/A')}'.")
                print(f"Fallo al guardar el inventario después de eliminar el host '{removed_host.get('name', 'N/A')}'.")
        else:
            app_logger.warning(f"Intento de eliminar host con número no válido: {choice}.")
            print("Número de host no válido.")
    except ValueError:
        app_logger.error("Entrada no válida para eliminar host. Se esperaba un número.")
        print("Entrada no válida. Por favor, introduce un número.")

def manage_inventory_menu(hosts):
    """Sub-menú para gestionar el inventario."""
    app_logger.info("Accediendo al menú de gestión de inventario.")
    while True:
        print("\n--- Gestión de Inventario ---")
        print("1. Mostrar todos los hosts")
        print("2. Añadir nuevo host")
        print("3. Eliminar host")
        print("4. Volver al menú principal")
        print("----------------------------")
        choice = input("Elige una opción: ").strip()

        if choice == '1':
            display_hosts(hosts)
            app_logger.info("Mostrando hosts del inventario.")
        elif choice == '2':
            add_host(hosts)
        elif choice == '3':
            delete_host(hosts)
        elif choice == '4':
            app_logger.info("Volviendo al menú principal desde gestión de inventario.")
            break
        else:
            app_logger.warning(f"Opción de inventario no válida: '{choice}'.")
            print("Opción no válida. Por favor, elige un número del 1 al 4.")


def main_app():
    """Bucle principal de la aplicación CLI."""
    app_logger.info("Iniciando aplicación IntraScan & Admin.")
    hosts_inventory = inventory_manager.load_hosts()

    while True:
        display_menu()
        choice = input("Elige una opción: ").strip()
        app_logger.info(f"Opción de menú seleccionada: {choice}")

        if choice == '1':
            # Escanear red
            print("\n--- Escanear Red ---")
            network_range = input("Introduce el rango de red a escanear (ej. 192.168.1.0/24): ").strip()
            
            try:
                ipaddress.ip_network(network_range, strict=False)
            except ValueError:
                app_logger.error(f"Error: El rango de red introducido '{network_range}' no es un formato CIDR válido.")
                print("Error: El rango de red introducido no es un formato CIDR válido (ej. 192.168.1.0/24).")
                continue

            if network_range:
                app_logger.info(f"Iniciando escaneo de red para el rango: {network_range}")
                scanned_results = scanner.scan_network(network_range) 
                
                print("\n--- Resumen del Escaneo ---")
                if scanned_results:
                    print("Se encontraron los siguientes hosts:")
                    for host_data in scanned_results:
                        print(f"- IP: {host_data['ip_address']} (Estado: {host_data['status']})")
                        if host_data['services']:
                            print(f"  Servicios Abiertos: {', '.join(host_data['services'])}")
                        else:
                            print("  Ningún servicio común abierto detectado.")
                    app_logger.info(f"Escaneo de red completado. Se mostraron {len(scanned_results)} hosts.")
                else:
                    print("No se encontraron hosts en el rango especificado.")
                    app_logger.info("Escaneo de red completado. No se encontraron hosts en línea.")
            else:
                app_logger.warning("Rango de red no válido introducido para escaneo.")
                print("Rango de red no válido. Por favor, inténtalo de nuevo.")

        elif choice == '2':
            # Encender equipo (Wake-on-LAN)
            print("\n--- Encender Equipo (Wake-on-LAN) ---")
            if not display_hosts(hosts_inventory):
                app_logger.warning("Intento de WoL sin hosts en el inventario.")
                continue
            
            try:
                host_choice = int(input("Introduce el NÚMERO del host a encender: "))
                if 1 <= host_choice <= len(hosts_inventory):
                    selected_host = hosts_inventory[host_choice - 1]
                    mac_address = selected_host.get('mac_address')
                    if mac_address:
                        app_logger.info(f"Intentando enviar WoL a '{selected_host.get('name', 'N/A')}' ({mac_address}).")
                        remote_control.send_wol_packet(mac_address)
                    else:
                        app_logger.error(f"El host '{selected_host.get('name', 'N/A')}' no tiene una dirección MAC guardada para WoL.")
                        print(f"Error: El host seleccionado no tiene una dirección MAC guardada.")
                else:
                    app_logger.warning(f"Número de host no válido para WoL: {host_choice}.")
                    print("Número de host no válido. Por favor, introduce un número de la lista.")
            except ValueError:
                app_logger.error("Entrada no válida para selección de host WoL. Se esperaba un número.")
                print("Entrada no válida. Por favor, introduce un NÚMERO.")

        elif choice == '3':
            # Apagar/Reiniciar equipo remoto
            print("\n--- Apagar/Reiniciar Equipo Remoto ---")
            if not display_hosts(hosts_inventory):
                app_logger.warning("Intento de apagado/reinicio sin hosts en el inventario.")
                continue

            try:
                host_choice = int(input("Introduce el NÚMERO del host a administrar: "))
                if 1 <= host_choice <= len(hosts_inventory):
                    selected_host = hosts_inventory[host_choice - 1]
                    ip_address = selected_host.get('ip_address')
                    username = selected_host.get('username')
                    password = selected_host.get('password')

                    if not (ip_address and username and password):
                        app_logger.error(f"El host '{selected_host.get('name', 'N/A')}' no tiene IP, usuario o contraseña completos para apagado/reinicio.")
                        print(f"Error: El host seleccionado no tiene IP, usuario o contraseña completos para esta operación.")
                        continue
                    
                    try:
                        ipaddress.ip_address(ip_address)
                    except ValueError:
                        app_logger.error(f"La IP '{ip_address}' del host '{selected_host.get('name', 'N/A')}' en el inventario no es válida.")
                        print(f"Error: La IP del host en el inventario no es válida.")
                        continue

                    action_choice = input(f"¿Quieres apagar (s) o reiniciar (r) '{selected_host['name']}'? ").strip().lower()
                    if action_choice in ['s', 'r']:
                        restart = True if action_choice == 'r' else False
                        app_logger.info(f"Intentando {'reiniciar' if restart else 'apagar'} '{selected_host['name']}' ({ip_address}).")
                        remote_control.remote_shutdown(ip_address, username, password, restart)
                    else:
                        app_logger.warning(f"Opción de acción no válida para apagado/reinicio: '{action_choice}'.")
                        print("Opción de acción no válida. Por favor, introduce 's' para apagar o 'r' para reiniciar.")
                else:
                    app_logger.warning(f"Número de host no válido para apagado/reinicio: {host_choice}.")
                    print("Número de host no válido. Por favor, introduce un número de la lista.")
            except ValueError:
                app_logger.error("Entrada no válida para selección de host (apagado/reinicio). Se esperaba un número.")
                print("Entrada no válida. Por favor, introduce un NÚMERO.")

        elif choice == '4':
            # Gestionar Inventario
            manage_inventory_menu(hosts_inventory)
            
        elif choice == '5':
            # Salir
            app_logger.info("Saliendo de IntraScan & Admin. ¡Hasta pronto!")
            print("Saliendo de IntraScan & Admin. ¡Hasta pronto!")
            sys.exit()

        else:
            app_logger.warning(f"Opción de menú principal no válida: '{choice}'.")
            print("Opción no válida. Por favor, elige un número del 1 al 5.")

if __name__ == "__main__":
    main_app()