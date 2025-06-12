# main.py

import scanner
import remote_control
import inventory_manager
import sys
import ipaddress # Importar para validación de IP

def display_menu():
    """Muestra el menú principal de opciones al usuario."""
    print("\n--- IntraScan & Admin - Menú Principal ---")
    print("1. Escanear red")
    print("2. Encender equipo (Wake-on-LAN)")
    print("3. Apagar/Reiniciar equipo remoto")
    print("4. Gestionar Inventario de Hosts")
    print("5. Salir")
    print("------------------------------------------")

# --- Funciones de Gestión de Inventario (ya las tienes, pero aquí las incluimos para contexto) ---
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

    # Validación básica de IP
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        print("Error: La dirección IP introducida no es válida.")
        return

    if not name: # El nombre es crucial para identificar en el inventario
        print("Nombre del host es obligatorio.")
        return

    new_host = {
        "name": name,
        "ip_address": ip_address,
        "mac_address": mac_address,
        "username": username,
        "password": password
    }
    hosts.append(new_host)
    inventory_manager.save_hosts(hosts)
    print(f"Host '{name}' añadido al inventario.")

def delete_host(hosts):
    """Permite al usuario eliminar un host del inventario."""
    if not display_hosts(hosts):
        return

    try:
        choice = int(input("Introduce el número del host a eliminar: "))
        if 1 <= choice <= len(hosts):
            removed_host = hosts.pop(choice - 1)
            inventory_manager.save_hosts(hosts)
            print(f"Host '{removed_host.get('name', 'N/A')}' eliminado del inventario.")
        else:
            print("Número de host no válido.")
    except ValueError:
        print("Entrada no válida. Por favor, introduce un número.")

def manage_inventory_menu(hosts):
    """Sub-menú para gestionar el inventario."""
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
        elif choice == '2':
            add_host(hosts)
        elif choice == '3':
            delete_host(hosts)
        elif choice == '4':
            break
        else:
            print("Opción no válida. Por favor, elige un número del 1 al 4.")


def main_app():
    """Bucle principal de la aplicación CLI."""
    hosts_inventory = inventory_manager.load_hosts() # Carga los hosts al inicio

    while True:
        display_menu()
        choice = input("Elige una opción: ").strip()

        if choice == '1':
            # Escanear red
            print("\n--- Escanear Red ---")
            network_range = input("Introduce el rango de red a escanear (ej. 192.168.1.0/24): ").strip()
            
            # Validación del rango de red
            try:
                ipaddress.ip_network(network_range, strict=False) # Valida el formato CIDR
            except ValueError:
                print("Error: El rango de red introducido no es un formato CIDR válido (ej. 192.168.1.0/24).")
                continue # Vuelve al menú principal

            if network_range:
                online_hosts = scanner.scan_network(network_range)
                print("\n--- Resumen del Escaneo ---")
                if online_hosts:
                    print("Se encontraron los siguientes hosts en línea:")
                    for host in online_hosts:
                        print(f"- {host}")
                else:
                    print("No se encontraron hosts en línea en el rango especificado.")
            else:
                print("Rango de red no válido. Por favor, inténtalo de nuevo.")

        elif choice == '2':
            # Encender equipo (Wake-on-LAN)
            print("\n--- Encender Equipo (Wake-on-LAN) ---")
            if not display_hosts(hosts_inventory):
                continue
            
            try:
                host_choice = int(input("Introduce el NÚMERO del host a encender: "))
                if 1 <= host_choice <= len(hosts_inventory):
                    selected_host = hosts_inventory[host_choice - 1]
                    mac_address = selected_host.get('mac_address')
                    if mac_address:
                        remote_control.send_wol_packet(mac_address)
                    else:
                        print(f"Error: El host '{selected_host.get('name', 'N/A')}' no tiene una dirección MAC guardada.")
                else:
                    print("Número de host no válido. Por favor, introduce un número de la lista.")
            except ValueError:
                print("Entrada no válida. Por favor, introduce un NÚMERO.")

        elif choice == '3':
            # Apagar/Reiniciar equipo remoto
            print("\n--- Apagar/Reiniciar Equipo Remoto ---")
            if not display_hosts(hosts_inventory):
                continue

            try:
                host_choice = int(input("Introduce el NÚMERO del host a administrar: "))
                if 1 <= host_choice <= len(hosts_inventory):
                    selected_host = hosts_inventory[host_choice - 1]
                    ip_address = selected_host.get('ip_address')
                    username = selected_host.get('username')
                    password = selected_host.get('password')

                    # Validar que todos los campos necesarios existan
                    if not (ip_address and username and password):
                        print(f"Error: El host '{selected_host.get('name', 'N/A')}' no tiene IP, usuario o contraseña completos para esta operación.")
                        continue
                    
                    # Validación básica de IP antes de intentar apagar
                    try:
                        ipaddress.ip_address(ip_address)
                    except ValueError:
                        print(f"Error: La IP '{ip_address}' del host '{selected_host.get('name', 'N/A')}' en el inventario no es válida.")
                        continue

                    action_choice = input(f"¿Quieres apagar (s) o reiniciar (r) '{selected_host['name']}'? ").strip().lower()
                    if action_choice in ['s', 'r']:
                        restart = True if action_choice == 'r' else False
                        remote_control.remote_shutdown(ip_address, username, password, restart)
                    else:
                        print("Opción de acción no válida. Por favor, introduce 's' para apagar o 'r' para reiniciar.")
                else:
                    print("Número de host no válido. Por favor, introduce un número de la lista.")
            except ValueError:
                print("Entrada no válida. Por favor, introduce un NÚMERO.")

        elif choice == '4':
            # Gestionar Inventario
            manage_inventory_menu(hosts_inventory)
            
        elif choice == '5':
            # Salir
            print("Saliendo de IntraScan & Admin. ¡Hasta pronto!")
            sys.exit()

        else:
            print("Opción no válida. Por favor, elige un número del 1 al 5.")

if __name__ == "__main__":
    main_app()