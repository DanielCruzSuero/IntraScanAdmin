# main.py

# Importa< módulos y funciones, sys para sys.exit
import scanner
import remote_control
import sys 
import inventory_manager

def display_menu():
    # Menu principal
    def display_menu():
        print("\n--- IntraScan & Admin - Menú Principal ---")
        print("1. Escanear red")
        print("2. Encender equipo (Wake-on-LAN)")
        print("3. Apagar/Reiniciar equipo remoto")
        print("4. Gestionar Inventario de Hosts") 
        print("5. Salir")
        print("------------------------------------------")

# ... (tus imports y display_menu aquí) ...

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
    # Añadir nuevo host
    print("\n--- Añadir Nuevo Host ---")
    name = input("Nombre del host (ej. PC-Salon): ").strip()
    ip_address = input("Dirección IP (ej. 192.168.1.100): ").strip()
    mac_address = input("Dirección MAC (ej. AA:BB:CC:DD:EE:FF, opcional para WoL): ").strip()
    username = input("Usuario administrador para acceso remoto (opcional): ").strip()
    password = input("Contraseña del usuario administrador (opcional): ").strip()

    if not name or not ip_address:
        print("Nombre y dirección IP son obligatorios.")
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
    # Eliminar host
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
    # Menu de inventario
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
            break # Sale del sub-menú
        else:
            print("Opción no válida. Por favor, elige un número del 1 al 4.")



def main_app():
    # Inicio de bucle principal
    hosts_inventory = inventory_manager.load_hosts()
    while True:
        display_menu()
        choice = input("Elige una opción: ").strip()

        if choice == '1':
            # Opción 1: Escanear red
            print("\n--- Escanear Red ---")
            network_range = input("Introduce el rango de red a escanear (ej. 192.168.1.0/24): ").strip()
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

       
        elif choice == '2': # Encender equipo (Wake-on-LAN)
            print("\n--- Encender Equipo (Wake-on-LAN) ---")
            if not display_hosts(hosts_inventory):
                continue # Vuelve al menú si no hay hosts

            try:
                host_choice = int(input("Introduce el número del host a encender: "))
                if 1 <= host_choice <= len(hosts_inventory):
                    selected_host = hosts_inventory[host_choice - 1]
                    mac_address = selected_host.get('mac_address')
                    if mac_address:
                        remote_control.send_wol_packet(mac_address)
                    else:
                        print("El host seleccionado no tiene una dirección MAC guardada.")
                else:
                    print("Número de host no válido.")
            except ValueError:
                print("Entrada no válida. Por favor, introduce un número.")

        elif choice == '3': # Apagar/Reiniciar equipo remoto
            print("\n--- Apagar/Reiniciar Equipo Remoto ---")
            if not display_hosts(hosts_inventory):
                continue # Vuelve al menú si no hay hosts

            try:
                host_choice = int(input("Introduce el número del host a administrar: "))
                if 1 <= host_choice <= len(hosts_inventory):
                    selected_host = hosts_inventory[host_choice - 1]
                    ip_address = selected_host.get('ip_address')
                    username = selected_host.get('username')
                    password = selected_host.get('password')

                    if not (ip_address and username and password):
                        print("El host seleccionado no tiene IP, usuario o contraseña completos para esta operación.")
                        continue

                    action_choice = input(f"¿Quieres apagar (s) o reiniciar (r) '{selected_host['name']}'? ").strip().lower()
                    if action_choice in ['s', 'r']:
                        restart = True if action_choice == 'r' else False
                        remote_control.remote_shutdown(ip_address, username, password, restart)
                    else:
                        print("Opción de acción no válida.")
                else:
                    print("Número de host no válido.")
            except ValueError:
                print("Entrada no válida. Por favor, introduce un número.")

        elif choice == '4': # Opción de Gestionar Inventario
            manage_inventory_menu(hosts_inventory) # Llama al nuevo sub-menú

        elif choice == '5': # Opción de Salir (cambia de número)
            print("Saliendo de IntraScan & Admin. ¡Hasta pronto!")
            sys.exit()

        else:
            print("Opción no válida. Por favor, elige un número del 1 al 4.")

# Solo ejecucion
if __name__ == "__main__":
    main_app()