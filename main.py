# main.py

# Importa tus módulos y funciones
import scanner
import remote_control
import sys # Para sys.exit()

def display_menu():
    # Menu principal
    print("\n--- IntraScan & Admin - Menú Principal ---")
    print("1. Escanear red")
    print("2. Encender equipo (Wake-on-LAN)")
    print("3. Apagar/Reiniciar equipo remoto")
    print("4. Salir")
    print("------------------------------------------")

def main_app():
    # Inicio de bucle principal
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

        elif choice == '2':
            # Opción 2: Encender equipo (Wake-on-LAN)
            print("\n--- Encender Equipo (Wake-on-LAN) ---")
            mac_address = input("Introduce la dirección MAC del equipo a encender (ej. AA:BB:CC:DD:EE:FF): ").strip()
            if mac_address:
                remote_control.send_wol_packet(mac_address)
            else:
                print("Dirección MAC no válida.")

        elif choice == '3':
            # Opción 3: Apagar/Reiniciar equipo remoto
            print("\n--- Apagar/Reiniciar Equipo Remoto ---")
            ip_address = input("Introduce la dirección IP del equipo: ").strip()
            username = input("Introduce el nombre de usuario administrador en el equipo remoto: ").strip()
            password = input("Introduce la contraseña del usuario remoto: ").strip()
            action_choice = input("¿Quieres apagar (s) o reiniciar (r) el equipo? ").strip().lower()

            if ip_address and username and password:
                restart = True if action_choice == 'r' else False
                remote_control.remote_shutdown(ip_address, username, password, restart)
            else:
                print("IP, usuario o contraseña no válidos.")

        elif choice == '4':
            # Opción 4: Salir
            print("Saliendo de IntraScan & Admin. ¡Hasta pronto!")
            sys.exit() # Sale del programa

        else:
            print("Opción no válida. Por favor, elige un número del 1 al 4.")

# Solo ejecucion
if __name__ == "__main__":
    main_app()