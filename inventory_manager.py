# inventory_manager.py

import json
import os

HOSTS_FILE = "hosts.json"

def load_hosts():
   
    if not os.path.exists(HOSTS_FILE):
        with open(HOSTS_FILE, 'w') as f:
            json.dump([], f) # crear Json vacio
        return []
    
    with open(HOSTS_FILE, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            print(f"Advertencia: El archivo '{HOSTS_FILE}' está corrupto o vacío. Se iniciará un inventario vacío.")
            return []

def save_hosts(hosts):
    # guardar host
    with open(HOSTS_FILE, 'w') as f:
        json.dump(hosts, f, indent=4) 
    print(f"Inventario guardado en '{HOSTS_FILE}'.")

# test local solo
if __name__ == "__main__":
    print("--- Probando Inventory Manager ---")

    # Cargar hosts existentes
    current_hosts = load_hosts()
    print(f"\nHosts cargados: {current_hosts}")

    # Añadir un nuevo host (ejemplo)
    new_host = {
        "name": "NuevoPC",
        "ip_address": "192.168.1.200",
        "mac_address": "FF:EE:DD:CC:BB:AA",
        "username": "usuario_nuevo",
        "password": "pass_nueva"
    }
    current_hosts.append(new_host)
    print(f"\nHost añadido. Nueva lista: {current_hosts}")

    # Guardar los hosts
    save_hosts(current_hosts)

    # Volver a cargar para verificar
    reloaded_hosts = load_hosts()
    print(f"\nHosts recargados: {reloaded_hosts}")