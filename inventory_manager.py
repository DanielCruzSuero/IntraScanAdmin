# inventory_manager.py

import json
import os
from logger_config import app_logger # Importa el logger

HOSTS_FILE = "hosts.json"

def load_hosts():
    """
    Carga la lista de hosts desde el archivo JSON.
    Crea un archivo vacío si no existe.
    :return: Una lista de diccionarios, cada uno representando un host.
    """
    if not os.path.exists(HOSTS_FILE):
        app_logger.info(f"El archivo de inventario '{HOSTS_FILE}' no existe. Creando uno vacío.")
        with open(HOSTS_FILE, 'w') as f:
            json.dump([], f)
        return []
    
    with open(HOSTS_FILE, 'r') as f:
        try:
            hosts = json.load(f)
            app_logger.info(f"Inventario cargado desde '{HOSTS_FILE}'. {len(hosts)} hosts encontrados.")
            return hosts
        except json.JSONDecodeError:
            app_logger.warning(f"Advertencia: El archivo '{HOSTS_FILE}' está corrupto o vacío. Se iniciará un inventario vacío.")
            return []
        except Exception as e:
            app_logger.exception(f"Error inesperado al cargar el inventario desde '{HOSTS_FILE}'.")
            return []

def save_hosts(hosts):
    """
    Guarda la lista actual de hosts en el archivo JSON.
    :param hosts: La lista de diccionarios de hosts a guardar.
    """
    try:
        with open(HOSTS_FILE, 'w') as f:
            json.dump(hosts, f, indent=4)
        app_logger.info(f"Inventario guardado en '{HOSTS_FILE}'. {len(hosts)} hosts.")
        return True
    except Exception as e:
        app_logger.exception(f"Error inesperado al guardar el inventario en '{HOSTS_FILE}'.")
        return False

# Ejemplo de uso (esto no es necesario en el archivo final para el proyecto, es solo para probar el módulo)
if __name__ == "__main__":
    app_logger.info("--- Probando Inventory Manager (Directo) ---")

    current_hosts = load_hosts()
    app_logger.info(f"Hosts cargados para la prueba: {current_hosts}")

    new_host = {
        "name": "PC-Prueba",
        "ip_address": "192.168.1.200",
        "mac_address": "FF:EE:DD:CC:BB:AA",
        "username": "usuario_prueba",
        "password": "pass_prueba"
    }
    current_hosts.append(new_host)
    app_logger.info(f"Host añadido para la prueba. Nueva lista: {current_hosts}")

    save_hosts(current_hosts)

    reloaded_hosts = load_hosts()
    app_logger.info(f"Hosts recargados para la prueba: {reloaded_hosts}")
    app_logger.info("Prueba de Inventory Manager completada.")