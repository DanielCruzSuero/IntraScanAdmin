# inventory_manager.py

import json
import os
from logger_config import app_logger # Importa el logger

INVENTORY_FILE = "hosts.json"

def load_hosts():
    """Carga la lista de hosts desde el archivo JSON."""
    if not os.path.exists(INVENTORY_FILE):
        app_logger.warning(f"Archivo de inventario '{INVENTORY_FILE}' no encontrado. Creando uno vacío.")
        with open(INVENTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump([], f, indent=4) # Crea un archivo JSON vacío con una lista vacía
        return []
    
    try:
        with open(INVENTORY_FILE, 'r', encoding='utf-8') as f:
            hosts = json.load(f)
            # Asegurarse de que hosts es una lista
            if not isinstance(hosts, list):
                app_logger.error(f"El archivo '{INVENTORY_FILE}' no contiene una lista JSON. Recreando archivo.")
                save_hosts([]) # Guardar un archivo vacío y devolver una lista vacía
                return []
            app_logger.info(f"Inventario cargado desde '{INVENTORY_FILE}'.")
            return hosts
    except json.JSONDecodeError as e:
        app_logger.error(f"Error al decodificar JSON de '{INVENTORY_FILE}': {e}. El archivo puede estar corrupto. Recreando archivo.")
        save_hosts([]) # Guardar un archivo vacío y devolver una lista vacía
        return []
    except Exception as e:
        app_logger.error(f"Error inesperado al cargar inventario: {e}. Recreando archivo.")
        save_hosts([]) # Guardar un archivo vacío y devolver una lista vacía
        return []

def save_hosts(hosts):
    """Guarda la lista de hosts en el archivo JSON."""
    try:
        with open(INVENTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(hosts, f, indent=4) # Guarda la lista de diccionarios
        app_logger.info(f"Inventario guardado en '{INVENTORY_FILE}'.")
    except Exception as e:
        app_logger.error(f"Error al guardar inventario en '{INVENTORY_FILE}': {e}")

# No necesitamos funciones de añadir/editar/eliminar aquí directamente,
# ya que la GUI gestionará la lista self.hosts_inventory y luego la guardará.
# Estas serían funciones si el inventory_manager fuera una clase o si se usara sin GUI.