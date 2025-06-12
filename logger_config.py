# logger_config.py

import logging
import os
from datetime import datetime

# Define la ruta del directorio de logs y el nombre del archivo de log
LOG_DIR = "logs"
# Nombre del archivo de log con fecha actual (ej. app_2024-06-12.log)
LOG_FILE = os.path.join(LOG_DIR, f"app_{datetime.now().strftime('%Y-%m-%d')}.log")

def setup_logging():
    """
    Configura el sistema de logging para la aplicación.
    Los logs se guardarán en un archivo y también se mostrarán en la consola.
    """
    # Crear el directorio de logs si no existe
    os.makedirs(LOG_DIR, exist_ok=True)

    # Nivel de log global (DEBUG para desarrollo, INFO para producción)
    logging.basicConfig(
        level=logging.INFO, # Cambiar a DEBUG para ver mensajes más detallados
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE, encoding='utf-8'), # Guardar logs en un archivo
            logging.StreamHandler() # Mostrar logs también en la consola
        ]
    )

    # Puedes obtener un logger específico para tu aplicación
    logger = logging.getLogger('IntraScanAdmin')
    logger.info("Sistema de logging configurado.")
    return logger

# Este bloque se ejecutará una vez cuando se importe el módulo
app_logger = setup_logging()

# Ejemplo de cómo usar el logger en este mismo archivo si fuera necesario
if __name__ == "__main__":
    app_logger.info("Este es un mensaje de información desde logger_config.")
    app_logger.warning("Esta es una advertencia desde logger_config.")
    app_logger.error("Este es un mensaje de error desde logger_config.")
    try:
        1 / 0
    except ZeroDivisionError:
        app_logger.exception("Se produjo una excepción de división por cero desde logger_config.")