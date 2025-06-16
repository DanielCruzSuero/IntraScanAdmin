import tkinter as tk
from tkinter import ttk, messagebox
import queue
import threading
import time
import logging
import json
from tkinter import scrolledtext
import inventory_manager # <-- Asegúrate de que esta línea esté presente
from logger_config import app_logger # <-- Si tienes logger_config.py
import os
import subprocess
from multiprocessing import Process, Queue, Event
import time
import scanner_worker
import traceback
import sys

# --- 1. Configuración del Sistema de Logging (Única vez) ---
# Aseguramos que el logger se configure una sola vez, incluso si el módulo se importa varias veces.
app_logger = logging.getLogger('IntraScanAdmin')
app_logger.setLevel(logging.INFO)

# SOLO configura los handlers si no están ya configurados
if not app_logger.handlers:
    # Handler para la consola
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    app_logger.addHandler(console_handler)

    # Handler para archivo (opcional, si quieres guardar logs en un archivo)
    # file_handler = logging.FileHandler('intrascan_admin.log')
    # file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    # app_logger.addHandler(file_handler)

    app_logger.info("Sistema de logging configurado.")

# --- 2. Asumimos la existencia de inventory_manager.py ---
# Por ahora, simularemos algunas funciones básicas si no tienes el archivo todavía.
# Si ya tienes tu inventory_manager.py funcionando, ASEGÚRATE de importarlo.

try:
    import inventory_manager
    app_logger.info("Módulo 'inventory_manager.py' cargado exitosamente.")
except ImportError:
    app_logger.warning("No se encontró 'inventory_manager.py'. Usando funciones de inventario simuladas.")
    # --- SIMULACIÓN BÁSICA DE inventory_manager SI NO EXISTE EL ARCHIVO ---
    # Esto es solo para que la GUI no falle si no tienes inventory_manager.py aún.
    # En un proyecto real, esto debería estar en un archivo separado y más robusto.
   

# --- 3. Definición de la Clase Principal de la GUI ---
class IntraScanAdminGUI:
    def __init__(self, master):
        self.master = master
        master.title("IntraScan & Admin GUI")
        master.geometry("1200x800")
        master.resizable(True, True)

        self.style = ttk.Style()
        self.style.theme_use('clam')

         # --- 1. Configuración de Logging y Colas de Comunicación ---
        self.log_queue = Queue() # multiprocessing.Queue para logs que cruzan procesos
        self.log_handler = self.QueueHandler(self.log_queue) 
        
        self.logger = logging.getLogger('IntraScanAdmin')
        self.logger.setLevel(logging.DEBUG) 
        
        if not self.logger.handlers: # Asegurarse de que el handler solo se añade una vez
            self.logger.addHandler(self.log_handler)
            self.logger.addHandler(logging.StreamHandler(sys.stdout)) # <-- ¡IMPORTANTE para ver en consola!
        
        self.create_log_console(master) 
        self.log_message("Aplicación Iniciada.", logging.INFO)
        # --- AÑADE ESTA LÍNEA DE PRUEBA ---
        self.log_message("DEBUG: Este es un mensaje de prueba para el registro de actividad.", logging.DEBUG)
        # ---------------------------------


        # Cola para resultados del escaneo de red (desde el proceso worker de Scapy a la GUI)
        self.scan_output_queue = Queue() # multiprocessing.Queue

        # Evento para detener el proceso de escaneo del worker
        self.stop_event = Event() # multiprocessing.Event

        # Proceso del worker de escaneo
        self.scan_process = None 
        # Bandera para indicar si un escaneo está activo (para el polling de la GUI)
        self.scan_thread_running = False 

        # Colas para otras funcionalidades (si las usas)
        # self.scan_queue = queue.Queue() # Puedes mantenerla si la usas para hilos NO-Scapy
        self.remote_command_queue = queue.Queue() # Para comandos remotos

        # Variables para la gestión del inventario
        self.hosts_inventory = inventory_manager.load_hosts()
        self.current_selected_host_id = None 

        # --- 2. Configuración de la Interfaz (Notebook y Pestañas) ---
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(pady=10, expand=True, fill="both")
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change) # Vincular evento de cambio de pestaña

        self.scan_tab = ttk.Frame(self.notebook)
        self.remote_tab = ttk.Frame(self.notebook)
        self.inventory_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.scan_tab, text="Escaneo de Red")
        self.notebook.add(self.remote_tab, text="Control Remoto")
        self.notebook.add(self.inventory_tab, text="Gestión de Inventario")

        # --- 3. Creación de Widgets de Cada Pestaña ---
        # Estos métodos deben existir en tu clase
        self.create_scan_tab_widgets(self.scan_tab)
        self.create_remote_tab_widgets(self.remote_tab)
        self.create_inventory_tab_widgets(self.inventory_tab)
        
        # Limpiar y cargar el inventario inicial
        self.clear_inventory_entries() 
        self.log_message(f"Inventario cargado al inicio: {len(self.hosts_inventory)} hosts.", logging.INFO)
        self._load_inventory_into_tree() 

        # Iniciar el procesamiento de colas usando .after (para el hilo principal de la GUI)
        self.master.after(100, self._check_gui_queue) 
        self.master.after(100, self.process_log_queue) 
        self.master.after(100, self.process_remote_command_queue)
        self.log_message("DEBUG: Llamada inicial a _check_gui_queue programada.", logging.DEBUG) 
        self.log_message("DEBUG: Llamada inicial a process_log_queue programada.", logging.DEBUG) 

    class QueueHandler(logging.Handler):
        def __init__(self, log_queue):
            super().__init__()
            self.log_queue = log_queue
            # Asegúrate de que un formateador se establece aquí
            # O asegúrate de que el handler global de logger tiene uno que este usará.
            # Es más seguro establecerlo aquí:
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            self.setFormatter(formatter)

        def emit(self, record):
            # Formatea el registro antes de ponerlo en la cola.
            # Opcional, pero puede ayudar si el receptor no tiene un formateador.
            # Sin embargo, el record ya contiene los atributos formateados por el logger global
            # si los has configurado así. Mejor poner el record crudo y formatear en el otro lado
            # como lo haces en process_log_queue.
            # Así que, por ahora, solo asegúrate que el self.setFormatter(formatter) está en __init__
            self.log_queue.put(record)

    def create_log_console(self, parent_frame):
        """
        Crea el área de texto para mostrar los logs de la aplicación.
        """
        log_frame = ttk.LabelFrame(parent_frame, text="Registro de Actividad", padding="10")
        log_frame.pack(side="bottom", fill="x", padx=10, pady=10) # Colocar abajo

        # Asegúrate de que self.log_text es un tk.Text widget y está accesible
        self.log_text = tk.Text(log_frame, wrap="word", state="disabled", height=10, width=80, bg="black", fg="white", font=("Courier New", 9))
        self.log_text.pack(side="left", fill="both", expand=True)

        log_scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        log_scrollbar.pack(side="right", fill="y")
        self.log_text.config(yscrollcommand=log_scrollbar.set)
        
        self.logger.info("Sistema de logging configurado.")

    def poll_log_queue(self):
        # Este método lee de self.log_queue y escribe en self.log_text
        while True:
            try:
                record = self.log_queue.get(block=False)
                msg = self.log_handler.format(record) # Usa el handler para formatear
                self.log_text.config(state='normal')
                self.log_text.insert(tk.END, msg + '\n')
                self.log_text.yview(tk.END)
                self.log_text.config(state='disabled')
            except queue.Empty:
                break
            except Exception as e:
                # Esto es importante para depurar errores en el propio log_queue
                self.logger.error(f"Error procesando cola de logs en GUI: {e}") 
                break
        self.master.after(100, self.poll_log_queue)

    def log_message(self, message, level=logging.INFO):
        # Simplificado, ya que el self.logger ya tiene el QueueHandler adjunto
        self.logger.log(level, message)


    def setup_logging(self):
        """
        Configura el sistema de logging para la aplicación.
        Crea un archivo de log y configura el nivel de logging.
        """
        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        log_file = os.path.join(log_dir, "intrascan_admin.log")

        # Configura el logger principal
        self.logger = logging.getLogger("IntraScanAdmin")
        self.logger.setLevel(logging.DEBUG) # Puedes ajustar el nivel de logging aquí (DEBUG, INFO, WARNING, ERROR)

        # Evitar añadir múltiples handlers si ya existen
        if not self.logger.handlers:
            # Handler para archivo
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)

            # Handler para consola (opcional, útil para depuración)
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO) # Nivel para la consola
            console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)

    def log_message(self, message, level=logging.INFO):
        """
        Envía un mensaje al logger configurado.
        """
        if hasattr(self, 'logger'):
            if level == logging.DEBUG:
                self.logger.debug(message)
            elif level == logging.INFO:
                self.logger.info(message)
            elif level == logging.WARNING:
                self.logger.warning(message)
            elif level == logging.ERROR:
                self.logger.error(message)
            elif level == logging.CRITICAL:
                self.logger.critical(message)
        else:
            # Fallback si el logger no está configurado (debería llamarse setup_logging primero)
            print(f"[{logging.getLevelName(level)}] (Pre-logger) {message}")


    # --- Métodos Auxiliares Comunes ---
    def log_message(self, message, level=logging.INFO):
        """Muestra mensajes en la caja de texto del log y en la consola."""
        app_logger.log(level, message) # También envía al logger configurado

    def redirect_logger_output(self):
        """Redirige los mensajes del logger a la caja de texto de la GUI."""
        class TextHandler(logging.Handler):
            def __init__(self, text_widget):
                super().__init__()
                self.text_widget = text_widget
                self.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

            def emit(self, record):
                msg = self.format(record)
                self.text_widget.configure(state='normal')
                self.text_widget.insert(tk.END, msg + '\n')
                self.text_widget.see(tk.END)
                self.text_widget.configure(state='disabled')

        text_handler = TextHandler(self.log_text)
        # Asegurarse de no añadir el handler varias veces si la GUI se recrea
        if not any(isinstance(h, TextHandler) for h in app_logger.handlers):
             app_logger.addHandler(text_handler)


    def on_tab_change(self, event):
        """Maneja los eventos de cambio de pestaña."""
        selected_tab_id = self.notebook.select()
        selected_tab_text = self.notebook.tab(selected_tab_id, "text")
        self.log_message(f"Cambiado a la pestaña: {selected_tab_text}")

        # Puedes añadir lógica específica aquí para cada pestaña si es necesario.
        # Por ejemplo, para refrescar el inventario si cambias a esa pestaña.
        if selected_tab_text == "Gestión de Inventario":
            # Recarga la lista de hosts desde el manager y refresca el Treeview
            self.hosts_inventory = inventory_manager.load_hosts()
            self._load_inventory_into_tree()
            self.populate_remote_host_dropdown() # Asegura que el desplegable de remotos esté actualizado
            self.log_message("Inventario refrescado desde la base de datos.")


    # --- Métodos de Procesamiento de Colas (para Operaciones Asíncronas) ---
    def process_scan_queue(self):
        """Procesa los resultados del escaneo que llegan a la cola."""
        try:
            while True:
                item = self.scan_queue.get_nowait()
                # item debería ser un diccionario con tipo y datos
                item_type = item.get('type')
                item_data = item.get('data')

                if item_type == 'scan_result':
                    ip = item_data.get('ip')
                    hostname = item_data.get('hostname')
                    status = item_data.get('status')
                    # Añadir al Treeview de resultados de escaneo (self.scan_results_tree)
                    if hasattr(self, 'scan_results_tree'):
                         self.scan_results_tree.insert('', tk.END, values=(ip, hostname, status))
                         self.log_message(f"Escaneo: {ip} - {hostname} ({status})")
                elif item_type == 'scan_progress':
                    self.log_message(f"Progreso del escaneo: {item_data}")
                    # Actualizar una barra de progreso, si tienes una
                elif item_type == 'scan_finished':
                    self.log_message(f"Escaneo de red completado: {item_data.get('message', 'Éxito')}")
                    # Habilitar botones, etc.
                else:
                    self.log_message(f"Mensaje desconocido en cola de escaneo: {item_type}", logging.WARNING)

        except queue.Empty:
            pass # No hay elementos en la cola por ahora
        finally:
            self.master.after(100, self.process_scan_queue) # Volver a revisar en 100ms


    def process_remote_command_queue(self):
        """Procesa los resultados de comandos remotos que llegan a la cola."""
        try:
            while True:
                item = self.remote_command_queue.get_nowait()
                item_type = item.get('type')
                item_data = item.get('data')

                if item_type == 'command_output':
                    target = item_data.get('target', 'N/A')
                    output = item_data.get('output', '')
                    self.log_message(f"Comando remoto en {target}:\n{output}")
                elif item_type == 'command_error':
                    target = item_data.get('target', 'N/A')
                    error = item_data.get('error', '')
                    self.log_message(f"Error remoto en {target}: {error}", logging.ERROR)
                elif item_type == 'remote_status':
                    self.log_message(f"Estado remoto: {item_data.get('message', 'N/A')}")
                else:
                    self.log_message(f"Mensaje desconocido en cola de comandos remotos: {item_type}", logging.WARNING)
        except queue.Empty:
            pass
        finally:
            self.master.after(100, self.process_remote_command_queue)


   
    def create_scan_tab_widgets(self, parent_frame):
        """
        Crea y organiza los widgets para la pestaña 'Escaneo de Red'.
        Incluye campos para rango IP, opciones de escaneo y un área de resultados.
        """
        scan_main_frame = ttk.Frame(parent_frame, padding="10")
        scan_main_frame.pack(expand=True, fill="both")

        # --- Sección de Opciones de Escaneo ---
        options_frame = ttk.LabelFrame(scan_main_frame, text="Opciones de Escaneo", padding="10")
        options_frame.pack(pady=10, padx=10, fill="x")

        # Rango de IP
        ttk.Label(options_frame, text="Rango de IP (ej. 192.168.1.0/24):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.ip_range_var = tk.StringVar(value="192.168.1.0/24") # Valor por defecto
        self.ip_range_entry = ttk.Entry(options_frame, textvariable=self.ip_range_var, width=40)
        self.ip_range_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        # Botón para iniciar escaneo
        self.start_scan_button = ttk.Button(options_frame, text="Iniciar Escaneo", command=self.start_scan)
        self.start_scan_button.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        # Botón para detener escaneo
        self.stop_scan_button = ttk.Button(options_frame, text="Detener Escaneo", command=self.stop_scan)
        self.stop_scan_button.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        self.stop_scan_button.config(state="disabled") # Deshabilitado por defecto

        # Configurar las columnas para que se expandan
        options_frame.columnconfigure(1, weight=1)

        # --- Sección de Resultados del Escaneo (Treeview) ---
        results_frame = ttk.LabelFrame(scan_main_frame, text="Resultados del Escaneo", padding="10")
        results_frame.pack(pady=10, padx=10, expand=True, fill="both")

        # Columnas para el Treeview de resultados de escaneo
        # ESTO DEBE SER EXACTAMENTE ASÍ, INCLUYENDO "MAC"
        scan_columns = ("IP", "Hostname", "MAC", "Estado", "Puertos Abiertos", "OS Detectado") 
        
        self.scan_results_tree = ttk.Treeview(results_frame, columns=scan_columns, show="headings")

        # Definir los encabezados y sus propiedades. El orden importa aquí también.
        # He añadido 'stretch' a la configuración de cada columna
        column_configs = {
            "IP": {"text": "Dirección IP", "width": 100, "anchor": "w", "stretch": tk.NO},
            "Hostname": {"text": "Nombre de Host", "width": 150, "anchor": "w", "stretch": tk.YES},
            "MAC": {"text": "Dirección MAC", "width": 120, "anchor": "w", "stretch": tk.NO}, # Aumentado ligeramente el ancho
            "Estado": {"text": "Estado", "width": 80, "anchor": "center", "stretch": tk.NO},
            "Puertos Abiertos": {"text": "Puertos Abiertos", "width": 200, "anchor": "w", "stretch": tk.YES}, # Aumentado el ancho
            "OS Detectado": {"text": "Sistema Operativo", "width": 150, "anchor": "w", "stretch": tk.YES}, # Aumentado el ancho
        }

        for col_name, config in column_configs.items():
            self.scan_results_tree.heading(col_name, text=config["text"], anchor=config["anchor"])
            # AHORA INCLUYE 'stretch'
            self.scan_results_tree.column(col_name, width=config["width"], anchor=config["anchor"], stretch=config["stretch"])
            
        # Añadir scrollbars al Treeview de escaneo
        scan_tree_scroll_y = ttk.Scrollbar(results_frame, orient="vertical", command=self.scan_results_tree.yview)
        scan_tree_scroll_y.pack(side="right", fill="y")
        self.scan_results_tree.configure(yscrollcommand=scan_tree_scroll_y.set)

        scan_tree_scroll_x = ttk.Scrollbar(results_frame, orient="horizontal", command=self.scan_results_tree.xview)
        scan_tree_scroll_x.pack(side="bottom", fill="x")
        self.scan_results_tree.configure(xscrollcommand=scan_tree_scroll_x.set)

        self.scan_results_tree.pack(expand=True, fill="both")

        # Botón para añadir hosts seleccionados al inventario
        self.add_scanned_to_inventory_button = ttk.Button(results_frame, text="Añadir Seleccionados al Inventario", command=self.add_scanned_hosts_to_inventory)
        self.add_scanned_to_inventory_button.pack(pady=5)
        self.add_scanned_to_inventory_button.config(state="disabled") # Deshabilitado hasta que haya resultados

        self.logger.info("Widgets de la pestaña 'Escaneo de Red' creados y organizados.")

    def create_remote_tab_widgets(self, parent_frame):
        # Este método será llenado con los widgets de control remoto.
        # Por ahora, solo un mensaje para confirmar que se llama.
        ttk.Label(parent_frame, text="Contenido de Control Remoto (Se rellenará en el siguiente paso)").pack(pady=20)
        # Necesitamos un Dropdown para los hosts remotos que se poblará desde el inventario
        self.remote_host_selection_var = tk.StringVar(parent_frame)
        self.remote_host_selection_var.set("Seleccionar Host") # Valor por defecto
        self.remote_host_dropdown = ttk.OptionMenu(parent_frame, self.remote_host_selection_var, "Seleccionar Host")
        self.remote_host_dropdown.pack_forget() # Ocultarlo hasta que tenga datos

        app_logger.info("Placeholder de la pestaña de control remoto creado.")


    def create_inventory_tab_widgets(self, parent_frame):
        """
        Crea y organiza los widgets para la pestaña 'Gestión de Inventario'.
        Incluye el formulario de entrada, botones de acción y el Treeview.
        """
        # --- Marco Principal de Inventario ---
        inventory_main_frame = ttk.Frame(parent_frame, padding="10")
        inventory_main_frame.pack(expand=True, fill="both")

        # --- Sección de Formulario de Entrada (Input Form) ---
        input_form_frame = ttk.LabelFrame(inventory_main_frame, text="Datos del Host", padding="10")
        input_form_frame.pack(pady=10, padx=10, fill="x")

        # Configuración de columnas para el grid (ajusta anchos si es necesario)
        input_form_frame.columnconfigure(0, weight=1) # Etiquetas
        input_form_frame.columnconfigure(1, weight=3) # Entradas
        input_form_frame.columnconfigure(2, weight=1) # Etiquetas
        input_form_frame.columnconfigure(3, weight=3) # Entradas

        # Definición de los Entry widgets y sus etiquetas
        # Usamos StringVars para una gestión más fácil de los datos
        self.inventory_ip_var = tk.StringVar()
        self.inventory_hostname_var = tk.StringVar()
        self.inventory_mac_var = tk.StringVar()
        self.inventory_os_var = tk.StringVar()
        self.inventory_desc_var = tk.StringVar()
        self.inventory_brand_var = tk.StringVar()
        self.inventory_model_var = tk.StringVar()
        self.inventory_processor_var = tk.StringVar()
        self.inventory_memory_var = tk.StringVar()
        self.inventory_disks_var = tk.StringVar()
        self.inventory_graphics_var = tk.StringVar()
        self.inventory_display_var = tk.StringVar()
        self.inventory_network_point_var = tk.StringVar()
        self.inventory_cable_length_var = tk.StringVar()
        self.inventory_office_var = tk.StringVar()
        self.inventory_user_var = tk.StringVar()
        self.inventory_department_var = tk.StringVar()
        self.inventory_floor_var = tk.StringVar()

        # Mapeo de etiquetas y variables para facilitar la creación de widgets
        # Este orden también se usará para el rellenado desde el Treeview
        # Asegúrate de que las claves de los diccionarios de host coincidan con los 'id' de _load_inventory_into_tree
        form_fields = [
            ("IP:", self.inventory_ip_var, 0, 0),
            ("Hostname:", self.inventory_hostname_var, 0, 2),
            ("MAC Address:", self.inventory_mac_var, 1, 0),
            ("Sistema Operativo:", self.inventory_os_var, 1, 2),
            ("Description:", self.inventory_desc_var, 2, 0),
            ("Marca:", self.inventory_brand_var, 2, 2),
            ("Modelo:", self.inventory_model_var, 3, 0),
            ("Procesador:", self.inventory_processor_var, 3, 2),
            ("Memoria:", self.inventory_memory_var, 4, 0),
            ("Discos:", self.inventory_disks_var, 4, 2),
            ("Gráfica:", self.inventory_graphics_var, 5, 0),
            ("Pantalla(s):", self.inventory_display_var, 5, 2),
            ("Punto de Red:", self.inventory_network_point_var, 6, 0),
            ("Long. Cable UTP:", self.inventory_cable_length_var, 6, 2),
            ("Despacho:", self.inventory_office_var, 7, 0),
            ("Usuario:", self.inventory_user_var, 7, 2),
            ("Departamento:", self.inventory_department_var, 8, 0),
            ("Planta:", self.inventory_floor_var, 8, 2),
        ]

        # Creación de los Entry widgets (usando los StringVars)
        # También creamos referencias directas a los Entry widgets para clear_inventory_entries
        self.entry_widgets_list = []
        for i, (label_text, var, row, col) in enumerate(form_fields):
            ttk.Label(input_form_frame, text=label_text).grid(row=row, column=col, padx=5, pady=2, sticky="w")
            entry = ttk.Entry(input_form_frame, textvariable=var, width=30)
            entry.grid(row=row, column=col + 1, padx=5, pady=2, sticky="ew")
            self.entry_widgets_list.append(entry) # Guarda la referencia al widget Entry

        # Asignar los Entry widgets directamente a self.inventory_xxx_entry para compatibilidad
        # con on_inventory_select y clear_inventory_entries (ajusta si los nombres de var difieren)
        self.inventory_ip_entry = self.entry_widgets_list[0]
        self.inventory_hostname_entry = self.entry_widgets_list[1]
        self.inventory_mac_entry = self.entry_widgets_list[2]
        self.inventory_os_entry = self.entry_widgets_list[3]
        self.inventory_desc_entry = self.entry_widgets_list[4]
        self.inventory_brand_entry = self.entry_widgets_list[5]
        self.inventory_model_entry = self.entry_widgets_list[6]
        self.inventory_processor_entry = self.entry_widgets_list[7]
        self.inventory_memory_entry = self.entry_widgets_list[8]
        self.inventory_disks_entry = self.entry_widgets_list[9]
        self.inventory_graphics_entry = self.entry_widgets_list[10]
        self.inventory_display_entry = self.entry_widgets_list[11]
        self.inventory_network_point_entry = self.entry_widgets_list[12]
        self.inventory_cable_length_entry = self.entry_widgets_list[13]
        self.inventory_office_entry = self.entry_widgets_list[14]
        self.inventory_user_entry = self.entry_widgets_list[15]
        self.inventory_department_entry = self.entry_widgets_list[16]
        self.inventory_floor_entry = self.entry_widgets_list[17]


        # --- Sección de Botones de Acción ---
        action_buttons_frame = ttk.Frame(inventory_main_frame, padding="5")
        action_buttons_frame.pack(pady=5, padx=10, fill="x")

        self.add_host_button = ttk.Button(action_buttons_frame, text="Añadir Host", command=self.add_host_to_inventory)
        self.add_host_button.pack(side="left", padx=5)

        self.update_host_button = ttk.Button(action_buttons_frame, text="Actualizar Host", command=self.update_selected_host)
        self.update_host_button.pack(side="left", padx=5)

        self.delete_host_button = ttk.Button(action_buttons_frame, text="Borrar Host", command=self.delete_selected_host)
        self.delete_host_button.pack(side="left", padx=5)

        self.clear_fields_button = ttk.Button(action_buttons_frame, text="Limpiar Campos", command=self.clear_inventory_entries)
        self.clear_fields_button.pack(side="left", padx=5)

        # --- Sección del Treeview de Inventario ---
        inventory_tree_frame = ttk.LabelFrame(inventory_main_frame, text="Lista de Hosts en Inventario", padding="10")
        inventory_tree_frame.pack(pady=10, padx=10, expand=True, fill="both")

        # Define las columnas del Treeview
        # NOTA: Estas columnas deben coincidir con las definidas en _load_inventory_into_tree
        # y también con el orden en que se extraen los datos de los diccionarios de host.
        columns = ("IP", "Hostname", "MAC Address", "Sistema Operativo", "Description",
                   "Marca", "Modelo", "Procesador", "Memoria", "Discos", "Gráfica",
                   "Pantalla(s)", "Punto de Red", "Long. Cable UTP", "Despacho", "Usuario",
                   "Departamento", "Planta")
        
        self.inventory_tree = ttk.Treeview(inventory_tree_frame, columns=columns, show="headings")
        
        # Configuración de los encabezados de columna
        for col_name in columns:
            self.inventory_tree.heading(col_name, text=col_name, anchor="w")
            self.inventory_tree.column(col_name, width=100, anchor="w") # Ancho por defecto, se puede ajustar

        # Añadir un scrollbar
        tree_scroll = ttk.Scrollbar(inventory_tree_frame, orient="vertical", command=self.inventory_tree.yview)
        tree_scroll.pack(side="right", fill="y")
        self.inventory_tree.configure(yscrollcommand=tree_scroll.set)

        self.inventory_tree.pack(expand=True, fill="both")

        # Vincular el evento de selección del Treeview al callback on_inventory_select
        self.inventory_tree.bind("<<TreeviewSelect>>", self.on_inventory_select)
        
        # Opcional: Cargar los datos en el Treeview al inicio (ya se hace en __init__, pero lo dejamos aquí por contexto)
        # self._load_inventory_into_tree() # Esto ya se llama en __init__

        app_logger.info("Widgets de la pestaña 'Gestión de Inventario' creados y organizados.")

    # --- Métodos de Inventario (clave para la consistencia del ID) ---
    # Este método será crucial para la consistencia del ID
    def _load_inventory_into_tree(self):
        """
        Carga el inventario de hosts (self.hosts_inventory) en el widget Treeview de inventario.
        Se asegura de usar el ID único del host (sea numérico o IP) como IID del Treeview.
        """
        # Limpiar el Treeview existente para evitar duplicados
        for item in self.inventory_tree.get_children():
            self.inventory_tree.delete(item)

        # Aquí vamos a asumir que CADA HOST TIENE UN 'id' NUMÉRICO ÚNICO
        # ESTO ES CRÍTICO: El 'id' en tu hosts.json o DB debe ser un número entero único.
        # Si tu identificador principal es la IP, lo ajustaremos más tarde.
        
        # Define las columnas en el Treeview que quieres mostrar y en qué orden
        # Este orden debe coincidir con el orden de `values_tuple` más abajo.
        columns_config = [
            {"id": "ip_address", "text": "IP", "width": 120},
            {"id": "hostname", "text": "Hostname", "width": 120},
            {"id": "mac_address", "text": "MAC Address", "width": 120},
            {"id": "os", "text": "Sistema Operativo", "width": 120},
            {"id": "description", "text": "Description", "width": 150},
            {"id": "brand", "text": "Marca", "width": 80},
            {"id": "model", "text": "Modelo", "width": 80},
            {"id": "processor", "text": "Procesador", "width": 100},
            {"id": "memory", "text": "Memoria", "width": 80},
            {"id": "disks", "text": "Discos", "width": 100},
            {"id": "graphics", "text": "Gráfica", "width": 100},
            {"id": "display", "text": "Pantalla(s)", "width": 100},
            {"id": "network_point", "text": "Punto de Red", "width": 100},
            {"id": "cable_length", "text": "Long. Cable UTP", "width": 100},
            {"id": "office", "text": "Despacho", "width": 80},
            {"id": "user", "text": "Usuario", "width": 100},
            {"id": "department", "text": "Departamento", "width": 100},
            {"id": "floor", "text": "Planta", "width": 50},
        ]

        # Configurar las columnas del Treeview dinámicamente
        column_ids = [col["id"] for col in columns_config]
        self.inventory_tree["columns"] = column_ids
        for col in columns_config:
            self.inventory_tree.heading(col["id"], text=col["text"], anchor="w")
            self.inventory_tree.column(col["id"], width=col["width"], anchor="w")

        # Insertar los datos
        for host in self.hosts_inventory:
            host_id = host.get('id')
            if host_id is None:
                self.log_message(f"Advertencia: Host sin ID único detectado: {host.get('ip_address', 'N/A')}. No se agregará al Treeview.", logging.WARNING)
                continue 
            
            # CRÍTICO: Usamos el ID NUMÉRICO del host como el IID del Treeview.
            # Esto es lo que se obtendrá con treeview.focus() y se usará para borrar.
            item_iid = str(host_id)

            values_tuple = tuple(host.get(col["id"], "") for col in columns_config)
            
            self.inventory_tree.insert('', tk.END, iid=item_iid, values=values_tuple)
            
        self.log_message(f"Inventario cargado en la tabla GUI: {len(self.hosts_inventory)} hosts.")
        self.inventory_tree.pack(expand=True, fill="both") # Asegúrate de que el Treeview sea visible


    def on_inventory_select(self, event):
        """
        Maneja la selección de un host en el Treeview del inventario.
        Carga los datos del host seleccionado en los campos de entrada.
        """
        self.log_message("DEBUG: on_inventory_select iniciado.") # AÑADE ESTO

        selected_item_iid = self.inventory_tree.focus() # Esto obtiene el IID de la fila (el ID numérico como string)
        self.log_message(f"DEBUG: on_inventory_select - selected_item_iid de Treeview.focus(): '{selected_item_iid}'") # AÑADE ESTO
        
        item_values = () # Inicializamos item_values
        
        if not selected_item_iid:
            self.clear_inventory_entries(reset_selection=False)
            self.current_selected_host_id = None 
            self.log_message("Selección de inventario: Ningún host seleccionado.")
            self.log_message("DEBUG: on_inventory_select - No hay ítem seleccionado. current_selected_host_id = None") # AÑADE ESTO
            return

        # Guardamos el IID del Treeview como el ID seleccionado.
        # ESTE ES EL ID NUMÉRICO DEL HOST EN LA DB/JSON
        self.current_selected_host_id = selected_item_iid 
        self.log_message(f"DEBUG: on_inventory_select - current_selected_host_id actualizado a: '{self.current_selected_host_id}'")
        
        try:
            tree_item_data = self.inventory_tree.item(selected_item_iid)
            if tree_item_data and 'values' in tree_item_data:
                item_values = tree_item_data['values']
            else:
                self.log_message(f"Advertencia: No se encontraron datos válidos para el ítem '{selected_item_iid}'.", logging.WARNING)
                self.clear_inventory_entries() # Aquí se limpiará y reseteará la selección por defecto si no hay datos válidos
                self.current_selected_host_id = None
                return


            self.clear_inventory_entries(reset_selection=False) # Limpiamos campos, pero MANTENEMOS la selección


            # Mapeo de StringVars a Entry widgets para rellenar
            # Este orden debe coincidir con el ORDEN de las columnas en self._load_inventory_into_tree
            # para que los índices de item_values coincidan.
            string_vars_order = [
                self.inventory_ip_var,
                self.inventory_hostname_var,
                self.inventory_mac_var,
                self.inventory_os_var,
                self.inventory_desc_var,
                self.inventory_brand_var,
                self.inventory_model_var,
                self.inventory_processor_var,
                self.inventory_memory_var,
                self.inventory_disks_var,
                self.inventory_graphics_var,
                self.inventory_display_var,
                self.inventory_network_point_var,
                self.inventory_cable_length_var,
                self.inventory_office_var,
                self.inventory_user_var,
                self.inventory_department_var,
                self.inventory_floor_var
            ]

            for i, var in enumerate(string_vars_order):
                if i < len(item_values):
                    value_to_insert = item_values[i]
                    var.set(value_to_insert) # Usar .set() para StringVars
                else:
                    var.set("") # Asegurarse de limpiar si no hay valor

            self.log_message(f"Datos del host con IID '{selected_item_iid}' cargados para edición.")

        except Exception as e:
            self.log_message(f"Error inesperado en on_inventory_select para IID '{selected_item_iid}': {e}", logging.ERROR)
            self.clear_inventory_entries(reset_selection=True)
            self.current_selected_host_id = None


    def clear_inventory_entries(self, reset_selection=True): # Añadimos un parámetro opcional
        """
        Limpia todos los campos de entrada del formulario de inventario.
        Si reset_selection es True, también deselecciona el ID actual.
        """
        if hasattr(self, 'entry_widgets_list'):
            for entry in self.entry_widgets_list:
                if entry.winfo_exists():
                    entry.delete(0, tk.END)
            self.log_message("Campos de inventario limpiados.")
            
            if reset_selection: # Solo resetea la selección si se pide explícitamente
                self.current_selected_host_id = None 
                self.log_message("DEBUG: current_selected_host_id reseteado a None por clear_inventory_entries.") # AÑADE ESTO
        else:
            self.log_message("Advertencia: No se pudieron limpiar los campos de inventario (widgets no inicializados).", logging.WARNING)


    def delete_selected_host(self):
        """
        Borra el host seleccionado del inventario (lista local y archivo JSON).
        Ahora usa self.current_selected_host_id, que debe ser el ID numérico del host.
        """
        self.log_message("DEBUG: delete_selected_host iniciado.")
        selected_item_iid = self.current_selected_host_id 
        self.log_message(f"DEBUG: delete_selected_host - Valor de current_selected_host_id al inicio: '{selected_item_iid}'")
        
        if not selected_item_iid:
            messagebox.showwarning("Borrar Host", "Por favor, seleccione un host para borrar.")
            self.log_message("Intento de borrado: No hay host seleccionado para borrar.")
            self.log_message("DEBUG: delete_selected_host - Condición 'not selected_item_iid' es TRUE.")
            return 

        item_values = () 
        display_info = ""

        try:
            # Convertimos el IID del Treeview a entero (ya que nuestro ID es numérico)
            host_db_id = int(selected_item_iid) 
            
            tree_item_data = self.inventory_tree.item(selected_item_iid)
            if tree_item_data and 'values' in tree_item_data:
                item_values = tree_item_data['values']
                if len(item_values) > 0:
                    ip_address = item_values[0]
                    hostname = item_values[1] if len(item_values) > 1 else "N/A"
                    display_info = f" (IP: {ip_address}, Hostname: {hostname})"
            else:
                # Esto puede ocurrir si el usuario selecciona y luego borra el host de otra forma
                messagebox.showwarning(
                    "Host no encontrado", 
                    f"El host con ID '{host_db_id}' ya no se encuentra en la lista visible. "
                    "Podría haber sido borrado o el inventario no está actualizado."
                )
                self.log_message(f"Advertencia: El ítem '{selected_item_iid}' (ID: {host_db_id}) no existe en el Treeview. No se procederá con el borrado.", logging.WARNING)
                self.current_selected_host_id = None # Reiniciar selección
                self.clear_inventory_entries(reset_selection=True) # Limpiar campos y selección
                return 

            confirm = messagebox.askyesno(
                "Confirmar Borrado",
                f"¿Está seguro de que desea borrar el host con ID {host_db_id}{display_info} de la base de datos?"
            )

            if confirm:
                # Filtrar la lista local de hosts para eliminar el que tiene el ID correspondiente
                initial_count = len(self.hosts_inventory)
                self.hosts_inventory = [host for host in self.hosts_inventory if host.get('id') != host_db_id]
                
                if len(self.hosts_inventory) < initial_count: # Si se eliminó al menos uno
                    # Guardar la lista actualizada en el archivo JSON
                    inventory_manager.save_hosts(self.hosts_inventory)
                    
                    self.inventory_tree.delete(selected_item_iid) # Eliminar del Treeview
                    self.clear_inventory_entries(reset_selection=True) # Limpiar campos y deseleccionar
                    # self.current_selected_host_id = None # Esto ya lo hace clear_inventory_entries(True)
                    self.populate_remote_host_dropdown() # Actualizar desplegable de remotos
                    
                    messagebox.showinfo("Borrado Exitoso", "Host borrado del inventario.")
                    self.log_message(f"Host con ID {host_db_id} borrado del inventario.")
                else:
                    messagebox.showerror("Error al Borrar", f"No se encontró el host con ID {host_db_id} en el inventario.")
                    self.log_message(f"Error: No se encontró el host con ID {host_db_id} para borrar.", logging.ERROR)

        except ValueError:
            messagebox.showerror("Error", "ID de host inválido para borrado. El ID no es un número entero.")
            self.log_message(f"Error: ID de host inválido para borrado: '{selected_item_iid}'. No se pudo convertir a entero.", logging.ERROR)
        except Exception as e:
            messagebox.showerror("Error Inesperado", f"Ocurrió un error inesperado al intentar borrar el host:\n{e}")
            self.log_message(f"Error inesperado al borrar host con IID {selected_item_iid}: {e}", logging.ERROR)
    # --- Métodos de Acción para las Pestañas (vacíos por ahora) ---
    def start_scan(self):
        if self.scan_process and self.scan_process.is_alive():
            self.log_message("ADVERTENCIA: Ya hay un escaneo en curso.", logging.WARNING)
            return

        ip_range = self.ip_range_var.get()
        if not ip_range:
            messagebox.showwarning("Entrada Vacía", "Por favor, introduce un rango de IP para escanear.")
            self.log_message("ADVERTENCIA: Intento de iniciar escaneo con rango IP vacío.", logging.WARNING)
            return

        self.log_message(f"INFO: Iniciando escaneo de red para {ip_range}...", logging.INFO)
        
        # Limpiar Treeview de resultados de escaneo anteriores
        for item in self.scan_results_tree.get_children():
            self.scan_results_tree.delete(item)
        self.add_scanned_to_inventory_button.config(state="disabled") # Deshabilitar hasta que haya resultados nuevos

        # Reiniciar eventos y colas para un nuevo escaneo
        self.stop_event = Event() # Resetear el evento de detención
        self.scan_output_queue = Queue() # Reiniciar la cola de salida del worker

        # Habilitar/Deshabilitar botones al iniciar escaneo
        self.start_scan_button.config(state="disabled")  # Deshabilita "Iniciar Escaneo"
        self.stop_scan_button.config(state="normal")     # Habilita "Detener Escaneo"
        
        print("--- SCAN INICIADO: Programando _check_gui_queue desde start_scan ---") # DEBUG INICIO SCAN
        try:
            self.scan_process = Process(
                target=scanner_worker.scan_network,
                args=(ip_range, self.scan_output_queue, self.stop_event, self.log_queue)
            )
            self.scan_process.start()
            self.scan_thread_running = True
            self.master.after(100, self._check_gui_queue) # Esta es la clave para la GUI
            self.log_message("DEBUG: Proceso de escaneo iniciado y _check_gui_queue programado.", logging.DEBUG)
        except Exception as e:
            print(f"--- ERROR CRITICO: Fallo al iniciar proceso de escaneo: {e} ---") # DEBUG ERROR
            self.log_message(f"ERROR: No se pudo iniciar el proceso de escaneo: {e}", logging.ERROR)
            self.log_message(f"DEBUG: Traceback: {traceback.format_exc()}", logging.DEBUG)
            self.start_scan_button.config(state="normal")
            self.stop_scan_button.config(state="disabled")

    def stop_scan(self):
        """
        Detiene el proceso de escaneo de red.
        """
        if self.scan_process and self.scan_process.is_alive():
            self.log_message("Intentando detener el escaneo del proceso worker...", logging.INFO)
            self.stop_event.set() # Establece el evento para señalar al worker que se detenga
            # Esperar un poco a que el proceso termine gracefully, sin bloquear la GUI
            self.scan_process.join(timeout=2) 
            if self.scan_process.is_alive():
                self.log_message("El proceso de escaneo no se detuvo gracefulmente. Terminando forzosamente...", logging.WARNING)
                self.scan_process.terminate() # Termina el proceso si no se detuvo en el timeout
            self.scan_process = None
            self.scan_thread_running = False # Actualiza la bandera

            self.start_scan_button.config(state="normal")
            self.stop_scan_button.config(state="disabled")
            # Podrías habilitar el botón de añadir si hay algo en el treeview, aunque el escaneo fue abortado.
            # if self.scan_results_tree.get_children():
            #     self.add_scanned_to_inventory_button.config(state="normal")
            
            self.log_message("Escaneo detenido.", logging.INFO)
        else:
            self.log_message("No hay escaneo activo para detener.", logging.INFO)

    def execute_remote_command(self):
        selected_host_ip = self.remote_host_selection_var.get()
        command = "echo 'Comando de prueba'" # Ejemplo, esto vendrá de un Entry en la GUI
        self.log_message(f"Ejecutar comando '{command}' en {selected_host_ip} (funcionalidad pendiente)")
        # self.remote_command_queue.put({'type': 'command_output', 'data': {'target': selected_host_ip, 'output': 'Salida simulada'}})

    def add_host_to_inventory(self):
        """
        Recoge los datos de los campos de entrada y añade un nuevo host al inventario.
        Genera un ID único y actualiza la lista local y el archivo JSON.
        """
        host_data = {
            "ip_address": self.inventory_ip_var.get().strip(),
            "hostname": self.inventory_hostname_var.get().strip(),
            "mac_address": self.inventory_mac_var.get().strip(),
            "os": self.inventory_os_var.get().strip(),
            "description": self.inventory_desc_var.get().strip(),
            "brand": self.inventory_brand_var.get().strip(),
            "model": self.inventory_model_var.get().strip(),
            "processor": self.inventory_processor_var.get().strip(),
            "memory": self.inventory_memory_var.get().strip(),
            "disks": self.inventory_disks_var.get().strip(),
            "graphics": self.inventory_graphics_var.get().strip(),
            "display": self.inventory_display_var.get().strip(),
            "network_point": self.inventory_network_point_var.get().strip(),
            "cable_length": self.inventory_cable_length_var.get().strip(),
            "office": self.inventory_office_var.get().strip(),
            "user": self.inventory_user_var.get().strip(),
            "department": self.inventory_department_var.get().strip(),
            "floor": self.inventory_floor_var.get().strip()
        }

        # Validaciones básicas
        if not host_data["ip_address"]:
            messagebox.showwarning("Faltan Datos", "La dirección IP es un campo obligatorio.")
            self.log_message("Error: Intento de añadir host sin IP.", logging.WARNING)
            return
        
        # Validar si la IP ya existe (¡CRÍTICO para evitar duplicados!)
        for host in self.hosts_inventory:
            if host.get('ip_address') == host_data["ip_address"]:
                messagebox.showwarning("Host Duplicado", f"Ya existe un host con la IP {host_data['ip_address']} en el inventario.")
                self.log_message(f"Error: Intento de añadir host con IP duplicada: {host_data['ip_address']}.", logging.WARNING)
                return

        try:
            # Generar un ID único para el nuevo host
            # Buscamos el ID más alto existente y le sumamos 1
            max_id = 0
            if self.hosts_inventory: # Solo si hay hosts en la lista
                # Nos aseguramos de que el 'id' sea un int antes de buscar el máximo
                max_id = max([h.get('id', 0) for h in self.hosts_inventory if isinstance(h.get('id'), int)])
            host_data['id'] = max_id + 1

            # Añadir el host a la lista local
            self.hosts_inventory.append(host_data)
            
            # Guardar la lista actualizada en el archivo JSON
            inventory_manager.save_hosts(self.hosts_inventory)
            
            messagebox.showinfo("Éxito", f"Host {host_data['ip_address']} añadido correctamente.")
            self.log_message(f"Host {host_data['ip_address']} añadido al inventario. ID asignado: {host_data['id']}.")

            self._load_inventory_into_tree() # Refrescar el Treeview con los datos actualizados
            self.clear_inventory_entries(reset_selection=True) # Limpiar el formulario y deseleccionar después de añadir
            self.populate_remote_host_dropdown() # Actualizar la lista de hosts remotos

        except Exception as e:
            messagebox.showerror("Error Inesperado", f"Ocurrió un error inesperado al añadir el host:\n{e}")
            self.log_message(f"Error inesperado al añadir host: {e}", logging.ERROR)
    def populate_remote_host_dropdown(self):
        """Rellena el OptionMenu de hosts remotos con IPs del inventario."""
        # Esto es un placeholder; la implementación real irá en Paso 3
        # Asegúrate de que self.remote_host_selection_var y self.remote_host_dropdown existen.
        if hasattr(self, 'remote_host_selection_var') and hasattr(self, 'remote_host_dropdown'):
            menu = self.remote_host_dropdown["menu"]
            menu.delete(0, "end") # Limpiar opciones existentes
            
            host_ips = [host.get('ip_address') for host in self.hosts_inventory if host.get('ip_address')]
            host_ips.sort() # Opcional: ordenar las IPs
            
            if not host_ips:
                host_ips = ["No hosts disponibles"]
                self.remote_host_selection_var.set("No hosts disponibles")
            else:
                # Si el valor actual no está en la nueva lista, establece el primero
                if self.remote_host_selection_var.get() not in host_ips:
                    self.remote_host_selection_var.set(host_ips[0])
            
            for ip in host_ips:
                menu.add_command(label=ip, command=tk._setit(self.remote_host_selection_var, ip))
            
            if self.remote_host_dropdown.winfo_ismapped(): # Solo si está visible
                self.log_message(f"Desplegable de hosts remotos actualizado con {len(host_ips)} hosts.")

    

    def update_selected_host(self):
        """
        Actualiza los datos del host seleccionado en el inventario.
        Recopila los datos de los campos de entrada, localiza el host por su ID,
        actualiza sus propiedades y guarda los cambios.
        """
        # Aseguramos que haya un host seleccionado para actualizar
        if not self.current_selected_host_id:
            messagebox.showwarning("Actualizar Host", "Por favor, seleccione un host en la tabla para actualizar.")
            self.log_message("Intento de actualización: No hay host seleccionado.")
            return

        # Recopilar los datos de los campos de entrada (actualizados)
        updated_host_data = {
            "ip_address": self.inventory_ip_var.get().strip(),
            "hostname": self.inventory_hostname_var.get().strip(),
            "mac_address": self.inventory_mac_var.get().strip(),
            "os": self.inventory_os_var.get().strip(),
            "description": self.inventory_desc_var.get().strip(),
            "brand": self.inventory_brand_var.get().strip(),
            "model": self.inventory_model_var.get().strip(),
            "processor": self.inventory_processor_var.get().strip(),
            "memory": self.inventory_memory_var.get().strip(),
            "disks": self.inventory_disks_var.get().strip(),
            "graphics": self.inventory_graphics_var.get().strip(),
            "display": self.inventory_display_var.get().strip(),
            "network_point": self.inventory_network_point_var.get().strip(),
            "cable_length": self.inventory_cable_length_var.get().strip(),
            "office": self.inventory_office_var.get().strip(),
            "user": self.inventory_user_var.get().strip(),
            "department": self.inventory_department_var.get().strip(),
            "floor": self.inventory_floor_var.get().strip()
        }

        # Validaciones básicas
        if not updated_host_data["ip_address"]:
            messagebox.showwarning("Faltan Datos", "La dirección IP es un campo obligatorio.")
            self.log_message("Error: Intento de actualizar host sin IP.", logging.WARNING)
            return
        
        try:
            # Convertir el ID de la cadena (Treeview IID) a entero para buscar en la lista
            host_id_to_update = int(self.current_selected_host_id)
            
            host_found = False
            for i, host in enumerate(self.hosts_inventory):
                if host.get('id') == host_id_to_update:
                    # Antes de actualizar, verificar si la nueva IP ya existe en otro host
                    # con un ID diferente (para evitar duplicados accidentales de IP)
                    for existing_host in self.hosts_inventory:
                        if existing_host.get('id') != host_id_to_update and \
                           existing_host.get('ip_address') == updated_host_data["ip_address"]:
                            messagebox.showwarning("IP Duplicada", f"La IP '{updated_host_data['ip_address']}' ya está asignada a otro host (ID: {existing_host.get('id')}).")
                            self.log_message(f"Error: Intento de actualizar host {host_id_to_update} a IP duplicada {updated_host_data['ip_address']}.", logging.WARNING)
                            return # Salir de la función si la IP es duplicada

                    # Actualizar las propiedades del host
                    for key, value in updated_host_data.items():
                        host[key] = value
                    
                    # Guardamos el ID original en los datos actualizados para referencia
                    host['id'] = host_id_to_update 
                    
                    self.hosts_inventory[i] = host # Actualizar el host en la lista
                    inventory_manager.save_hosts(self.hosts_inventory) # Guardar la lista completa
                    
                    messagebox.showinfo("Éxito", f"Host con ID {host_id_to_update} (IP: {host['ip_address']}) actualizado correctamente.")
                    self.log_message(f"Host con ID {host_id_to_update} actualizado en el inventario.")
                    
                    host_found = True
                    break
            
            if host_found:
                self._load_inventory_into_tree() # Refrescar el Treeview con los datos actualizados
                self.clear_inventory_entries(reset_selection=True) # Limpiar campos y deseleccionar
                self.populate_remote_host_dropdown() # Actualizar la lista de hosts remotos
            else:
                messagebox.showerror("Error al Actualizar", f"No se encontró el host con ID {host_id_to_update} en el inventario para actualizar.")
                self.log_message(f"Error: No se encontró el host con ID {host_id_to_update} para actualizar.", logging.ERROR)

        except ValueError:
            messagebox.showerror("Error", "ID de host inválido para actualización. El ID no es un número entero.")
            self.log_message(f"Error: ID de host inválido para actualización: '{self.current_selected_host_id}'. No se pudo convertir a entero.", logging.ERROR)
        except Exception as e:
            messagebox.showerror("Error Inesperado", f"Ocurrió un error inesperado al intentar actualizar el host:\n{e}")
            self.log_message(f"Error inesperado al actualizar host con IID {self.current_selected_host_id}: {e}", logging.ERROR)
    # Variable para la cola de comunicación entre hilos (para resultados del escaneo)
    # Colócala en tu __init__ method, justo debajo de self.master = master
    # self.scan_queue = queue.Queue() 

    # Placeholder para el hilo de escaneo
    

    # Métodos Placeholder para la lógica de escaneo
    # Reemplaza completamente tu método 'start_network_scan_thread' si lo encuentras.
    # O, si no existe, asegúrate de que el botón de escaneo esté llamando a 'start_scan' directamente.
    def start_network_scan_thread(self): # Asegúrate que este sea el nombre del método
        self.start_scan() # Simplemente llama al método principal start_scan

    def _perform_network_scan(self, ip_range, nmap_options):
        """
        Realiza un escaneo de hosts activos (ping scan) usando Scapy.
        Este método se ejecuta en un hilo separado y envía resultados en tiempo real.
        """
        try:
            from scapy.all import IP, ICMP, sr, conf # ¡Importante: importar 'conf' también!
            import ipaddress
            
            self.log_message(f"Iniciando ping scan con Scapy para {ip_range}...")
            
            # scapy.all.conf.verb = 0  # Descomentar para suprimir la salida de Scapy a la consola

            target_ips = []
            try:
                network = ipaddress.ip_network(ip_range, strict=False)
                for ip in network.hosts():
                    target_ips.append(str(ip))
                
                if "/" not in ip_range:
                    try:
                        single_ip = str(ipaddress.ip_address(ip_range))
                        if single_ip not in target_ips:
                            target_ips.append(single_ip)
                    except ValueError:
                        pass
            
            except ValueError as e:
                error_message = f"Rango de IP inválido: '{ip_range}'. Error de formato: {e}"
                self.log_message(error_message, logging.ERROR)
                self.scan_queue.put({"status": "error", "message": error_message})
                return

            if not target_ips:
                error_message = f"El rango de IP '{ip_range}' no contiene direcciones de host válidas para escanear."
                self.log_message(error_message, logging.ERROR)
                self.scan_queue.put({"status": "error", "message": error_message})
                return

            target_ips.sort(key=lambda ip: ipaddress.ip_address(ip))

            for ip in target_ips:
                if not self.scan_thread_running:
                    self.log_message("Escaneo detenido por el usuario.")
                    break

                # Reducir el timeout para una respuesta más rápida, incluso sin host.
                ans, unans = sr(IP(dst=ip)/ICMP(), timeout=0.1, verbose=0) 

                for s, r in ans:
                    if r.haslayer(ICMP) and r[ICMP].type == 0:
                        host_ip = s[IP].dst
                        hostname = "N/A"
                        try:
                            import socket
                            hostname = socket.gethostbyaddr(host_ip)[0]
                        except (socket.herror, socket.gaierror):
                            pass
                        
                        self.scan_queue.put({
                            "status": "host_found",
                            "data": {
                                "ip": host_ip,
                                "hostname": hostname,
                                "state": "up",
                                "ports": "No escaneado (solo ping)",
                                "os": "Desconocido"
                            }
                        })
                        self.log_message(f"Host activo encontrado: {host_ip}")
                
            self.scan_queue.put({"status": "completed"})
            self.log_message(f"Ping scan con Scapy completado para {ip_range}.")

        except ImportError:
            error_message = "La librería 'Scapy' no está instalada. Por favor, instálela con 'pip install scapy'."
            self.log_message(error_message, logging.ERROR)
            self.scan_queue.put({"status": "error", "message": error_message})
        except PermissionError as e:
            error_message = f"Error de permisos: {e}. Scapy a menudo requiere permisos de administrador (sudo en Linux/macOS, ejecutar como administrador en Windows) o que Npcap esté instalado y configurado correctamente."
            self.log_message(error_message, logging.ERROR)
            self.scan_queue.put({"status": "error", "message": error_message})
        except Exception as e:
            error_message = f"Error inesperado durante el escaneo con Scapy: {e}"
            self.log_message(error_message, logging.ERROR)
            self.scan_queue.put({"status": "error", "message": error_message})
        finally:
            self.scan_queue.put({"status": "scan_finished_ui_update"}) 
            self.scan_thread_running = False
            self.log_message(f"DEBUG: _perform_network_scan finalizado. scan_thread_running={self.scan_thread_running}", logging.DEBUG)
            
            # --- NUEVAS LÍNEAS CLAVE PARA REINICIAR SCAPY ---
            try:
                from scapy.all import conf, srp, L3RawSocket # Asegúrate de que L3RawSocket esté importado si lo usas
                
                # Intentar cerrar el socket L3 si existe
                if hasattr(conf, 'L3socket') and conf.L3socket:
                    conf.L3socket.close()
                    conf.L3socket = None # Ponerlo a None para que Scapy lo re-inicialice

                # Esto intentará cerrar todos los descriptores de archivos/sockets abiertos por Scapy
                # Puede ser un poco más agresivo que solo L3socket.close()
                for sock in conf.open_sockets:
                    try:
                        sock.close()
                    except Exception as ex:
                        self.log_message(f"ADVERTENCIA: Error al cerrar un socket abierto: {ex}", logging.WARNING)
                conf.open_sockets = [] # Limpiar la lista de sockets abiertos

                # Re-inicializar la configuración de Scapy para forzar una nueva configuración de sockets
                # Esto es como "reiniciar" Scapy sin cerrar la aplicación.
                conf.load_base_config()
                self.log_message("DEBUG: Scapy re-inicializado completamente para liberar recursos.", logging.DEBUG)

            except Exception as e:
                self.log_message(f"ADVERTENCIA: Error durante la limpieza/re-inicialización de Scapy: {e}", logging.WARNING)

                self.log_message(f"ADVERTENCIA: Error al intentar cerrar el socket de Scapy: {e}", logging.WARNING)
    def _check_gui_queue(self): # Renombrado de _check_scan_queue
        
        # --- ¡ESTA ES LA LÍNEA MÁS CRÍTICA AÑADIDA! ---
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!! _check_gui_queue HA SIDO LLAMADO !!!!!!!!!!!!!!!!!!!!!!!!!!!") 
        # -----------------------------------------------

        print("--- RAW PRINT: _check_gui_queue EJECUTÁNDOSE ---") 
        self.logger.debug("--- DEBUG: _check_gui_queue INICIANDO CICLO ---") 

        messages_processed = 0
        try:
            while True:
                try:
                    message = self.scan_output_queue.get(block=False)
                    messages_processed += 1
                    
                    print(f"--- RAW PRINT: MENSAJE OBTENIDO - Status='{message.get('status', 'NO_STATUS_KEY')}' --- Data: {message.get('data', 'NO_DATA_KEY')}")
                    self.log_message(f"DEBUG: Mensaje recibido de cola del worker: Status='{message.get('status', 'NO_STATUS_KEY')}'", logging.DEBUG)

                    if message["status"] == "host_found":
                        host_info = message["data"]
                        print(f"--- RAW PRINT: INSERTANDO HOST - IP: {host_info['ip']} ---") 
                        self.scan_results_tree.insert("", "end", values=(
                            host_info["ip"],
                            host_info["hostname"],
                            host_info["mac"],
                            host_info["state"],
                            host_info["ports"],
                            host_info["os"]
                        ))
                        self.scan_results_tree.yview_moveto(1)
                        self.log_message(f"DEBUG: Host {host_info['ip']} insertado en Treeview.", logging.DEBUG)
                    
                    elif message["status"] == "total_ips":
                        print(f"--- RAW PRINT: TOTAL IPS - Count: {message['data']['count']} ---")
                        self.log_message(f"INFO: Total de IPs a escanear: {message['data']['count']}.", logging.INFO)
                    
                    elif message["status"] == "completed":
                        print("--- RAW PRINT: ESCANEO COMPLETADO ---")
                        self.log_message("INFO: Escaneo de red completado por el worker.", logging.INFO)
                        self.scan_thread_running = False 
                        self.start_scan_button.config(state="normal")
                        self.stop_scan_button.config(state="disabled")
                        if self.scan_results_tree.get_children(): 
                            self.add_scanned_to_inventory_button.config(state="normal")
                        else:
                            self.add_scanned_to_inventory_button.config(state="disabled")
                        self.log_message("INFO: Proceso de escaneo finalizado. Deteniendo chequeo periódico de cola de GUI.", logging.INFO)
                        return 
                    
                    elif message["status"] == "error":
                        print(f"--- RAW PRINT: ERROR EN ESCANEO - {message['data']['message']} ---")
                        self.log_message(f"ERROR: Error en el proceso de escaneo: {message['data']['message']}", logging.ERROR)
                        self.scan_thread_running = False 
                        self.start_scan_button.config(state="normal")
                        self.stop_scan_button.config(state="disabled")
                        self.add_scanned_to_inventory_button.config(state="disabled")
                        self.log_message("INFO: Proceso de escaneo finalizado debido a un error. Deteniendo chequeo periódico de cola de GUI.", logging.INFO)
                        return
                    
                except queue.Empty:
                    break 
                except Exception as e:
                    print(f"--- RAW PRINT: EXCEPCIÓN EN PROCESAMIENTO DE COLA: {e} --- Traceback: {traceback.format_exc()}")
                    self.log_message(f"ERROR: Error al procesar mensaje de la cola de la GUI: {e}", logging.ERROR)
                    self.log_message(f"DEBUG: Traceback: {traceback.format_exc()}", logging.DEBUG)
                    break 

        except Exception as e:
            print(f"--- RAW PRINT: EXCEPCIÓN EN BUCLE PRINCIPAL DE _check_gui_queue: {e} --- Traceback: {traceback.format_exc()}")
            self.log_message(f"ERROR: Error en el bucle principal de _check_gui_queue: {e}", logging.ERROR)
            self.log_message(f"DEBUG: Traceback: {traceback.format_exc()}", logging.DEBUG)
        
        finally:
            print(f"--- RAW PRINT: _check_gui_queue FINALIZANDO CICLO, procesados: {messages_processed} ---")
            self.log_message(f"DEBUG: _check_gui_queue finalizado el procesamiento de {messages_processed} mensajes.", logging.DEBUG)
            if self.scan_thread_running or (self.scan_process and self.scan_process.is_alive()):
                print("--- RAW PRINT: _check_gui_queue REPROGRAMADO ---")
                self.master.after(100, self._check_gui_queue)
                self.log_message("DEBUG: _check_gui_queue reprogramado.", logging.DEBUG)
            else:
                print("--- RAW PRINT: _check_gui_queue NO REPROGRAMADO ---")
                self.log_message("INFO: _check_gui_queue no reprogramado porque el escaneo ha terminado.", logging.INFO)
                self.start_scan_button.config(state="normal")
                self.stop_scan_button.config(state="disabled")

    def process_log_queue(self):
        """
        Procesa mensajes de log de la cola y los muestra en el Text widget de la GUI.
        Esta función es llamada periódicamente por el método .after() de Tkinter.
        """
        print("--- DEBUG RAW PRINT: process_log_queue HA SIDO LLAMADO ---") # <-- AÑADE ESTA LÍNEA

        messages_processed_in_cycle = 0 # Para contar si se procesan mensajes en este ciclo

        while True:
            try:
                # Intenta obtener un registro de la cola sin bloquear
                record = self.log_queue.get(block=False)
                messages_processed_in_cycle += 1 # Incrementa si se obtiene un mensaje

                print(f"--- DEBUG RAW PRINT: Log Record Obtenido: {record.levelname} - {record.msg[:50]}...") # <-- AÑADE ESTA LÍNEA
                
                # Formatear el mensaje de log usando el mismo handler que lo puso en la cola
                log_entry = self.log_handler.format(record)
                
                print(f"--- DEBUG RAW PRINT: Log Formateado: {log_entry[:50]}...") # <-- AÑADE ESTA LÍNEA

                # Insertar en el Text widget y asegurar que se vea el final
                if hasattr(self, 'log_text') and self.log_text is not None:
                    self.log_text.config(state="normal") # Habilitar la edición del Text widget
                    self.log_text.insert(tk.END, log_entry + "\n") # Insertar el mensaje al final
                    self.log_text.see(tk.END) # Hacer scroll automático al final
                    self.log_text.config(state="disabled") # Deshabilitar la edición de nuevo
                    print("--- DEBUG RAW PRINT: Mensaje Insertado en log_text ---") # <-- AÑADE ESTA LÍNEA
                else:
                    print("--- DEBUG RAW PRINT: ERROR: self.log_text NO ESTÁ DISPONIBLE ---") # <-- AÑADE ESTA LÍNEA

            except queue.Empty:
                # No hay más mensajes en la cola por ahora, salir del bucle interno
                print(f"--- DEBUG RAW PRINT: Cola de Logs Vacía. Mensajes procesados en este ciclo: {messages_processed_in_cycle} ---") # <-- AÑADE ESTA LÍNEA
                break 
            except Exception as e:
                # Capturar cualquier otro error que ocurra al procesar un log
                print(f"--- DEBUG RAW PRINT: EXCEPCIÓN EN process_log_queue: {e} ---") # <-- AÑADE ESTA LÍNEA
                traceback.print_exc() # Imprimir el traceback completo para depuración
                break # Salir del bucle interno para evitar un error continuo

        # Reprogramar la llamada a esta función para que se ejecute de nuevo después de 100ms
        self.master.after(100, self.process_log_queue)
        print("--- DEBUG RAW PRINT: process_log_queue REPROGRAMADO ---") # <-- AÑADE ESTA LÍNEA

    def _display_scan_results(self, results):
        """Pobla el Treeview de resultados de escaneo con los datos."""
        # Limpiar el Treeview antes de añadir nuevos resultados
        for item in self.scan_results_tree.get_children():
            self.scan_results_tree.delete(item)
            
        for host in results:
            # Asegúrate de que los valores coincidan con las columnas definidas
            values = (
                host.get("ip", ""),
                host.get("hostname", ""),
                host.get("state", ""),
                host.get("ports", ""),
                host.get("os", "")
            )
            # Usar la IP o un ID único como iid para el Treeview
            self.scan_results_tree.insert("", "end", iid=host.get("ip"), values=values)
        self.log_message(f"Mostrados {len(results)} hosts encontrados en el escaneo.")

    def add_scanned_hosts_to_inventory(self):
        """Añade los hosts seleccionados del Treeview de escaneo al inventario principal."""
        selected_items = self.scan_results_tree.selection()
        if not selected_items:
            messagebox.showwarning("Selección Vacía", "Por favor, seleccione al menos un host del escaneo para añadir al inventario.")
            return

        added_count = 0
        for iid in selected_items:
            item_data = self.scan_results_tree.item(iid)['values']
            # Mapear los valores del Treeview a la estructura del host de inventario
            # Asegúrate de que este mapeo sea exacto a la estructura de tu host en hosts.json
            new_host = {
                "ip_address": item_data[0],  # Columna IP
                "hostname": item_data[1],    # Columna Hostname
                "mac_address": "Desconocida", # Nmap no siempre da MAC en todos los escaneos/OS
                "os": item_data[4] if len(item_data) > 4 else "Desconocido", # Columna OS Detectado
                "description": "Añadido desde escaneo de red",
                "brand": "",
                "model": "",
                "processor": "",
                "memory": "",
                "disks": "",
                "graphics": "",
                "display": "",
                "network_point": "",
                "cable_length": "",
                "office": "",
                "user": "",
                "department": "",
                "floor": ""
            }

            # Validar si ya existe un host con la misma IP en el inventario antes de añadir
            ip_exists = False
            for existing_host in self.hosts_inventory:
                if existing_host.get('ip_address') == new_host["ip_address"]:
                    self.log_message(f"Advertencia: Host con IP {new_host['ip_address']} ya existe en el inventario. Saltando.", logging.WARNING)
                    ip_exists = True
                    break
            
            if not ip_exists:
                # Generar un ID único (reutilizando la lógica de add_host_to_inventory)
                max_id = 0
                if self.hosts_inventory:
                    max_id = max([h.get('id', 0) for h in self.hosts_inventory if isinstance(h.get('id'), int)])
                new_host['id'] = max_id + 1

                self.hosts_inventory.append(new_host)
                added_count += 1
                self.log_message(f"Host {new_host['ip_address']} añadido al inventario desde escaneo.")

        if added_count > 0:
            inventory_manager.save_hosts(self.hosts_inventory) # Guardar todos los hosts añadidos
            self._load_inventory_into_tree() # Refrescar Treeview de inventario
            self.populate_remote_host_dropdown() # Actualizar la lista de hosts remotos
            messagebox.showinfo("Hosts Añadidos", f"{added_count} host(s) añadido(s) al inventario desde el escaneo.")
        else:
            messagebox.showinfo("Sin Cambios", "Ningún nuevo host fue añadido al inventario (quizás ya existían).")
# --- 4. Inicialización de la Aplicación ---
if __name__ == "__main__":
    root = tk.Tk()
    app = IntraScanAdminGUI(root)
    root.mainloop()