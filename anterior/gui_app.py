import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import sys
import os
import logging
import threading
import queue
import re
import csv
import actual.inventory_manager as inventory_manager
import json


# Asegúrate de que las rutas a tus módulos sean correctas
import actual.scanner as scanner
import actual.remote_control as remote_control
import actual.inventory_manager as inventory_manager
from actual.logger_config import app_logger


class CustomLogHandler(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
        self.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    def emit(self, record):
        msg = self.format(record)
        # Usar after para actualizar la GUI en el hilo principal de forma segura
        self.text_widget.after(0, self.append_record, msg)

    def append_record(self, msg):
        self.text_widget.configure(state='normal')
        self.text_widget.insert(tk.END, msg + '\n')
        self.text_widget.configure(state='disabled')
        # Autoscroll al final
        self.text_widget.see(tk.END)

# --- Configuración del logger global (si no lo tienes ya, ponlo aquí) ---
# Asegúrate de que inventory_manager esté importado para que el logger funcione
# Si no está importado, añade 'import inventory_manager' al principio.
# from . import inventory_manager # o la forma en que lo importes

app_logger = logging.getLogger("IntraScanAdmin")
app_logger.setLevel(logging.INFO)
# Configura un manejador de consola por defecto (para ver logs en la consola también)
if not app_logger.handlers:
    console_handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    app_logger.addHandler(console_handler)
    app_logger.info("Sistema de logging configurado.")

class IntraScanAdminGUI:
    def __init__(self, master):
        self.master = master
        master.title("IntraScan & Admin GUI")
        master.geometry("1100x750")
        master.resizable(True, True)
        self.current_selected_host_id = None

        self.style = ttk.Style()
        self.style.theme_use('clam')

        self.scan_queue = queue.Queue()
        # self.master.after(100, self.process_scan_queue) # Esto puede ir al final del __init__
        self.current_selected_host_id = None # Para almacenar el ID del host seleccionado
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(pady=10, expand=True, fill="both")

        # Pestaña de Escaneo
        self.scan_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_tab, text="Escaneo de Red")
        self.create_scan_tab_widgets(self.scan_tab)

        # Pestaña de Control Remoto
        self.remote_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.remote_tab, text="Control Remoto")
        self.create_remote_tab_widgets(self.remote_tab)

        # Pestaña de Gestión de Inventario
        self.inventory_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.inventory_tab, text="Gestión de Inventario")
        self.create_inventory_tab_widgets(self.inventory_tab) # <-- ¡Aquí se crea self.inventory_tree!

        # Cargar inventario ANTES de cargarlo en el Treeview
        self.hosts_inventory = inventory_manager.load_hosts()
        app_logger.info(f"Inventario cargado al inicio: {len(self.hosts_inventory)} hosts.")
        
        # AHORA que self.inventory_tree existe y self.hosts_inventory está cargado, lo llenamos:
        self._load_inventory_into_tree() # <--- ¡Añade esta línea aquí!

        # Rellenar el desplegable de hosts remotos (después de cargar inventario)
        self.populate_remote_host_dropdown()
        app_logger.info("GUI: Desplegable de hosts remotos actualizado.") # Muevo esta línea aquí para que siempre se loguee después de la actualización.

        # Marco para el registro de actividad (log)
        self.log_frame = ttk.LabelFrame(master, text="Registro de Actividad")
        self.log_frame.pack(side="bottom", fill="x", padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(self.log_frame, width=120, height=8, state='disabled', wrap='word')
        self.log_text.pack(padx=5, pady=5)

        # Redirigir la salida del logger a la caja de texto
        self.redirect_logger_output()

        app_logger.info("Interfaz Gráfica de IntraScan & Admin iniciada.")
        self.log_message("¡Bienvenido a IntraScan & Admin GUI!")
        self.log_message("Utiliza las pestañas para navegar por las funciones.")
        
        # Vincular el evento de cambio de pestaña para refrescar el inventario y hosts remotos
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)

        # Iniciar el procesamiento de la cola de escaneo (asegúrate de que process_scan_queue existe)
        self.master.after(100, self.process_scan_queue)

     # Dentro de la clase IntraScanAdminGUI, con la misma indentación que otros métodos:

# Dentro de tu clase IntraScanAdminGUI

    def on_inventory_select(self, event):
        """
        Callback que se ejecuta cuando se selecciona una fila en el Treeview de inventario.
        Carga los datos del host seleccionado en los campos de entrada para su edición.
        """
        selected_item_iid = self.inventory_tree.focus() # Obtiene el IID del elemento seleccionado
        
        # ¡IMPORTANTE! Definimos item_values aquí, inicializado a una tupla vacía
        # Esto asegura que item_values siempre exista.
        item_values = () 

        if not selected_item_iid:
            self.clear_inventory_entries()
            self.current_selected_host_id = None # Limpiar el ID si no hay selección
            self.log_message("Selección de inventario: Ningún host seleccionado.")
            return

        # Guardamos el ID seleccionado aquí para uso posterior (ej. borrar/modificar)
        self.current_selected_host_id = selected_item_iid

        try:
            # Obtener los datos del ítem seleccionado desde el Treeview
            tree_item_data = self.inventory_tree.item(selected_item_iid)
            
            # Verificar si el ítem existe y tiene valores
            if tree_item_data and 'values' in tree_item_data:
                item_values = tree_item_data['values']
            else:
                self.log_message(f"Advertencia: No se encontraron datos válidos para el elemento '{selected_item_iid}' en el Treeview.")
                self.clear_inventory_entries()
                self.current_selected_host_id = None # Limpiar selección
                return

            # Ahora que item_values está definido y contiene datos (o una tupla vacía si no hay valores)
            # y hemos confirmado que el ítem existe, procedemos a rellenar los campos.

            # Primero, limpiar todos los campos para evitar datos residuales
            self.clear_inventory_entries()

            # Mapeo de los nombres de las columnas a los Entry widgets.
            # Asegúrate de que los nombres de las claves aquí coincidan EXACTAMENTE
            # con los "text" de los self.inventory_tree.heading() que definiste
            # en create_inventory_tab_widgets.
            entry_widgets_map = {
                "IP": self.inventory_ip_entry,
                "Hostname": self.inventory_hostname_entry,
                "MAC Address": self.inventory_mac_entry,
                "Sistema Operativo": self.inventory_os_entry,
                "Description": self.inventory_desc_entry,
                "Marca": self.inventory_brand_entry,
                "Modelo": self.inventory_model_entry,
                "Procesador": self.inventory_processor_entry,
                "Memoria": self.inventory_memory_entry,
                "Discos": self.inventory_disks_entry,
                "Gráfica": self.inventory_graphics_entry,
                "Pantalla(s)": self.inventory_display_entry,
                "Punto de Red": self.inventory_network_point_entry,
                "Long. Cable UTP": self.inventory_cable_length_entry,
                "Despacho": self.inventory_office_entry,
                "Usuario": self.inventory_user_entry,
                "Departamento": self.inventory_department_entry,
                "Planta": self.inventory_floor_entry,
            }

            # Obtener el orden de las columnas reales del Treeview
            # Esto es robusto porque itera sobre las columnas en el orden correcto
            treeview_columns_order = list(self.inventory_tree["columns"])

            # Insertar los valores en los campos de entrada correspondientes
            for i, column_id in enumerate(treeview_columns_order):
                # Obtener el texto del encabezado para esa columna
                heading_text = self.inventory_tree.heading(column_id, "text")

                if heading_text in entry_widgets_map:
                    entry_widget = entry_widgets_map[heading_text]
                    # Asegurarse de que el índice 'i' es válido para item_values
                    value_to_insert = item_values[i] if i < len(item_values) else ""
                    
                    # Insertar el valor. Si el widget es un Entry, ya debería ser limpiado por clear_inventory_entries()
                    entry_widget.insert(0, value_to_insert if value_to_insert else "") 

            self.log_message(f"Datos del host con IP '{item_values[0] if item_values and len(item_values) > 0 else 'N/A'}' cargados para edición.")

        except IndexError as e:
            self.log_message(f"Error (IndexError) al cargar datos del host en los campos. "
                            f"Asegúrate de que las columnas del Treeview coinciden con los índices de 'item_values': {e}. "
                            f"item_values actual: {item_values}")
            self.clear_inventory_entries()
            self.current_selected_host_id = None
        except Exception as e:
            self.log_message(f"Error inesperado en on_inventory_select: {e}")
            self.clear_inventory_entries()
            self.current_selected_host_id = None

    def clear_inventory_entries(self):
        """
        Limpia el contenido de todos los campos de entrada en la pestaña de inventario.
        """
        self.inventory_ip_entry.delete(0, tk.END)
        self.inventory_hostname_entry.delete(0, tk.END)
        self.inventory_mac_entry.delete(0, tk.END)
        self.inventory_os_entry.delete(0, tk.END)
        self.inventory_desc_entry.delete(0, tk.END)
        # Limpiar los nuevos campos añadidos
        self.inventory_brand_entry.delete(0, tk.END)
        self.inventory_model_entry.delete(0, tk.END)
        self.inventory_processor_entry.delete(0, tk.END)
        self.inventory_memory_entry.delete(0, tk.END)
        self.inventory_disks_entry.delete(0, tk.END)
        self.inventory_graphics_entry.delete(0, tk.END)
        self.inventory_display_entry.delete(0, tk.END)
        self.inventory_network_point_entry.delete(0, tk.END)
        self.inventory_cable_length_entry.delete(0, tk.END)
        self.inventory_office_entry.delete(0, tk.END)
        self.inventory_user_entry.delete(0, tk.END)
        self.inventory_department_entry.delete(0, tk.END)
        self.inventory_floor_entry.delete(0, tk.END)

        self.log_message("Campos de inventario limpiados.")  

    def save_inventory_to_file(self):
        """
        Guarda el inventario actual (self.hosts_inventory) en el archivo hosts.json.
        """
        try:
            # Aquí llamas a la función de tu módulo inventory_manager que guarda los hosts.
            # Asumo que inventory_manager tiene una función save_hosts()
            # y que esta función recibe la lista de hosts a guardar.
            inventory_manager.save_hosts(self.hosts_inventory)
            messagebox.showinfo("Guardar Inventario", "Inventario guardado con éxito en hosts.json.")
            self.log_message("Inventario guardado con éxito en hosts.json.")
        except Exception as e:
            messagebox.showerror("Error al Guardar", f"No se pudo guardar el inventario:\n{e}")
            self.log_message(f"Error al guardar inventario en hosts.json: {e}")

    def export_inventory_to_csv(self):
        """
        Exporta el inventario actual de la base de datos a un archivo CSV.
        """
        # Abrir un diálogo para que el usuario elija la ubicación y el nombre del archivo
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("Archivos CSV", "*.csv"), ("Todos los archivos", "*.*")],
            title="Guardar Inventario como CSV"
        )

        if not file_path: # Si el usuario cancela el diálogo
            self.log_message("Exportación de inventario cancelada por el usuario.")
            return

        try:
            # Obtener todos los hosts desde la base de datos usando inventory_manager
            all_computers = inventory_manager.get_all_computers()

            if not all_computers:
                messagebox.showinfo("Exportar Inventario", "No hay datos en el inventario para exportar.")
                self.log_message("No hay hosts en el inventario para exportar a CSV.")
                return

            # Definir los encabezados del CSV. Es crucial que estos coincidan con las claves de tus diccionarios de host.
            # Una forma robusta es extraer todas las claves de todos los diccionarios de hosts.
            headers = set()
            for computer in all_computers:
                headers.update(computer.keys())

            # Convertir a lista y ordenar para consistencia (opcional, pero buena práctica)
            headers = sorted(list(headers))

            # Puedes ajustar el orden de las columnas si lo deseas, por ejemplo, IP y Hostname primero
            desired_order = ["id", "ip_address", "hostname", "mac_address", "os", "description", 
                            "brand", "model", "processor", "memory", "disks", "graphics", "display",
                            "network_point", "cable_length", "office", "user", "department", "floor"]

            # Reordenar los encabezados para que sigan el orden deseado, añadiendo los que falten al final
            ordered_headers = [h for h in desired_order if h in headers]
            for h in headers:
                if h not in ordered_headers:
                    ordered_headers.append(h)


            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                # Usa csv.DictWriter para escribir diccionarios directamente al CSV
                writer = csv.DictWriter(csvfile, fieldnames=ordered_headers)

                writer.writeheader() # Escribe la primera fila con los encabezados
                for computer in all_computers:
                    writer.writerow(computer) # Escribe cada diccionario como una fila

            messagebox.showinfo("Exportar Inventario", f"Inventario exportado con éxito a:\n{file_path}")
            self.log_message(f"Inventario exportado con éxito a: {file_path}")

        except Exception as e:
            messagebox.showerror("Error de Exportación", f"Ocurrió un error al exportar el inventario:\n{e}")
            self.log_message(f"Error al exportar inventario a CSV: {e}")

    # Dentro de la clase IntraScanAdminGUI
# Dentro de tu clase IntraScanAdminGUI, a la misma indentación que tus otros métodos:

    def delete_selected_host(self):
        """
        Borra el host seleccionado del inventario y de la base de datos.
        Ahora utiliza self.current_selected_host_id para una selección más robusta.
        """
        selected_item_iid = self.current_selected_host_id 
        
        # 1. Comprobar si hay un host seleccionado
        if not selected_item_iid:
            messagebox.showwarning("Borrar Host", "Por favor, seleccione un host para borrar.")
            self.log_message("Intento de borrado: No hay host seleccionado para borrar.")
            return 

        # Inicializar item_values aquí para asegurar que siempre esté definido
        item_values = () 
        display_info = ""

        try:
            # Convertimos el IID a entero, asumiendo que es el ID de la base de datos
            host_db_id = int(selected_item_iid) 
            
            # 2. Intentar obtener los datos del ítem del Treeview usando el IID
            # Esto es importante para el mensaje de confirmación y para verificar que el ítem existe.
            tree_item_data = self.inventory_tree.item(selected_item_iid)
            
            if tree_item_data and tree_item_data.get('values'):
                item_values = tree_item_data.get('values')
                
                # Obtener datos para la confirmación más descriptiva
                ip_address = item_values[0] if len(item_values) > 0 else "N/A"
                hostname = item_values[1] if len(item_values) > 1 else "N/A"
                display_info = f" (IP: {ip_address}, Hostname: {hostname})"
            else:
                # Esto ocurre si el ítem seleccionado ya no existe en el Treeview
                # (ej. fue borrado previamente, o la tabla se refrescó)
                messagebox.showwarning(
                    "Host no encontrado", 
                    f"El host con ID '{host_db_id}' ya no se encuentra en la lista visible. "
                    "Podría haber sido borrado o el inventario no está actualizado."
                )
                self.log_message(f"Advertencia: El ítem '{selected_item_iid}' (ID: {host_db_id}) no existe en el Treeview. No se procederá con el borrado.")
                # Limpiar la selección y campos si el ítem no es válido
                self.current_selected_host_id = None
                self.clear_inventory_entries()
                return # Salir de la función, ya que no hay nada que borrar en la GUI

            # 3. Confirmación de borrado
            confirm = messagebox.askyesno(
                "Confirmar Borrado",
                f"¿Está seguro de que desea borrar el host con ID {host_db_id}{display_info} de la base de datos?"
            )

            if confirm:
                # 4. Borrar de la base de datos a través de inventory_manager
                success = inventory_manager.delete_computer_by_id(host_db_id)
                if success:
                    # 5. Borrar de la lista local de inventario
                    self.hosts_inventory = [host for host in self.hosts_inventory if host.get('id') != host_db_id]
                    
                    # 6. Borrar visualmente del Treeview
                    self.inventory_tree.delete(selected_item_iid)
                    
                    # 7. Limpiar los campos de entrada y la selección guardada
                    self.clear_inventory_entries()
                    self.current_selected_host_id = None # ¡Importante limpiar esto!
                    
                    # 8. Actualizar el desplegable de hosts remotos si es necesario
                    self.update_remote_hosts_dropdown()

                    messagebox.showinfo("Borrado Exitoso", "Host borrado del inventario.")
                    self.log_message(f"Host con ID {host_db_id} borrado del inventario.")
                else:
                    messagebox.showerror("Error al Borrar", f"No se pudo borrar el host con ID {host_db_id} de la base de datos. Verifique los logs.")
                    self.log_message(f"Error al borrar host con ID {host_db_id} de la base de datos.")

        except ValueError:
            # Esto ocurriría si selected_item_iid no se puede convertir a entero (ej. no es un ID válido)
            messagebox.showerror("Error", "ID de host inválido para borrado. Posiblemente el ID no es un número.")
            self.log_message(f"Error: ID de host inválido para borrado: '{selected_item_iid}'. No se pudo convertir a entero.")
            self.current_selected_host_id = None # Limpiar la selección inválida
            self.clear_inventory_entries()
        except Exception as e:
            messagebox.showerror("Error Inesperado", f"Ocurrió un error inesperado al intentar borrar el host:\n{e}")
            self.log_message(f"Error inesperado al borrar host con IID {selected_item_iid}: {e}")

    def start_scan(self):
        """
        Inicia el proceso de escaneo de red.
        Por ahora, solo es un placeholder para evitar el error.
        La lógica real de escaneo (probablemente en un hilo separado) se añadiría aquí.
        """
        network_range = self.network_range_entry.get()
        if not network_range:
            messagebox.showwarning("Escaneo de Red", "Por favor, introduce un rango de red para escanear.")
            return

        self.log_message(f"Iniciando escaneo de red para: {network_range}...")
        self.scan_button.config(state=tk.DISABLED) # Desactivar el botón mientras simula el escaneo

        # Opcional: Limpiar resultados anteriores en el Treeview de escaneo
        # self.scan_results_tree.delete(*self.scan_results_tree.get_children())

        # --- Placeholder temporal para que funcione ---
        messagebox.showinfo("Escaneo de Red", f"Simulación de escaneo para {network_range} iniciada (funcionalidad pendiente).")
        # --- Fin del placeholder ---

        self.scan_button.config(state=tk.NORMAL) # Volver a activar el botón
        self.log_message("Escaneo de red (simulado) finalizado.")

        # En el futuro, aquí iniciarías un hilo de escaneo real y manejarías los resultados.
        # Por ejemplo:
        # scan_thread = threading.Thread(target=self._run_actual_scan, args=(network_range,))
        # scan_thread.daemon = True
        # scan_thread.start()

        # Dentro de la clase IntraScanAdminGUI:

    def process_scan_queue(self):
        """
        Procesa la cola de tareas (como escaneos de red o actualizaciones de inventario)
        en segundo plano para evitar bloquear la GUI.
        """
        # Aquí irá la lógica real de procesamiento de cola en el futuro.
        # Por ahora, un simple log y volver a programar la ejecución es suficiente.

        # Puedes añadir un log si tienes un logger configurado como self.logger en __init__
        # if hasattr(self, 'logger'): # Comprueba si self.logger existe antes de usarlo
        #    self.logger.info("Procesando cola de escaneo (placeholder)...")

        # Esto es crucial: vuelve a programarse para ejecutarse después de un corto retraso.
        # Esto mantiene el "bucle" de procesamiento de la cola activo sin bloquear la GUI.
        self.master.after(100, self.process_scan_queue)

    def on_tab_change(self, event):
        """Maneja el evento de cambio de pestaña."""
        selected_tab = self.notebook.tab(self.notebook.select(), "text")
        if selected_tab == "Gestión de Inventario":
            self.load_inventory_display()
        elif selected_tab == "Control Remoto":
            # Al cambiar a la pestaña de Control Remoto, actualiza el desplegable
            self.populate_remote_host_dropdown()
            # Y precarga la MAC/IP si ya hay un host seleccionado
            self.on_remote_host_selection(self.selected_remote_host.get())

    def create_scan_tab_widgets(self, tab):
        """Crea los widgets para la pestaña de Escaneo de Red."""
        scan_frame = ttk.LabelFrame(tab, text="Configuración de Escaneo")
        scan_frame.pack(padx=10, pady=10, fill="x", expand=True)

        ttk.Label(scan_frame, text="Rango de Red (ej. 192.168.1.0/24):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.network_range_entry = ttk.Entry(scan_frame, width=40)
        self.network_range_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.network_range_entry.insert(0, "192.168.1.0/24") # Valor por defecto

        self.scan_button = ttk.Button(scan_frame, text="Iniciar Escaneo", command=self.start_scan)
        self.scan_button.grid(row=0, column=2, padx=5, pady=5)

        self.help_scan_button = ttk.Button(scan_frame, text="Ayuda Escaneo de Red", command=self.show_scan_help)
        self.help_scan_button.grid(row=0, column=3, padx=5, pady=5) # Añadido en una nueva columna
        results_frame = ttk.LabelFrame(tab, text="Resultado del Escaneo")
        results_frame.pack(padx=10, pady=10, fill="both", expand=True)

        # Frame para el Treeview y el scrollbar
        tree_container_frame = ttk.Frame(results_frame)
        tree_container_frame.pack(padx=5, pady=5, fill="both", expand=True)

        self.scan_results_tree = ttk.Treeview(tree_container_frame, columns=("IP", "Status", "Services"), show="headings")
        self.scan_results_tree.heading("IP", text="Dirección IP")
        self.scan_results_tree.heading("Status", text="Estado")
        self.scan_results_tree.heading("Services", text="Servicios Abiertos")
        self.scan_results_tree.column("IP", width=150, anchor="center")
        self.scan_results_tree.column("Status", width=100, anchor="center")
        self.scan_results_tree.column("Services", width=300, anchor="w")
        
        # Scrollbar para el Treeview de escaneo
        tree_scrollbar = ttk.Scrollbar(tree_container_frame, orient="vertical", command=self.scan_results_tree.yview)
        
        # Empaquetar Treeview y Scrollbar
        self.scan_results_tree.grid(row=0, column=0, sticky="nsew")
        tree_scrollbar.grid(row=0, column=1, sticky="ns")

        # Configurar expansión de filas y columnas para el Treeview
        tree_container_frame.grid_rowconfigure(0, weight=1)
        tree_container_frame.grid_columnconfigure(0, weight=1)

        self.scan_results_tree.configure(yscrollcommand=tree_scrollbar.set)

    def create_remote_tab_widgets(self, tab):
        """Crea los widgets para la pestaña de Control Remoto."""
        # Frame para seleccionar el host
        host_selection_frame = ttk.LabelFrame(tab, text="Selección de Host")
        host_selection_frame.pack(padx=10, pady=10, fill="x")
        host_selection_frame.columnconfigure(1, weight=1)

        ttk.Label(host_selection_frame, text="Introducir IP/Hostname:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.remote_target_entry = ttk.Entry(host_selection_frame, width=40)
        self.remote_target_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Label(host_selection_frame, text="O seleccionar del inventario:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.selected_remote_host = tk.StringVar(self.master)
        self.remote_host_options = ["Selecciona un Host"] # Opción por defecto inicial
        self.remote_host_dropdown = ttk.OptionMenu(host_selection_frame, self.selected_remote_host, self.remote_host_options[0], *self.remote_host_options)
        self.remote_host_dropdown.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
       # Botón de Ayuda para Conexión Remota ---
        self.help_remote_button = ttk.Button(host_selection_frame, text="Ayuda Conexión Remota", command=self.show_remote_connection_help)
        self.help_remote_button.grid(row=0, column=2, padx=5, pady=5)

        # Frame para Wake-on-LAN
        wol_frame = ttk.LabelFrame(tab, text="Wake-on-LAN")
        wol_frame.pack(padx=10, pady=10, fill="x")

        ttk.Label(wol_frame, text="MAC Address del Host:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.wol_mac_entry = ttk.Entry(wol_frame, width=30)
        self.wol_mac_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(wol_frame, text="Enviar Paquete Mágico", command=self.send_wol_packet).grid(row=0, column=2, padx=5, pady=5)

        # Frame para Apagado/Reinicio Remoto
        power_frame = ttk.LabelFrame(tab, text="Apagado/Reinicio Remoto")
        power_frame.pack(padx=10, pady=10, fill="x")
        power_frame.columnconfigure(1, weight=1)

        ttk.Label(power_frame, text="Usuario:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.remote_user_entry = ttk.Entry(power_frame)
        self.remote_user_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(power_frame, text="Contraseña:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.remote_password_entry = ttk.Entry(power_frame, show="*") # Ocultar contraseña
        self.remote_password_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        ttk.Button(power_frame, text="Apagar", command=lambda: self.initiate_remote_action("shutdown")).grid(row=2, column=0, padx=5, pady=5)
        ttk.Button(power_frame, text="Reiniciar", command=lambda: self.initiate_remote_action("reboot")).grid(row=2, column=1, padx=5, pady=5)
        # Botón para obtener información remota (nuevo)
        self.get_remote_info_button = ttk.Button(power_frame, text="Obtener Info Remota", command=self.initiate_remote_info_gathering)
        self.get_remote_info_button.grid(row=2, column=2, padx=5, pady=5)

        #  Frame para Ejecución de Comandos Remotos
        command_frame = ttk.LabelFrame(tab, text="Ejecución de Comandos Remotos")
        command_frame.pack(padx=10, pady=10, fill="x", expand=True)
        command_frame.columnconfigure(1, weight=1) # Permite que la entrada de comando se expanda

        ttk.Label(command_frame, text="Comando (PowerShell/CMD):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.remote_command_entry = ttk.Entry(command_frame, width=70)
        self.remote_command_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.execute_command_button = ttk.Button(command_frame, text="Ejecutar Comando", command=self.execute_remote_command)
        self.execute_command_button.grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(command_frame, text="Salida del Comando:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.command_output_text = scrolledtext.ScrolledText(command_frame, height=10, state='disabled', wrap='word')
        self.command_output_text.grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

        command_frame.grid_rowconfigure(2, weight=1) # Permite que la caja de texto se expanda verticalmente
        

    def show_remote_connection_help(self):
        """Muestra una ventana de ayuda para la conexión remota."""
        help_text = (
            "Para que la conexión remota funcione correctamente (Obtener Info, Apagar, Reiniciar), "
            "asegúrate de lo siguiente en el **equipo Windows remoto**:\n\n"
            "1.  **Versión de Windows:** Debe ser **Windows 10 Pro, Windows 11 Pro** o una versión de servidor (no Home).\n\n"
            "2.  **Habilitar PowerShell Remoting (WinRM):**\n"
            "    Abre PowerShell como Administrador y ejecuta:\n"
            "    `Enable-PSRemoting -Force`\n"
            "    Esto configura el servicio WinRM para aceptar conexiones.\n\n"
            "3.  **Configurar Firewall de Windows:**\n"
            "    Asegúrate de que el Firewall permite las conexiones para WinRM y WMI. "
            "    `Enable-PSRemoting` suele configurar WinRM, pero puedes verificar/añadir:\n"
            "    `Set-NetFirewallRule -DisplayName \"Windows Management Instrumentation (WMI-In)\" -Enabled True`\n"
            "    `Set-NetFirewallRule -DisplayName \"Windows Remote Management (HTTP-In)\" -Enabled True`\n"
            "    O para todas las reglas de WinRM:\n"
            "    `Get-NetFirewallRule -DisplayName *WinRM* | Enable-NetFirewallRule`\n\n"
            "4.  **Credenciales de Administrador:**\n"
            "    Debes usar un **nombre de usuario y contraseña** de una cuenta que tenga permisos de administrador local en el equipo remoto. "
            "    Si la cuenta no tiene contraseña, WinRM puede dar problemas (política de seguridad). "
            "    Para cuentas locales, el usuario debe tener una contraseña.\n\n"
            "5.  **Conectividad de Red:**\n"
            "    Asegúrate de que no hay firewalls intermedios de red o configuraciones de router "
            "    que impidan la comunicación al puerto 5985 (HTTP) o 5986 (HTTPS) del host remoto."
        )
        messagebox.showinfo("Ayuda de Conexión Remota", help_text)
        app_logger.info("GUI: Se mostró la ayuda de conexión remota.")

    def show_scan_help(self):
                """Muestra una ventana de ayuda para el escaneo de red."""
                help_text = (
                    "Esta función realiza un escaneo de red para detectar hosts activos y servicios abiertos.\n\n"
                    "**1. Rango de Red:**\n"
                    "   Introduce el rango de red que deseas escanear en formato CIDR (ej. `192.168.1.0/24`). "
                    "   Esto es fundamental para que la herramienta sepa dónde buscar.\n\n"
                    "**2. Permisos y Firewall:**\n"
                    "   Para que el escaneo funcione correctamente, tu sistema (donde ejecutas la aplicación) "
                    "   necesita permisos para realizar solicitudes de red a otros hosts.\n"
                    "   * **Firewall de Windows:** Asegúrate de que tu firewall local no esté bloqueando las "
                    "       conexiones salientes necesarias para el escaneo (por ejemplo, Ping ICMP, o puertos TCP).\n"
                    "       En algunos casos, puede que necesites una excepción para la aplicación Python.\n"
                    "   * **Privilegios:** Aunque Python puede escanear puertos básicos, para escaneos más "
                    "       profundos o acceso a nivel de red (como algunos pings), a veces ejecutar la aplicación "
                    "       con privilegios de administrador puede ayudar, aunque no siempre es estrictamente necesario "
                    "       para la funcionalidad básica de esta herramienta.\n\n"
                    "**3. Configuración de Red Local:**\n"
                    "   Tu equipo debe estar en la misma red o tener acceso de enrutamiento a la red que intentas escanear.\n"
                    "   Los resultados mostrarán hosts activos y los servicios (puertos TCP) que estén abiertos y "
                    "   respondiendo al escaneo."
                )
                messagebox.showinfo("Ayuda de Escaneo de Red", help_text)
                app_logger.info("GUI: Se mostró la ayuda de escaneo de red.")

    # --- NUEVA FUNCIÓN DE AYUDA PARA INVENTARIO (ASEGÚRATE DE LA INDENTACIÓN) ---
    def show_inventory_help(self):
        """Muestra una ventana de ayuda para la gestión de inventario."""
        help_text = (
            "La pestaña de Gestión de Inventario te permite mantener un registro de tus equipos.\n\n"
            "**1. Campos de Detalles del Host:**\n"
            "   Rellena manualmente los campos con la información del equipo, o utiliza la función "
            "   'Obtener Info Remota' (desde la pestaña Control Remoto) para auto-rellenar los datos "
            "   de un equipo detectado.\n\n"
            "**2. Botones de Acción:**\n"
            "   * **Añadir Host:** Guarda la información de los campos actuales como un nuevo host en el inventario.\n"
            "   * **Editar Host Seleccionado:** Si has seleccionado un host de la tabla, los campos se precargan. "
            "     Modifica la información y haz clic en este botón para actualizar los detalles del host.\n"
            "     **Importante:** La IP es el identificador único. Si cambias la IP, se creará un nuevo registro.\n"
            "   * **Eliminar Host Seleccionado:** Elimina el host seleccionado de la tabla.\n"
            "   * **Guardar Inventario:** Guarda todos los cambios (añadidos, editados, eliminados) en el archivo "
            "     `hosts.json`. **Es crucial guardar para que los cambios persistan.**\n"
            "   * **Limpiar Campos:** Borra el contenido de todos los campos de entrada para un nuevo registro.\n\n"
            "**3. Tabla de Inventario:**\n"
            "   Muestra todos los hosts registrados. Puedes hacer clic en una fila para precargar sus "
            "   detalles en los campos de entrada, facilitando la edición o eliminación.\n\n"
            "Los datos se guardan en el archivo `hosts.json` en el directorio de la aplicación."
        )
        messagebox.showinfo("Ayuda de Gestión de Inventario", help_text)
        app_logger.info("GUI: Se mostró la ayuda de gestión de inventario.")

    def _is_valid_ip_or_hostname(self, target):
        """Valida si una cadena es una dirección IP válida o un hostname básico."""
        # Patrón para IPv4 (ej. 192.168.1.1)
        ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        # Patrón para hostname básico (letras, números, guiones, puntos, no empieza/termina con guion/punto)
        hostname_pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*$"

        if re.match(ipv4_pattern, target):
            # Comprobar que cada octeto está entre 0 y 255
            parts = target.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                return True
        elif re.match(hostname_pattern, target):
            # Para hostname, la validación se basa en el patrón básico.
            # No se puede validar si existe sin una resolución DNS.
            return True
        return False

    def create_inventory_tab_widgets(self, tab):
        """Crea los widgets para la pestaña de Gestión de Inventario."""
        # Frame para la entrada de datos del host
        input_frame = ttk.LabelFrame(tab, text="Detalles del Host")
        input_frame.pack(padx=10, pady=10, fill="x")

        input_frame.columnconfigure(1, weight=1) # Columna de entradas expandible

        # Bloque de campos existentes
        ttk.Label(input_frame, text="IP:").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.inventory_ip_entry = ttk.Entry(input_frame)
        self.inventory_ip_entry.grid(row=0, column=1, padx=5, pady=2, sticky="ew")

        ttk.Label(input_frame, text="Hostname:").grid(row=1, column=0, padx=5, pady=2, sticky="w")
        self.inventory_hostname_entry = ttk.Entry(input_frame)
        self.inventory_hostname_entry.grid(row=1, column=1, padx=5, pady=2, sticky="ew")

        ttk.Label(input_frame, text="MAC:").grid(row=2, column=0, padx=5, pady=2, sticky="w")
        self.inventory_mac_entry = ttk.Entry(input_frame)
        self.inventory_mac_entry.grid(row=2, column=1, padx=5, pady=2, sticky="ew")

        ttk.Label(input_frame, text="OS:").grid(row=3, column=0, padx=5, pady=2, sticky="w")
        self.inventory_os_entry = ttk.Entry(input_frame)
        self.inventory_os_entry.grid(row=3, column=1, padx=5, pady=2, sticky="ew")

        ttk.Label(input_frame, text="Description:").grid(row=4, column=0, padx=5, pady=2, sticky="w")
        self.inventory_desc_entry = ttk.Entry(input_frame)
        self.inventory_desc_entry.grid(row=4, column=1, padx=5, pady=2, sticky="ew")

        # --- NUEVOS CAMPOS DE INVENTARIO ---
        current_row = 5 # Empezamos después de los 5 campos existentes

        ttk.Label(input_frame, text="Marca:").grid(row=current_row, column=0, padx=5, pady=2, sticky="w")
        self.inventory_brand_entry = ttk.Entry(input_frame)
        self.inventory_brand_entry.grid(row=current_row, column=1, padx=5, pady=2, sticky="ew")
        current_row += 1

        ttk.Label(input_frame, text="Modelo:").grid(row=current_row, column=0, padx=5, pady=2, sticky="w")
        self.inventory_model_entry = ttk.Entry(input_frame)
        self.inventory_model_entry.grid(row=current_row, column=1, padx=5, pady=2, sticky="ew")
        current_row += 1

        ttk.Label(input_frame, text="Procesador:").grid(row=current_row, column=0, padx=5, pady=2, sticky="w")
        self.inventory_processor_entry = ttk.Entry(input_frame)
        self.inventory_processor_entry.grid(row=current_row, column=1, padx=5, pady=2, sticky="ew")
        current_row += 1

        ttk.Label(input_frame, text="Memoria (RAM):").grid(row=current_row, column=0, padx=5, pady=2, sticky="w")
        self.inventory_memory_entry = ttk.Entry(input_frame)
        self.inventory_memory_entry.grid(row=current_row, column=1, padx=5, pady=2, sticky="ew")
        current_row += 1

        ttk.Label(input_frame, text="Discos:").grid(row=current_row, column=0, padx=5, pady=2, sticky="w")
        self.inventory_disks_entry = ttk.Entry(input_frame)
        self.inventory_disks_entry.grid(row=current_row, column=1, padx=5, pady=2, sticky="ew")
        current_row += 1

        ttk.Label(input_frame, text="Gráfica:").grid(row=current_row, column=0, padx=5, pady=2, sticky="w")
        self.inventory_graphics_entry = ttk.Entry(input_frame)
        self.inventory_graphics_entry.grid(row=current_row, column=1, padx=5, pady=2, sticky="ew")
        current_row += 1

        ttk.Label(input_frame, text="Pantalla(s):").grid(row=current_row, column=0, padx=5, pady=2, sticky="w")
        self.inventory_display_entry = ttk.Entry(input_frame)
        self.inventory_display_entry.grid(row=current_row, column=1, padx=5, pady=2, sticky="ew")
        current_row += 1

        ttk.Label(input_frame, text="Punto de Red:").grid(row=current_row, column=0, padx=5, pady=2, sticky="w")
        self.inventory_network_point_entry = ttk.Entry(input_frame)
        self.inventory_network_point_entry.grid(row=current_row, column=1, padx=5, pady=2, sticky="ew")
        current_row += 1

        ttk.Label(input_frame, text="Longitud Cable UTP:").grid(row=current_row, column=0, padx=5, pady=2, sticky="w")
        self.inventory_cable_length_entry = ttk.Entry(input_frame)
        self.inventory_cable_length_entry.grid(row=current_row, column=1, padx=5, pady=2, sticky="ew")
        current_row += 1

        ttk.Label(input_frame, text="Despacho:").grid(row=current_row, column=0, padx=5, pady=2, sticky="w")
        self.inventory_office_entry = ttk.Entry(input_frame)
        self.inventory_office_entry.grid(row=current_row, column=1, padx=5, pady=2, sticky="ew")
        current_row += 1

        ttk.Label(input_frame, text="Usuario del Equipo:").grid(row=current_row, column=0, padx=5, pady=2, sticky="w")
        self.inventory_user_entry = ttk.Entry(input_frame)
        self.inventory_user_entry.grid(row=current_row, column=1, padx=5, pady=2, sticky="ew")
        current_row += 1

        ttk.Label(input_frame, text="Departamento:").grid(row=current_row, column=0, padx=5, pady=2, sticky="w")
        self.inventory_department_entry = ttk.Entry(input_frame)
        self.inventory_department_entry.grid(row=current_row, column=1, padx=5, pady=2, sticky="ew")
        current_row += 1

        ttk.Label(input_frame, text="Planta:").grid(row=current_row, column=0, padx=5, pady=2, sticky="w")
        self.inventory_floor_entry = ttk.Entry(input_frame)
        self.inventory_floor_entry.grid(row=current_row, column=1, padx=5, pady=2, sticky="ew")
        current_row += 1

        # Botón de Ayuda para Inventario ---
        self.help_inventory_button = ttk.Button(input_frame, text="Ayuda de Inventario", command=self.show_inventory_help)
        # Asegúrate de ajustar el 'row' si los tuyos no van del 0 al 10.
        # Si tienes 11 campos (0 a 10), la siguiente fila disponible es 11.
        self.help_inventory_button.grid(row=10, column=2, padx=5, pady=2, sticky="e")
        
        # --- FIN NUEVOS CAMPOS ---


        # Frame para los botones de acción del inventario
        button_frame = ttk.Frame(tab)
        button_frame.pack(padx=10, pady=5, fill="x")

        ttk.Button(button_frame, text="Añadir Host", command=self.add_host_to_inventory).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Aplicar Cambios", command=self.edit_selected_host).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Eliminar Host", command=self.delete_selected_host).pack(side="left", padx=5)
        self.export_inventory_button = ttk.Button(button_frame, text="Exportar Inventario", command=self.export_inventory_to_csv)
        self.export_inventory_button.pack(side="right", padx=5)
        ttk.Button(button_frame, text="Guardar Inventario", command=self.save_inventory_to_file).pack(side="right", padx=5)
        ttk.Button(button_frame, text="Limpiar Campos", command=self.clear_inventory_entries).pack(side="right", padx=5)

        # Frame para el Treeview del inventario
        inventory_tree_frame = ttk.LabelFrame(tab, text="Inventario de Hosts")
        inventory_tree_frame.pack(padx=10, pady=10, fill="both", expand=True)

        # Definir las columnas del Treeview, incluyendo las nuevas
        treeview_columns = (
            "IP", "Hostname", "MAC", "OS", "Description",
            "Marca", "Modelo", "Procesador", "Memoria", "Discos", "Gráfica", "Pantalla(s)",
            "Punto de Red", "Longitud Cable UTP", "Despacho", "Usuario", "Departamento", "Planta"
        )
        self.inventory_tree = ttk.Treeview(inventory_tree_frame,
                                          columns=treeview_columns,
                                          show="headings")

        # Scrollbars para el Treeview del inventario
        inventory_tree_scrollbar_y = ttk.Scrollbar(inventory_tree_frame, orient="vertical", command=self.inventory_tree.yview)
        inventory_tree_scrollbar_x = ttk.Scrollbar(inventory_tree_frame, orient="horizontal", command=self.inventory_tree.xview)
        self.inventory_tree.config(yscrollcommand=inventory_tree_scrollbar_y.set, xscrollcommand=inventory_tree_scrollbar_x.set)

        inventory_tree_scrollbar_y.pack(side="right", fill="y")
        inventory_tree_scrollbar_x.pack(side="bottom", fill="x")
        self.inventory_tree.pack(fill="both", expand=True)

        # Definir encabezados y anchos de columnas
        self.inventory_tree.heading("IP", text="IP")
        self.inventory_tree.heading("Hostname", text="Hostname")
        self.inventory_tree.heading("MAC", text="MAC Address")
        self.inventory_tree.heading("OS", text="Sistema Operativo")
        self.inventory_tree.heading("Description", text="Descripción")
        
        self.inventory_tree.heading("Marca", text="Marca")
        self.inventory_tree.heading("Modelo", text="Modelo")
        self.inventory_tree.heading("Procesador", text="Procesador")
        self.inventory_tree.heading("Memoria", text="Memoria")
        self.inventory_tree.heading("Discos", text="Discos")
        self.inventory_tree.heading("Gráfica", text="Gráfica")
        self.inventory_tree.heading("Pantalla(s)", text="Pantalla(s)")
        self.inventory_tree.heading("Punto de Red", text="Punto de Red")
        self.inventory_tree.heading("Longitud Cable UTP", text="Long. Cable UTP")
        self.inventory_tree.heading("Despacho", text="Despacho")
        self.inventory_tree.heading("Usuario", text="Usuario")
        self.inventory_tree.heading("Departamento", text="Departamento")
        self.inventory_tree.heading("Planta", text="Planta")

        self.inventory_tree.column("IP", width=120, anchor="center")
        self.inventory_tree.column("Hostname", width=150, anchor="w")
        self.inventory_tree.column("MAC", width=130, anchor="center")
        self.inventory_tree.column("OS", width=100, anchor="w")
        self.inventory_tree.column("Description", width=200, anchor="w")
        
        self.inventory_tree.column("Marca", width=100, anchor="w")
        self.inventory_tree.column("Modelo", width=100, anchor="w")
        self.inventory_tree.column("Procesador", width=150, anchor="w")
        self.inventory_tree.column("Memoria", width=100, anchor="w")
        self.inventory_tree.column("Discos", width=120, anchor="w")
        self.inventory_tree.column("Gráfica", width=100, anchor="w")
        self.inventory_tree.column("Pantalla(s)", width=100, anchor="w")
        self.inventory_tree.column("Punto de Red", width=100, anchor="w")
        self.inventory_tree.column("Longitud Cable UTP", width=100, anchor="center")
        self.inventory_tree.column("Despacho", width=100, anchor="w")
        self.inventory_tree.column("Usuario", width=100, anchor="w")
        self.inventory_tree.column("Departamento", width=120, anchor="w")
        self.inventory_tree.column("Planta", width=80, anchor="center")

        # Vincular el evento de selección de fila para precargar datos en los campos de entrada
        self.inventory_tree.bind("<<TreeviewSelect>>", self.on_inventory_select)

    def populate_remote_host_dropdown(self):
        """
        Rellena el desplegable de hosts con los hosts del inventario.
        Se llama al inicio y cada vez que se cambia a la pestaña de Control Remoto.
        """
        menu = self.remote_host_dropdown["menu"]
        menu.delete(0, "end") # Eliminar todas las opciones actuales

        # Reinicializar la lista de opciones y el valor por defecto
        self.remote_host_options = ["Selecciona un Host"]
        self.selected_remote_host.set(self.remote_host_options[0])

        # Vincular la variable selected_remote_host a una función de callback.
        # Esto asegura que on_remote_host_selection se llama cada vez que se selecciona una opción.
        self.selected_remote_host.trace("w", self.on_remote_host_selection)

        # Añadir las opciones del inventario
        for host in self.hosts_inventory:
            ip = host.get('ip_address')
            hostname = host.get('hostname')
            if ip:
                display_name = f"{ip} ({hostname})" if hostname and hostname != "N/A" else ip
                self.remote_host_options.append(display_name)
                # Añadir cada opción al menú
                menu.add_command(label=display_name, command=tk._setit(self.selected_remote_host, display_name))
        
        # Si el inventario está vacío, asegurarse de que solo esté la opción por defecto o una de "No hay hosts"
        if not self.hosts_inventory:
            menu.add_command(label="No hay hosts", command=tk._setit(self.selected_remote_host, "No hay hosts"))

        app_logger.info("GUI: Desplegable de hosts remotos actualizado.")

    def on_remote_host_selection(self, *args):
        """
        Callback que se ejecuta cuando se selecciona un host del desplegable de Control Remoto.
        Precarga la IP en remote_target_entry y la MAC en wol_mac_entry.
        """
        selected_value = self.selected_remote_host.get()
        self.remote_target_entry.delete(0, tk.END)
        self.wol_mac_entry.delete(0, tk.END)

        if selected_value == "Selecciona un Host" or selected_value == "No hay hosts":
            return

        # Extraer la IP de la cadena (ej. "192.168.1.1 (PC-SALON)" -> "192.168.1.1")
        selected_ip = selected_value.split(' ')[0]
        self.remote_target_entry.insert(0, selected_ip) # Precargar la IP en el campo de entrada manual

        # Buscar la MAC en el inventario para precargarla
        mac_found = False
        for host in self.hosts_inventory:
            if host.get("ip_address") == selected_ip:
                mac = host.get("mac_address", "").strip()
                if mac:
                    self.wol_mac_entry.insert(0, mac) # Precargar la MAC en el campo de WoL
                    app_logger.info(f"GUI: MAC {mac} precargada para host {selected_ip}.")
                    mac_found = True
                break
        
        if not mac_found:
            app_logger.warning(f"GUI: No se encontró MAC para el host seleccionado {selected_ip}. Es posible que no esté en el inventario o no tenga MAC asignada.")

    def initiate_remote_info_gathering(self):
        """
        Inicia el proceso de obtener información remota en un hilo separado.
        """
        target_ip_or_hostname = self.remote_target_entry.get().strip()
        username = self.remote_user_entry.get().strip()
        password = self.remote_password_entry.get().strip()

        # Si no se proporcionó IP/Hostname manualmente, usar la selección del desplegable
        if not target_ip_or_hostname and self.selected_remote_host.get() not in ["Selecciona un Host", "No hay hosts"]:
            target_ip_or_hostname = self.selected_remote_host.get().split(' ')[0] # Extraer solo la IP

        if not target_ip_or_hostname:
            messagebox.showwarning("Host Requerido", "Por favor, introduce una IP/Hostname o selecciona un host del inventario para obtener información remota.")
            return

        if not username or not password:
            messagebox.showwarning("Credenciales Requeridas", "Por favor, introduce un nombre de usuario y contraseña para la conexión remota.")
            return

        self.log_message(f"Intentando obtener información remota del host: {target_ip_or_hostname}...")
        app_logger.info(f"GUI: Solicitando información remota para {target_ip_or_hostname}.")
        
        # Desactivar botón y cambiar cursor mientras se procesa
        self.get_remote_info_button.config(state=tk.DISABLED)
        self.master.config(cursor="wait")

        # Iniciar la recolección de información en un hilo separado
        threading.Thread(target=self._perform_remote_info_gathering, 
                         args=(target_ip_or_hostname, username, password)).start()
        
    
    # Dentro de tu clase IntraScanAdminGUI, al mismo nivel que __init__, etc.

    def create_scan_tab_widgets(self, parent_frame):
        """
        Crea y organiza los widgets para la pestaña 'Escaneo de Red'.
        """
        # Marco principal para organizar los widgets de esta pestaña
        scan_main_frame = ttk.Frame(parent_frame, padding="10")
        scan_main_frame.pack(expand=True, fill="both")

        # --- Sección de Rangos de IP ---
        ip_range_frame = ttk.LabelFrame(scan_main_frame, text="Rango de IP para Escanear", padding="10")
        ip_range_frame.pack(pady=10, padx=10, fill="x")

        # Ejemplo de un campo de entrada para la IP inicial
        ttk.Label(ip_range_frame, text="IP Inicial:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.scan_start_ip_entry = ttk.Entry(ip_range_frame, width=20)
        self.scan_start_ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        # Ejemplo de un campo de entrada para la IP final
        ttk.Label(ip_range_frame, text="IP Final:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.scan_end_ip_entry = ttk.Entry(ip_range_frame, width=20)
        self.scan_end_ip_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        # --- Sección de Opciones de Escaneo ---
        scan_options_frame = ttk.LabelFrame(scan_main_frame, text="Opciones de Escaneo", padding="10")
        scan_options_frame.pack(pady=10, padx=10, fill="x")

        # Ejemplo de un botón para iniciar el escaneo
        self.start_scan_button = ttk.Button(scan_options_frame, text="Iniciar Escaneo", command=self.start_scan)
        self.start_scan_button.pack(pady=5, padx=5)

        # --- Sección de Resultados del Escaneo ---
        results_frame = ttk.LabelFrame(scan_main_frame, text="Resultados del Escaneo", padding="10")
        results_frame.pack(pady=10, padx=10, expand=True, fill="both")

        # Treeview para mostrar resultados (ejemplo, ajusta tus columnas)
        columns = ("IP", "Hostname", "Status")
        self.scan_results_tree = ttk.Treeview(results_frame, columns=columns, show="headings")
        for col in columns:
            self.scan_results_tree.heading(col, text=col, anchor="w")
            self.scan_results_tree.column(col, width=150, anchor="w")
        self.scan_results_tree.pack(expand=True, fill="both")

        # Puedes añadir más widgets aquí según las necesidades de tu pestaña de escaneo
        # Por ejemplo, un botón para detener el escaneo, una barra de progreso, etc.

        self.log_message("Widgets de la pestaña 'Escaneo de Red' creados.")
        # ... (después de initiate_remote_info_gathering, o donde prefieras añadir funciones de control remoto) ...

    def execute_remote_command(self):
        """
        Inicia la ejecución de un comando remoto en un hilo separado.
        """
        target_ip_or_hostname = self.remote_target_entry.get().strip()
        username = self.remote_user_entry.get().strip()
        password = self.remote_password_entry.get().strip()
        command = self.remote_command_entry.get().strip()

        # Validaciones
        if not target_ip_or_hostname:
            messagebox.showwarning("Host Requerido", "Por favor, introduce una IP/Hostname o selecciona un host del inventario para ejecutar el comando.")
            return
        
        if not self._is_valid_ip_or_hostname(target_ip_or_hostname):
            messagebox.showerror("Error de Entrada", "La IP/Hostname introducido no es válido.")
            app_logger.warning(f"GUI: Intento de ejecución de comando con target inválido: {target_ip_or_hostname}")
            return

        if not username or not password:
            messagebox.showwarning("Credenciales Requeridas", "Por favor, introduce un nombre de usuario y contraseña para la conexión remota.")
            return
        
        if not command:
            messagebox.showwarning("Comando Requerido", "Por favor, introduce el comando a ejecutar en el host remoto.")
            return

        self.log_message(f"Intentando ejecutar comando en {target_ip_or_hostname}: '{command}'...")
        app_logger.info(f"GUI: Solicitando ejecución de comando para {target_ip_or_hostname}.")
        
        # Desactivar botón y cambiar cursor mientras se procesa
        self.execute_command_button.config(state=tk.DISABLED)
        self.master.config(cursor="wait")
        self.command_output_text.config(state='normal')
        self.command_output_text.delete(1.0, tk.END) # Limpiar salida anterior
        self.command_output_text.config(state='disabled')

        # Iniciar la ejecución del comando en un hilo separado
        threading.Thread(target=self._perform_remote_command_execution, 
                            args=(target_ip_or_hostname, username, password, command)).start()

    def _perform_remote_command_execution(self, target, username, password, command):
        """
        Función que ejecuta el comando remoto en un hilo separado y actualiza la GUI.
        """
        try:
            results = remote_control.execute_remote_powershell_command(target, username, password, command)
            
            output_msg = ""
            if results["stdout"]:
                output_msg += "--- STDOUT ---\n" + results["stdout"] + "\n"
            if results["stderr"]:
                output_msg += "\n--- STDERR (ERRORES) ---\n" + results["stderr"] + "\n"
            if results["shell_output"]:
                output_msg += "\n--- OBJETOS DE POWERSHELL ---\n" + results["shell_output"] + "\n"
            
            if not output_msg:
                output_msg = "El comando se ejecutó, pero no devolvió ninguna salida."

            self.master.after(0, lambda: self._update_command_output_gui(output_msg))
            self.log_message(f"Comando '{command}' ejecutado en {target}. Salida actualizada.")
            app_logger.info(f"GUI: Comando '{command}' ejecutado en {target}.")

        except ConnectionError as ce:
            error_msg = f"Error de conexión/autenticación al ejecutar comando en {target}: {ce}"
            self.master.after(0, lambda: self._update_command_output_gui(error_msg, is_error=True))
            self.log_message(f"ERROR: {error_msg}")
            app_logger.error(f"GUI: {error_msg}", exc_info=True)
        except RuntimeError as re:
            error_msg = f"Error en la ejecución del comando remoto en {target}: {re}"
            self.master.after(0, lambda: self._update_command_output_gui(error_msg, is_error=True))
            self.log_message(f"ERROR: {error_msg}")
            app_logger.error(f"GUI: {error_msg}", exc_info=True)
        except Exception as e:
            error_msg = f"Error inesperado al ejecutar comando en {target}: {e}"
            self.master.after(0, lambda: self._update_command_output_gui(error_msg, is_error=True))
            self.log_message(f"ERROR: {error_msg}")
            app_logger.error(f"GUI: {error_msg}", exc_info=True)
        finally:
            self.master.after(0, lambda: self.execute_command_button.config(state=tk.NORMAL))
            self.master.after(0, lambda: self.master.config(cursor=""))

    def _update_command_output_gui(self, message, is_error=False):
        """Actualiza la caja de texto de salida del comando en el hilo principal."""
        self.command_output_text.config(state='normal')
        self.command_output_text.insert(tk.END, message + "\n")
        self.command_output_text.see(tk.END) # Scroll automático al final
        self.command_output_text.config(state='disabled')
        if is_error:
            self.command_output_text.tag_configure("error", foreground="red")
            self.command_output_text.tag_add("error", "1.0", tk.END)

    def _perform_remote_info_gathering(self, target, username, password):
        """
        Función que ejecuta la recolección de información remota en un hilo separado.
        """
        try:
            # Llamar a la nueva función en remote_control.py
            retrieved_data = remote_control.get_remote_host_info(target, username, password)
            self.master.after(0, lambda: self._update_inventory_from_remote_data(retrieved_data))
            self.log_message(f"Información de {target} obtenida y precargada en el inventario.")
            app_logger.info(f"GUI: Información remota de {target} obtenida y procesada.")
        except ConnectionError as ce: # Errores específicos de conexión (WinRMError)
            error_msg = f"Error de conexión al obtener información remota de {target}: {ce}"
            self.log_message(f"ERROR: {error_msg}")
            app_logger.error(f"GUI: {error_msg}", exc_info=True)
            self.master.after(0, lambda: messagebox.showerror("Error de Conexión", error_msg))
        except Exception as e:
            error_msg = f"Error inesperado al obtener información remota de {target}: {e}"
            self.log_message(f"ERROR: {error_msg}")
            app_logger.exception(f"GUI: {error_msg}")
            self.master.after(0, lambda: messagebox.showerror("Error de Recolección", error_msg))
        finally:
            self.master.after(0, lambda: self.get_remote_info_button.config(state=tk.NORMAL)) # Re-activar botón
            self.master.after(0, lambda: self.master.config(cursor="")) # Restaurar cursor


    def _update_inventory_from_remote_data(self, data):
        """
        Actualiza los campos de entrada del inventario con los datos obtenidos remotamente.
        También cambia a la pestaña de inventario.
        """
        self.clear_inventory_entries()
        
        # Mapeo de campos y sus entradas
        field_map = {
            "ip_address": self.inventory_ip_entry,
            "hostname": self.inventory_hostname_entry,
            "mac_address": self.inventory_mac_entry,
            "os": self.inventory_os_entry,
            "description": self.inventory_desc_entry,
            "brand": self.inventory_brand_entry,
            "model": self.inventory_model_entry,
            "processor": self.inventory_processor_entry,
            "memory": self.inventory_memory_entry,
            "disks": self.inventory_disks_entry,
            "graphics": self.inventory_graphics_entry,
            "display": self.inventory_display_entry,
            "network_point": self.inventory_network_point_entry,
            "cable_length": self.inventory_cable_length_entry,
            "office": self.inventory_office_entry,
            "user": self.inventory_user_entry,
            "department": self.inventory_department_entry,
            "planta": self.inventory_floor_entry
        }

        for key, entry_widget in field_map.items():
            value = data.get(key, "")
            value = str(value) if value is not None else "" # Asegura que el valor sea siempre una cadena, convierte None a cadena vacía
            entry_widget.delete(0, 'end') # Borra todo el contenido actual del Entry
            entry_widget.insert(0, value) # Inserta el nuevo valor

        self.notebook.select(self.inventory_tab) # Cambiar a la pestaña de inventario
        self.log_message("Datos remotos precargados. Revisa y 'Añade Host' o 'Aplica Cambios'.")


    def send_wol_packet(self):
        """Envía un paquete mágico Wake-on-LAN."""
        mac_address = self.wol_mac_entry.get().strip()
        target_ip_or_hostname = self.remote_target_entry.get().strip()
        
        # Lógica para priorizar la MAC: campo manual > inventario
        selected_dropdown_value = self.selected_remote_host.get()
        if not mac_address and selected_dropdown_value not in ["Selecciona un Host", "No hay hosts"]:
            ip_from_dropdown = selected_dropdown_value.split(' ')[0]
            for host in self.hosts_inventory:
                if host.get("ip_address") == ip_from_dropdown:
                    mac_address = host.get("mac_address", "").strip()
                    break

        if not mac_address:
            messagebox.showwarning("MAC Requerida", "Por favor, introduce una dirección MAC o selecciona un host con MAC en el inventario para WoL.")
            app_logger.warning("GUI: Intento de WoL sin dirección MAC.")
            return
        
        # Validación de formato MAC (opcional pero recomendable)
        if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac_address):
            messagebox.showerror("Formato de MAC Inválido", "La dirección MAC debe tener el formato XX:XX:XX:XX:XX:XX (o guiones).")
            return


        if not target_ip_or_hostname:
            self.log_message("No se especificó IP/Hostname objetivo para WoL, se intentará broadcast.")
            target_ip_or_hostname = "255.255.255.255" # IP de broadcast por defecto

        self.log_message(f"Enviando paquete mágico a {mac_address} ({target_ip_or_hostname})...")
        app_logger.info(f"GUI: Solicitando WoL para MAC: {mac_address}, IP/Host: {target_ip_or_hostname}.")

        try:
            remote_control.send_magic_packet(mac_address, ip_address=target_ip_or_hostname)
            self.log_message(f"Paquete mágico enviado a {mac_address}.")
            app_logger.info(f"GUI: Paquete mágico enviado a {mac_address}.")
            messagebox.showinfo("WoL", f"Paquete mágico enviado a {mac_address}.")
        except Exception as e:
            error_msg = f"Error al enviar paquete WoL: {e}"
            self.log_message(f"ERROR: {error_msg}")
            app_logger.error(f"GUI: {error_msg}", exc_info=True) # exc_info=True para el traceback completo
            messagebox.showerror("Error WoL", error_msg)

    def initiate_remote_action(self, action_type):
        """Inicia una acción remota (shutdown/reboot) en un host."""
        target_ip_or_hostname = self.remote_target_entry.get().strip()
        username = self.remote_user_entry.get().strip()
        password = self.remote_password_entry.get().strip()

        # Si no se proporcionó IP/Hostname manualmente, usar la selección del desplegable
        if not target_ip_or_hostname and self.selected_remote_host.get() not in ["Selecciona un Host", "No hay hosts"]:
            target_ip_or_hostname = self.selected_remote_host.get().split(' ')[0] # Extraer solo la IP

        if not target_ip_or_hostname:
            messagebox.showwarning("Host Requerido", "Por favor, introduce una IP/Hostname o selecciona un host del inventario.")
            app_logger.warning("GUI: Intento de acción remota sin host especificado.")
            return
        
        if not username or not password:
            messagebox.showwarning("Credenciales Requeridas", "Por favor, introduce un nombre de usuario y contraseña.")
            app_logger.warning("GUI: Intento de acción remota sin credenciales.")
            return

        confirm_msg = f"¿Estás seguro de que quieres {action_type} el host '{target_ip_or_hostname}'?"
        if not messagebox.askyesno("Confirmar Acción Remota", confirm_msg):
            return

        self.log_message(f"Iniciando {action_type} remoto para {target_ip_or_hostname}...")
        app_logger.info(f"GUI: Solicitando {action_type} para {target_ip_or_hostname}.")

        # Ejecutar la acción en un hilo para no bloquear la GUI
        threading.Thread(target=self._run_remote_action_in_thread, 
                         args=(action_type, target_ip_or_hostname, username, password)).start()

    def _run_remote_action_in_thread(self, action_type, target, username, password):
        """Ejecuta la acción remota en un hilo separado."""
        try:
            success = False
            if action_type == "shutdown":
                success = remote_control.remote_shutdown(target, username, password)
            elif action_type == "reboot":
                success = remote_control.remote_reboot(target, username, password)
            
            if success:
                msg = f"¡{action_type.capitalize()} remoto exitoso para {target}!"
                self.log_message(msg)
                app_logger.info(f"GUI: {action_type} exitoso para {target}.")
                self.master.after(0, lambda: messagebox.showinfo(f"{action_type.capitalize()} Exitoso", msg))
            else:
                msg = f"Fallo al {action_type} el host {target}. Comprueba logs, credenciales y que el host esté accesible."
                self.log_message(f"ERROR: {msg}")
                app_logger.error(f"GUI: {msg}")
                self.master.after(0, lambda: messagebox.showerror(f"Error de {action_type.capitalize()}", msg))
        except Exception as e:
            error_msg = f"Error inesperado al ejecutar {action_type} remoto en {target}: {e}"
            self.log_message(f"ERROR: {error_msg}")
            app_logger.exception(f"GUI: {error_msg}")
            self.master.after(0, lambda: messagebox.showerror(f"Error Inesperado", error_msg))

    def load_inventory_display(self):
        """Carga y muestra el inventario de hosts en el Treeview."""
        for item in self.inventory_tree.get_children():
            self.inventory_tree.delete(item)
        for host in self.hosts_inventory:
            # Los valores deben coincidir con el orden de las columnas definidas en create_inventory_tab_widgets
            self.inventory_tree.insert("", tk.END, values=(
                host.get("ip_address", "N/A"),
                host.get("hostname", "N/A"),
                host.get("mac_address", "N/A"),
                host.get("os", "N/A"),
                host.get("description", "N/A"),
                host.get("brand", "N/A"),         # Nuevo
                host.get("model", "N/A"),         # Nuevo
                host.get("processor", "N/A"),     # Nuevo
                host.get("memory", "N/A"),        # Nuevo
                host.get("disks", "N/A"),         # Nuevo
                host.get("graphics", "N/A"),      # Nuevo
                host.get("display", "N/A"),       # Nuevo
                host.get("network_point", "N/A"), # Nuevo
                host.get("cable_length", "N/A"),  # Nuevo
                host.get("office", "N/A"),        # Nuevo
                host.get("user", "N/A"),          # Nuevo
                host.get("department", "N/A"),    # Nuevo
                host.get("planta", "N/A")         # Nuevo
            ), iid=host.get("ip_address")) # Usamos la IP como IID (identificador único de la fila)
        self.log_message(f"Inventario mostrado. Total: {len(self.hosts_inventory)} hosts.")
        app_logger.info(f"GUI: Inventario actualizado en la visualización.")

    def add_host_to_inventory(self):
        """Añade un nuevo host al inventario desde los campos de entrada."""
        ip = self.inventory_ip_entry.get().strip()
        hostname = self.inventory_hostname_entry.get().strip()
        mac = self.inventory_mac_entry.get().strip()
        os_name = self.inventory_os_entry.get().strip()
        description = self.inventory_desc_entry.get().strip()
        
        # --- NUEVOS CAMPOS ---
        brand = self.inventory_brand_entry.get().strip()
        model = self.inventory_model_entry.get().strip()
        processor = self.inventory_processor_entry.get().strip()
        memory = self.inventory_memory_entry.get().strip()
        disks = self.inventory_disks_entry.get().strip()
        graphics = self.inventory_graphics_entry.get().strip()
        display = self.inventory_display_entry.get().strip()
        network_point = self.inventory_network_point_entry.get().strip()
        cable_length = self.inventory_cable_length_entry.get().strip()
        office = self.inventory_office_entry.get().strip()
        user = self.inventory_user_entry.get().strip()
        department = self.inventory_department_entry.get().strip()
        planta = self.inventory_floor_entry.get().strip()
        # --- FIN NUEVOS CAMPOS ---

        if not ip or not hostname:
            messagebox.showwarning("Entrada Requerida", "IP y Hostname son campos obligatorios.")
            app_logger.warning("GUI: Intento de añadir host sin IP o Hostname.")
            return
        
        if any(h['ip_address'] == ip for h in self.hosts_inventory):
            messagebox.showwarning("Host Existente", f"El host con IP {ip} ya existe en el inventario. Usa 'Aplicar Cambios' si quieres modificarlo.")
            app_logger.warning(f"GUI: Intento de añadir host duplicado: {ip}.")
            return
        
        # Validar formato MAC (opcional)
        if mac and not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
            messagebox.showerror("Formato de MAC Inválido", "La dirección MAC debe tener el formato XX:XX:XX:XX:XX:XX (o guiones).")
            return


        new_host = {
            "ip_address": ip,
            "hostname": hostname,
            "mac_address": mac,
            "os": os_name,
            "description": description,
            "brand": brand,             # Nuevo
            "model": model,             # Nuevo
            "processor": processor,     # Nuevo
            "memory": memory,           # Nuevo
            "disks": disks,             # Nuevo
            "graphics": graphics,       # Nuevo
            "display": display,         # Nuevo
            "network_point": network_point, # Nuevo
            "cable_length": cable_length,   # Nuevo
            "office": office,           # Nuevo
            "user": user,               # Nuevo
            "department": department,   # Nuevo
            "planta": planta            # Nuevo
        }
        self.hosts_inventory.append(new_host)
        self.load_inventory_display() # Refrescar la tabla
        self.clear_inventory_entries() # Limpiar campos
        self.log_message(f"Host '{hostname}' ({ip}) añadido al inventario.")
        app_logger.info(f"GUI: Host {ip} añadido.")

    def edit_selected_host(self):
        """Edita un host seleccionado en el inventario con los datos de los campos de entrada."""
        selected_item = self.inventory_tree.focus() # Obtiene el IID del elemento seleccionado
        if not selected_item:
            messagebox.showwarning("Ningún Host Seleccionado", "Por favor, selecciona un host de la tabla para editar.")
            return
        
        current_ip_in_table = selected_item # selected_item YA ES el IID, que es la IP del host

        new_ip = self.inventory_ip_entry.get().strip()
        new_hostname = self.inventory_hostname_entry.get().strip()
        new_mac = self.inventory_mac_entry.get().strip()
        new_os_name = self.inventory_os_entry.get().strip()
        new_description = self.inventory_desc_entry.get().strip()

        # --- NUEVOS CAMPOS ---
        new_brand = self.inventory_brand_entry.get().strip()
        new_model = self.inventory_model_entry.get().strip()
        new_processor = self.inventory_processor_entry.get().strip()
        new_memory = self.inventory_memory_entry.get().strip()
        new_disks = self.inventory_disks_entry.get().strip()
        new_graphics = self.inventory_graphics_entry.get().strip()
        new_display = self.inventory_display_entry.get().strip()
        new_network_point = self.inventory_network_point_entry.get().strip()
        new_cable_length = self.inventory_cable_length_entry.get().strip()
        new_office = self.inventory_office_entry.get().strip()
        new_user = self.inventory_user_entry.get().strip()
        new_department = self.inventory_department_entry.get().strip()
        new_planta = self.inventory_floor_entry.get().strip()
        # --- FIN NUEVOS CAMPOS ---

        if not new_ip or not new_hostname:
            messagebox.showwarning("Entrada Requerida", "IP y Hostname son campos obligatorios para editar.")
            return
        
        # Validar formato MAC (opcional)
        if new_mac and not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', new_mac):
            messagebox.showerror("Formato de MAC Inválido", "La dirección MAC debe tener el formato XX:XX:XX:XX:XX:XX (o guiones).")
            return

        found = False
        for i, host in enumerate(self.hosts_inventory):
            if host['ip_address'] == current_ip_in_table:
                # Comprobar si la nueva IP ya existe en otro host (excepto el que estamos editando)
                if new_ip != current_ip_in_table and any(h['ip_address'] == new_ip for idx, h in enumerate(self.hosts_inventory) if idx != i):
                    messagebox.showwarning("IP Duplicada", f"La nueva IP '{new_ip}' ya está asignada a otro host en el inventario.")
                    return
                
                self.hosts_inventory[i] = {
                    "ip_address": new_ip,
                    "hostname": new_hostname,
                    "mac_address": new_mac,
                    "os": new_os_name,
                    "description": new_description,
                    "brand": new_brand,             # Nuevo
                    "model": new_model,             # Nuevo
                    "processor": new_processor,     # Nuevo
                    "memory": new_memory,           # Nuevo
                    "disks": new_disks,             # Nuevo
                    "graphics": new_graphics,       # Nuevo
                    "display": new_display,         # Nuevo
                    "network_point": new_network_point, # Nuevo
                    "cable_length": new_cable_length,   # Nuevo
                    "office": new_office,           # Nuevo
                    "user": new_user,               # Nuevo
                    "department": new_department,   # Nuevo
                    "planta": new_planta            # Nuevo
                }
                found = True
                break
        if found:
            self.load_inventory_display() # Refrescar la tabla
            self.clear_inventory_entries() # Limpiar campos
            self.log_message(f"Host '{current_ip_in_table}' editado a '{new_ip}'.")
            app_logger.info(f"GUI: Host {current_ip_in_table} editado a {new_ip}.")
        else:
            messagebox.showerror("Error", "No se encontró el host seleccionado para editar en la lista de inventario.")
            app_logger.error(f"GUI: No se encontró el host {current_ip_in_table} para editar.")

    def delete_selected_host(self):

        """
        Borra el host seleccionado del inventario y de la base de datos.
        """
        selected_item_iid = self.current_selected_host_id # Usa el ID guardado
        print(f"DEBUG: delete_selected_host - Valor de current_selected_host_id al inicio: {selected_item_iid}") # DEBUG
        
        # 1. Comprobar si hay un host seleccionado
        if not selected_item_iid:
            messagebox.showwarning("Borrar Host", "Por favor, seleccione un host para borrar.")
            self.log_message("Intento de borrado: No hay host seleccionado para borrar.")
            print("DEBUG: delete_selected_host - selected_item_iid es None/vacío, se muestra advertencia.") # DEBUG
            return 
        selected_items = self.inventory_tree.selection() # Esto devuelve una tupla de iids de los elementos seleccionados

        if not selected_items:
            messagebox.showwarning("Eliminar Host", "Por favor, selecciona un host para eliminar.")
            return

        # Asumimos que solo se selecciona un elemento para eliminar, y que el iid del Treeview es el ID de la base de datos.
        selected_db_id = selected_items[0] 

        # Obtenemos los valores de las columnas del elemento seleccionado
        # Aquí estamos asumiendo que la IP Address es la segunda columna que muestras en tu Treeview
        # (es decir, el índice 1 en la tupla de valores, si la primera columna es Hostname, por ejemplo).
        # DEBERÁS AJUSTAR EL ÍNDICE [1] SI TU COLUMNA DE IP ESTÁ EN OTRA POSICIÓN.
        # Por ejemplo, si IP Address es la primera columna mostrada, sería item_values[0]
        
        item_values = self.inventory_tree.item(selected_db_id, 'values')
        
        # Verificamos que item_values no esté vacío y tenga suficientes elementos para la IP
        if not item_values:
            messagebox.showerror("Error al Eliminar", "No se pudieron obtener los datos del host seleccionado.")
            return
        
        # Si sabes que IP es la segunda columna (después de Hostname, por ejemplo)
        # Si tienes el Hostname como primera columna y IP como segunda, el índice sería 1
        # Si la IP es la primera columna visible, el índice sería 0
        
        # Para ser más seguros, si tienes definida la columna "IP Address" con su heading, puedes buscar el índice:
        # (Necesitaríamos cómo definiste tus columnas y headings en el Treeview para esto)
        
        # Por ahora, usaremos el índice 1 como ejemplo, ajústalo si es diferente:
        host_ip_to_delete = item_values[1] # <--- ¡AJUSTA ESTE ÍNDICE [1] SEGÚN LA POSICIÓN DE LA IP EN TUS COLUMNAS DEL TREEVIEW!

        confirm = messagebox.askyesno(
            "Confirmar Eliminación",
            f"¿Estás seguro de que quieres eliminar el host {host_ip_to_delete} del inventario?"
        )
        if confirm:
            # Aquí usamos el ID de la base de datos (selected_db_id) para eliminar el registro.
            if inventory_manager.delete_computer_by_id(selected_db_id):
                messagebox.showinfo("Eliminar Host", f"Host {host_ip_to_delete} eliminado con éxito.")
                self._load_inventory_into_tree() # Necesitarás una función para recargar el Treeview
            else:
                messagebox.showerror("Error al Eliminar", f"No se pudo eliminar el host {host_ip_to_delete} de la base de datos.")

    def save_inventory_to_file(self):
        """Guarda el inventario actual en el archivo hosts.json."""
        try:
            inventory_manager.save_hosts(self.hosts_inventory)
            self.log_message("Inventario guardado exitosamente en hosts.json.")
            app_logger.info("GUI: Inventario guardado en hosts.json.")
        except Exception as e:
            messagebox.showerror("Error al Guardar", f"No se pudo guardar el inventario: {e}")
            self.log_message(f"ERROR: No se pudo guardar el inventario: {e}")
            app_logger.exception("GUI: Error al guardar inventario.", exc_info=True)
            # ... (otras funciones existentes) ...

    def save_inventory_to_file(self):
        """Guarda el inventario actual en el archivo hosts.json."""
        inventory_manager.save_hosts(self.hosts_inventory)
        self.log_message("Inventario guardado correctamente en hosts.json.")
        app_logger.info("Inventario guardado.")

    def clear_inventory_entries(self):
        """Limpia todos los campos de entrada de la pestaña de inventario."""
        for entry_name in self.inventory_entries:
            self.inventory_entries[entry_name].delete(0, tk.END)
        # Limpiar también los campos nuevos si no están en self.inventory_entries (si los definiste por separado)
        # Aquí asumo que todos tus campos de inventario tienen un nombre como self.inventory_IP_entry, etc.
        # Y que la función `clear_inventory_entries` necesita ser actualizada para limpiar TODOS ellos.
        # Por ahora, me centraré en la nueva función de exportación.

    #  ---Exportar Inventario a CSV ---
    def export_inventory_to_csv(self):
        """
        Exporta los datos del inventario a un archivo CSV.
        Permite al usuario elegir la ubicación y el nombre del archivo.
        """
        if not self.hosts_inventory:
            messagebox.showinfo("Exportar Inventario", "El inventario está vacío. No hay datos para exportar.")
            app_logger.warning("GUI: Intento de exportar inventario vacío.")
            return

        # Abrir un diálogo para guardar el archivo
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("Archivos CSV", "*.csv"), ("Todos los archivos", "*.*")],
            title="Guardar Inventario como CSV"
        )

        if not file_path:  # El usuario canceló el diálogo
            self.log_message("Exportación de inventario CSV cancelada.")
            app_logger.info("GUI: Exportación de inventario CSV cancelada.")
            return

        try:
            # Obtener todos los nombres de las columnas que manejamos en el Treeview
            # Esto asegura que el CSV tenga los encabezados correctos y el orden.
            headers = [
                "ip_address", "hostname", "mac_address", "os", "description",
                "marca", "modelo", "procesador", "memoria", "discos", "grafica", "pantalla",
                "punto_de_red", "longitud_cable_utp", "despacho", "usuario_equipo", "departamento", "planta"
            ]
            
            # Abrir el archivo CSV en modo escritura
            with open(file_path, mode='w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=headers)
                
                writer.writeheader()  # Escribir la fila de encabezados

                # Escribir cada host del inventario
                for host_data in self.hosts_inventory:
                    # Crear un diccionario para la fila CSV, asegurando que todos los campos estén presentes
                    row_data = {header: host_data.get(header, "N/A") for header in headers}
                    writer.writerow(row_data)

            self.log_message(f"Inventario exportado a: {file_path}")
            messagebox.showinfo("Exportar Inventario", f"Inventario exportado exitosamente a:\n{file_path}")
            app_logger.info(f"GUI: Inventario exportado exitosamente a {file_path}.")

        except Exception as e:
            error_msg = f"Error al exportar inventario a CSV: {e}"
            self.log_message(f"ERROR: {error_msg}")
            messagebox.showerror("Error de Exportación", error_msg)
            app_logger.error(f"GUI: {error_msg}", exc_info=True)
    
    
    def clear_inventory_entries(self):
        """Limpia todos los campos de entrada de la pestaña de inventario."""
        self.inventory_ip_entry.delete(0, tk.END)
        self.inventory_hostname_entry.delete(0, tk.END)
        self.inventory_mac_entry.delete(0, tk.END)
        self.inventory_os_entry.delete(0, tk.END)
        self.inventory_desc_entry.delete(0, tk.END)
        
        # --- LIMPIAR NUEVOS CAMPOS ---
        self.inventory_brand_entry.delete(0, tk.END)
        self.inventory_model_entry.delete(0, tk.END)
        self.inventory_processor_entry.delete(0, tk.END)
        self.inventory_memory_entry.delete(0, tk.END)
        self.inventory_disks_entry.delete(0, tk.END)
        self.inventory_graphics_entry.delete(0, tk.END)
        self.inventory_display_entry.delete(0, tk.END)
        self.inventory_network_point_entry.delete(0, tk.END)
        self.inventory_cable_length_entry.delete(0, tk.END)
        self.inventory_office_entry.delete(0, tk.END)
        self.inventory_user_entry.delete(0, tk.END)
        self.inventory_department_entry.delete(0, tk.END)
        self.inventory_floor_entry.delete(0, tk.END)
        # --- FIN LIMPIEZA NUEVOS CAMPOS ---

        self.inventory_tree.selection_remove(self.inventory_tree.selection()) # Deseleccionar elemento en la tabla

    def on_inventory_select(self, event):
        """
        Callback que se ejecuta cuando se selecciona una fila en el Treeview del inventario.
        Precarga los datos de la fila en los campos de entrada para edición.
        """
        selected_item = self.inventory_tree.focus()
        if selected_item:
            values = self.inventory_tree.item(selected_item, "values")
            self.clear_inventory_entries() # Limpiar antes de insertar para evitar duplicados
            
            # Asegurarse de que 'values' tiene suficientes elementos antes de acceder a ellos
            # Los índices deben coincidir con el orden de las columnas en el Treeview
            self.inventory_ip_entry.insert(0, values[0] if len(values) > 0 else "")
            self.inventory_hostname_entry.insert(0, values[1] if len(values) > 1 else "")
            self.inventory_mac_entry.insert(0, values[2] if len(values) > 2 else "")
            self.inventory_os_entry.insert(0, values[3] if len(values) > 3 else "")
            self.inventory_desc_entry.insert(0, values[4] if len(values) > 4 else "")
            
            # --- PRECARGAR NUEVOS CAMPOS ---
            self.inventory_brand_entry.insert(0, values[5] if len(values) > 5 else "")
            self.inventory_model_entry.insert(0, values[6] if len(values) > 6 else "")
            self.inventory_processor_entry.insert(0, values[7] if len(values) > 7 else "")
            self.inventory_memory_entry.insert(0, values[8] if len(values) > 8 else "")
            self.inventory_disks_entry.insert(0, values[9] if len(values) > 9 else "")
            self.inventory_graphics_entry.insert(0, values[10] if len(values) > 10 else "")
            self.inventory_display_entry.insert(0, values[11] if len(values) > 11 else "")
            self.inventory_network_point_entry.insert(0, values[12] if len(values) > 12 else "")
            self.inventory_cable_length_entry.insert(0, values[13] if len(values) > 13 else "")
            self.inventory_office_entry.insert(0, values[14] if len(values) > 14 else "")
            self.inventory_user_entry.insert(0, values[15] if len(values) > 15 else "")
            self.inventory_department_entry.insert(0, values[16] if len(values) > 16 else "")
            self.inventory_floor_entry.insert(0, values[17] if len(values) > 17 else "")
            selected_item_iid = self.inventory_tree.focus() 
    
        
            selected_item_iid = self.inventory_tree.focus() 
        
        # ¡IMPORTANTE! Definimos item_values aquí, inicializado a una tupla vacía
        item_values = () 

        if not selected_item_iid:
            self.clear_inventory_entries()
            self.current_selected_host_id = None 
            self.log_message("Selección de inventario: Ningún host seleccionado.")
            print("DEBUG: on_inventory_select - No hay ítem seleccionado. current_selected_host_id = None") # DEBUG
            return

        # Guardamos el ID seleccionado aquí
        self.current_selected_host_id = selected_item_iid
        print(f"DEBUG: on_inventory_select - Ítem seleccionado: {selected_item_iid}. current_selected_host_id actualizado.") # DEBUG


    
    def log_message(self, message):
        """
        Envía un mensaje al logger, que será mostrado en la consola y en la GUI.
        """
        app_logger.info(message)

    def redirect_logger_output(self):
        """
        Redirige la salida del logger principal (app_logger) al widget de texto de la GUI.
        """
        # Eliminar cualquier CustomLogHandler existente para evitar que los mensajes se dupliquen
        for handler in list(app_logger.handlers): # Importante: usa app_logger, no self.logger
            if isinstance(handler, CustomLogHandler):
                app_logger.removeHandler(handler)

        # Crear y añadir el nuevo manejador personalizado para la GUI
        gui_handler = CustomLogHandler(self.log_text)
        app_logger.addHandler(gui_handler)
        app_logger.info("Salida del logger redirigida a la GUI.")

    def start_scan(self):
        """Inicia el proceso de escaneo de red en un hilo separado."""
        network_range = self.network_range_entry.get()
        if not network_range:
            messagebox.showwarning("Entrada Vacía", "Por favor, introduce un rango de red para escanear.")
            app_logger.warning("GUI: Intento de escaneo con rango de red vacío.")
            return

        self.log_message(f"Iniciando escaneo para el rango: {network_range}...")
        app_logger.info(f"GUI: Solicitando escaneo de red para {network_range}")

        # Limpiar resultados anteriores
        for item in self.scan_results_tree.get_children():
            self.scan_results_tree.delete(item)

        self.scan_button.config(state=tk.DISABLED) # Desactivar botón durante el escaneo

        # Ejecutar el escaneo en un hilo para no bloquear la GUI
        self.scan_thread = threading.Thread(target=self._run_scan_in_thread, args=(network_range,))
        self.scan_thread.daemon = True # Permite que el hilo termine cuando la aplicación principal lo haga
        self.scan_thread.start()

    def _run_scan_in_thread(self, network_range):
        """Función que ejecuta el escaneo de red en un hilo."""
        try:
            scanned_results = scanner.scan_network(network_range)
            # Poner los resultados en la cola para procesar en el hilo principal de la GUI
            self.scan_queue.put({"type": "results", "data": scanned_results})
            self.scan_queue.put({"type": "complete"}) # Señal de completado

        except Exception as e:
            error_msg = f"Error en el hilo de escaneo: {e}"
            app_logger.exception(error_msg) # Registra el error completo con traceback
            self.scan_queue.put({"type": "error", "message": error_msg})
            self.scan_queue.put({"type": "complete"})

    def process_scan_queue(self):
        """Procesa los mensajes de la cola del escaneo para actualizar la GUI."""
        try:
            while True:
                message = self.scan_queue.get_nowait() # Intenta obtener un mensaje sin bloquear
                
                if message["type"] == "results":
                    for host_data in message["data"]:
                        ip = host_data.get('ip_address', 'N/A')
                        status = host_data.get('status', 'N/A')
                        services = ", ".join(host_data.get('services', [])) if host_data.get('services') else "Ninguno"
                        self.scan_results_tree.insert("", tk.END, values=(ip, status, services))
                elif message["type"] == "progress":
                    self.log_message(f"Progreso de escaneo: {message['data']}")
                elif message["type"] == "error":
                    self.log_message(f"ERROR: {message['message']}")
                    messagebox.showerror("Error de Escaneo", message['message'])
                elif message["type"] == "complete":
                    self.log_message("Escaneo de red completado.")
                    self.scan_button.config(state=tk.NORMAL) # Reactivar botón
                    app_logger.info("GUI: Escaneo de red finalizado.")
                
                self.scan_queue.task_done() # Marca la tarea como completada en la cola
        except queue.Empty:
            pass # No hay más mensajes en la cola por ahora
        finally:
            self.master.after(100, self.process_scan_queue) # Vuelve a programar esta función para que se ejecute de nuevo

    # Dentro de la clase IntraScanAdminGUI:

    # Dentro de tu clase IntraScanAdminGUI, a la misma indentación que tus otros métodos:

    def _load_inventory_into_tree(self):
        """
        Carga el inventario de hosts (self.hosts_inventory) en el widget Treeview de inventario.
        Se asegura de usar el ID único del host como IID del Treeview para facilitar la gestión.
        """
        # 1. Limpiar el Treeview existente para evitar duplicados
        for item in self.inventory_tree.get_children():
            self.inventory_tree.delete(item)

        # 2. Recorrer la lista de hosts cargada en self.hosts_inventory
        # self.hosts_inventory debería ser una lista de diccionarios, donde cada diccionario es un host.
        # Asegúrate de que 'id' es la clave para el ID único del host en tus datos.
        for host in self.hosts_inventory:
            # **PASO CRÍTICO:** Usar el ID del host como el IID del Treeview.
            # Esto es lo que permite que selected_item_iid en delete_selected_host
            # sea el ID real de la base de datos.
            host_id = host.get('id')
            if host_id is None:
                self.log_message(f"Advertencia: Host sin ID único detectado: {host.get('ip_address', 'N/A')}. No se agregará al Treeview.")
                continue # Saltar hosts sin ID

            item_id = str(host_id) # El IID debe ser una cadena

            # Obtener los valores para las columnas del Treeview.
            # ¡IMPORTANTE! El ORDEN de estos valores debe COINCIDIR exactamente
            # con el orden de las columnas que definiste para tu Treeview
            # en create_inventory_tab_widgets (ej. IP, Hostname, MAC Address, etc.)
            values_tuple = (
                host.get('ip_address', ''),
                host.get('hostname', ''),
                host.get('mac_address', ''),
                host.get('os', ''),
                host.get('description', ''),
                host.get('brand', ''),
                host.get('model', ''),
                host.get('processor', ''),
                host.get('memory', ''),
                host.get('disks', ''),
                host.get('graphics', ''),
                host.get('display', ''),
                host.get('network_point', ''),
                host.get('cable_length', ''),
                host.get('office', ''),
                host.get('user', ''),
                host.get('department', ''),
                host.get('floor', '')
            )
            
            # Insertar la fila en el Treeview
            self.inventory_tree.insert('', tk.END, iid=item_id, values=values_tuple)
            
        self.log_message(f"Inventario cargado en la tabla GUI: {len(self.hosts_inventory)} hosts.")

    def populate_remote_host_dropdown(self):
        """
        Rellena el desplegable de selección de host remoto con las IPs del inventario.
        """
        # Asegúrate de que 'self.remote_host_selection' y 'self.remote_host_dropdown'
        # estén inicializados en create_remote_tab_widgets.

        if not hasattr(self, 'remote_host_selection') or not hasattr(self, 'remote_host_dropdown'):
            self.log_message("Advertencia: Componentes del desplegable de host remoto no inicializados.")
            return

        host_ips = [host['ip_address'] for host in self.hosts_inventory if 'ip_address' in host]

        # Necesitas un OptionMenu o Combobox para esto.
        # Si usas ttk.Combobox:
        self.remote_host_dropdown['values'] = host_ips
        if host_ips:
            self.remote_host_dropdown.set(host_ips[0]) # Seleccionar el primero por defecto
        else:
            self.remote_host_dropdown.set("") # Limpiar si no hay hosts

        self.log_message("GUI: Desplegable de hosts remotos actualizado.")    

if __name__ == "__main__":
    root = tk.Tk()
    app = IntraScanAdminGUI(root)
    root.mainloop()