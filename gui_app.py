import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import sys
import os
import logging
import threading
import queue
import re # Para validación de IP/MAC si es necesario

# Asegúrate de que las rutas a tus módulos sean correctas
import scanner
import remote_control
import inventory_manager
from logger_config import app_logger

class IntraScanAdminGUI:
    def __init__(self, master):
        self.master = master
        master.title("IntraScan & Admin GUI")
        master.geometry("1100x750") # Un poco más grande para los nuevos campos
        master.resizable(True, True)

        self.style = ttk.Style()
        self.style.theme_use('clam')

        self.scan_queue = queue.Queue()
        self.master.after(100, self.process_scan_queue)

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

        # Cargar inventario al inicio
        self.hosts_inventory = inventory_manager.load_hosts()
        app_logger.info(f"Inventario cargado al inicio: {len(self.hosts_inventory)} hosts.")
        
        # Rellenar el desplegable de hosts remotos al inicio de la aplicación
        self.populate_remote_host_dropdown()

        # Pestaña de Gestión de Inventario
        self.inventory_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.inventory_tab, text="Gestión de Inventario")
        self.create_inventory_tab_widgets(self.inventory_tab)

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
        
        # Botón para obtener información remota (nuevo)
        self.get_remote_info_button = ttk.Button(host_selection_frame, text="Obtener Info Remota", command=self.get_remote_host_info)
        self.get_remote_info_button.grid(row=1, column=2, padx=5, pady=5)


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
        # --- FIN NUEVOS CAMPOS ---


        # Frame para los botones de acción del inventario
        button_frame = ttk.Frame(tab)
        button_frame.pack(padx=10, pady=5, fill="x")

        ttk.Button(button_frame, text="Añadir Host", command=self.add_host_to_inventory).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Aplicar Cambios", command=self.edit_selected_host).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Eliminar Host", command=self.delete_selected_host).pack(side="left", padx=5)
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
                display_name = f"{ip} ({hostname})" if hostname else ip
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

    def get_remote_host_info(self):
        """
        Función placeholder para obtener información remota del host.
        Esta será la base para la futura funcionalidad de auditoría.
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
        
        # Aquí es donde integraríamos la lógica real para obtener la información.
        # Por ahora, es un placeholder.
        messagebox.showinfo("Funcionalidad Pendiente", 
                            f"La función para obtener información remota de '{target_ip_or_hostname}' está en desarrollo.\n"
                            "Se utilizarán las credenciales proporcionadas.")
        
        # Puedes iniciar un hilo aquí que haga la consulta real y luego actualice la GUI.
        # threading.Thread(target=self._perform_remote_info_gathering, args=(target_ip_or_hostname, username, password)).start()

    # def _perform_remote_info_gathering(self, target, username, password):
    #     """
    #     Función que ejecutará la recolección de información remota en un hilo separado.
    #     Esto es un ESQUELETO. La lógica real iría aquí.
    #     """
    #     try:
    #         # Lógica para usar pypsrp o WMI para obtener los datos
    #         # Ejemplo:
    #         # from pypsrp.powershell import PowerShell
    #         # from pypsrp.wsman import WSMan
    #         # with WSMan(target, auth_method='negotiate', username=username, password=password) as wsman:
    #         #     with PowerShell(wsman) as ps:
    #         #         ps.add_cmd("Get-ComputerInfo")
    #         #         ps.invoke()
    #         #         result = ps.output_streams.stdout
    #         #         # Parsear result y actualizar la GUI
    #         #         self.master.after(0, lambda: self._update_inventory_from_remote_data(result))
    #         
    #         retrieved_data = {
    #             "ip_address": target,
    #             "hostname": "HOSTNAME_REMOTO", # Reemplazar con datos reales
    #             "mac_address": "AA:BB:CC:DD:EE:FF",
    #             "os": "Windows 10 Pro",
    #             "description": "Obtenido remotamente",
    #             "brand": "Dell",
    #             "model": "OptiPlex 7010",
    #             "processor": "Intel Core i7-3770",
    #             "memory": "16GB DDR3",
    #             "disks": "256GB SSD, 1TB HDD",
    #             "graphics": "Intel HD Graphics 4000",
    #             "display": "Dell 24\" (x2)",
    #             "network_point": "A12",
    #             "cable_length": "5m",
    #             "office": "Despacho 101",
    #             "user": "d.fernandez",
    #             "department": "IT",
    #             "planta": "1"
    #         }
    #         self.master.after(0, lambda: self._update_inventory_from_remote_data(retrieved_data))
    #         self.log_message(f"Información de {target} obtenida y lista para precargar.")
    #         app_logger.info(f"GUI: Información remota de {target} obtenida.")
    #     except Exception as e:
    #         error_msg = f"Error al obtener información remota de {target}: {e}"
    #         self.log_message(f"ERROR: {error_msg}")
    #         app_logger.exception(f"GUI: {error_msg}")
    #         self.master.after(0, lambda: messagebox.showerror("Error de Recolección", error_msg))

    # def _update_inventory_from_remote_data(self, data):
    #     """Actualiza los campos de entrada del inventario con los datos obtenidos remotamente."""
    #     self.clear_inventory_entries()
    #     self.inventory_ip_entry.insert(0, data.get("ip_address", ""))
    #     self.inventory_hostname_entry.insert(0, data.get("hostname", ""))
    #     self.inventory_mac_entry.insert(0, data.get("mac_address", ""))
    #     self.inventory_os_entry.insert(0, data.get("os", ""))
    #     self.inventory_desc_entry.insert(0, data.get("description", ""))
    #     self.inventory_brand_entry.insert(0, data.get("brand", ""))
    #     self.inventory_model_entry.insert(0, data.get("model", ""))
    #     self.inventory_processor_entry.insert(0, data.get("processor", ""))
    #     self.inventory_memory_entry.insert(0, data.get("memory", ""))
    #     self.inventory_disks_entry.insert(0, data.get("disks", ""))
    #     self.inventory_graphics_entry.insert(0, data.get("graphics", ""))
    #     self.inventory_display_entry.insert(0, data.get("display", ""))
    #     self.inventory_network_point_entry.insert(0, data.get("network_point", ""))
    #     self.inventory_cable_length_entry.insert(0, data.get("cable_length", ""))
    #     self.inventory_office_entry.insert(0, data.get("office", ""))
    #     self.inventory_user_entry.insert(0, data.get("user", ""))
    #     self.inventory_department_entry.insert(0, data.get("department", ""))
    #     self.inventory_floor_entry.insert(0, data.get("planta", ""))
    #     self.notebook.select(self.inventory_tab) # Cambiar a la pestaña de inventario


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
        """Elimina el host seleccionado del inventario."""
        selected_item = self.inventory_tree.focus()
        if not selected_item:
            messagebox.showwarning("Ningún Host Seleccionado", "Por favor, selecciona un host de la tabla para eliminar.")
            return
        host_ip_to_delete = self.inventory_tree.item(selected_item, "iid") # Obtener la IP del elemento seleccionado
        
        if messagebox.askyesno("Confirmar Eliminación", f"¿Estás seguro de que quieres eliminar el host '{host_ip_to_delete}'?"):
            self.hosts_inventory = [host for host in self.hosts_inventory if host['ip_address'] != host_ip_to_delete]
            self.load_inventory_display() # Refrescar la tabla
            self.clear_inventory_entries() # Limpiar campos
            self.log_message(f"Host '{host_ip_to_delete}' eliminado del inventario.")
            app_logger.info(f"GUI: Host {host_ip_to_delete} eliminado.")

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
            # --- FIN PRECARGA NUEVOS CAMPOS ---


    def log_message(self, message):
        """Añade un mensaje al cuadro de texto de registro de la GUI."""
        self.log_text.configure(state='normal')
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END) # Scroll automático al final
        self.log_text.configure(state='disabled')

    def redirect_logger_output(self):
        """Redirige la salida del logger a la caja de texto de la GUI."""
        class TextHandler(logging.Handler):
            def __init__(self, text_widget):
                super().__init__()
                self.text_widget = text_widget
                self.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

            def emit(self, record):
                msg = self.format(record)
                # Ejecutar la inserción en el hilo principal de Tkinter
                self.text_widget.after(0, lambda: self._insert_text(msg + "\n"))

            def _insert_text(self, text):
                self.text_widget.configure(state='normal')
                self.text_widget.insert(tk.END, text)
                self.text_widget.see(tk.END)
                self.text_widget.configure(state='disabled')

        # Remover handlers existentes para evitar duplicados si se recarga el módulo
        for handler in app_logger.handlers[:]:
            if isinstance(handler, logging.StreamHandler) or (hasattr(handler, 'name') and handler.name == 'text_handler'):
                app_logger.removeHandler(handler)

        text_handler = TextHandler(self.log_text)
        text_handler.setLevel(logging.INFO) # Nivel de log para mostrar en la GUI
        app_logger.addHandler(text_handler)
        text_handler.name = 'text_handler' # Darle un nombre para fácil identificación

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

        # Ejecutar el escaneo en un hilo para no congelar la GUI
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

if __name__ == "__main__":
    root = tk.Tk()
    app = IntraScanAdminGUI(root)
    root.mainloop()