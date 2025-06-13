import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import sys
import os
import logging
import threading
import queue
import re
import csv


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
            entry_widget.insert(0, value)

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

if __name__ == "__main__":
    root = tk.Tk()
    app = IntraScanAdminGUI(root)
    root.mainloop()