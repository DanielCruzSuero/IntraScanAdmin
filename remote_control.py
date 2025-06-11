# remote_control.py

from wakeonlan import send_magic_packet

def send_wol_packet(mac_address):
    """
    Envía un paquete mágico Wake-on-LAN a la dirección MAC especificada.
    :param mac_address: La dirección MAC del equipo a encender (ej. "AA:BB:CC:DD:EE:FF").
    """
    try:
        
        send_magic_packet(mac_address)
        print(f"Paquete mágico WoL enviado a la MAC: {mac_address}. El equipo debería encenderse si WoL está configurado.")
    except Exception as e:
        print(f"Error al enviar el paquete WoL a {mac_address}: {e}")

if __name__ == "__main__":
    print("--- Probando Wake-on-LAN ---")
    
    target_mac = "XX:XX:XX:XX:XX:XX" # <-- ¡CAMBIAR ESTO POR UNA MAC REAL!

    if target_mac == "XX:XX:XX:XX:XX:XX":
        print("ADVERTENCIA: Por favor, reemplaza 'XX:XX:XX:XX:XX:XX' con una MAC real para probar.")
        print("Para que WoL funcione, el equipo de destino debe tener WoL habilitado en su BIOS/UEFI y adaptador de red.")
    else:
        send_wol_packet(target_mac)