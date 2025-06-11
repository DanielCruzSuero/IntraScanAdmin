# Escaner ip´s 
import subprocess
import platform


# Funcion de ping enviamos un solo ping  con un segundo de tiempo de espera
def ping_host (ip_address, count =1, timeout =1):

    # verificar plataforma de ejecucion

    param_n = "-n" if platform.system().lower() == "windows" else "-c"
    param_w = "-w" if platform.system().lower() == "windows" else "-W"

    # definir el comando ping a utilizar

    ping_command = ["ping", param_n, str(count), ip_address]

    if platform.system().lower() == "windows":
        # Convertir segundos a milisegundos
        ping_command.extend(["-w", str(timeout * 1000)]) 
    else:
        ping_command.extend([param_w, str(timeout)])

    # Ejecucion de ping

    try:
        salida = subprocess.run(ping_command, capture_output=True, text=True, check=False)
        if salida.returncode == 0:
            return True
        else:
            return False
    except FileNotFoundError:
        print ("No se encuentra comando ping en el sistema de archivos")
        return False
    except Exception as e:
        print (f"Fallo en la realizacion del comando ping a {ip_address}, error {e}")


if __name__ == "__main__":
    print ("Test de ping")

    ip1 = "8.8.8.8"
    ip2 = " 10.0.0.1"

    print (f"Realizando ping a {ip1}")
    if ping_host(ip1):
        print (f"Ip {ip1} esta en linea")
    else:
        print (f"Ip {ip1} esta fuera de linea")

    print (f"Realizando ping a {ip2}")
    if ping_host(ip2):
        print (f"Ip {ip2} esta en linea")
    else:
        print (f"Ip {ip2} esta fuera de linea")
