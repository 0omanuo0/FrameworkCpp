import requests
import time
import statistics
from concurrent.futures import ThreadPoolExecutor

# Configuración
url = "https://localhost:8445/portfolio"
num_requests = 1000  # Número total de solicitudes
num_threads = 15    # Número de hilos concurrentes
verify_ssl = False  # Cambiar a True si tienes un certificado SSL válido
# ignore warning for self-signed certificate
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Función para realizar una solicitud
def make_request(request_id):
    try:
        start_time = time.time()
        response = requests.get(url, verify=verify_ssl)
        elapsed_time = time.time() - start_time
        return (request_id, response.status_code, elapsed_time)
    except requests.exceptions.RequestException as e:
        return (request_id, None, str(e))

# Ejecutar las solicitudes concurrentemente
def run_tests():
    print(f"Realizando {num_requests} solicitudes a {url} con {num_threads} hilos...\n")
    response_times = []

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        # Crear y enviar las tareas
        futures = [executor.submit(make_request, i) for i in range(1, num_requests + 1)]

        for future in futures:
            request_id, status_code, result = future.result()
            if isinstance(result, float):  # Éxito
                response_times.append(result)
                print(f"Solicitud {request_id}: Código {status_code}, Tiempo: {result:.4f}s")
            else:  # Error
                print(f"Solicitud {request_id}: Error - {result}")

    # Resumen de rendimiento
    if response_times:
        print("\n--- Resumen de la Prueba ---")
        print(f"Número de solicitudes: {num_requests}")
        print(f"Tiempo mínimo: {min(response_times):.4f}s")
        print(f"Tiempo máximo: {max(response_times):.4f}s")
        print(f"Tiempo promedio: {statistics.mean(response_times):.4f}s")
        print(f"Desviación estándar: {statistics.stdev(response_times):.4f}s")
    else:
        print("No se completaron solicitudes exitosas.")

if __name__ == "__main__":
    run_tests()
