#!/usr/bin/env python3
"""
Script para encriptar archivos usando RSA
Genera llaves pública y privada, y encripta un archivo
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# ============================================
# CONFIGURACIÓN: Ruta del archivo a encriptar
# ============================================
ARCHIVO_A_ENCRIPTAR = r"C:\ruta\al\archivo.txt"

def generar_llaves():
    """Genera un par de llaves RSA (pública y privada)"""
    print("Generando llaves RSA...")
    
    # Generar llave privada
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Obtener llave pública
    public_key = private_key.public_key()
    
    # Serializar llave privada
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serializar llave pública
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem, private_key, public_key


def guardar_llaves(private_pem, public_pem, directorio_script):
    """Guarda las llaves en archivos PEM en el directorio del script"""
    ruta_privada = os.path.join(directorio_script, "llave_privada.pem")
    ruta_publica = os.path.join(directorio_script, "llave_publica.pem")
    
    with open(ruta_privada, "wb") as f:
        f.write(private_pem)
    print(f" Llave privada guardada: {ruta_privada}")
    
    with open(ruta_publica, "wb") as f:
        f.write(public_pem)
    print(f" Llave pública guardada: {ruta_publica}")


def encriptar_archivo_hibrido(ruta_archivo, public_key, directorio_script):
    """
    Encripta un archivo usando cifrado híbrido (RSA + AES)
    RSA solo puede encriptar datos pequeños, por eso usamos AES para el archivo
    y RSA para encriptar la clave AES
    """
    print(f"\nEncriptando archivo: {ruta_archivo}")
    
    # Verificar que el archivo existe
    if not os.path.exists(ruta_archivo):
        raise FileNotFoundError(f"El archivo no existe: {ruta_archivo}")
    
    # Leer el contenido del archivo
    with open(ruta_archivo, "rb") as f:
        datos_originales = f.read()
    
    print(f"  Tamaño del archivo: {len(datos_originales)} bytes")
    
    # Generar una clave AES simétrica
    clave_aes = Fernet.generate_key()
    cipher = Fernet(clave_aes)
    
    # Encriptar el archivo con AES
    datos_encriptados_aes = cipher.encrypt(datos_originales)
    
    # Encriptar la clave AES con RSA
    clave_aes_encriptada = public_key.encrypt(
        clave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Guardar el archivo encriptado
    nombre_original = os.path.basename(ruta_archivo)
    ruta_encriptada = os.path.join(directorio_script, f"{nombre_original}.encrypted")
    
    # Formato: [tamaño de clave RSA (4 bytes)] + [clave AES encriptada] + [datos AES]
    with open(ruta_encriptada, "wb") as f:
        # Escribir el tamaño de la clave RSA encriptada (para saber dónde termina)
        f.write(len(clave_aes_encriptada).to_bytes(4, byteorder='big'))
        # Escribir la clave AES encriptada con RSA
        f.write(clave_aes_encriptada)
        # Escribir los datos del archivo encriptados con AES
        f.write(datos_encriptados_aes)
    
    print(f"Archivo encriptado guardado: {ruta_encriptada}")
    return ruta_encriptada


def main():
    """Función principal"""
    print("=" * 60)
    print("  ENCRIPTADOR RSA DE ARCHIVOS")
    print("=" * 60)
    
    # Obtener directorio donde está el script
    directorio_script = os.path.dirname(os.path.abspath(__file__))
    print(f"\nDirectorio del script: {directorio_script}")
    
    try:
        # 1. Generar llaves
        private_pem, public_pem, private_key, public_key = generar_llaves()
        
        # 2. Guardar llaves en el directorio del script
        guardar_llaves(private_pem, public_pem, directorio_script)
        
        # 3. Encriptar el archivo
        archivo_encriptado = encriptar_archivo_hibrido(
            ARCHIVO_A_ENCRIPTAR,
            public_key,
            directorio_script
        )
        
        print("\n" + "=" * 60)
        print(" PROCESO COMPLETADO EXITOSAMENTE")
        print("=" * 60)
        print("\nArchivos generados:")
        print(f"  1. llave_privada.pem  (para desencriptar)")
        print(f"  2. llave_publica.pem  (para encriptar)")
        print(f"  3. {os.path.basename(archivo_encriptado)}")
        print("\nIMPORTANTE: Guarda 'llave_privada.pem' en un lugar seguro")
        print("  Sin ella NO podrás desencriptar el archivo.")
        
    except FileNotFoundError as e:
        print(f"\n ERROR: {e}")
        print("\nPor favor, edita la variable ARCHIVO_A_ENCRIPTAR en el script")
        print("con la ruta correcta de tu archivo.")
    except Exception as e:
        print(f"\n ERROR: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
