#!/usr/bin/env python3
"""
Script para desencriptar archivos encriptados con RSA
Usa la llave privada para recuperar el archivo original
"""

import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# ============================================
# CONFIGURACIÓN: Rutas de archivos
# ============================================
ARCHIVO_ENCRIPTADO = r"archivo.txt.encrypted"  # Nombre del archivo encriptado
LLAVE_PRIVADA = r"llave_privada.pem"            # Ruta a la llave privada


def cargar_llave_privada(ruta_llave):
    """Carga la llave privada desde un archivo PEM"""
    print(f"Cargando llave privada: {ruta_llave}")
    
    if not os.path.exists(ruta_llave):
        raise FileNotFoundError(f"No se encontró la llave privada: {ruta_llave}")
    
    with open(ruta_llave, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    print("Llave privada cargada correctamente")
    return private_key


def desencriptar_archivo(ruta_encriptada, private_key, directorio_salida):
    """Desencripta un archivo que fue encriptado con el sistema híbrido RSA+AES"""
    print(f"\nDesencriptando archivo: {ruta_encriptada}")
    
    if not os.path.exists(ruta_encriptada):
        raise FileNotFoundError(f"El archivo encriptado no existe: {ruta_encriptada}")
    
    # Leer el archivo encriptado
    with open(ruta_encriptada, "rb") as f:
        # Leer el tamaño de la clave RSA encriptada
        tamano_clave_rsa = int.from_bytes(f.read(4), byteorder='big')
        
        # Leer la clave AES encriptada con RSA
        clave_aes_encriptada = f.read(tamano_clave_rsa)
        
        # Leer los datos del archivo encriptados con AES
        datos_encriptados_aes = f.read()
    
    print(f"  Tamaño del archivo encriptado: {os.path.getsize(ruta_encriptada)} bytes")
    
    # Desencriptar la clave AES usando RSA
    clave_aes = private_key.decrypt(
        clave_aes_encriptada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Desencriptar el archivo usando AES
    cipher = Fernet(clave_aes)
    datos_originales = cipher.decrypt(datos_encriptados_aes)
    
    # Guardar el archivo desencriptado
    nombre_archivo = os.path.basename(ruta_encriptada)
    if nombre_archivo.endswith('.encrypted'):
        nombre_archivo = nombre_archivo[:-10]  # Remover '.encrypted'
    
    nombre_salida = f"{nombre_archivo}.decrypted"
    ruta_salida = os.path.join(directorio_salida, nombre_salida)
    
    with open(ruta_salida, "wb") as f:
        f.write(datos_originales)
    
    print(f"Archivo desencriptado guardado: {ruta_salida}")
    print(f"  Tamaño del archivo original: {len(datos_originales)} bytes")
    
    return ruta_salida


def main():
    """Función principal"""
    print("=" * 60)
    print("  DESENCRIPTADOR RSA DE ARCHIVOS")
    print("=" * 60)
    
    # Obtener directorio donde está el script
    directorio_script = os.path.dirname(os.path.abspath(__file__))
    print(f"\nDirectorio del script: {directorio_script}")
    
    # Convertir rutas relativas a absolutas
    ruta_encriptada = os.path.join(directorio_script, ARCHIVO_ENCRIPTADO)
    ruta_llave = os.path.join(directorio_script, LLAVE_PRIVADA)
    
    try:
        # 1. Cargar llave privada
        private_key = cargar_llave_privada(ruta_llave)
        
        # 2. Desencriptar el archivo
        archivo_desencriptado = desencriptar_archivo(
            ruta_encriptada,
            private_key,
            directorio_script
        )
        
        print("\n" + "=" * 60)
        print(" DESENCRIPTACIÓN COMPLETADA EXITOSAMENTE")
        print("=" * 60)
        print(f"\nArchivo desencriptado: {os.path.basename(archivo_desencriptado)}")
        
    except FileNotFoundError as e:
        print(f"\n ERROR: {e}")
        print("\nAsegúrate de que:")
        print("  1. El archivo encriptado existe")
        print("  2. La llave privada (llave_privada.pem) está en el directorio")
        print("\nPuedes editar las variables ARCHIVO_ENCRIPTADO y LLAVE_PRIVADA")
        print("en el script para especificar las rutas correctas.")
    except Exception as e:
        print(f"\n ERROR durante la desencriptación: {e}")
        print("\n⚠  Posibles causas:")
        print("  - La llave privada no corresponde al archivo encriptado")
        print("  - El archivo encriptado está corrupto")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
