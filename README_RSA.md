# Encriptador/Desencriptador RSA

Scripts en Python para encriptar y desencriptar archivos usando algoritmo RSA con cifrado híbrido (RSA + AES).

## Requisitos

Instalar las librerías necesarias:

```bash
pip install cryptography PyQt6
```

## �️ Interfaz Gráfica (RECOMENDADO)

### Ejecutar la aplicación con interfaz gráfica:

```bash
python encriptador_ui.py
```

La interfaz incluye:
- **Pestaña de Encriptación**: Selecciona un archivo, haz clic en "Examinar", y luego en "Encriptar Archivo"
- **Pestaña de Desencriptación**: Selecciona el archivo encriptado y la llave privada, luego haz clic en "Desencriptar Archivo"
- **Barra de progreso**: Visualiza el progreso de cada operación
- **Auto-guardado inteligente**: Los archivos se guardan en la misma carpeta del archivo original
  - Archivos encriptados: `enc_nombrearchivo`
  - Archivos desencriptados: `dec_nombrearchivo`
  - Llaves RSA: `llave_privada.pem` y `llave_publica.pem`

## Uso del Encriptador (Línea de comandos)

### 1. Editar el script `encriptar_rsa.py`

Abre el archivo y modifica la ruta del archivo a encriptar:

```python
ARCHIVO_A_ENCRIPTAR = r"C:\ruta\al\tu\archivo.txt"
```

### 2. Ejecutar el script

```bash
python encriptar_rsa.py
```

### 3. Archivos generados (en la misma carpeta del script):

- **llave_privada.pem** - Para desencriptar (¡MUY IMPORTANTE! Guárdala en lugar seguro)
- **llave_publica.pem** - Para encriptar otros archivos
- **archivo.txt.encrypted** - Tu archivo encriptado

## Uso del Desencriptador

### 1. Editar el script `desencriptar_rsa.py`

Abre el archivo y especifica:

```python
ARCHIVO_ENCRIPTADO = r"archivo.txt.encrypted"  # Nombre del archivo a desencriptar
LLAVE_PRIVADA = r"llave_privada.pem"           # Ruta de la llave privada
```

### 2. Ejecutar el script

```bash
python desencriptar_rsa.py
```

### 3. Resultado:

Se generará el archivo desencriptado con el nombre: `archivo.txt.decrypted`

## Cómo funciona

El sistema usa **cifrado híbrido** porque RSA tiene limitaciones de tamaño:

1. **Encriptación:**
   - Se genera una clave AES aleatoria
   - El archivo se encripta con AES (rápido, sin límite de tamaño)
   - La clave AES se encripta con RSA (seguro)
   - Todo se guarda en un solo archivo

2. **Desencriptación:**
   - Se usa la llave privada RSA para recuperar la clave AES
   - Se usa la clave AES para desencriptar el archivo
   - Se recupera el archivo original

## Seguridad

- **RSA 2048 bits**: Estándar de seguridad actual
- **AES (Fernet)**: Cifrado simétrico de alta seguridad
- **SHA-256**: Para funciones hash

## IMPORTANTE

1. **Guarda la llave privada** (`llave_privada.pem`) en un lugar MUY seguro
2. Sin la llave privada, **NO podrás recuperar tus archivos**
3. No compartas la llave privada con nadie
4. La llave pública puede compartirse para que otros te envíen archivos encriptados

## Estructura de archivos esperada

```
tu_carpeta/
├── encriptador_ui.py          (Interfaz gráfica - RECOMENDADO)
├── encriptar_rsa.py           (Script de línea de comandos)
├── desencriptar_rsa.py        (Script de línea de comandos)
├── README.md
└── (después de ejecutar)
    ├── llave_privada.pem
    ├── llave_publica.pem
    ├── enc_archivo.txt        (archivo encriptado)
    └── dec_enc_archivo.txt    (archivo desencriptado)
```

## Solución de problemas

**Error: "No module named 'cryptography'" o "No module named 'PyQt6'"**
```bash
pip install cryptography PyQt6
```

**Error: "El archivo no existe"**
- Verifica que la ruta del archivo sea correcta
- Usa `r` antes de las comillas para rutas en Windows: `r"C:\ruta\archivo.txt"`

**Error: "La llave privada no corresponde"**
- Asegúrate de usar la misma llave privada que se generó al encriptar
- Verifica que los archivos no estén corruptos

## Licencia

Libre uso para fines educativos y personales.
