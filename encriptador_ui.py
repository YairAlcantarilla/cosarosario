#!/usr/bin/env python3


import os
import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel, QProgressBar, QTabWidget,
    QFileDialog, QMessageBox
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


# ============================================
# WORKERS PARA PROCESAR EN SEGUNDO PLANO
# ============================================

class EncriptarWorker(QThread):
    """Worker para encriptar archivos sin bloquear la UI"""
    progreso = pyqtSignal(int)
    terminado = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, ruta_archivo):
        super().__init__()
        self.ruta_archivo = ruta_archivo
    
    def run(self):
        try:
            self.progreso.emit(10)
            
            # Generar llaves RSA
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            self.progreso.emit(25)
            
            # Obtener directorio del archivo original
            directorio_archivo = os.path.dirname(self.ruta_archivo)
            nombre_archivo = os.path.basename(self.ruta_archivo)
            
            # Guardar llaves en el mismo directorio que el archivo
            self._guardar_llaves(private_key, public_key, directorio_archivo)
            self.progreso.emit(40)
            
            # Leer archivo
            with open(self.ruta_archivo, "rb") as f:
                datos_originales = f.read()
            self.progreso.emit(50)
            
            # Generar clave AES y encriptar datos
            clave_aes = Fernet.generate_key()
            cipher = Fernet(clave_aes)
            datos_encriptados_aes = cipher.encrypt(datos_originales)
            self.progreso.emit(70)
            
            # Encriptar la clave AES con RSA
            clave_aes_encriptada = public_key.encrypt(
                clave_aes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.progreso.emit(85)
            
            # Guardar archivo encriptado con prefijo enc_
            ruta_encriptada = os.path.join(directorio_archivo, f"enc_{nombre_archivo}")
            
            with open(ruta_encriptada, "wb") as f:
                f.write(len(clave_aes_encriptada).to_bytes(4, byteorder='big'))
                f.write(clave_aes_encriptada)
                f.write(datos_encriptados_aes)
            
            self.progreso.emit(100)
            self.terminado.emit(ruta_encriptada)
            
        except Exception as e:
            self.error.emit(str(e))
    
    def _guardar_llaves(self, private_key, public_key, directorio):
        """Guarda las llaves en el directorio especificado"""
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(os.path.join(directorio, "llave_privada.pem"), "wb") as f:
            f.write(private_pem)
        
        with open(os.path.join(directorio, "llave_publica.pem"), "wb") as f:
            f.write(public_pem)


class DesencriptarWorker(QThread):
    """Worker para desencriptar archivos sin bloquear la UI"""
    progreso = pyqtSignal(int)
    terminado = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, ruta_archivo, ruta_llave_privada):
        super().__init__()
        self.ruta_archivo = ruta_archivo
        self.ruta_llave_privada = ruta_llave_privada
    
    def run(self):
        try:
            self.progreso.emit(10)
            
            # Cargar llave privada
            with open(self.ruta_llave_privada, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            self.progreso.emit(30)
            
            # Leer archivo encriptado
            with open(self.ruta_archivo, "rb") as f:
                tamano_clave_rsa = int.from_bytes(f.read(4), byteorder='big')
                clave_aes_encriptada = f.read(tamano_clave_rsa)
                datos_encriptados_aes = f.read()
            self.progreso.emit(50)
            
            # Desencriptar clave AES
            clave_aes = private_key.decrypt(
                clave_aes_encriptada,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.progreso.emit(70)
            
            # Desencriptar datos
            cipher = Fernet(clave_aes)
            datos_originales = cipher.decrypt(datos_encriptados_aes)
            self.progreso.emit(85)
            
            # Guardar archivo desencriptado en el mismo directorio
            directorio_archivo = os.path.dirname(self.ruta_archivo)
            nombre_archivo = os.path.basename(self.ruta_archivo)
            
            # Remover prefijo enc_ si existe
            if nombre_archivo.startswith("enc_"):
                nombre_archivo = nombre_archivo[4:]
            
            nombre_salida = f"dec_{nombre_archivo}"
            ruta_salida = os.path.join(directorio_archivo, nombre_salida)
            
            with open(ruta_salida, "wb") as f:
                f.write(datos_originales)
            
            self.progreso.emit(100)
            self.terminado.emit(ruta_salida)
            
        except Exception as e:
            self.error.emit(str(e))


# ============================================
# INTERFAZ GRÁFICA PRINCIPAL
# ============================================

class EncriptadorUI(QMainWindow):
    """Ventana principal de la aplicación"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Encriptador/Desencriptador RSA")
        self.setMinimumSize(700, 400)
        
        # Widget central con pestañas
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        # Crear pestañas
        self.tab_encriptar = self._crear_tab_encriptar()
        self.tab_desencriptar = self._crear_tab_desencriptar()
        
        self.tabs.addTab(self.tab_encriptar, "🔒 Encriptar")
        self.tabs.addTab(self.tab_desencriptar, "🔓 Desencriptar")
        
        # Workers
        self.worker_encriptar = None
        self.worker_desencriptar = None
    
    def _crear_tab_encriptar(self):
        """Crea la pestaña de encriptación"""
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Título
        titulo = QLabel("Encriptar Archivo")
        titulo.setStyleSheet("font-size: 18px; font-weight: bold; color: #2c3e50;")
        layout.addWidget(titulo)
        
        # Sección de selección de archivo
        layout.addWidget(QLabel("Archivo a encriptar:"))
        
        file_layout = QHBoxLayout()
        self.input_archivo_enc = QLineEdit()
        self.input_archivo_enc.setPlaceholderText("Selecciona un archivo...")
        self.input_archivo_enc.setReadOnly(True)
        file_layout.addWidget(self.input_archivo_enc)
        
        btn_examinar_enc = QPushButton("Examinar")
        btn_examinar_enc.setFixedWidth(120)
        btn_examinar_enc.clicked.connect(self._examinar_archivo_encriptar)
        file_layout.addWidget(btn_examinar_enc)
        
        layout.addLayout(file_layout)
        
        # Barra de progreso
        layout.addWidget(QLabel("Progreso:"))
        self.progress_enc = QProgressBar()
        self.progress_enc.setMaximum(100)
        self.progress_enc.setValue(0)
        layout.addWidget(self.progress_enc)
        
        # Botón de encriptar
        self.btn_encriptar = QPushButton("Encriptar Archivo")
        self.btn_encriptar.setFixedHeight(40)
        self.btn_encriptar.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #229954;
            }
            QPushButton:disabled {
                background-color: #95a5a6;
            }
        """)
        self.btn_encriptar.clicked.connect(self._iniciar_encriptacion)
        self.btn_encriptar.setEnabled(False)
        layout.addWidget(self.btn_encriptar)
        
        # Espacio flexible
        layout.addStretch()
        
        # Información
        info = QLabel("El archivo encriptado se guardará en la misma carpeta\ncon el prefijo 'enc_' y se generarán las llaves RSA.")
        info.setStyleSheet("color: #7f8c8d; font-size: 11px;")
        layout.addWidget(info)
        
        tab.setLayout(layout)
        return tab
    
    def _crear_tab_desencriptar(self):
        """Crea la pestaña de desencriptación"""
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Título
        titulo = QLabel("Desencriptar Archivo")
        titulo.setStyleSheet("font-size: 18px; font-weight: bold; color: #2c3e50;")
        layout.addWidget(titulo)
        
        # Sección de archivo encriptado
        layout.addWidget(QLabel("Archivo encriptado:"))
        
        file_layout = QHBoxLayout()
        self.input_archivo_dec = QLineEdit()
        self.input_archivo_dec.setPlaceholderText("Selecciona el archivo encriptado...")
        self.input_archivo_dec.setReadOnly(True)
        file_layout.addWidget(self.input_archivo_dec)
        
        btn_examinar_dec = QPushButton("Examinar")
        btn_examinar_dec.setFixedWidth(120)
        btn_examinar_dec.clicked.connect(self._examinar_archivo_desencriptar)
        file_layout.addWidget(btn_examinar_dec)
        
        layout.addLayout(file_layout)
        
        # Sección de llave privada
        layout.addWidget(QLabel("Llave privada (llave_privada.pem):"))
        
        key_layout = QHBoxLayout()
        self.input_llave = QLineEdit()
        self.input_llave.setPlaceholderText("Selecciona la llave privada...")
        self.input_llave.setReadOnly(True)
        key_layout.addWidget(self.input_llave)
        
        btn_examinar_llave = QPushButton("Examinar")
        btn_examinar_llave.setFixedWidth(120)
        btn_examinar_llave.clicked.connect(self._examinar_llave_privada)
        key_layout.addWidget(btn_examinar_llave)
        
        layout.addLayout(key_layout)
        
        # Barra de progreso
        layout.addWidget(QLabel("Progreso:"))
        self.progress_dec = QProgressBar()
        self.progress_dec.setMaximum(100)
        self.progress_dec.setValue(0)
        layout.addWidget(self.progress_dec)
        
        # Botón de desencriptar
        self.btn_desencriptar = QPushButton("Desencriptar Archivo")
        self.btn_desencriptar.setFixedHeight(40)
        self.btn_desencriptar.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:disabled {
                background-color: #95a5a6;
            }
        """)
        self.btn_desencriptar.clicked.connect(self._iniciar_desencriptacion)
        self.btn_desencriptar.setEnabled(False)
        layout.addWidget(self.btn_desencriptar)
        
        # Espacio flexible
        layout.addStretch()
        
        # Información
        info = QLabel("El archivo desencriptado se guardará en la misma carpeta\ncon el prefijo 'dec_'.")
        info.setStyleSheet("color: #7f8c8d; font-size: 11px;")
        layout.addWidget(info)
        
        tab.setLayout(layout)
        return tab
    
    # ============================================
    # MÉTODOS DE SELECCIÓN DE ARCHIVOS
    # ============================================
    
    def _examinar_archivo_encriptar(self):
        """Abre diálogo para seleccionar archivo a encriptar"""
        archivo, _ = QFileDialog.getOpenFileName(
            self,
            "Seleccionar archivo a encriptar",
            "",
            "Todos los archivos (*.*)"
        )
        if archivo:
            self.input_archivo_enc.setText(archivo)
            self.btn_encriptar.setEnabled(True)
    
    def _examinar_archivo_desencriptar(self):
        """Abre diálogo para seleccionar archivo encriptado"""
        archivo, _ = QFileDialog.getOpenFileName(
            self,
            "Seleccionar archivo encriptado",
            "",
            "Archivos encriptados (enc_*.*);; Todos los archivos (*.*)"
        )
        if archivo:
            self.input_archivo_dec.setText(archivo)
            self._actualizar_boton_desencriptar()
            
            # Intentar autocargar la llave privada del mismo directorio
            directorio = os.path.dirname(archivo)
            llave_privada = os.path.join(directorio, "llave_privada.pem")
            if os.path.exists(llave_privada):
                self.input_llave.setText(llave_privada)
                self._actualizar_boton_desencriptar()
    
    def _examinar_llave_privada(self):
        """Abre diálogo para seleccionar llave privada"""
        archivo, _ = QFileDialog.getOpenFileName(
            self,
            "Seleccionar llave privada",
            "",
            "Archivos PEM (*.pem);; Todos los archivos (*.*)"
        )
        if archivo:
            self.input_llave.setText(archivo)
            self._actualizar_boton_desencriptar()
    
    def _actualizar_boton_desencriptar(self):
        """Habilita el botón de desencriptar si hay archivo y llave"""
        tiene_archivo = bool(self.input_archivo_dec.text())
        tiene_llave = bool(self.input_llave.text())
        self.btn_desencriptar.setEnabled(tiene_archivo and tiene_llave)
    
    # ============================================
    # MÉTODOS DE PROCESAMIENTO
    # ============================================
    
    def _iniciar_encriptacion(self):
        """Inicia el proceso de encriptación"""
        ruta_archivo = self.input_archivo_enc.text()
        
        if not os.path.exists(ruta_archivo):
            QMessageBox.warning(self, "Error", "El archivo seleccionado no existe.")
            return
        
        # Deshabilitar controles
        self.btn_encriptar.setEnabled(False)
        self.progress_enc.setValue(0)
        
        # Crear y conectar worker
        self.worker_encriptar = EncriptarWorker(ruta_archivo)
        self.worker_encriptar.progreso.connect(self.progress_enc.setValue)
        self.worker_encriptar.terminado.connect(self._encriptacion_terminada)
        self.worker_encriptar.error.connect(self._encriptacion_error)
        self.worker_encriptar.start()
    
    def _encriptacion_terminada(self, ruta_salida):
        """Callback cuando la encriptación termina"""
        self.btn_encriptar.setEnabled(True)
        QMessageBox.information(
            self,
            "Encriptación Exitosa",
            f"Archivo encriptado guardado en:\n{ruta_salida}\n\n"
            "Las llaves RSA también se han guardado en el mismo directorio.\n\n"
            "IMPORTANTE: Guarda 'llave_privada.pem' en un lugar seguro."
        )
    
    def _encriptacion_error(self, mensaje_error):
        """Callback cuando hay error en la encriptación"""
        self.btn_encriptar.setEnabled(True)
        self.progress_enc.setValue(0)
        QMessageBox.critical(
            self,
            "Error de Encriptación",
            f"Ha ocurrido un error:\n\n{mensaje_error}"
        )
    
    def _iniciar_desencriptacion(self):
        """Inicia el proceso de desencriptación"""
        ruta_archivo = self.input_archivo_dec.text()
        ruta_llave = self.input_llave.text()
        
        if not os.path.exists(ruta_archivo):
            QMessageBox.warning(self, "Error", "El archivo encriptado no existe.")
            return
        
        if not os.path.exists(ruta_llave):
            QMessageBox.warning(self, "Error", "La llave privada no existe.")
            return
        
        # Deshabilitar controles
        self.btn_desencriptar.setEnabled(False)
        self.progress_dec.setValue(0)
        
        # Crear y conectar worker
        self.worker_desencriptar = DesencriptarWorker(ruta_archivo, ruta_llave)
        self.worker_desencriptar.progreso.connect(self.progress_dec.setValue)
        self.worker_desencriptar.terminado.connect(self._desencriptacion_terminada)
        self.worker_desencriptar.error.connect(self._desencriptacion_error)
        self.worker_desencriptar.start()
    
    def _desencriptacion_terminada(self, ruta_salida):
        """Callback cuando la desencriptación termina"""
        self.btn_desencriptar.setEnabled(True)
        QMessageBox.information(
            self,
            "Desencriptación Exitosa",
            f"Archivo desencriptado guardado en:\n{ruta_salida}"
        )
    
    def _desencriptacion_error(self, mensaje_error):
        """Callback cuando hay error en la desencriptación"""
        self.btn_desencriptar.setEnabled(True)
        self.progress_dec.setValue(0)
        QMessageBox.critical(
            self,
            "Error de Desencriptación",
            f"Ha ocurrido un error:\n\n{mensaje_error}\n\n"
            "Verifica que:\n"
            "- La llave privada corresponde al archivo\n"
            "- El archivo no está corrupto"
        )


# ============================================
# PUNTO DE ENTRADA
# ============================================

def main():
    """Función principal"""
    app = QApplication(sys.argv)
    
    # Estilo general de la aplicación
    app.setStyle("Fusion")
    
    ventana = EncriptadorUI()
    ventana.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
