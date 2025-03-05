import os

def xor_bytes(data, key):
    """Aplica XOR a cada byte con la clave dada"""
    return bytes([b ^ key for b in data])

def is_valid_exe(data):
    """Verifica si los datos tienen características de un ejecutable válido"""
    # Verificar si contiene la firma MZ
    if b'MZ' not in data:
        return False
    
    # Verificar si contiene otras cadenas comunes en ejecutables
    common_strings = [b'This program', b'.text', b'.data', b'.rdata', 
                     b'GetProcAddress', b'LoadLibrary', b'kernel32', 
                     b'user32', b'PE', b'.exe', b'DOS mode']
    
    count = 0
    for s in common_strings:
        if s in data:
            count += 1
    
    # Si contiene al menos algunas de estas cadenas, es probablemente un ejecutable
    return count >= 2

def find_mz_offset(data):
    """Encuentra la posición del MZ en el archivo"""
    return data.find(b'MZ')

def brute_force_decrypt(input_file, output_file):
    """Prueba todas las claves XOR posibles y guarda el resultado correcto"""
    
    # Cargar el archivo cifrado
    with open(input_file, "rb") as f:
        encrypted_data = f.read()
    
    print(f"Analizando archivo de {len(encrypted_data)} bytes...")
    
    # Probar cada posible clave (0-255)
    best_key = None
    best_score = 0
    best_data = None
    best_mz_pos = None
    
    for key in range(256):
        # Descifrar con esta clave
        decrypted = xor_bytes(encrypted_data, key)
        
        # Verificar si parece un ejecutable válido
        if is_valid_exe(decrypted):
            # Encontrar el inicio del ejecutable (posición de MZ)
            mz_pos = find_mz_offset(decrypted)
            
            # Calcular una puntuación basada en cantidad de cadenas reconocibles
            # y la presencia de un encabezado DOS válido después de MZ
            score = 0
            common_strings = [b'This program', b'.text', b'.data', b'.rdata', 
                             b'GetProcAddress', b'LoadLibrary', b'kernel32', 
                             b'user32', b'PE', b'.exe', b'DOS mode',
                             b'Windows', b'Microsoft', b'DLL', b'cannot', b'program']
            
            for s in common_strings:
                if s in decrypted:
                    score += 1
            
            # Verificar si hay un encabezado PE válido
            if mz_pos != -1 and mz_pos + 0x40 < len(decrypted):
                try:
                    pe_offset_bytes = decrypted[mz_pos+0x3C:mz_pos+0x40]
                    pe_offset = int.from_bytes(pe_offset_bytes, byteorder='little')
                    if mz_pos + pe_offset + 1 < len(decrypted) and decrypted[mz_pos+pe_offset:mz_pos+pe_offset+2] == b'PE':
                        score += 5  # Bonus grande por tener un PE header válido
                except:
                    pass
            
            # Mostrar resultado parcial para esta clave
            print(f"Clave {key} (0x{key:02X}): puntuación {score}, MZ en posición {mz_pos}")
            
            # Si es mejor que lo que teníamos antes, actualizamos
            if score > best_score:
                best_score = score
                best_key = key
                best_data = decrypted
                best_mz_pos = mz_pos
                print(f"  ¡Nueva mejor clave encontrada!")
                
                # Mostrar una vista previa de los primeros bytes
                preview = ' '.join(f'{b:02X}' for b in decrypted[:16])
                ascii_preview = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in decrypted[:16])
                print(f"  Vista previa: {preview} | {ascii_preview}")
                
                # Si encontramos un resultado muy bueno, podemos terminar temprano
                if score >= 10:
                    print("  ¡Alto puntaje! Esta es probablemente la clave correcta.")
    
    # Si encontramos una clave prometedora
    if best_key is not None:
        print(f"\n¡Éxito! Mejor clave encontrada: {best_key} (0x{best_key:02X})")
        print(f"Puntuación: {best_score}")
        
        if best_mz_pos is not None:
            print(f"La firma MZ comienza en posición: {best_mz_pos}")
        
        # Guardar el resultado
        with open(output_file, "wb") as f:
            f.write(best_data)
        
        print(f"Archivo descifrado guardado como: {output_file}")
        
        # También guardar una versión sin cabecera si se encontró MZ
        if best_mz_pos is not None and best_mz_pos > 0:
            clean_output = output_file.replace('.bin', '_no_header.bin')
            with open(clean_output, "wb") as f:
                f.write(best_data[best_mz_pos:])
            print(f"Archivo sin cabecera guardado como: {clean_output}")
        
        return best_key, best_mz_pos
    else:
        print("\nNo se encontró ninguna clave válida mediante fuerza bruta.")
        
        # Intento desesperado: guardar una versión con cada clave
        print("Guardando resultados para cada clave posible...")
        os.makedirs("todas_las_claves", exist_ok=True)
        
        for key in range(256):
            decrypted = xor_bytes(encrypted_data, key)
            with open(f"todas_las_claves/key_{key}.bin", "wb") as f:
                f.write(decrypted)
        
        print("Revisa manualmente los archivos en la carpeta 'todas_las_claves'")
        return None, None

if __name__ == "__main__":
    input_file = "57FD6325.VBN"
    output_file = "malware_decrypted.bin"
    
    if not os.path.exists(input_file):
        print(f"Error: No se encuentra el archivo {input_file}")
    else:
        key, mz_pos = brute_force_decrypt(input_file, output_file)
        
        if key is not None:
            print("\n¡ADVERTENCIA! El archivo resultante es malware real.")
            print("No lo ejecute en sistemas Windows.")
            
            # Instrucciones para extraer el malware
            if mz_pos is not None and mz_pos > 0:
                print(f"\nPara extraer el malware manualmente:")
                print(f"1. Abra {output_file} con un editor hexadecimal")
                print(f"2. Elimine los primeros {mz_pos} bytes (desde 0 hasta {mz_pos-1})")
                print(f"3. Guarde el archivo resultante")
                print(f"O simplemente use el archivo {output_file.replace('.bin', '_no_header.bin')}")
                