def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)

def xor_bytes(b1, b2):
    return bytes(a ^ b for a, b in zip(b1, b2))

# Criptogramas proporcionados
criptogramas = [
    "72212b29402b66342437255717562d652e5748692f2452206b17153b36364b2236172f2b372b2a2c2c6f2d6e3e3347",
    "5a74202b412f243123743459175c3737394b1224382f5d332244747436364b35365b3426276a3d762e2e206e273f46312a30203b",
    # ... (agrega los demás criptogramas)
    "62212078533c2f313e743e5759132f242b185f282324562034173d3a7210512333562a67062f253a"
]

# Convertir los criptogramas a bytes
criptogramas_bytes = [hex_to_bytes(c) for c in criptogramas]

# Último criptograma
ultimo_criptograma = criptogramas_bytes[-1]

# Aplicar XOR entre el último criptograma y los demás
for i, criptograma in enumerate(criptogramas_bytes[:-1]):
    resultado_xor = xor_bytes(ultimo_criptograma, criptograma)
    print(f"XOR entre último criptograma y criptograma {i+1}: {resultado_xor}")

# Reconstruir el mensaje original y la clave
# (Este paso requiere análisis manual basado en los resultados del XOR)