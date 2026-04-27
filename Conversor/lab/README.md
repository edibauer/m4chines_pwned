# Laboratorio de XSLT Injection

Este repositorio contiene un entorno Docker vulnerable a **XSLT Injection**. Está diseñado con fines educativos para entender cómo los atacantes pueden explotar procesadores XML/XSLT mal configurados.

## ¿Qué es XSLT Injection?

Ocurre cuando una aplicación web permite a un usuario controlar o influir en la hoja de estilos XSLT (Extensible Stylesheet Language Transformations) utilizada para transformar un documento XML.

Si el procesador XSLT no está endurecido (hardened), un atacante puede:
1. **Leer archivos locales (LFI):** Usando la función `document()`.
2. **SSRF (Server-Side Request Forgery):** Haciendo peticiones a recursos internos.
3. **Ejecución de comandos:** En algunos procesadores (como Java o PHP antiguo) permitiendo llamadas a funciones del sistema.

## Cómo iniciar el laboratorio

1. Asegúrate de tener Docker y Docker Compose instalados.
2. Clona o descarga este repositorio.
3. Ejecuta el siguiente comando en la terminal:

```bash
docker-compose up --build