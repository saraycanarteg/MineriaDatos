"""Catálogo de las veinte categorías de OWASP Top 10:2025 y API Security Top 10:2023."""

OWASP_2025 = {
    "A01:2025": "Pérdida de control de acceso",
    "A02:2025": "Configuración de seguridad incorrecta",
    "A03:2025": "Fallas en la cadena de suministro de software",
    "A04:2025": "Fallas criptográficas",
    "A05:2025": "Inyección",
    "A06:2025": "Diseño inseguro",
    "A07:2025": "Fallas de autenticación",
    "A08:2025": "Fallas en la integridad del software o de los datos",
    "A09:2025": "Fallas en el registro, alerta y monitoreo de seguridad",
    "A10:2025": "Manejo inadecuado de condiciones excepcionales",
}

API_2023 = {
    "API1:2023": "Autorización incorrecta a nivel de objeto",
    "API2:2023": "Autenticación incorrecta",
    "API3:2023": "Autorización incorrecta a nivel de propiedades del objeto",
    "API4:2023": "Consumo ilimitado de recursos",
    "API5:2023": "Autorización incorrecta a nivel de función",
    "API6:2023": "Acceso ilimitado a flujos de negocio sensibles",
    "API7:2023": "Falsificación de solicitudes del lado del servidor",
    "API8:2023": "Configuración de seguridad incorrecta",
    "API9:2023": "Gestión inadecuada del inventario de API",
    "API10:2023": "Consumo inseguro de API",
}

# Categorías sin datos de entrenamiento ni un mecanismo de detección estática
# razonable. Se declaran explícitamente como no evaluadas.
NO_EVALUADAS = {
    "API6:2023": "Depende de la lógica de negocio; requiere análisis dinámico.",
    "API9:2023": "Es un problema de inventario y despliegue, no visible en un archivo aislado.",
    "API10:2023": "Requiere conocer la confianza depositada en APIs de terceros.",
}

ETIQUETAS = list(OWASP_2025) + list(API_2023)
