# Fase 1 · Sample: fuentes, diccionario de datos y muestreo

Este documento acompaña al dataset `data/dataset_vulnerabilidades.csv` y reúne los entregables escritos de la fase Sample: la descripción de las fuentes, el diccionario de datos, la justificación del procedimiento de muestreo y la correspondencia entre CWE y categorías OWASP. La verificación numérica de todo lo que se describe aquí está en `notebooks/01_sample.ipynb`.

## Fuentes de datos

**OWASP Benchmark para Java, versión 1.2** ([repositorio](https://github.com/OWASP-Benchmark/BenchmarkJava), commit `10dfcc54`). Es un conjunto de 2740 servlets escritos por OWASP para medir la precisión de herramientas de análisis de seguridad. Cada caso es un archivo independiente y el proyecto publica, en `expectedresults-1.2.csv`, si el caso es realmente vulnerable y qué CWE representa. La mitad aproximada de los casos son falsos positivos intencionales: contienen una llamada peligrosa, pero el dato del usuario nunca llega a ella. Eso los hace muy valiosos como ejemplos no vulnerables difíciles. Cubre once categorías: inyección SQL, de comandos, LDAP y XPath, XSS, path traversal, cifrado débil, hash débil, aleatoriedad débil, cookies sin atributo `secure` y violación de límites de confianza.

**OWASP Benchmark para Python, versión 0.1** ([repositorio](https://github.com/OWASP-Benchmark/BenchmarkPython), commit `f1291485`). Es el equivalente en Flask, con 1230 casos y la misma forma de etiquetado. Además de las categorías anteriores, incluye inyección de código, deserialización insegura, redirecciones abiertas y XXE.

**Casos controlados del equipo** (`scripts/casos_controlados.py`). Benchmark no contiene riesgos propios de APIs REST ni archivos de configuración de microservicios, que son el foco del laboratorio. Para cubrirlos se escribieron 97 plantillas en Spring Boot, FastAPI, YAML, properties, Dockerfile, docker-compose, `pom.xml` y `requirements.txt`. Cada patrón tiene una versión vulnerable y una versión corregida que resuelve el problema de la forma recomendada por la documentación del framework. Los patrones cubiertos son autorización a nivel de objeto (BOLA), autorización a nivel de función (BFLA), SSRF, asignación masiva, consumo ilimitado de recursos, autenticación (JWT sin verificar, secretos embebidos, login sin límite de intentos), manejo de excepciones, registro de eventos, configuración insegura, credenciales en archivos de configuración y dependencias con vulnerabilidades conocidas.

Las plantillas se instancian cinco veces cambiando el nombre de la entidad (Order, Invoice, Account...), la ruta base, el identificador, el nombre del servicio y el puerto. Estos valores se asignan recorriendo cada lista en ciclo, con un contador separado para las plantillas vulnerables y otro para las seguras, de modo que ambas clases reciben la misma distribución de nombres y ninguno queda asociado a una etiqueta. Los archivos de dependencias combinan al azar librerías con versiones afectadas por CVE públicos (por ejemplo log4j-core 2.14.1, CVE-2021-44228) o con su versión vigente a noviembre de 2026.

El código de ambos Benchmark se distribuye bajo licencia GPL. Se incluye en el dataset con fines académicos y conservando la referencia al archivo de origen.

## Procedimiento de muestreo y su justificación

Los dos Benchmark están desbalanceados por categoría. En Java, por ejemplo, hay 504 casos de inyección SQL y 35 de inyección XPath. Tomarlos completos daría un dataset dominado por unas pocas categorías, y el modelo resultante sería bueno reconociendo SQL e incapaz con el resto. Por eso se aplicó un **muestreo estratificado con tope**: los casos se agrupan por la pareja (categoría, etiqueta real) y de cada grupo se toman como máximo 25, elegidos al azar con semilla fija. Los grupos más pequeños se incluyen completos. Con esto cada categoría queda representada por ejemplos vulnerables y no vulnerables en cantidades parecidas, y el dataset sigue siendo pequeño como para revisarlo manualmente.

Después de unir las tres fuentes se eliminaron los duplicados exactos, comparando el hash SHA-256 del código. Se eliminaron 28 registros, todos de plantillas controladas cuyo texto no depende de los valores que se varían.

El resultado son 1541 registros: 535 de Benchmark Java, 541 de Benchmark Python y 465 casos controlados, con 772 vulnerables y 769 no vulnerables.

## Partición en entrenamiento, validación y prueba

El enunciado recomienda 70/15/15 y separar por proyecto de origen. Separar literalmente por proyecto no es viable, porque cada Benchmark es un único proyecto y quedaría entero en una partición. El objetivo de esa recomendación es evitar que variantes casi idénticas de un mismo ejemplo queden a la vez en entrenamiento y en prueba, y eso se logró de otra forma:

- En Benchmark cada caso es un archivo distinto, así que se usó una partición estratificada por (categoría, etiqueta).
- En los casos controlados, las instancias de una misma plantilla son casi iguales entre sí, así que se reparten **plantillas completas**. Dentro de cada (categoría, etiqueta) se reserva al menos una plantilla para prueba y, cuando hay cuatro o más, otra para validación. En los archivos de dependencias, que son combinaciones aleatorias distintas, la unidad es cada archivo.

La proporción final es 67 % entrenamiento (1031), 16 % validación (247) y 17 % prueba (263). Se comprobó que ninguna plantilla y ningún código idéntico aparece en más de una partición.

## Control de sesgo

Que las clases estén balanceadas no garantiza que el dataset esté libre de sesgo: puede haber detalles que permitan adivinar la etiqueta sin entender la vulnerabilidad. El script `scripts/auditar_sesgo.py` busca ese tipo de atajos (metadatos, longitud, nombres de las plantillas, literales de Benchmark y las características que usa un clasificador lineal). Sus resultados y las correcciones que motivó se explican en la sección 9 de `notebooks/03_modify.ipynb`. Las que afectan al muestreo son la asignación balanceada de nombres en los casos controlados, descrita arriba, y la eliminación en la fase Modify de los literales de relleno que Benchmark usa en sus casos seguros.

## Diccionario de datos

Archivo `data/dataset_vulnerabilidades.csv`, un registro por fragmento de código o archivo de configuración.

| Columna | Tipo | Descripción |
|---|---|---|
| `id` | texto | Identificador único del registro (`VM00001`...). |
| `fuente` | texto | Fuente de la que proviene: `OWASP BenchmarkJava`, `OWASP BenchmarkPython` o `Casos controlados del equipo`. |
| `proyecto_origen` | texto | Proyecto de origen (`BenchmarkJava`, `BenchmarkPython`, `casos_controlados`). |
| `archivo_origen` | texto | Ruta del archivo original dentro del repositorio fuente o, en los casos controlados, plantilla que lo generó. |
| `lenguaje` | texto | `java`, `python` o `config` (cualquier archivo de configuración o dependencias). |
| `tipo_archivo` | texto | Formato concreto: `java`, `python`, `yml`, `properties`, `dockerfile`, `compose`, `pom`, `requirements`. |
| `framework` | texto | Tecnología del fragmento: `servlet`, `flask`, `spring`, `fastapi`, `docker`, `maven`, `pip`. |
| `categoria_vuln` | texto | Tipo de vulnerabilidad al que se refiere el ejemplo (por ejemplo `inyeccion_sql`, `bola`, `configuracion`). En los ejemplos no vulnerables indica contra qué debilidad está protegido el fragmento. |
| `cwe` | texto | Debilidad CWE asociada (`CWE-89`). Mismo criterio que la columna anterior para los no vulnerables. |
| `vulnerable` | entero | 1 si el fragmento contiene la vulnerabilidad, 0 si no. Es la etiqueta binaria. |
| `owasp2025` | texto | Categoría OWASP Top 10:2025 derivada del CWE (`A05:2025`). Vacía en los no vulnerables. |
| `api2023` | texto | Categoría OWASP API Security Top 10:2023 derivada del CWE (`API1:2023`). Vacía si el riesgo no es de API o el ejemplo no es vulnerable. |
| `grupo` | texto | Unidad de partición: el caso de Benchmark o la plantilla controlada. Registros del mismo grupo siempre están en la misma partición. |
| `particion` | texto | `train`, `val` o `test`. |
| `n_lineas` | entero | Número de líneas del código original. |
| `sha256` | texto | Hash del código original, usado para detectar duplicados. |
| `codigo` | texto | Contenido completo del fragmento o archivo, sin modificar. |

## Correspondencia CWE–OWASP

Las etiquetas OWASP no se asignaron a mano, sino a partir del CWE de cada registro usando `data/mapeo_cwe_owasp.csv`. Para OWASP Top 10:2025 la fuente es la lista oficial de CWE asociados a cada categoría en [top10.owasp.org/2025](https://top10.owasp.org/2025). OWASP API Security Top 10:2023 no publica una tabla completa de CWE, así que se usaron los CWE citados en las referencias de cada riesgo y, para los demás, el criterio del equipo a partir de la descripción del riesgo. La columna de fuente de la tabla indica qué asignaciones son oficiales y cuáles son criterio del equipo.

| CWE | Debilidad | OWASP 2025 | API 2023 |
|---|---|---|---|
| CWE-22 | Path Traversal | A01 | – |
| CWE-601 | Open Redirect | A01 | – |
| CWE-639 | Authorization Bypass Through User-Controlled Key | A01 | API1 |
| CWE-285 | Improper Authorization | A01 | API5 |
| CWE-918 | Server-Side Request Forgery | A01 | API7 |
| CWE-16 | Configuration | A02 | API8 |
| CWE-942 | Permissive Cross-domain Policy | A02 | API8 |
| CWE-489 | Active Debug Code | A02 | API8 * |
| CWE-614 | Sensitive Cookie Without Secure Attribute | A02 | – |
| CWE-611 | XML External Entity | A02 | – |
| CWE-250 | Execution with Unnecessary Privileges | A02 * | API8 * |
| CWE-1104 | Use of Unmaintained Third Party Components | A03 | – |
| CWE-327 | Broken or Risky Cryptographic Algorithm | A04 | – |
| CWE-328 | Use of Weak Hash | A04 | – |
| CWE-330 | Use of Insufficiently Random Values | A04 | – |
| CWE-347 | Improper Verification of Cryptographic Signature | A04 | API2 * |
| CWE-89 | SQL Injection | A05 | – |
| CWE-78 | OS Command Injection | A05 | – |
| CWE-79 | Cross-site Scripting | A05 | – |
| CWE-90 | LDAP Injection | A05 | – |
| CWE-643 | XPath Injection | A05 | – |
| CWE-94 | Code Injection | A05 | – |
| CWE-501 | Trust Boundary Violation | A06 | – |
| CWE-770 | Allocation of Resources Without Limits | A06 * | API4 |
| CWE-287 | Improper Authentication | A07 | API2 * |
| CWE-798 | Use of Hard-coded Credentials | A07 | API2 * |
| CWE-307 | Excessive Authentication Attempts | A07 | API2 |
| CWE-502 | Deserialization of Untrusted Data | A08 | – |
| CWE-915 | Mass Assignment | A08 | API3 |
| CWE-117 | Improper Output Neutralization for Logs | A09 | – |
| CWE-532 | Sensitive Information in Log File | A09 | – |
| CWE-778 | Insufficient Logging | A09 | – |
| CWE-209 | Error Message Containing Sensitive Information | A10 | API8 |
| CWE-755 | Improper Handling of Exceptional Conditions | A10 | – |

\* Asignación por criterio del equipo. CWE-770 y CWE-250 no figuran en la lista oficial de 2025; se ubicaron en A06 (la ausencia de límites es una decisión de diseño) y A02 (un contenedor que corre como root es un problema de configuración del despliegue). En API 2023, los JWT sin verificar y las credenciales embebidas se asignaron a API2 porque la descripción de ese riesgo menciona explícitamente la aceptación de tokens sin firma y las claves débiles.

Con esta tabla el dataset cubre las diez categorías de OWASP Top 10:2025 y siete de OWASP API Security Top 10:2023. API6 (flujos de negocio sensibles), API9 (inventario de APIs) y API10 (consumo inseguro de APIs) quedan **no evaluadas**, porque dependen de la lógica de negocio, del inventario de despliegue o de la confianza depositada en terceros, y nada de eso puede observarse en un archivo aislado.
