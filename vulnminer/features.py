"""
Fase 3 (Modify): limpieza, tokenización y extracción de características.

Este módulo se usa tanto al preparar los datos de entrenamiento como, más
adelante, dentro de la herramienta CLI. Por eso todo el preprocesamiento vive
aquí y no en los notebooks: el pipeline serializado depende de estas funciones
y debe poder reconstruirse igual al analizar un proyecto nuevo.

La representación final de cada fragmento combina tres bloques:

  * TF-IDF sobre tokens de código (identificadores partidos en subpalabras,
    literales y algunos operadores relevantes).
  * Indicadores de seguridad: conteos de patrones asociados a las
    características sugeridas en el enunciado (consultas dinámicas, uso de
    criptografía, autenticación, validación, manejo de excepciones, etc.).
    No asignan ninguna categoría por sí mismos; son variables de entrada
    que el modelo pondera durante el entrenamiento.
  * El tipo de archivo (java, python, yml, dockerfile...) codificado one-hot.
"""

import re

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MaxAbsScaler, OneHotEncoder

# ---------------------------------------------------------------------------
# Limpieza
# ---------------------------------------------------------------------------

ESTILO_COMENTARIOS = {
    "java": ("//", ("/*", "*/")),
    "python": ("#", None),
    "yml": ("#", None),
    "compose": ("#", None),
    "properties": ("#", None),
    "dockerfile": ("#", None),
    "requirements": ("#", None),
    "pom": (None, ("<!--", "-->")),
}

# Los casos de OWASP Benchmark incluyen en rutas y nombres de plantilla el
# nombre de la categoría (p. ej. "/sqli-00/BenchmarkTest00012"). Si se dejan,
# el modelo aprende a leer la etiqueta en lugar del patrón de código.
_FUGA_CATEGORIA = re.compile(
    r"\b(cmdi|crypto|hash|ldapi|pathtraver|securecookie|sqli|trustbound|weakrand|"
    r"xpathi|xss|codeinj|deserialization|redirect|xxe)-\d{2}\b")
_ID_BENCHMARK = re.compile(r"BenchmarkTest\d{5}")

# Benchmark usa cadenas de relleno en las ramas de código muerto que deciden si
# un caso es vulnerable ("This_should_always_happen", "bobs_your_uncle"...).
# Su presencia se correlaciona con la etiqueta pero no tiene relación con la
# seguridad, así que se sustituyen por un literal neutro.
_RELLENO_BENCHMARK = re.compile(
    r"([\"'])(?:This_should_always_happen|This should never happen|safe!|safe|moresafe|alsosafe|"
    r"a_Value|another_Value|bob's your uncle|bobs_your_uncle|barbarians_at_the_gate|"
    r"snapes on a plane|bob|no pickles to be seen here|Unpickling failed!)\1")
# Mensajes de respuesta que repiten literalmente la etiqueta del caso
_MENSAJE_ETIQUETA = re.compile(r"secure flag set to:? (?:true|false)")
_DOCSTRING_INICIAL = re.compile(r'^\s*(\'\'\'|""")[\s\S]*?\1', re.MULTILINE)


def _quitar_comentarios(texto, linea, bloque):
    """Elimina comentarios respetando el contenido de las cadenas de texto."""
    salida = []
    i, n = 0, len(texto)
    comilla = None
    while i < n:
        c = texto[i]
        if comilla:
            salida.append(c)
            if c == "\\" and i + 1 < n:
                salida.append(texto[i + 1])
                i += 2
                continue
            if c == comilla:
                comilla = None
            i += 1
            continue
        if bloque and texto.startswith(bloque[0], i):
            fin = texto.find(bloque[1], i + len(bloque[0]))
            i = n if fin == -1 else fin + len(bloque[1])
            continue
        if linea and texto.startswith(linea, i):
            fin = texto.find("\n", i)
            i = n if fin == -1 else fin
            continue
        triple = texto[i:i + 3]
        if triple in ('"""', "'''"):
            fin = texto.find(triple, i + 3)
            fin = n if fin == -1 else fin + 3
            salida.append(texto[i:fin])
            i = fin
            continue
        if c in "\"'":
            comilla = c
        salida.append(c)
        i += 1
    return "".join(salida)


def limpiar_codigo(codigo, tipo_archivo):
    """Quita comentarios, metadatos que filtran la etiqueta y espacios redundantes."""
    texto = codigo.replace("\r\n", "\n").replace("\t", "    ")
    if tipo_archivo == "python":
        texto = _DOCSTRING_INICIAL.sub("", texto, count=1)
    linea, bloque = ESTILO_COMENTARIOS.get(tipo_archivo, ("#", None))
    # en YAML, properties y Dockerfile un apóstrofo suele ser texto libre, no una cadena
    if tipo_archivo in ("java", "python"):
        texto = _quitar_comentarios(texto, linea, bloque)
    else:
        if bloque:
            texto = re.sub(re.escape(bloque[0]) + r"[\s\S]*?" + re.escape(bloque[1]), "", texto)
        if linea:
            texto = re.sub(r"(^|\s)" + re.escape(linea) + r".*$", r"\1", texto, flags=re.MULTILINE)
    texto = _FUGA_CATEGORIA.sub("test-00", texto)
    texto = _ID_BENCHMARK.sub("BenchmarkTest", texto)
    texto = _RELLENO_BENCHMARK.sub('"CONST"', texto)
    texto = _MENSAJE_ETIQUETA.sub("secure flag set", texto)
    lineas = [l.rstrip() for l in texto.split("\n")]
    texto = re.sub(r"\n{3,}", "\n\n", "\n".join(lineas)).strip()
    return texto + "\n"


# ---------------------------------------------------------------------------
# Tokenización
# ---------------------------------------------------------------------------

_TOKEN = re.compile(
    r"\d+(?:\.\d+)+"           # versiones: 2.14.1
    r"|[A-Za-z_][A-Za-z0-9_]*"  # identificadores y palabras clave
    r"|\d+"                     # números
    r"|\$\{|[+*?%!]"            # operadores con significado para seguridad
)
_CAMEL = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")


def tokenizar_codigo(texto):
    """
    Convierte código en una lista de tokens.

    Los identificadores compuestos se conservan completos y además se parten en
    subpalabras (executeQuery -> executequery, execute, query), lo que permite
    que el modelo relacione nombres distintos que comparten significado.
    Los números sueltos se reemplazan por NUM; las versiones se conservan
    porque en archivos de dependencias son la información relevante.
    """
    tokens = []
    for t in _TOKEN.findall(texto):
        if t[0].isdigit():
            tokens.append("VER_" + t.replace(".", "_") if "." in t else "NUM")
        elif t[0].isalpha() or t[0] == "_":
            base = t.lower()
            tokens.append(base)
            partes = [p.lower() for p in _CAMEL.findall(t.replace("_", " ")) if len(p) > 1]
            if len(partes) > 1:
                tokens.extend(partes)
        else:
            tokens.append(t)
    return tokens


# ---------------------------------------------------------------------------
# Indicadores de seguridad
# ---------------------------------------------------------------------------

def _r(patron, flags=re.IGNORECASE):
    return re.compile(patron, flags)


INDICADORES = {
    # consultas a base de datos
    "sql_dinamico": _r(r"(select|insert|update|delete)\b[^;\n]*[\"']\s*(\+|%|\.format)"
                       r"|f[\"'][^\"'\n]*\b(select|insert|update|delete)\b[^\"'\n]*\{"),
    "sql_parametrizado": _r(r"preparestatement|\bset(string|int|long)\s*\(|"
                            r"execute\s*\([^)]*,\s*[\(\[]"),
    # ejecución de comandos y código
    "ejecucion_comandos": _r(r"runtime\.getruntime\(\)\.exec|processbuilder|subprocess\.|"
                             r"os\.system|os\.popen"),
    "shell_activado": _r(r"shell\s*=\s*true"),
    "evaluacion_dinamica": _r(r"\beval\s*\(|\bexec\s*\(|scriptengine"),
    "deserializacion": _r(r"objectinputstream|readobject\s*\(|pickle\.loads?|"
                          r"yaml\.load\s*\(|jsonpickle|marshal\.loads"),
    "parser_xml": _r(r"documentbuilder|saxparser|xmlinputfactory|etree|lxml|xpath"),
    # criptografía y aleatoriedad
    "cripto_debil": _r(r"[\"'](md5|md4|sha-?1|des|desede|rc4)[\"'/]|hashlib\.(md5|sha1)|"
                       r"/ecb/|\bdes\.new|arc4"),
    "cripto_fuerte": _r(r"sha-?256|sha-?512|aes/gcm|bcrypt|pbkdf2|argon2|scrypt|"
                        r"hmacshakeyfor"),
    "aleatorio_inseguro": _r(r"new\s+(java\.util\.)?random\s*\(|math\.random|"
                             r"\brandom\.(random|randint|choice|getrandbits|uniform)"),
    "aleatorio_seguro": _r(r"securerandom|\bsecrets\.|os\.urandom"),
    # cookies y sesión
    "cookies": _r(r"addcookie|set_cookie|new\s+cookie\s*\("),
    "cookie_segura": _r(r"setsecure\s*\(\s*true|\bsecure\s*=\s*true"),
    "cookie_no_segura": _r(r"setsecure\s*\(\s*false|\bsecure\s*=\s*false"),
    # autenticación, autorización y tokens
    "control_roles": _r(r"@preauthorize|@secured|@rolesallowed|hasrole|hasauthority|"
                        r"require_role|role\s*[!=]=|role_\w+"),
    "usuario_autenticado": _r(r"@authenticationprincipal|\bprincipal\b|authentication\b|"
                              r"get_current_user|current_user"),
    "verificacion_propietario": _r(r"owner\w*\s*(==|!=|\.equals)|\.equals\([^)]*owner|"
                                   r"findby\w*owner|owner_id\s*=="),
    "uso_jwt": _r(r"\bjwt\b|jwts\.|bearer"),
    "jwt_sin_verificar": _r(r"verify_signature[\"']?\s*:\s*false|parseclaimsjwt|"
                            r"base64\.geturldecoder\(\)\.decode\(token"),
    "credencial_literal": _r(r"(password|passwd|secret|api[_-]?key|token|access[_-]?key)"
                             r"\w*[\"']?\s*[:=]\s*[\"']?(?!\$\{)[A-Za-z0-9!@#\-_]{4,}"),
    "variable_entorno": _r(r"os\.environ|getenv|\$\{|@value\("),
    "limite_intentos": _r(r"limiter|ratelimit|too_many_requests|isblocked|attempts"),
    # validación de entradas
    "validacion_entrada": _r(r"@valid\b|@validated|@max\(|@min\(|@size\(|@pattern\(|"
                             r"query\([^)]*\b(le|ge)=|basemodel|field\(|extra\s*=\s*[\"']forbid|"
                             r"encodefor\w+|escape\w*\("),
    "entrada_usuario": _r(r"getparameter|getheader|getcookies|request\.(args|form|cookies|"
                          r"headers|json|values)|@requestparam|@requestbody|@pathvariable"),
    # endpoints REST y llamadas externas
    "endpoints": _r(r"@(get|post|put|delete|patch|request)mapping|@webservlet|"
                    r"@(app|router)\.(get|post|put|delete|patch|route)"),
    "parametro_ruta": _r(r"\{\w+\}"),
    "peticion_saliente": _r(r"resttemplate|webclient|httpurlconnection|openstream|"
                            r"requests\.(get|post|put)|httpx\.|urlopen"),
    "validacion_url": _r(r"urlparse|gethost\(\)|\.hostname|allowed_hosts|allowlist|whitelist"),
    "redireccion": _r(r"sendredirect|redirect\s*\("),
    # asignación de atributos y paginación
    "asignacion_dinamica": _r(r"setattr\s*\(|__dict__\.update|beanwrapper|"
                              r"setpropertyvalue|\(\*\*\w+\)"),
    "consulta_completa": _r(r"findall\s*\(\s*\)|\.all\s*\(\s*\)"),
    "paginacion": _r(r"pagerequest|pageable|\blimit\b|\boffset\b"),
    "limite_maximo": _r(r"math\.min|\bmin\s*\(|\ble\s*=|@max\(|max_\w+"),
    # excepciones y registro
    "bloques_excepcion": _r(r"\bcatch\s*\(|\bexcept\b"),
    "excepcion_expuesta": _r(r"printstacktrace|getstacktrace|traceback\.|str\(e\w*\)|"
                             r"\{e!r\}|e\.tostring\(\)|ex\.getmessage\(\)"),
    "excepcion_silenciada": _r(r"catch\s*\([^)]*\)\s*\{\s*\}|except[^:\n]*:\s*\n\s*pass\b"),
    "registro_eventos": _r(r"\blog\.|logger\.|logging\.|audit\."),
    "registro_concatenado": _r(r"(log|logger|audit)\.\w+\(\s*(f[\"']|[^)]*[\"']\s*\+)"),
    "registro_sensible": _r(r"(log|logger)\.\w+\([^)]*password"),
    # archivos de configuración y contenedores
    "modo_debug": _r(r"debug\s*[:=]\s*(true|1)|debug=true|reload\s*=\s*true|--reload"),
    "cors_abierto": _r(r"allow_origins\s*=\s*\[\s*[\"']\*|allowedorigin\w*\(\s*[\"']\*|"
                       r"allowed-origins\s*[:=]\s*[\"']?\*"),
    "exposicion_diagnostico": _r(r"include:\s*[\"']?\*|include-stacktrace:\s*always|"
                                 r"h2\.console\.enabled=true|show-values:\s*always|show-sql=true"),
    "contenedor_privilegiado": _r(r"privileged:\s*true|user\s+root|docker\.sock"),
    "imagen_sin_version": _r(r"(from|image:)\s*[\w./-]+:latest"),
    "endurecimiento_contenedor": _r(r"^user\s+(?!root)\w+|no-new-privileges|read_only:\s*true",
                                    re.IGNORECASE | re.MULTILINE),
    "dependencias_declaradas": _r(r"<dependency>|^[\w.-]+==", re.IGNORECASE | re.MULTILINE),
}

# La longitud del fragmento no se incluye: en el dataset delata la fuente
# (Benchmark Java es mucho más largo que los casos controlados) y, dentro de los
# casos controlados, la versión corregida suele tener unas líneas más que la
# vulnerable. Usarla enseñaría al modelo que "más largo = más seguro".
NOMBRES_INDICADORES = list(INDICADORES)


def extraer_indicadores(texto):
    return [len(p.findall(texto)) for p in INDICADORES.values()]


class ExtractorIndicadores(BaseEstimator, TransformerMixin):
    """Transformador de scikit-learn que calcula los indicadores de seguridad."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        serie = X.iloc[:, 0] if isinstance(X, pd.DataFrame) else pd.Series(np.ravel(X))
        return np.array([extraer_indicadores(t) for t in serie], dtype=float)

    def get_feature_names_out(self, input_features=None):
        return np.array(NOMBRES_INDICADORES, dtype=object)


# ---------------------------------------------------------------------------
# Pipeline de preprocesamiento
# ---------------------------------------------------------------------------

def construir_preprocesador(max_features=5000, min_df=2):
    """
    ColumnTransformer que recibe un DataFrame con las columnas
    'codigo_limpio' y 'tipo_archivo' y devuelve una matriz dispersa.
    Se ajusta únicamente con la partición de entrenamiento.
    """
    tfidf = TfidfVectorizer(tokenizer=tokenizar_codigo, lowercase=False, token_pattern=None,
                            ngram_range=(1, 2), min_df=min_df, max_features=max_features,
                            sublinear_tf=True)
    indicadores = Pipeline([("extraer", ExtractorIndicadores()), ("escalar", MaxAbsScaler())])
    return ColumnTransformer([
        ("tfidf", tfidf, "codigo_limpio"),
        ("ind", indicadores, ["codigo_limpio"]),
        ("tipo", OneHotEncoder(handle_unknown="ignore"), ["tipo_archivo"]),
    ], sparse_threshold=1.0)
