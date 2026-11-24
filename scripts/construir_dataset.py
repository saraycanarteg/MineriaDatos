"""
Fase 1 (Sample): construcción del dataset etiquetado.

Combina tres fuentes:
  1. OWASP Benchmark para Java v1.2 (casos de prueba con etiqueta oficial).
  2. OWASP Benchmark para Python v0.1 (ídem).
  3. Casos controlados escritos por el equipo (scripts/casos_controlados.py).

De cada Benchmark se toma una muestra estratificada por (categoría, etiqueta)
con un tope por estrato, de modo que las categorías muy grandes (sqli, weakrand)
no dominen el conjunto. Las etiquetas OWASP se derivan del CWE mediante la
tabla data/mapeo_cwe_owasp.csv, por lo que cada etiqueta es trazable.

Finalmente se eliminan duplicados exactos y se asigna la partición
train/val/test agrupando los casos controlados por plantilla para evitar
que variantes de un mismo caso queden repartidas entre particiones.

Uso:
    python scripts/construir_dataset.py
"""

import hashlib
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

import casos_controlados

RAIZ = Path(__file__).resolve().parents[1]
RAW = RAIZ / "data" / "raw"
SALIDA = RAIZ / "data" / "dataset_vulnerabilidades.csv"
MAPEO = RAIZ / "data" / "mapeo_cwe_owasp.csv"

SEMILLA = 42
MAX_POR_ESTRATO = 25

# Nombres de categoría de Benchmark -> nombres usados en el dataset
CATEGORIAS_BENCHMARK = {
    "cmdi": "inyeccion_comandos", "sqli": "inyeccion_sql", "ldapi": "inyeccion_ldap",
    "xpathi": "inyeccion_xpath", "codeinj": "inyeccion_codigo", "xss": "xss",
    "pathtraver": "path_traversal", "redirect": "redireccion_abierta",
    "crypto": "cifrado_debil", "hash": "hash_debil", "weakrand": "aleatorio_debil",
    "securecookie": "cookie_insegura", "trustbound": "limite_confianza",
    "deserialization": "deserializacion", "xxe": "xxe",
}


def leer_benchmark(nombre, ruta_codigo, extension, lenguaje, framework):
    carpeta = RAW / nombre
    esperado = next(carpeta.glob("expectedresults-*.csv"))
    tabla = pd.read_csv(esperado, comment="#", header=None,
                        names=["test", "categoria", "vulnerable", "cwe"])
    tabla["vulnerable"] = tabla["vulnerable"].astype(str).str.strip().str.lower() == "true"

    # muestreo estratificado con tope por (categoria, etiqueta)
    muestra = (tabla.sample(frac=1, random_state=SEMILLA)
               .groupby(["categoria", "vulnerable"]).head(MAX_POR_ESTRATO)
               .sort_values("test"))

    filas = []
    for r in muestra.itertuples():
        archivo = carpeta / ruta_codigo / f"{r.test}{extension}"
        filas.append(dict(
            fuente=f"OWASP {nombre}",
            proyecto_origen=nombre,
            archivo_origen=str(archivo.relative_to(RAW)).replace("\\", "/"),
            lenguaje=lenguaje, tipo_archivo=lenguaje, framework=framework,
            categoria_vuln=CATEGORIAS_BENCHMARK[r.categoria],
            cwe=f"CWE-{r.cwe}", vulnerable=int(r.vulnerable),
            grupo=f"{nombre}:{r.test}",
            codigo=archivo.read_text(encoding="utf-8"),
        ))
    return filas


def leer_controlados():
    filas = []
    for c in casos_controlados.generar(instancias=5, semilla=SEMILLA):
        filas.append(dict(
            fuente="Casos controlados del equipo",
            proyecto_origen="casos_controlados",
            archivo_origen=f"scripts/casos_controlados.py#{c['plantilla']}",
            lenguaje=c["lenguaje"], tipo_archivo=c["tipo_archivo"], framework=c["framework"],
            categoria_vuln=c["categoria_vuln"], cwe=c["cwe"], vulnerable=c["vulnerable"],
            grupo=f"controlado:{c['grupo']}",
            codigo=c["codigo"],
        ))
    return filas


def asignar_etiquetas(df):
    """Etiquetas OWASP a partir del CWE. Los ejemplos seguros no llevan etiqueta."""
    mapeo = pd.read_csv(MAPEO, dtype=str).fillna("").set_index("cwe")
    faltantes = set(df["cwe"]) - set(mapeo.index)
    if faltantes:
        raise ValueError(f"CWE sin mapeo: {faltantes}")
    vulnerable = df["vulnerable"] == 1
    df["owasp2025"] = np.where(vulnerable, df["cwe"].map(mapeo["owasp2025"]), "")
    df["api2023"] = np.where(vulnerable, df["cwe"].map(mapeo["api2023"]), "")
    return df


def particionar(df):
    """
    Asigna train/val/test (~70/15/15).

    En Benchmark cada caso de prueba es un archivo independiente, así que se usa
    una partición estratificada por (categoría, etiqueta). En los casos
    controlados la unidad es la plantilla: dentro de cada (categoría, etiqueta)
    se reservan plantillas completas para test y val, de modo que esas
    particiones contienen código cuya estructura el modelo no vio al entrenar.
    """
    estrato = df["categoria_vuln"] + "_" + df["vulnerable"].astype(str)
    particion = pd.Series("train", index=df.index)
    rng = np.random.default_rng(SEMILLA)

    bench = df["proyecto_origen"] != "casos_controlados"
    idx = df.index[bench]
    resto, test = train_test_split(idx, test_size=0.15, stratify=estrato[idx],
                                   random_state=SEMILLA)
    _, val = train_test_split(resto, test_size=0.15 / 0.85, stratify=estrato[resto],
                              random_state=SEMILLA)
    particion[test] = "test"
    particion[val] = "val"

    controlados = df[~bench]
    for _, bloque in controlados.groupby(estrato[~bench]):
        grupos = rng.permutation(bloque["grupo"].unique())
        n = len(grupos)
        n_eval = max(1, round(n * 0.15))
        en_test = set(grupos[:n_eval])
        en_val = set(grupos[n_eval:2 * n_eval]) if n >= 4 else set()
        particion[bloque.index[bloque["grupo"].isin(en_test)]] = "test"
        particion[bloque.index[bloque["grupo"].isin(en_val)]] = "val"
    return particion


def main():
    filas = []
    filas += leer_benchmark("BenchmarkJava", "src/main/java/org/owasp/benchmark/testcode",
                            ".java", "java", "servlet")
    filas += leer_benchmark("BenchmarkPython", "testcode", ".py", "python", "flask")
    filas += leer_controlados()
    df = pd.DataFrame(filas)

    df["sha256"] = df["codigo"].map(lambda s: hashlib.sha256(s.encode("utf-8")).hexdigest())
    antes = len(df)
    df = df.drop_duplicates("sha256").reset_index(drop=True)
    print(f"Duplicados exactos eliminados: {antes - len(df)}")

    df = asignar_etiquetas(df)
    df["n_lineas"] = df["codigo"].str.count("\n") + 1
    df["particion"] = particionar(df)
    df.insert(0, "id", [f"VM{i:05d}" for i in range(1, len(df) + 1)])

    columnas = ["id", "fuente", "proyecto_origen", "archivo_origen", "lenguaje",
                "tipo_archivo", "framework", "categoria_vuln", "cwe", "vulnerable",
                "owasp2025", "api2023", "grupo", "particion", "n_lineas", "sha256", "codigo"]
    df[columnas].to_csv(SALIDA, index=False, encoding="utf-8")

    print(f"Registros: {len(df)}  (vulnerables: {df.vulnerable.sum()}, "
          f"no vulnerables: {(df.vulnerable == 0).sum()})")
    print(df["particion"].value_counts(normalize=True).round(3).to_string())
    print(f"Dataset guardado en {SALIDA.relative_to(RAIZ)}")


if __name__ == "__main__":
    main()
