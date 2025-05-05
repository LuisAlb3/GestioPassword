from flask import Flask, request, render_template_string
import random
import string
import re
import hashlib
import requests

app = Flask(__name__)

# Leer el HTML desde el archivo plano (fuera de templates/)
def cargar_html():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

def generar_contraseña(longitud=12):
    if longitud < 8:
        longitud = 8
    caracteres = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(caracteres) for _ in range(longitud))

def evaluar_seguridad(contraseña):
    criterios = {
        "longitud": len(contraseña) >= 8,
        "mayúsculas": any(c.isupper() for c in contraseña),
        "minúsculas": any(c.islower() for c in contraseña),
        "números": any(c.isdigit() for c in contraseña),
        "símbolos": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", contraseña))
    }
    puntaje = sum(criterios.values())
    if puntaje == 5:
        nivel = "Muy segura"
    elif puntaje >= 3:
        nivel = "Medianamente segura"
    else:
        nivel = "Débil"
    return criterios, nivel

def verificar_fuga(contraseña):
    sha1 = hashlib.sha1(contraseña.encode('utf-8')).hexdigest().upper()
    prefijo = sha1[:5]
    sufijo = sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefijo}"
    response = requests.get(url)
    if response.status_code != 200:
        return "Error al verificar la contraseña online."

    hashes = (line.split(":") for line in response.text.splitlines())
    for hash_sufijo, cantidad in hashes:
        if hash_sufijo == sufijo:
            return f" Aparece en filtraciones: {cantidad} veces."
    return " No aparece en filtraciones públicas."

@app.route("/", methods=["GET", "POST"])
def index():
    resultado = ""
    criterios = {}
    fuga = ""
    generada = ""

    if request.method == "POST":
        if "generar" in request.form:
            try:
                longitud = int(request.form.get("longitud", 12))
                generada = generar_contraseña(longitud)
            except ValueError:
                generada = "Error: longitud inválida."

        elif "verificar" in request.form:
            contraseña = request.form.get("contraseña", "")
            if contraseña:
                criterios, nivel = evaluar_seguridad(contraseña)
                fuga = verificar_fuga(contraseña)
                resultado = f"Seguridad: {nivel}"

    html = cargar_html()
    return render_template_string(html, resultado=resultado, criterios=criterios, fuga=fuga, generada=generada)

if __name__ == "__main__":
    app.run(debug=True)
