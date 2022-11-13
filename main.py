from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import datetime
import requests
import re

app = Flask(__name__)
cors = CORS(app)

from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app.config["JWT_SECRET_KEY"] = "super-secret"
jwt = JWTManager(app)

@app.route("/login", methods=['POST'])
def login():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-security'] + '/usuarios/validate'
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(days=1)
        acces_token = create_access_token(identity=user, expires_delta=expires)
        return {"token": acces_token, "user_id": user["_id"]}
    else:
        return {"mensaje": "Usuario y/o contraseña incorrecta"}


#Rutas de partidos en el API-GATEWAY
@app.route("/partidos", methods=['GET'])
def getPartidos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + '/partidos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/partidos", methods=['POST'])
def createPartidos():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + '/partidos'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/partidos/<string:id>", methods=['PUT'])
def updatePartidos(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + '/partidos/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/partidos/<string:id>", methods=['DELETE'])
def deletePartidos(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + '/partidos/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/partidos/<string:id>", methods=['GET'])
def showPartidos(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + '/partidos/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
#FIN Rutas de partidos en el API-GATEWAY

#Rutas de candidatos en el API-GATEWAY
@app.route("/candidatos", methods=['GET'])
def getCandidatos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + '/candidatos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos", methods=['POST'])
def createCandidatos():
     data = request.get_json()
     headers = {"Content-Type": "application/json; charset=utf-8"}
     url = dataConfig['url-backend-registry'] + '/candidatos'
     response = requests.post(url, headers=headers, json=data)
     json = response.json()
     return jsonify(json)

@app.route("/candidatos/<string:id>", methods=['PUT'])
def updateCandidatos(id):
     data = request.get_json()
     headers = {"Content-Type": "application/json; charset=utf-8"}
     url = dataConfig['url-backend-registry'] + '/candidatos/' + id
     response = requests.put(url, headers=headers, json=data)
     json = response.json()
     return jsonify(json)

@app.route("/candidatos/<string:id>", methods=['DELETE'])
def deleteCandidatos(id):
     headers = {"Content-Type": "application/json; charset=utf-8"}
     url = dataConfig['url-backend-registry'] + '/candidatos/' + id
     response = requests.delete(url, headers=headers)
     json = response.json()
     return jsonify(json)

@app.route("/candidatos/<string:id>", methods=['GET'])
def showCandidatos(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + '/candidatos/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos/<string:id_candidato>/partidos/<string:id_partido>", methods=['PUT'])
def setPartidoCandidato(id_candidato, id_partido):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + '/candidatos/' + id_candidato + '/partidos/' + id_partido
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
#FIN Rutas de candidatos en el API-GATEWAY

#Rutas de mesas en el API-GATEWAY
@app.route("/mesas", methods=['GET'])
def getMesas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + '/mesas'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/mesas", methods=['POST'])
def createMesas():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + '/mesas'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/mesas/<string:id>", methods=['PUT'])
def updateMesas(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + '/mesas/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/mesas/<string:id>", methods=['DELETE'])
def deleteMesas(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + '/mesas/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/mesas/<string:id>", methods=['GET'])
def showMesas(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + '/mesas/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/buscarMesa/<string:id>", methods=['GET'])
def getbuscarMesa(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + '/buscarMesa/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
#FIN Rutas de mesas en el API-GATEWAY

#Rutas de resultados en el API-GATEWAY
@app.route("/resultados", methods=['GET'])
def getResultados():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + '/resultados'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultados/mesas/<string:id_mesa>/candidatos/<string:id_candidato>", methods=['POST'])
def createResultados(id_mesa, id_candidato):
     data = request.get_json()
     headers = {"Content-Type": "application/json; charset=utf-8"}
     url = dataConfig['url-backend-registry'] + '/resultados/mesas/' + id_mesa + '/candidatos/'+ id_candidato
     response = requests.post(url, headers=headers, json=data)
     json = response.json()
     return jsonify(json)

@app.route("/resultados/<string:id_resultado>/mesas/<string:id_mesa>/candidatos/<string:id_candidato>", methods=['PUT'])
def updateResultados(id_resultado, id_mesa, id_candidato):
     data = request.get_json()
     headers = {"Content-Type": "application/json; charset=utf-8"}
     url = dataConfig['url-backend-registry'] + '/resultados/' + id_resultado +'/mesas/' + id_mesa + '/candidatos/' + id_candidato
     response = requests.put(url, headers=headers, json=data)
     json = response.json()
     return jsonify(json)

@app.route("/resultados/<string:id>", methods=['DELETE'])
def deleteResultados(id):
     headers = {"Content-Type": "application/json; charset=utf-8"}
     url = dataConfig['url-backend-registry'] + '/resultados/' + id
     response = requests.delete(url, headers=headers)
     json = response.json()
     return jsonify(json)

@app.route("/resultados/<string:id>", methods=['GET'])
def showResultados(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + '/resultados/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
#FIN Rutas de resultados en el API-GATEWAY

@app.before_request
def before_request():
    endPoint = limpiar_url(request.path)
    excludedRoutes = ["/login", "/register"]
    if excludedRoutes.__contains__(request.path):
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        if usuario["rol"] is not None:
            tienePermiso = validarPermiso(endPoint, request.method, usuario["rol"]["_id"])
            if tienePermiso:
                pass
            else:
                return jsonify({"message": "Permiso denegado"})
        else:
            return jsonify({"message": "Permiso denegado, no se ha asignado el rol"})

def limpiar_url(url):
    partes = url.split('/')
    for parte in partes:
        if re.search('\\d', parte):
            url = url.replace(parte, "?")
    return url

def validarPermiso(endPoint, metodo, rol):
    url = dataConfig['url-backend-security'] + "/permisos-roles/validar-permiso/rol/" + str(rol)
    tienePermiso = False
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body = {
        "url": endPoint,
        "metodo": metodo
    }
    response = requests.get(url, json=body, headers=headers)
    try:
        data = response.json()
        if ("_id" in data):
            tienePermiso = True
    except:
        pass
    return tienePermiso

@app.route("/", methods=['GET'])
def test():
    json = {}
    json["message"] = "Servidor ejecutandose..."
    return jsonify(json)

def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data

if __name__ == '__main__':
    dataConfig = loadFileConfig()
    print("Servidor ejecutandose... http://" + dataConfig['url-backend'] + ":" + str(dataConfig['port']))
    serve(app, host=dataConfig['url-backend'], port=dataConfig['port'])

