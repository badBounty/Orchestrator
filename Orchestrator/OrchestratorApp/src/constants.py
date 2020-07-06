"""
CONSTANTS.PY
"""

### LANGUAGES ###
LANGUAGE_ENGLISH = 'eng'
LANGUAGE_SPANISH = 'spa'

### GENERAL ###
BURP_SCAN = {
    'english_name': '[BURP SCAN] - ',
    'spanish_name': '[BURP SCAN] - ',
}

NESSUS_SCAN = {
    'english_name': '[NESSUS SCAN] - ',
    'spanish_name': '[NESSUS SCAN] - ',
}

ACUNETIX_SCAN = {
    'english_name': '[ACUNETIX SCAN] - ',
    'spanish_name': '[ACUNETIX SCAN] - ',
}

### VULNERABILITIES ###
INVALID_VALUE_ON_HEADER = {
    'english_name': 'Insecure HTTP Response Header Configuration',
    'spanish_name': 'Inadecuada configuración de encabezados de seguridad',
    'status' : 1
}
HEADER_NOT_FOUND = {
    'english_name': 'Insecure HTTP Response Header Configuration',
    'spanish_name': 'Inadecuada configuración de encabezados de seguridad',
    'status': 1
}
HOST_HEADER_ATTACK = {
    'english_name': 'Host header attack possible',
    'spanish_name': 'Ataque de cabecera Host posible',
    'status': 12
}
UNSECURE_METHOD = {
    'english_name': 'Extended HTTP methods enabled',
    'spanish_name': 'Métodos HTTP extendidos habilitados',
    'status': 12
}
SSL_TLS = {
    'english_name': 'Weak transport layer security (TLS) configuration',
    'spanish_name': 'Inadecuada configuración de seguridad de capa de transporte (TLS)',
    'status': 1
}
OUTDATED_3RD_LIBRARIES = {
    'english_name': 'Outdated 3rd party libraries in use',
    'spanish_name': 'Librerias 3rd party desactualizadas en uso',
    'status': 12
}
CORS = {
    'english_name': 'CORS vulnerability found',
    'spanish_name': 'Se encontro una vulnerabilidad de CORS',
    'status': 12
}
ENDPOINT = {
    'english_name': 'Vulnerable endpoints were found',
    'spanish_name': 'Se encontraron endpoints vulnerables',
    'status': 12
}
BUCKET = {
    'english_name': 'Misconfiguration in Bucket found',
    'spanish_name': 'Mala configuración en Bucket',
    'status': 1
}
TOKEN_SENSITIVE_INFO = {
    'english_name': 'Token information disclosure was found',
    'spanish_name': 'Token con informacion sensible encontrado',
    'status': 12
}
CSS_INJECTION = {
    'english_name': 'Possible css injection found',
    'spanish_name': 'Posible inyeccion css',
    'status': 12
}
OPEN_FIREBASE = {
    'english_name': 'Firebase found open',
    'spanish_name': 'Se encontro firebase abierta',
    'status': 1
}
OUTDATED_SOFTWARE_NMAP = {
    'english_name': 'Outdated software in use',
    'spanish_name': 'Software desactualizado',
    'status': 1
}
HTTP_PASSWD_NMAP = {
    'english_name': 'Path traversal found',
    'spanish_name': 'Path traversal encontrado',
    'status': 12
}
WEB_VERSIONS_NMAP = {
    'english_name': 'Web versions vulnerabilities found',
    'spanish_name': 'Vulnerabilidades de versiones web encontradas',
    'status': 1
}
ANON_ACCESS_FTP = {
    'english_name': 'Anonymous access to FTP server',
    'spanish_name': 'Permisos de escritura en servidor FTP en forma anónima',
    'status': 1
}
# TODO revisar spanish name
CRED_ACCESS_FTP = {
    'english_name': 'Access to FTP server with default credentials',
    'spanish_name': 'Acceso administrativo mediante usuarios por defecto',
    'status': 1
}
DEFAULT_CREDS = {
    'english_name': 'Default credentials in use',
    'spanish_name': 'Acceso administrativo mediante usuarios por defecto',
    'status': 1
}
IIS_SHORTNAME_MICROSOFT = {
    'english_name': 'Microsoft short name directory and file enumeration',
    'spanish_name': 'Enumeración de nombres cortos de archivos y directorios de Microsoft',
    'status': 1
}
POSSIBLE_ERROR_PAGES = {
    'english_name': 'Possible information disclosure within system error messages',
    'spanish_name': 'Posible inadecuado manejo de errores',
    'status': 12
}
PLAINTEXT_COMUNICATION = {
    'english_name': 'Plaintext communication services',
    'spanish_name': 'Comunicación no cifrada',
    'status': 1
}
UNNECESSARY_SERVICES = {
    'english_name': 'Unnecessary services exposed to the Internet',
    'spanish_name': 'Servicios innecesarios disponibles en internet',
    'status': 1
}

# HEADERS #
INVALID_VALUE_ON_HEADER_DESCRIPTION = 'Header/s found with invalid value at %s'
HEADER_NOT_FOUND_DESCRIPTION = 'Certain security header/s were not found at %s'
X_FRAME_OPTIONS_NOT_PRESENT_DESCRIPTION = 'Clickjacking X-Frame-Options header missing at %s'
X_FRAME_OPTIONS_INVALID_DESCRIPTION = 'Clickjacking attack possible at %s'
HSTS_DESCRIPTION = 'HTTP Strict Transport Security not enforced at %s'
HOST_HEADER_ATTACK_DESCRIPTION = 'Host header attack possible at %s'
# METHODS #
UNSECURE_METHOD_DESCRIPTION = 'Extended HTTP methods enabled at %s. %s'
# SSL_TLS #
SSL_TLS_DESCRIPTION = 'Weak transport layer security (TLS) configuration at %s'
# OUTDATED 3RD PARTY LIBRARIES #
OUTDATED_3RD_LIBRARIES_DESCRIPTION = 'Outdated 3rd party libraries in use at %s, some extra info %s \n'
# CORS #
CORS_DESCRIPTION = 'CORS vulnerability found at %s. CORS type %s with origin %s'
# ENDPOINT #
ENDPOINT_DESCRIPTION = 'Vulnerable endpoints were found at %s. \n Extra info: \n %s'
# BUCKETS #
BUCKET_DESCRIPTION = 'Bucket %s found at %s'
# SENSITIVE INFO #
SENSITIVE_INFO_DESCRIPTION = 'Found at %s \n %s'
# CSS #
CSS_DESCRIPTION = 'Found at %s. %s'
# FIREBASE #
FIREBASE_DESCRIPTION = 'Firebase %s found open at %s'
# IIS SHORTNAME #
IIS_DESCRIPTION = 'IIS Microsoft files and directories enumeration found at %s'
# NMAP #
OUTDATED_SOFTWARE_NMAP_DESCRIPTION = 'Outdated software nmap script'
HTTP_PASSWD_NMAP_DESCRIPTION = 'Http passwd nmap script'
WEB_VERSIONS_NMAP_DESCRIPTION = 'Web versions nmap script'
# BURP #
BURP_SCAN_DESCRIPTION = 'Burp scan ran against %s'


### REPORTING ###
recursoAfectadoPlu_ES = "Recursos Afectados"
recursoAfectadoPlu_EN = "Affected Resources"
recursoAfectadoSin_ES = "Recurso Afectado"
recursoAfectadoSin_EN = "Affected Resource"
urlAfectada_ES = "La URL afectada es:"
urlAfectada_EN = "The affected URL is:"
libSingular_ES = "La librería afectada es:"
libSingular_EN = "The affected librarie is:"
enlacesRecomendacion_ES = "Para información adicional, por favor referirse a los siguientes enlaces: (con contenido en inglés)"
enlacesRecomendacion_EN = "For additional information, please refer to the following links :"