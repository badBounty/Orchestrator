"""
CONSTANTS.PY
"""

### LANGUAGES ###
LANGUAGE_ENGLISH = 'eng'
LANGUAGE_SPANISH = 'spa'

### ENGLISH VULNERABILITIES ###
# HEADERS #
INVALID_VALUE_ON_HEADER_ENGLISH = 'Insecure HTTP Response Header Configuration'
HEADER_NOT_FOUND_ENGLISH = 'Insecure HTTP Response Header Configuration'
X_FRAME_OPTIONS_NOT_PRESENT_ENGLISH = 'Clickjacking X-Frame-Options header missing'
X_FRAME_OPTIONS_INVALID_ENGLISH = 'Clickjacking attack possible'
HSTS_ENGLISH = 'HTTP Strict Transport Security not enforced'
# METHODS #
UNSECURE_METHOD_ENGLISH = 'Extended HTTP methods enabled'
# SSL_TLS #
SSL_TLS_ENGLISH = 'Weak transport layer security (TLS) configuration'
# OUTDATED 3RD PARTY LIBRARIES #
OUTDATED_3RD_LIBRARIES_ENGLISH = 'Outdated 3rd party libraries in use'
# CORS #
CORS_ENGLISH = 'Found CORS %s with origin %s'
# ENDPOINT #
ENDPOINT_ENGLISH = 'Vulnerable endpoints were found'
# BUCKETS #
BUCKET_LS_ENGLISH = 'Bucket with ls allowed found'
BUCKET_NF_ENGLISH = 'Bucket is called but does not exist'
BUCKET_CPRM_ENGLISH = 'Bucket with copy remove allowed fund'
# SENSITIVE INFO #
SENSITIVE_INFO_ENGLISH = 'Sensitive information was found'
# CSS #
CSS_ENGLISH = 'Possible css injection at %s'
# FIREBASE #
FIREBASE_ENGLISH = 'Firebase %s was found open'
# NMAP #
OUTDATED_SOFTWARE_NMAP_ENGLISH = 'Outdated software nmap script'
HTTP_PASSWD_NMAP_ENGLISH = 'Http passwd nmap script'
WEB_VERSIONS_NMAP_ENGLISH = 'Web versions nmap script'

### SPANISH VULNERABILITIES ###
# HEADERS #
INVALID_VALUE_ON_HEADER_SPANISH = 'Inadecuada configuración de encabezados de seguridad'
HEADER_NOT_FOUND_SPANISH = 'Inadecuada configuración de encabezados de seguridad'
X_FRAME_OPTIONS_NOT_PRESENT_SPANISH = 'Inexistencia de protección contra IFRAMES'
X_FRAME_OPTIONS_INVALID_SPANISH = 'Ataque de Clickjacking posible'
HSTS_SPANISH = 'HTTP Strict Transport Security (HSTS) no aplicada'
# METHODS #
UNSECURE_METHOD_SPANISH = 'Métodos HTTP extendidos habilitados'
# SSL_TLS #
SSL_TLS_SPANISH = 'Inadecuada configuración de seguridad de capa de transporte (TLS)'
# OUTDATED 3RD PARTY LIBRARIES #
OUTDATED_3RD_LIBRARIES_SPANISH = 'Librerias 3rd party desactualizadas en uso'
# CORS #
CORS_SPANISH = 'Se encontro CORS %s usando origin %s'
# ENDPOINT #
ENDPOINT_SPANISH = 'Se encontraron endpoints vulnerables'
# BUCKETS #
BUCKET_LS_SPANISH = 'Bucket con listado disponible encontrado'
BUCKET_NF_SPANISH = 'Bucket fue invocado pero no existe'
BUCKET_CPRM_SPANISH = 'Bucket con copia y borrado encontrado'
# SENSITIVE INFO #
SENSITIVE_INFO_SPANISH = 'Se encontro informacion sensible'
# CSS #
CSS_SPANISH = 'Posible inyeccion css en %s'
# FIREBASE #
FIREBASE_SPANISH = 'Se encontro la firebase %s abierta'
# NMAP #
OUTDATED_SOFTWARE_NMAP_SPANISH = 'Software desactualizado nmap script'
HTTP_PASSWD_NMAP_SPANISH = 'Path traversal nmap script'
WEB_VERSIONS_NMAP_SPANISH = 'Versiones web nmap script'


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