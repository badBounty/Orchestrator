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
HOST_HEADER_ATTACK_ENGLISH = 'Host header attack possible'
# METHODS #
UNSECURE_METHOD_ENGLISH = 'Extended HTTP methods enabled'
# SSL_TLS #
SSL_TLS_ENGLISH = 'Weak transport layer security (TLS) configuration'
# OUTDATED 3RD PARTY LIBRARIES #
OUTDATED_3RD_LIBRARIES_ENGLISH = 'Outdated 3rd party libraries in use'
# CORS #
CORS_ENGLISH = 'CORS vulnerability found'
# ENDPOINT #
ENDPOINT_ENGLISH = 'Vulnerable endpoints were found'
# BUCKETS #
BUCKET_LS_ENGLISH = 'Bucket with ls allowed found'
BUCKET_NF_ENGLISH = 'Bucket is called but does not exist'
BUCKET_CPRM_ENGLISH = 'Bucket with copy remove allowed found'
# SENSITIVE INFO #
TOKEN_SENSITIVE_INFO_ENGLISH = 'Token information disclosure was found'
# CSS #
CSS_ENGLISH = 'Possible css injection found'
# FIREBASE #
FIREBASE_ENGLISH = 'Firebase found open'
# NMAP #
OUTDATED_SOFTWARE_NMAP_ENGLISH = 'Outdated software found'
HTTP_PASSWD_NMAP_ENGLISH = 'Path traversal found'
WEB_VERSIONS_NMAP_ENGLISH = 'Web versions vulnerabilities found'
# FTP #
ANONYMOUS_ACCESS_FTP_ENGLISH = 'Anonymous access to FTP server'
CREDENTIALS_ACCESS_FTP_ENGLISH = 'Access to FTP server with default credentials'
# SSH #
DEFAULT_CREDENTIALS_ENGLISH = 'Default credentials in use'
# IIS SHORTNAME #
IIS_SHORTNAME_MICROSOFT_ENGLISH = 'Microsoft short name directory and file enumeration'

### SPANISH VULNERABILITIES ###
# HEADERS #
INVALID_VALUE_ON_HEADER_SPANISH = 'Inadecuada configuración de encabezados de seguridad'
HEADER_NOT_FOUND_SPANISH = 'Inadecuada configuración de encabezados de seguridad'
X_FRAME_OPTIONS_NOT_PRESENT_SPANISH = 'Inexistencia de protección contra IFRAMES'
X_FRAME_OPTIONS_INVALID_SPANISH = 'Ataque de Clickjacking posible'
HSTS_SPANISH = 'HTTP Strict Transport Security (HSTS) no aplicada'
HOST_HEADER_ATTACK_SPANISH = 'Ataque de cabecera Host posible'
# METHODS #
UNSECURE_METHOD_SPANISH = 'Métodos HTTP extendidos habilitados'
# SSL_TLS #
SSL_TLS_SPANISH = 'Inadecuada configuración de seguridad de capa de transporte (TLS)'
# OUTDATED 3RD PARTY LIBRARIES #
OUTDATED_3RD_LIBRARIES_SPANISH = 'Librerias 3rd party desactualizadas en uso'
# CORS #
CORS_SPANISH = 'Se encontro una vulnerabilidad de CORS'
# ENDPOINT #
ENDPOINT_SPANISH = 'Se encontraron endpoints vulnerables'
# BUCKETS #
BUCKET_LS_SPANISH = 'Bucket con listado disponible encontrado'
BUCKET_NF_SPANISH = 'Bucket fue invocado pero no existe'
BUCKET_CPRM_SPANISH = 'Bucket con copia y borrado encontrado'
# SENSITIVE INFO #
TOKEN_SENSITIVE_INFO_SPANISH = 'Token con informacion sensible encontrado'
# CSS #
CSS_SPANISH = 'Posible inyeccion css'
# FIREBASE #
FIREBASE_SPANISH = 'Se encontro firebase abierta'
# NMAP #
OUTDATED_SOFTWARE_NMAP_SPANISH = 'Software desactualizado en uso'
HTTP_PASSWD_NMAP_SPANISH = 'Path traversal encontrado'
WEB_VERSIONS_NMAP_SPANISH = 'Vulnerabilidades de versiones web encontradas'
# FTP #
ANONYMOUS_ACCESS_FTP_SPANISH = 'Permisos de escritura en servidor FTP en forma anónima'
# SSH #TODO ESTO POR AHORA COORDINAR EL NOMBRE CORRECTO DESPUES
DEFAULT_CREDENTIALS_SPANISH = 'Acceso administrativo mediante usuarios por defecto'
# IIS SHORTNAME #
IIS_SHORTNAME_MICROSOFT_SPANISH = 'Enumeración de nombres cortos de archivos y directorios de Microsoft'

### REDMINE DESCRIPTIONS ###
# HEADERS #
REDMINE_INVALID_VALUE_ON_HEADER = 'Header/s found with invalid value at %s'
REDMINE_HEADER_NOT_FOUND = 'Certain security header/s were not found at %s'
REDMINE_X_FRAME_OPTIONS_NOT_PRESENT = 'Clickjacking X-Frame-Options header missing at %s'
REDMINE_X_FRAME_OPTIONS_INVALID = 'Clickjacking attack possible at %s'
REDMINE_HSTS = 'HTTP Strict Transport Security not enforced at %s'
REDMINE_HOST_HEADER_ATTACK = 'Host header attack possible at %s'
# METHODS #
REDMINE_UNSECURE_METHOD = 'Extended HTTP methods enabled at %s'
# SSL_TLS #
REDMINE_SSL_TLS = 'Weak transport layer security (TLS) configuration at %s'
# OUTDATED 3RD PARTY LIBRARIES #
REDMINE_OUTDATED_3RD_LIBRARIES = 'Outdated 3rd party libraries in use at %s, some extra info %s \n'
# CORS #
REDMINE_CORS = 'CORS vulnerability found at %s. CORS type %s with origin %s'
# ENDPOINT #
REDMINE_ENDPOINT = 'Vulnerable endpoints were found at %s. \n Extra info: \n %s'
# BUCKETS #
REDMINE_BUCKET = 'Bucket %s found at %s'
# SENSITIVE INFO #
REDMINE_SENSITIVE_INFO = 'Found at %s \n %s'
# CSS #
REDMINE_CSS = 'Found at %s. %s'
# FIREBASE #
REDMINE_FIREBASE = 'Firebase %s found open at %s'
# IIS SHORTNAME #
REDMINE_IIS = 'IIS Microsoft files and directories enumeration found at %s'
# NMAP #
REDMINE_OUTDATED_SOFTWARE_NMAP = 'Outdated software nmap script'
REDMINE_HTTP_PASSWD_NMAP = 'Http passwd nmap script'
REDMINE_WEB_VERSIONS_NMAP = 'Web versions nmap script'


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