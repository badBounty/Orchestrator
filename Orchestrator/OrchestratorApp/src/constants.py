"""
CONSTANTS.PY
"""

### LANGUAGES ###
LANGUAGE_ENGLISH = 'eng'
LANGUAGE_SPANISH = 'spa'

### ENGLISH VULNERABILITIES ###
INVALID_VALUE_ON_HEADER_ENGLISH = 'Insecure HTTP Response Header Configuration'
HEADER_NOT_FOUND_ENGLISH = 'Insecure HTTP Response Header Configuration'
UNSECURE_METHOD_ENGLISH = 'Extended HTTP methods enabled'
SSL_TLS_ENGLISH = 'Weak transport layer security (TLS) configuration'

### SPANISH VULNERABILITIES ###
INVALID_VALUE_ON_HEADER_SPANISH = 'Inadecuada configuración de encabezados de seguridad'
HEADER_NOT_FOUND_SPANISH = 'Inadecuanda configuración de encabezados de seguridad'
UNSECURE_METHOD_SPANISH = 'Métodos HTTP extendidos habilitados'
SSL_TLS_SPANISH = 'Inadecuada configuración de seguridad de capa de transporte (TLS)'


'''
'Content-Security-Policy',      #Generico, ya est apuesto
'X-XSS-Protection',             #Generico
'x-frame-options',              # Clickjacking attack possible   # Clickjacking X-Frame-Options header missing
                                # Ataque de Clickjacking posible # Inexistencia de protección contra IFRAMES
                                # Generico
'X-Content-Type-options',       # Generico
'Strict-Transport-Security',    # Genrico
'Access-Control-Allow-Origin'   # Generico


'''
