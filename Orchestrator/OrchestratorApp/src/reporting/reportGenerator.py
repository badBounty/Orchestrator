# Nombre del reporte
# Findins con titulo y recursos afectados
# En base al titulo se obtienen de una DB  (so far json file)
# Parametros a recibir:
#   Idioma: eng o spa
#   Tipo Reporte: S o F (indica si es Estado o Final)
#   json con los titulos de los findings a buscar

from copy import deepcopy

import datetime,docx,json,os,ast

from .. import constants
from ..mongo import mongo

# Variables Generales
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
# Determina el idioma del reporte
eng = False
# Determina el tipo de reporte
estado = True
# Estos indices son para copiar el finding de inicio a fin varian segundo el tipo de reporte
indexNros = (0, 0, 0)
# Documento
doc = docx.Document()


############################################################
# PARA REPORTES ESTADO DE AVANCE EN ESPAÑOL O FINAL SLATAM #
############################################################
# Se agrega la informacion del cliente dependiente del tipo de reporte
def setClientInDoc(doc, estado, client):
    if client:
        if estado:
            cliText = doc.tables[0].cell(1, 1).text.replace("<CLIENTE>", client)
            doc.tables[0].cell(1, 1).text = cliText
            footerCli = doc.sections[0].footer.tables[0].cell(0, 1).paragraphs[0].runs[0].text.replace("<CLIENTE>",
                                                                                                       client)
            doc.sections[0].footer.tables[0].cell(0, 1).paragraphs[0].runs[0].text = footerCli
        else:
            cliText = doc.tables[1].cell(0, 0).paragraphs[0].text.replace("<CLIENTE>", client)
            doc.tables[1].cell(0, 0).paragraphs[0].text = cliText
            headerText = doc.sections[0].header.paragraphs[0].runs[3].text.replace("<CLIENTE>", client)
            doc.sections[0].header.paragraphs[0].runs[3].text = headerText
            # Declaracion de responsabilidad
            for i in range(3, 7):
                paraText = doc.paragraphs[i].text.replace("<CLIENTE>", client)
                doc.paragraphs[i].text = paraText
            # Privado y confidencial
            for i in range(31, 34):
                paraText = doc.paragraphs[i].text.replace("<CLIENTE>", client)
                doc.paragraphs[i].text = paraText
                # Resumen ejecutivo
                paraText = doc.paragraphs[54].text.replace("<CLIENTE>", client)
                doc.paragraphs[54].text = paraText


# Buscamos la nota en el listado de los paragraph
def agregarNota(p, nota):
    if "Nota" in p.text:
        p.text = "Nota: " + nota
    elif "Note:" in p.text:
        p.text = "Note: " + nota

def add_cves(jsonFinding):
    message=""
    if jsonFinding['extra_info'] != None :
        for info in ast.literal_eval(jsonFinding['extra_info']):
            info_title= "Name: "+info['name']
            version = info['versions'][0] if info['versions'] else ""
            last_version = info['last_version']
            if version or last_version:
                info_title+=' Version: '+version+' Last Version :'+last_version
            message+="\t"+info_title+'\n'
            for cve in info['cves']:
                cve_info='CVE ID: '+cve['CVE ID']+' - Vulnerability: '+cve['Vulnerability Type(s)']+'- CVSS Score: '+cve['Score']
                message+="\t\t"+cve_info+'\n'
    return message

# Agregar info en celda sin romper formato
def addFindingInfo(table, language, urls):
    # ---------------------Recursos afectados--------------------------------
    paragNumber = 0
    resourcesTitle = table.cell(0, 0).paragraphs[paragNumber]
    # Cargamos los recursos afectados y borramos los valores que trae el documento por defecto
    tableResources = table.cell(1, 0)
    paragraph = tableResources.paragraphs[paragNumber]
    urlsSize = len(urls)
    if urlsSize > 1:
        resourcesTitle.text = constants.recursoAfectadoPlu_EN if language else constants.recursoAfectadoPlu_ES
        if urlsSize < 3:
            for rec in urls:
                p = deepcopy(paragraph)
                p.text = rec
                paragraph._p.addnext(p._p)
                paragNumber += 1
        else:
            p = deepcopy(paragraph)
            p.text = "CREAR APENDICE"
            paragraph._p.addnext(p._p)
            paragNumber += 1
        # Borro primer recurso ya que no se necesita
        p1 = tableResources.paragraphs[0]._element
        p1.getparent().remove(p1)
        p1._p = p1._element = None
    else:
        # Al ser un solo recurso va en singular
        resourcesTitle.text = constants.recursoAfectadoSin_EN if language else constants.recursoAfectadoSin_ES
        paragraph.text = urls


def clonarTemplateYAgregarFinding(doc, indexNros, language, jsonFinding):
    nroParagraph = indexNros[0]
    nroTable = indexNros[1]
    nroPageBreak = indexNros[2]
    urls = jsonFinding['resourceAf']
    refUrls = jsonFinding['RECOMMENDATION']['URLS']
    page_break = doc.paragraphs[nroPageBreak]
    templateParag = deepcopy(doc.paragraphs[nroParagraph])
    # Titulo finding
    runNro = 9
    if not indexNros[3]: runNro = 7
    templateParag.runs[runNro].text = jsonFinding['TITLE']
    # Agarra pagebreak anterior y pone el nuevo titulo abajo
    page_break._p.addnext(templateParag._p)
    # Agregar todo el contenido
    new_tbl = deepcopy(doc.tables[nroTable])
    p, pb = templateParag._p, page_break._p
    new_pb = deepcopy(pb)
    p.addnext(new_pb)
    # Clonamos toda la informacion que es parte del finding (Observacion, tabla, impacto, etc.)
    obsTitle = deepcopy(doc.paragraphs[nroParagraph + 2])
    obsText = deepcopy(doc.paragraphs[nroParagraph + 3])
    urlTitle = deepcopy(doc.paragraphs[nroParagraph + 4])
    obsNote = deepcopy(doc.paragraphs[nroParagraph + 7])
    legendTable = deepcopy(doc.paragraphs[nroParagraph + 8])
    figureText = deepcopy(doc.paragraphs[nroParagraph + 9])
    legendFigure = deepcopy(doc.paragraphs[nroParagraph + 10])
    impactTitle = deepcopy(doc.paragraphs[nroParagraph + 11])
    impactDesc = deepcopy(doc.paragraphs[nroParagraph + 12])
    likelihoodTitle = deepcopy(doc.paragraphs[nroParagraph + 13])
    likelihoodDesc = deepcopy(doc.paragraphs[nroParagraph + 14])
    recomendTitle = deepcopy(doc.paragraphs[nroParagraph + 15])
    recomendNote = deepcopy(doc.paragraphs[nroParagraph + 16])
    recomendText = deepcopy(doc.paragraphs[nroParagraph + 17])
    referenceTitle = deepcopy(doc.paragraphs[nroParagraph + 18])
    referenceLinkLegend = deepcopy(doc.paragraphs[nroParagraph + 19])
    # Cargamos la informacion en base a lo que se tenga
    # URLS RECOMENDACIONES
    if len(refUrls) >= 1:
        for url in refUrls:
            urlRef = deepcopy(doc.paragraphs[nroParagraph + 20])
            urlRef.text = url
            p.addnext(urlRef._p)
        if len(refUrls) > 1:
            referenceLinkLegend.text = constants.enlacesRecomendacion_EN if language else constants.enlacesRecomendacion_ES
            p.addnext(referenceLinkLegend._p)
        else:
            p.addnext(referenceLinkLegend._p)
        p.addnext(referenceTitle._p)
    recomendText.text = jsonFinding['RECOMMENDATION']['TITLE']
    p.addnext(recomendText._p)
    p.addnext(recomendNote._p)
    p.addnext(recomendTitle._p)
    p.addnext(likelihoodDesc._p)
    p.addnext(likelihoodTitle._p)
    impactDesc.text = jsonFinding['IMPLICATION']
    p.addnext(impactDesc._p)
    p.addnext(impactTitle._p)
    p.addnext(legendFigure._p)
    p.addnext(figureText._p)
    p.addnext(legendTable._p)
    mid_tbl = deepcopy(doc.tables[nroTable + 1])
    p.addnext(mid_tbl._tbl)
    if jsonFinding['OBSERVATION']['NOTE']:
        agregarNota(obsNote, jsonFinding['OBSERVATION']['NOTE'])
    else:
        obsNote.text = ""
    p.addnext(obsNote._p)
    for url in urls:
        urlExample = deepcopy(doc.paragraphs[nroParagraph + 5])
        urlExample.text = url
        p.addnext(urlExample._p)
    if len(urls) == 1:
        urlTitle.text = constants.urlAfectada_EN if language else constants.urlAfectada_ES
        p.addnext(urlTitle._p)
    else:
        p.addnext(urlTitle._p)
    obsText.text = jsonFinding['OBSERVATION']['TITLE']
    obsText.text+= add_cves(jsonFinding)
    p.addnext(obsText._p)
    p.addnext(obsTitle._p)
    # Espacio vacio para respetar el formato
    p.addnext(deepcopy(doc.paragraphs[nroParagraph + 1])._p)
    p.addnext(new_tbl._tbl)
    addFindingInfo(new_tbl, language, urls)


def crearReporte(language, reportType, client, findings):
    eng = True if language == "eng" else False
    estado = True if reportType == "S" else False
    global doc
    # Template a utilizar acorde al tipo de reporte que se necesite generar, va a variar dependiendo del idioma, avance o final
    if not eng:
        if estado:
            doc = docx.Document(ROOT_DIR + '/out/TEMPLATE - REPORTE DE ESTADO - DELOITTE S-LATAM - v1.1.docm')
            indexNros = (13, 3, 34, estado)
        else:
            doc = docx.Document(ROOT_DIR + '/out/TEMPLATE - REPORTE FINAL - DELOITTE S-LATAM - v1.docm')
            indexNros = (76, 5, 97, estado)
    else:
        if estado:
            # Voy a necesitar los reportes para ingles POR AHORA USA REPORTE DE ESTADO
            doc = docx.Document(ROOT_DIR + '/out/TEMPLATE - REPORTE DE ESTADO - DELOITTE S-LATAM - v1.1.docm')
            indexNros = (13, 3, 34, estado)
        else:
            doc = docx.Document(ROOT_DIR + '/out/TEMPLATE - REPORTE FINAL - DELOITTE S-LATAM - v1.docm')
            indexNros = (76, 5, 97, estado)

    # Itero sobre la lista recibida si el finding existe lo agrego sino pongo un mensaje de alerta
    print("Generando Reporte espere")
    setClientInDoc(doc, estado, client)
    for finding in findings:
        # Obtenemos finding de la KB
        json_value = mongo.get_specific_finding_info(finding, language)
        if json_value:
            clonarTemplateYAgregarFinding(doc, indexNros, eng, json_value)
        else:
            #TODO mensaje a slack
            print("The following finding was not found: "+finding['title'])
    print("Se genero el reporte con los findings que fueron encontrados")
    d1 = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    name = ""
    # Muy probable que esto cambie
    if not eng:
        if estado:
            name += client + "REPORTE_DE_ESTADO_" + d1 + ".docm"
            doc.save(ROOT_DIR + '/out/' + name)
        else:
            name += client + "REPORTE_FINAL_" + d1 + ".docm"
            doc.save(ROOT_DIR + '/out/' + name)
    else:
        name += client + "REPORTE_CON_FINDINGS_INGLES-" + d1 + ".docm"
        doc.save(ROOT_DIR + '/out/' + name)
    return ROOT_DIR + '/out/' + name