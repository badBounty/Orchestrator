from ..src.mongo import mongo


def load_information(vuln_name, language):
    info = mongo.get_observation_for_object(vuln_name, language)
    return info


class Observation:

    def __init__(self, vuln_name, language):

        info = load_information(vuln_name, language)
        self.language = language
        self.type = info['TYPE']
        self.title = info['TITLE']
        self.observation_title = info['OBSERVATION']['TITLE']
        self.observation_note = info['OBSERVATION']['NOTE']
        self.implication = info['IMPLICATION']
        self.recommendation_title = info['RECOMMENDATION']['TITLE']
        self.recommendation_urls = info['RECOMMENDATION']['URLS']
        self.severity = info['SEVERITY']
        self.effort_to_fix = info['EFFORT TO FIX']
        self.cibc_risk = info['CIBC RISK']
        self.impact = info['IMPACT']
        self.likelihood = info['LIKELIHOOD']
        self.attacker_objective = info['ATTACKER OBJECTIVE AND APPROACH']
        self.how_to = info['HOW TO']
        self.summary = info['SUMMARY']
        self.comments = info['COMMENTS']
