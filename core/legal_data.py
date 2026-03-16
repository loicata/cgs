"""
CGS — Country-specific legal data.

Contacts, procédures de dépôt de plainte, législation applicable
et modèles de déclaration pour chaque pays supporté.

Supported countries :
  - IE : Ireland (An Garda Síochána, NCSC Ireland)
  - FR : France (ANSSI, Police/Gendarmerie, CNIL)
  - US : United States (FBI IC3, CISA, FTC)
"""

COUNTRIES = {

    # ══════════════════════════════════════════════
    # IRLANDE
    # ══════════════════════════════════════════════
    "IE": {
        "name": "Ireland",
        "flag": "🇮🇪",
        "lang": "en",

        "police": {
            "name": "An Garda Síochána",
            "unit": "Garda National Cyber Crime Bureau (GNCCB)",
            "how": "Se rendre au commissariat local (Garda Station) avec le rapport et le fichier forensique sur clé USB",
            "phone": "1800 250 025 (Crimestoppers, anonyme)",
            "url": "https://www.garda.ie/en/crime/cyber-crime/",
            "note": "Le GNCCB dispose d'experts en forensique informatique pouvant témoigner en tribunal.",
        },

        "csirt": {
            "name": "NCSC / CSIRT-IE",
            "role": "Signalement d'incident technique (enrichit la veille nationale)",
            "email": "certreport@ncsc.gov.ie",
            "email_alt": "incident@ncsc.gov.ie",
            "phone": "+353 1 678 2333",
            "pgp": "9BA0 07E2 9FFD 368D EE1E E6C6 43D5 224D 2432 B331",
            "pgp_url": "https://www.ncsc.gov.ie/PGP/pgpkey.asc",
            "address": "NCSC, Dept. of Justice, Tom Johnson House, Haddington Road, D04 K7X4, Dublin",
            "url": "https://www.ncsc.gov.ie/incidentreporting/",
        },

        "nis2": {
            "applicable": True,
            "contact": "nis2@ncsc.gov.ie",
            "deadlines": "24h alerte précoce, 72h notification détaillée, 1 mois rapport final",
        },

        "dpa": {
            "name": "Data Protection Commission (DPC)",
            "url": "https://forms.dataprotection.ie/report-a-breach",
            "deadline": "72h",
        },

        "eu_portal": {
            "url": "https://www.europol.europa.eu/report-a-crime/report-cybercrime-online",
            "note": "Europol redirige vers les autorités nationales (Gardaí pour l'Ireland).",
        },

        "laws": [
            "Criminal Justice (Offences Relating to Information Systems) Act 2017",
            "Criminal Damage Act 1991 (Section 5 — Unauthorised access to data)",
            "Criminal Justice (Theft and Fraud Offences) Act 2001",
        ],

        "pdf_declaration": (
            "Je soussigné(e), déclare par la présente que les informations "
            "contenues dans ce document sont exactes à ma connaissance. "
            "Les données techniques ont été collectées automatiquement par le "
            "système CGS et n'ont pas été modifiées. "
            "Je souhaite porter plainte pour les faits décrits ci-dessus, "
            "constitutifs d'une ou plusieurs infractions au regard du droit irlandais."
        ),

        "pdf_id_fields": [
            ("Entreprise / Organisation", ""),
            ("Adresse", ""),
            ("Eircode", ""),
            ("Nom du déclarant", ""),
            ("Fonction", ""),
            ("Phone", ""),
            ("Email", ""),
        ],

        "impact_fields": [
            ("Données compromises", "☐ Oui    ☐ Non    ☐ Unknown"),
            ("Type de données", "☐ Personnelles (RGPD)  ☐ Financières  ☐ Commerciales  ☐ Autres"),
            ("Service interrompu", "☐ Oui    ☐ Non    Duration : ____________"),
            ("Nb postes affectés", "____________"),
            ("Pertes financières", "☐ Oui    ☐ Non    Montant estimé : ____________ EUR"),
            ("Rançon demandée", "☐ Oui    ☐ Non    Montant : ____________"),
        ],
    },

    # ══════════════════════════════════════════════
    # FRANCE
    # ══════════════════════════════════════════════
    "FR": {
        "name": "France",
        "flag": "🇫🇷",
        "lang": "fr",

        "police": {
            "name": "Police Nationale / Gendarmerie Nationale",
            "unit": "OCLCTIC (Office Central de Lutte contre la Criminalité liée aux TIC) / C3N (Gendarmerie)",
            "how": "File a complaint au commissariat ou à la brigade de gendarmerie, ou en ligne via la plateforme THESEE pour les escroqueries en ligne",
            "phone": "0 805 805 817 (Info Escroqueries, gratuit)",
            "url": "https://www.service-public.fr/particuliers/vosdroits/N31138",
            "url_online": "https://www.masecurite.interieur.gouv.fr/fr/demarches-en-ligne/plainte-en-ligne",
            "note": "Pour les entreprises, le dépôt de plainte peut aussi se faire auprès du Procureur de la République.",
        },

        "csirt": {
            "name": "ANSSI / CERT-FR",
            "role": "Signalement d'incident de sécurité informatique (obligatoire pour les OIV et OSE)",
            "email": "cert-fr.cossi@ssi.gouv.fr",
            "email_alt": "",
            "phone": "+33 1 71 75 84 68",
            "pgp": "",
            "pgp_url": "https://www.cert.ssi.gouv.fr/contact/",
            "address": "ANSSI, 51 boulevard de la Tour-Maubourg, 75700 Paris 07 SP",
            "url": "https://www.cert.ssi.gouv.fr/",
            "url_form": "https://www.cert.ssi.gouv.fr/contact/",
        },

        "nis2": {
            "applicable": True,
            "contact": "cert-fr.cossi@ssi.gouv.fr",
            "deadlines": "24h alerte précoce, 72h notification détaillée, 1 mois rapport final",
        },

        "dpa": {
            "name": "CNIL (Commission Nationale de l'Informatique et des Libertés)",
            "url": "https://notifications.cnil.fr/notifications/index",
            "deadline": "72h",
        },

        "eu_portal": {
            "url": "https://www.europol.europa.eu/report-a-crime/report-cybercrime-online",
            "note": "Europol redirige vers les autorités nationales.",
        },

        "extra_resources": {
            "cybermalveillance": {
                "name": "Cybermalveillance.gouv.fr",
                "role": "Plateforme nationale d'assistance aux victimes de cybermalveillance",
                "url": "https://www.cybermalveillance.gouv.fr/",
                "note": "Diagnostic en ligne gratuit et mise en relation avec des prestataires labellisés.",
            },
        },

        "laws": [
            "Code pénal — Art. 323-1 à 323-8 (Atteintes aux STAD)",
            "Loi n°78-17 du 6 janvier 1978 (Informatique et Libertés)",
            "Règlement Général sur la Protection des Données (RGPD)",
            "Loi n°2024-449 (transposition NIS2)",
        ],

        "pdf_declaration": (
            "Je soussigné(e), déclare par la présente que les informations "
            "contenues dans ce document sont exactes à ma connaissance. "
            "Les données techniques ont été collectées automatiquement par le "
            "système CGS et n'ont pas été modifiées. "
            "Je souhaite porter plainte pour les faits décrits ci-dessus, "
            "constitutifs d'une ou plusieurs infractions aux articles 323-1 "
            "à 323-8 du Code pénal (atteintes aux systèmes de traitement "
            "automatisé de données)."
        ),

        "pdf_id_fields": [
            ("Reason sociale", ""),
            ("SIRET", ""),
            ("Adresse du siège", ""),
            ("Code postal / Ville", ""),
            ("Nom du déclarant", ""),
            ("Fonction", ""),
            ("Phone", ""),
            ("Email", ""),
        ],

        "impact_fields": [
            ("Données compromises", "☐ Oui    ☐ Non    ☐ Unknown"),
            ("Type de données", "☐ Personnelles (RGPD)  ☐ Financières  ☐ Commerciales  ☐ Autres"),
            ("Notification CNIL", "☐ Effectuée    ☐ En cours    ☐ Non applicable"),
            ("Service interrompu", "☐ Oui    ☐ Non    Duration : ____________"),
            ("Nb postes affectés", "____________"),
            ("Préjudice financier", "☐ Oui    ☐ Non    Montant estimé : ____________ EUR"),
            ("Rançon demandée", "☐ Oui    ☐ Non    Montant : ____________"),
        ],
    },

    # ══════════════════════════════════════════════
    # ÉTATS-UNIS
    # ══════════════════════════════════════════════
    "US": {
        "name": "United States",
        "flag": "🇺🇸",
        "lang": "en",

        "police": {
            "name": "FBI — Internet Crime Complaint Center (IC3)",
            "unit": "IC3 (signalement en ligne) + bureau local FBI",
            "how": "File a complaint en ligne sur ic3.gov (formulaire dédié aux cybercrimes) et contacter le bureau local du FBI",
            "phone": "1-800-CALL-FBI (1-800-225-5324)",
            "url": "https://www.ic3.gov/",
            "url_online": "https://www.ic3.gov/Home/ComplaintChoice",
            "note": "L'IC3 accepte les signalements en ligne avec upload de preuves. Le fichier forensique peut être joint directement.",
        },

        "csirt": {
            "name": "CISA (Cybersecurity and Infrastructure Security Agency)",
            "role": "Signalement d'incident de cybersécurité (recommandé pour toute organisation)",
            "email": "report@cisa.gov",
            "email_alt": "",
            "phone": "1-888-282-0870",
            "pgp": "",
            "pgp_url": "",
            "address": "CISA, 245 Murray Lane SW, Washington, DC 20528",
            "url": "https://www.cisa.gov/report",
            "url_form": "https://www.cisa.gov/report",
        },

        "nis2": {
            "applicable": False,
        },

        "dpa": {
            "name": "FTC (Federal Trade Commission) + State Attorney General",
            "url": "https://reportfraud.ftc.gov/",
            "url_identity": "https://www.identitytheft.gov/",
            "deadline": "Varies by state (California: 72h, New York: ASAP)",
        },

        "eu_portal": None,

        "extra_resources": {
            "secret_service": {
                "name": "U.S. Secret Service — Cyber Fraud Task Force",
                "role": "Enquêtes sur les fraudes financières et cybercriminelles",
                "url": "https://www.secretservice.gov/investigation/cyber",
            },
        },

        "laws": [
            "Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030",
            "Identity Theft and Assumption Deterrence Act, 18 U.S.C. § 1028",
            "Electronic Communications Privacy Act (ECPA)",
            "State-specific data breach notification laws",
        ],

        "pdf_declaration": (
            "I, the undersigned, hereby declare that the information contained "
            "in this document is accurate to the best of my knowledge. "
            "The technical data was automatically collected by the CGS "
            "Sentinel defense system and has not been altered. "
            "I wish to report the above-described incident as a potential "
            "violation of the Computer Fraud and Abuse Act (18 U.S.C. § 1030) "
            "and/or other applicable federal and state cybercrime statutes."
        ),

        "pdf_id_fields": [
            ("Company / Organization", ""),
            ("Address", ""),
            ("City, State, ZIP", ""),
            ("Contact Name", ""),
            ("Title / Role", ""),
            ("Phone", ""),
            ("Email", ""),
            ("EIN (optional)", ""),
        ],

        "impact_fields": [
            ("Data compromised", "☐ Yes    ☐ No    ☐ Unknown"),
            ("Data type", "☐ PII  ☐ Financial  ☐ Trade secrets  ☐ PHI (HIPAA)  ☐ Other"),
            ("Service disruption", "☐ Yes    ☐ No    Duration: ____________"),
            ("Systems affected", "____________"),
            ("Financial losses", "☐ Yes    ☐ No    Estimated: $ ____________"),
            ("Ransom demanded", "☐ Yes    ☐ No    Amount: $ ____________"),
            ("Ransom paid", "☐ Yes    ☐ No    Amount: $ ____________"),
        ],
    },
}


def get_country(code: str) -> dict:
    """Returns les données juridiques d'un pays (ou IE par défaut)."""
    return COUNTRIES.get(code.upper(), COUNTRIES["IE"])


def get_supported_countries() -> list[tuple[str, str, str]]:
    """Returns la liste des pays supportés : [(code, flag, name), ...]"""
    return [(code, d["flag"], d["name"]) for code, d in COUNTRIES.items()]
