__author__ = 'Vitalii Balashov'

import re
import json
import hashlib
from dojo.models import Finding


class AnchoreJSONParser(object):
    def __init__(self, filename, test):
        bug_patterns = dict()
        dupes = dict()

        all_findings = json.load(filename)

        for bug in all_findings["data"]:
            desc = """
                Image %s is includes a known vulnerabily
                with id %s. 
                Vulnerable component is %s.
                Please, find the recommendation below in "mitigation" block.
                """ % (bug[0], bug[1], bug[3])

            dupe_key = hashlib.md5(str(bug)).hexdigest()

            title = "Component " + bug[3] + " is vulnerable for: " + bug[1]
            cwe = 0
            severity = bug[2]

            # Normalization of severities
            if severity == "Negligible" or severity == "Unknown":
                severity = "Low"

            description = desc

            url = re.findall('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', bug[5])
            mitigation = """
            Please find the recommendations in the offical soures:[%s](%s)
            """ % (url[0], url[0])

            impact = "N/A"
            references = "N/A"

            if dupe_key in dupes:
                finding = dupes[dupe_key]
            else:
                finding = Finding(
                    title=title,
                    cwe=cwe,
                    severity=severity,
					description=description,
                    mitigation=mitigation,
                    impact=impact,
                    references=references,
                    test=test,
                    active=False,
                    verified=False,
                    numerical_severity=Finding.get_numerical_severity(severity),
                    static_finding=True
                )
                dupes[dupe_key] = finding

        self.items = dupes.values()


